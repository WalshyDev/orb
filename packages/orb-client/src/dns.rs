use hyper_util::client::legacy::connect::{
    HttpConnector,
    dns::{GaiResolver, Name},
};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower_service::Service;

use crate::events::{BoxedEventHandler, ClientEvent, noop_handler};

/// Represents a override rule
#[derive(Clone, Debug)]
pub struct OverrideRule {
    /// Source host pattern (empty = any)
    pub from_host: String,
    /// Source port (None = any)
    pub from_port: Option<u16>,
    /// Target host to connect to
    pub to_host: String,
    /// Target port to connect to
    pub to_port: u16,
}

impl OverrideRule {
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host_matches = self.from_host.is_empty() || self.from_host == host;
        let port_matches = self.from_port.is_none() || self.from_port == Some(port);
        host_matches && port_matches
    }

    /// Parse an override rule: "HOST1:PORT1:HOST2:PORT2"
    /// HOST1 and PORT1 can be empty for wildcard matching
    /// IPv6 addresses must be wrapped in brackets, e.g., "[::1]:80:[::1]:8080"
    pub fn parse(rule: &str) -> Option<Self> {
        let (from_host, rest) = parse_host_from_rule(rule)?;
        let rest = rest.strip_prefix(':')?;

        let (from_port_str, rest) = parse_port_from_rule(rest)?;
        let rest = rest.strip_prefix(':')?;

        let (to_host, rest) = parse_host_from_rule(rest)?;
        let rest = rest.strip_prefix(':')?;

        let (to_port_str, rest) = parse_port_from_rule(rest)?;

        // Should have consumed the entire string
        if !rest.is_empty() {
            return None;
        }

        // TARGET host cannot be empty
        if to_host.is_empty() {
            return None;
        }

        let from_port: Option<u16> = if from_port_str.is_empty() {
            None // Empty = any port
        } else {
            Some(from_port_str.parse().ok()?)
        };

        let to_port: u16 = to_port_str.parse().ok()?;

        Some(OverrideRule {
            from_host,
            from_port,
            to_host,
            to_port,
        })
    }
}

/// Parse a host from the beginning of a connect-to rule segment.
/// Handles IPv6 addresses in brackets (e.g., "[::1]").
/// Returns (host, remaining_string).
fn parse_host_from_rule(s: &str) -> Option<(String, &str)> {
    if s.starts_with('[') {
        // IPv6 address in brackets
        let end_bracket = s.find(']')?;
        let host = &s[1..end_bracket]; // Strip brackets
        let rest = &s[end_bracket + 1..];
        Some((host.to_string(), rest))
    } else {
        // Regular hostname or IPv4 - read until ':'
        match s.find(':') {
            Some(pos) => Some((s[..pos].to_string(), &s[pos..])),
            None => Some((s.to_string(), "")),
        }
    }
}

/// Parse a port from the beginning of a connect-to rule segment.
/// Returns (port_string, remaining_string).
fn parse_port_from_rule(s: &str) -> Option<(String, &str)> {
    // Read until ':' or end of string
    match s.find(':') {
        Some(pos) => Some((s[..pos].to_string(), &s[pos..])),
        None => Some((s.to_string(), "")),
    }
}

/// A DNS resolver that emits events during resolution
#[derive(Clone)]
pub struct OrbDnsResolver {
    inner: GaiResolver,
    event_handler: BoxedEventHandler,
}

impl OrbDnsResolver {
    pub fn new(event_handler: Option<BoxedEventHandler>) -> Self {
        Self {
            inner: GaiResolver::new(),
            event_handler: event_handler.unwrap_or_else(noop_handler),
        }
    }
}

impl Service<Name> for OrbDnsResolver {
    type Response = Box<dyn Iterator<Item = SocketAddr> + Send>;
    type Error = <GaiResolver as Service<Name>>::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_string();
        let start = Instant::now();
        let mut inner = self.inner.clone();
        let event_handler = self.event_handler.clone();

        Box::pin(async move {
            // Emit DNS resolution started event
            event_handler.on_event(ClientEvent::DnsResolutionStarted { host: host.clone() });

            let result = inner.call(name).await;
            let duration = start.elapsed();

            // Emit completion or failure event
            match result {
                Ok(addrs) => {
                    // Collect addresses to get the first IP for the event
                    let addrs_vec: Vec<SocketAddr> = addrs.collect();
                    if let Some(first_addr) = addrs_vec.first() {
                        event_handler.on_event(ClientEvent::DnsResolutionCompleted {
                            host,
                            ip: first_addr.ip(),
                            duration,
                        });
                    }
                    // Convert Vec back to an iterator of SocketAddr
                    Ok(Box::new(addrs_vec.into_iter())
                        as Box<dyn Iterator<Item = SocketAddr> + Send>)
                }
                Err(e) => {
                    event_handler.on_event(ClientEvent::DnsResolutionFailed { host, duration });
                    Err(e)
                }
            }
        })
    }
}

/// A connector that wraps HttpConnector and handles --connect-to URL rewriting
#[derive(Clone)]
pub struct OrbConnector {
    inner: HttpConnector<OrbDnsResolver>,
    overrides: Arc<Vec<OverrideRule>>,
    event_handler: BoxedEventHandler,
}

impl OrbConnector {
    pub fn new(
        overrides: Arc<Vec<OverrideRule>>,
        connect_timeout: Option<Duration>,
        event_handler: Option<BoxedEventHandler>,
    ) -> Self {
        let event_handler = event_handler.unwrap_or_else(noop_handler);
        let resolver = OrbDnsResolver::new(Some(event_handler.clone()));
        let mut http_connector = HttpConnector::new_with_resolver(resolver);
        http_connector.enforce_http(false);

        if let Some(timeout) = connect_timeout {
            http_connector.set_connect_timeout(Some(timeout));
        }

        Self {
            inner: http_connector,
            overrides,
            event_handler,
        }
    }

    fn rewrite_uri(&self, uri: http::Uri) -> http::Uri {
        let host = uri.host().unwrap_or("");
        let port = uri.port_u16().unwrap_or_else(|| {
            if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            }
        });

        // Find first override rule
        for rule in self.overrides.iter() {
            if rule.matches(host, port) {
                // Emit connect-to override event
                self.event_handler.on_event(ClientEvent::ConnectToOverride {
                    from_host: host.to_string(),
                    from_port: port,
                    to_host: rule.to_host.clone(),
                    to_port: rule.to_port,
                });

                // Rewrite the URI to connect to the target host:port
                let scheme = uri.scheme_str().unwrap_or("http");
                let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

                let new_uri_str = format!(
                    "{}://{}:{}{}",
                    scheme, rule.to_host, rule.to_port, path_and_query
                );
                return new_uri_str.parse().unwrap_or(uri);
            }
        }

        uri
    }
}

impl Service<http::Uri> for OrbConnector {
    type Response = <HttpConnector<OrbDnsResolver> as Service<http::Uri>>::Response;
    type Error = <HttpConnector<OrbDnsResolver> as Service<http::Uri>>::Error;
    type Future = <HttpConnector<OrbDnsResolver> as Service<http::Uri>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let rewritten = self.rewrite_uri(uri);
        self.inner.call(rewritten)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_override_rule_parse_basic() {
        let rule = OverrideRule::parse("example.com:80:127.0.0.1:8080").unwrap();
        assert_eq!(rule.from_host, "example.com");
        assert_eq!(rule.from_port, Some(80));
        assert_eq!(rule.to_host, "127.0.0.1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_wildcard_host() {
        let rule = OverrideRule::parse(":80:127.0.0.1:8080").unwrap();
        assert_eq!(rule.from_host, "");
        assert_eq!(rule.from_port, Some(80));
        assert_eq!(rule.to_host, "127.0.0.1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_wildcard_port() {
        let rule = OverrideRule::parse("example.com::127.0.0.1:8080").unwrap();
        assert_eq!(rule.from_host, "example.com");
        assert_eq!(rule.from_port, None);
        assert_eq!(rule.to_host, "127.0.0.1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_wildcard_both() {
        let rule = OverrideRule::parse("::127.0.0.1:8080").unwrap();
        assert_eq!(rule.from_host, "");
        assert_eq!(rule.from_port, None);
        assert_eq!(rule.to_host, "127.0.0.1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_ipv6_target() {
        let rule = OverrideRule::parse("example.com:80:[::1]:8080").unwrap();
        assert_eq!(rule.from_host, "example.com");
        assert_eq!(rule.from_port, Some(80));
        assert_eq!(rule.to_host, "::1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_ipv6_source() {
        let rule = OverrideRule::parse("[::1]:80:127.0.0.1:8080").unwrap();
        assert_eq!(rule.from_host, "::1");
        assert_eq!(rule.from_port, Some(80));
        assert_eq!(rule.to_host, "127.0.0.1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_ipv6_both() {
        let rule = OverrideRule::parse("[2001:db8::1]:80:[::1]:8080").unwrap();
        assert_eq!(rule.from_host, "2001:db8::1");
        assert_eq!(rule.from_port, Some(80));
        assert_eq!(rule.to_host, "::1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_ipv6_wildcard_port() {
        let rule = OverrideRule::parse("[::1]::[::1]:8080").unwrap();
        assert_eq!(rule.from_host, "::1");
        assert_eq!(rule.from_port, None);
        assert_eq!(rule.to_host, "::1");
        assert_eq!(rule.to_port, 8080);
    }

    #[test]
    fn test_override_rule_parse_invalid_missing_parts() {
        assert!(OverrideRule::parse("example.com").is_none());
        assert!(OverrideRule::parse("example.com:80").is_none());
        assert!(OverrideRule::parse("example.com:80:127.0.0.1").is_none());
    }

    #[test]
    fn test_override_rule_parse_invalid_empty_target_host() {
        assert!(OverrideRule::parse("example.com:80::8080").is_none());
    }

    #[test]
    fn test_override_rule_parse_invalid_port() {
        assert!(OverrideRule::parse("example.com:abc:127.0.0.1:8080").is_none());
        assert!(OverrideRule::parse("example.com:80:127.0.0.1:abc").is_none());
    }

    #[test]
    fn test_override_rule_parse_invalid_ipv6_unclosed_bracket() {
        assert!(OverrideRule::parse("[::1:80:127.0.0.1:8080").is_none());
    }

    #[test]
    fn test_override_rule_matches() {
        let rule = OverrideRule::parse("example.com:80:127.0.0.1:8080").unwrap();
        assert!(rule.matches("example.com", 80));
        assert!(!rule.matches("example.com", 443));
        assert!(!rule.matches("other.com", 80));
    }

    #[test]
    fn test_override_rule_matches_wildcard_host() {
        let rule = OverrideRule::parse(":80:127.0.0.1:8080").unwrap();
        assert!(rule.matches("example.com", 80));
        assert!(rule.matches("any.host", 80));
        assert!(!rule.matches("example.com", 443));
    }

    #[test]
    fn test_override_rule_matches_wildcard_port() {
        let rule = OverrideRule::parse("example.com::127.0.0.1:8080").unwrap();
        assert!(rule.matches("example.com", 80));
        assert!(rule.matches("example.com", 443));
        assert!(!rule.matches("other.com", 80));
    }

    #[test]
    fn test_override_rule_matches_wildcard_both() {
        let rule = OverrideRule::parse("::127.0.0.1:8080").unwrap();
        assert!(rule.matches("example.com", 80));
        assert!(rule.matches("any.host", 443));
    }
}

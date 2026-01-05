use std::sync::Mutex;

use orb_client::{ClientEvent, EventHandler};

/// Pending request info to print after DNS resolution
struct PendingRequest {
    scheme: String,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

/// CLI event handler that prints verbose output to stderr
pub struct VerboseEventHandler {
    /// Stores request info to print after DNS resolution (for HTTP/1+2)
    pending_request: Mutex<Option<PendingRequest>>,
}

impl VerboseEventHandler {
    pub fn new() -> Self {
        Self {
            pending_request: Mutex::new(None),
        }
    }

    /// Print request info
    fn print_request(req: &PendingRequest) {
        eprintln!("> {} {}", req.method, req.path);
        for (name, value) in &req.headers {
            eprintln!("> {}: {}", name, value);
        }
        eprintln!(">");
    }

    /// Take and print pending request if scheme matches
    fn print_pending_request_if(&self, expected_scheme: &str) {
        let mut pending = self.pending_request.lock().unwrap();
        if let Some(req) = pending.take_if(|r| r.scheme == expected_scheme) {
            Self::print_request(&req);
        }
    }
}

impl EventHandler for VerboseEventHandler {
    fn on_event(&self, event: ClientEvent) {
        match event {
            ClientEvent::DnsResolutionStarted { host } => {
                eprintln!("* Resolving host: {}", host);
            }
            ClientEvent::DnsResolutionCompleted { host, ip, duration } => {
                eprintln!(
                    "*   Resolved {} to {} ({:.3}ms)",
                    host,
                    ip,
                    duration.as_secs_f64() * 1000.0
                );

                // For HTTP (no TLS), print request info now after DNS resolution
                self.print_pending_request_if("http");
            }
            ClientEvent::DnsResolutionFailed { host, duration } => {
                eprintln!(
                    "*   Failed to resolve {} ({:.3}ms)",
                    host,
                    duration.as_secs_f64() * 1000.0
                );
            }
            ClientEvent::ConnectToOverride {
                from_host,
                from_port,
                to_host,
                to_port,
            } => {
                eprintln!(
                    "* Connecting to {}:{} (overriden from {}:{})",
                    to_host, to_port, from_host, from_port
                );
            }
            ClientEvent::PrepareRequest {
                scheme,
                method,
                host,
                path,
                headers,
            } => {
                // Check if host is an IP address (no DNS resolution will occur)
                // and if there is no TLS handshake, print request info now
                let is_ip = host.parse::<std::net::IpAddr>().is_ok();
                if is_ip && scheme == "http" {
                    Self::print_request(&PendingRequest {
                        scheme,
                        method,
                        path,
                        headers,
                    });
                } else {
                    // Store request info to print after DNS resolution
                    let mut pending = self.pending_request.lock().unwrap();
                    *pending = Some(PendingRequest {
                        scheme,
                        method,
                        path,
                        headers,
                    });
                }
            }
            ClientEvent::RequestSent {
                method,
                path,
                headers,
            } => {
                eprintln!("> {} {}", method, path);
                for (name, value) in headers {
                    eprintln!("> {}: {}", name, value);
                }
                eprintln!(">");
            }
            ClientEvent::QuicConnectionStarted { host, port } => {
                eprintln!("* QUIC connecting to {}:{}", host, port);
            }
            ClientEvent::QuicConnectionEstablished {
                host,
                port,
                duration,
            } => {
                eprintln!(
                    "*   QUIC connection established to {}:{} ({:.3}ms)",
                    host,
                    port,
                    duration.as_secs_f64() * 1000.0
                );
            }
            ClientEvent::QuicConnectionFailed { host, port, error } => {
                eprintln!("*   QUIC connection to {}:{} failed: {}", host, port, error);
            }
            ClientEvent::Http3ResponseReceived { status, duration } => {
                eprintln!(
                    "*   HTTP/3 response: {} ({:.3}ms)",
                    status,
                    duration.as_secs_f64() * 1000.0
                );
            }
            ClientEvent::TlsHandshakeCompleted {
                version,
                cipher,
                alpn,
                cert,
            } => {
                eprintln!("* TLS handshake completed");
                eprintln!("*   Version: {}", version);
                if let Some(cipher) = cipher {
                    eprintln!("*   Cipher: {}", cipher);
                }
                if let Some(alpn) = alpn {
                    eprintln!("*   ALPN: {}", alpn);
                }
                if let Some(cert) = cert {
                    eprintln!("*   Server certificate:");
                    eprintln!("*     Subject: {}", cert.subject);
                    eprintln!("*     Issuer: {}", cert.issuer);
                    eprintln!("*     Valid from: {}", cert.not_before);
                    eprintln!("*     Valid until: {}", cert.not_after);
                }

                // For HTTPS, print request info now after TLS handshake
                self.print_pending_request_if("https");
            }

            // WebSocket events
            ClientEvent::WebSocketConnecting {
                host,
                port,
                is_secure,
            } => {
                let scheme = if is_secure { "wss" } else { "ws" };
                eprintln!("* Connecting to {}://{}:{}", scheme, host, port);
            }
            ClientEvent::WebSocketConnected {
                host,
                port,
                duration,
            } => {
                eprintln!(
                    "*   WebSocket connected to {}:{} ({:.3}ms)",
                    host,
                    port,
                    duration.as_secs_f64() * 1000.0
                );
            }
            ClientEvent::WebSocketConnectionFailed { host, port, error } => {
                eprintln!(
                    "*   WebSocket connection to {}:{} failed: {}",
                    host, port, error
                );
            }
            ClientEvent::WebSocketMessageSent { message_type, size } => {
                eprintln!("> {} message ({} bytes)", message_type, size);
            }
            ClientEvent::WebSocketMessageReceived { message_type, size } => {
                eprintln!("< {} message ({} bytes)", message_type, size);
            }
            ClientEvent::WebSocketClosed { code, reason } => {
                if let (Some(c), Some(r)) = (code, reason) {
                    eprintln!("* WebSocket closed: {} {}", c, r);
                } else if let Some(c) = code {
                    eprintln!("* WebSocket closed with code {}", c);
                } else {
                    eprintln!("* WebSocket closed");
                }
            }
        }
    }
}

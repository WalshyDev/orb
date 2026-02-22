use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Version};
use http_body::Body;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

use crate::tls::{TlsCapturingConnector, insecure_cert_verifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::timeout;
use url::Url;

use crate::Response;
use crate::body::{BodyStream, RequestBody, ResponseBody};
use crate::dns::{OrbConnector, OverrideRule};
use crate::error::OrbError;
use crate::events::{BoxedEventHandler, ClientEvent};

/// Boxed body type for requests
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, OrbError>;

type HyperClient = Client<TlsCapturingConnector, BoxBody>;

/// Builder for HttpClient
#[derive(Default)]
pub struct HttpClientBuilder {
    connect_timeout: Option<Duration>,
    insecure: bool,
    use_system_cert_store: bool,
    overrides: Vec<OverrideRule>,
    event_handler: Option<BoxedEventHandler>,
    ca_certs: Vec<CertificateDer<'static>>,
    client_cert: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    http_version: Option<Version>,
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Use the system's native certificate store instead of the bundled webpki-roots
    pub fn use_system_cert_store(mut self, use_system: bool) -> Self {
        self.use_system_cert_store = use_system;
        self
    }

    pub fn dns_override(mut self, override_rule: OverrideRule) -> Self {
        self.overrides.push(override_rule);
        self
    }

    pub fn dns_overrides(mut self, overrides: Vec<OverrideRule>) -> Self {
        self.overrides = overrides;
        self
    }

    pub fn event_handler(mut self, handler: BoxedEventHandler) -> Self {
        self.event_handler = Some(handler);
        self
    }

    pub fn ca_certs(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        self.ca_certs = certs;
        self
    }

    pub fn add_root_certificate(mut self, cert: CertificateDer<'static>) -> Self {
        self.ca_certs.push(cert);
        self
    }

    pub fn client_cert(
        mut self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.client_cert = Some((certs, key));
        self
    }

    pub fn http_version(mut self, version: Version) -> Self {
        self.http_version = Some(version);
        self
    }

    pub fn build(self) -> HttpClient {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let tls_config = if self.insecure {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(insecure_cert_verifier())
                .with_no_client_auth()
        } else {
            let mut root_store = rustls::RootCertStore::empty();

            if self.use_system_cert_store {
                // Load certificates from the system's native certificate store
                let native_certs = rustls_native_certs::load_native_certs();
                for cert in native_certs.certs {
                    root_store.add(cert).ok();
                }
            } else {
                // Use bundled webpki-roots (Mozilla's root certificates)
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }

            // Add custom CA certificates if provided
            for cert in &self.ca_certs {
                root_store.add(cert.clone()).ok();
            }

            let config_builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

            // Add client certificate if provided
            if let Some((certs, key)) = self.client_cert {
                config_builder
                    .with_client_auth_cert(certs, key)
                    .expect("Failed to set client certificate")
            } else {
                config_builder.with_no_client_auth()
            }
        };

        // Create the connector (either with or without overrides rules)
        let connector = OrbConnector::new(
            Arc::new(self.overrides),
            self.connect_timeout,
            self.event_handler.clone(),
        );

        // Configure ALPN based on requested HTTP version
        let https_builder = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http();

        let https = match self.http_version {
            Some(Version::HTTP_11) => https_builder.enable_http1().wrap_connector(connector),
            Some(Version::HTTP_2) => https_builder.enable_http2().wrap_connector(connector),
            _ => https_builder
                .enable_all_versions()
                .wrap_connector(connector),
        };

        // Wrap with TLS-capturing connector to emit TLS handshake events
        let tls_capturing = TlsCapturingConnector::new(https, self.event_handler.clone());

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build(tls_capturing);

        HttpClient { client }
    }
}

/// HTTP client that can execute requests
pub struct HttpClient {
    client: HyperClient,
}

impl HttpClient {
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    /// Execute a request built by RequestBuilder
    pub async fn execute(&self, builder: RequestBuilder) -> Result<Response, OrbError> {
        let uri: http::Uri = builder.url.as_str().parse().expect("Invalid URL");

        let mut req_builder = Request::builder().uri(uri).method(builder.method.clone());

        // Only set version if explicitly specified - otherwise let hyper use what ALPN negotiated
        if let Some(version) = builder.http_version {
            req_builder = req_builder.version(version);
        }

        for (key, value) in builder.headers.iter() {
            // Skip Host header - hyper handles this via :authority for HTTP/2
            // and generates it from the URI for HTTP/1.1
            if key == http::header::HOST {
                continue;
            }
            req_builder = req_builder.header(key, value);
        }

        let boxed_body = match &builder.body {
            RequestBody::Empty => boxed_empty(),
            RequestBody::Bytes(bytes) => boxed_full(bytes.clone()),
        };

        let content_length = boxed_body.size_hint().exact();
        if let Some(len) = content_length
            && len > 0
            && !builder.headers.contains_key(http::header::CONTENT_LENGTH)
        {
            req_builder = req_builder.header(http::header::CONTENT_LENGTH, len);
        }

        let request = req_builder
            .body(boxed_body)
            .expect("Failed to build request");

        self.execute_with_redirects(request, &builder).await
    }

    async fn execute_with_redirects(
        &self,
        request: Request<BoxBody>,
        builder: &RequestBuilder,
    ) -> Result<Response, OrbError> {
        let mut current_request = request;
        let mut redirect_count = 0;
        let mut first_request = true;

        loop {
            let current_uri = current_request.uri().clone();
            let request_uri = current_uri.to_string();

            // Emit PrepareRequest event (only for the first request, not redirects)
            // This stores request info to be printed after DNS resolution/TLS handshake
            if first_request {
                if let Some(ref handler) = builder.event_handler {
                    let headers: Vec<(String, String)> = builder
                        .headers
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
                        .collect();
                    handler.on_event(ClientEvent::PrepareRequest {
                        scheme: builder.url.scheme().to_string(),
                        method: builder.method.to_string(),
                        host: builder.url.host_str().unwrap_or("").to_string(),
                        path: builder.url.path().to_string(),
                        headers,
                    });
                }
                first_request = false;
            }

            let response = self
                .client
                .request(current_request)
                .await
                .map_err(Self::handle_error)?;
            let status = response.status();

            if !status.is_redirection() || !builder.follow_redirects {
                return Self::handle_response(response);
            }

            redirect_count += 1;

            if redirect_count > builder.max_redirects {
                return Err(OrbError::TooManyRedirects {
                    count: builder.max_redirects,
                    url: request_uri,
                });
            }

            let location = response
                .headers()
                .get(http::header::LOCATION)
                .ok_or(OrbError::MissingRedirectLocation)?;

            let location_str = location
                .to_str()
                .map_err(|_| OrbError::InvalidRedirectLocation)?
                .trim();

            let new_uri = resolve_redirect_uri(&current_uri, location_str)?;

            // 307/308: Preserve method and body
            // 301/302/303: Change to GET with no body
            let (method, body) = match status.as_u16() {
                307 | 308 => (builder.method.clone(), builder.body.clone()),
                _ => (Method::GET, RequestBody::Empty),
            };

            let mut req_builder = Request::builder().method(method).uri(new_uri.clone());

            // Determine headers for redirect request
            let redirect_headers =
                if !builder.location_trusted && is_cross_host(&current_uri, &new_uri) {
                    strip_sensitive_headers(&builder.headers)
                } else {
                    builder.headers.clone()
                };

            // Copy headers (except Host which hyper handles)
            for (key, value) in redirect_headers.iter() {
                if key != http::header::HOST {
                    req_builder = req_builder.header(key, value);
                }
            }

            let boxed_body = match body {
                RequestBody::Empty => boxed_empty(),
                RequestBody::Bytes(bytes) => boxed_full(bytes),
            };

            current_request = req_builder
                .body(boxed_body)
                .map_err(|e| OrbError::RequestBuild(e.to_string()))?;
        }
    }

    fn handle_response(response: http::Response<Incoming>) -> Result<Response, OrbError> {
        let status = response.status();
        let version = response.version();
        let headers = response.headers().clone();
        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let body_stream = response.into_body();
        let stream = BodyStream::new(body_stream);
        let response_body = ResponseBody::new(stream);

        Ok(Response::new(
            status,
            version,
            headers,
            response_body,
            content_length,
        ))
    }

    fn handle_error(error: hyper_util::client::legacy::Error) -> OrbError {
        let err_str = format!("{:?}", error);

        if err_str.contains("InvalidCertificate") {
            if err_str.contains("ExpiredContext") {
                return OrbError::TlsExpiredCert;
            } else if err_str.contains("UnknownIssuer") {
                return OrbError::TlsUnknownIssuer;
            } else if err_str.contains("NotValidForNameContext") {
                return OrbError::TlsInvalidForName;
            }
        } else if err_str.contains("dns error")
            && err_str.contains("failed to lookup address information")
        {
            return OrbError::DnsLookupFailed;
        } else if err_str.contains("tcp connect error") && err_str.contains("kind: TimedOut") {
            return OrbError::Timeout {
                timeout: Duration::from_secs(0),
            };
        }

        OrbError::Request(format!("{}", error))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Builder for HTTP requests
pub struct RequestBuilder {
    pub(crate) http_version: Option<Version>,
    pub(crate) url: Url,
    pub(crate) method: Method,
    pub(crate) headers: HeaderMap,
    pub(crate) body: RequestBody,
    pub(crate) follow_redirects: bool,
    pub(crate) max_redirects: usize,
    pub(crate) location_trusted: bool,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) max_time: Option<Duration>,
    pub(crate) insecure: bool,
    pub(crate) use_system_cert_store: bool,
    pub(crate) dns_overrides: Vec<OverrideRule>,
    pub(crate) event_handler: Option<BoxedEventHandler>,
    pub(crate) ca_certs: Vec<CertificateDer<'static>>,
    pub(crate) client_cert: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
}

impl RequestBuilder {
    pub fn new(url: Url) -> Self {
        Self {
            http_version: None,
            url,
            method: Method::GET,
            headers: HeaderMap::new(),
            body: RequestBody::empty(),
            follow_redirects: false,
            max_redirects: 10,
            location_trusted: false,
            connect_timeout: None,
            max_time: None,
            insecure: false,
            use_system_cert_store: false,
            dns_overrides: Vec::new(),
            event_handler: None,
            ca_certs: Vec::new(),
            client_cert: None,
        }
    }

    pub fn http_version(mut self, version: Version) -> Self {
        self.http_version = Some(version);
        self
    }

    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        HeaderValue: TryFrom<V>,
        <HeaderName as TryFrom<K>>::Error: std::fmt::Debug,
        <HeaderValue as TryFrom<V>>::Error: std::fmt::Debug,
    {
        let header_name = HeaderName::try_from(key).expect("Invalid header name");
        let header_value = HeaderValue::try_from(value).expect("Invalid header value");
        self.headers.insert(header_name, header_value);
        self
    }

    pub fn headers(mut self, headers: HeaderMap) -> Self {
        for (key, value) in headers.iter() {
            self.headers.insert(key.clone(), value.clone());
        }
        self
    }

    pub fn body(mut self, body: RequestBody) -> Self {
        self.body = body;
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }

    pub fn location_trusted(mut self, trusted: bool) -> Self {
        self.location_trusted = trusted;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    pub fn max_time(mut self, timeout: Duration) -> Self {
        self.max_time = Some(timeout);
        self
    }

    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Use the system's native certificate store instead of the bundled webpki-roots
    pub fn use_system_cert_store(mut self, use_system: bool) -> Self {
        self.use_system_cert_store = use_system;
        self
    }

    pub fn dns_override(mut self, override_rule: OverrideRule) -> Self {
        self.dns_overrides.push(override_rule);
        self
    }

    pub fn dns_overrides(mut self, override_rules: Vec<OverrideRule>) -> Self {
        self.dns_overrides = override_rules;
        self
    }

    pub fn event_handler(mut self, handler: BoxedEventHandler) -> Self {
        self.event_handler = Some(handler);
        self
    }

    pub fn ca_certs(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        self.ca_certs = certs;
        self
    }

    pub fn add_root_certificate(mut self, cert: CertificateDer<'static>) -> Self {
        self.ca_certs.push(cert);
        self
    }

    pub fn client_cert(
        mut self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.client_cert = Some((certs, key));
        self
    }

    /// Send the request using a new HttpClient
    /// For better performance with multiple requests, create an HttpClient and use client.execute()
    pub async fn send(self) -> Result<Response, OrbError> {
        // Dispatch to HTTP/3 if requested
        if self.http_version == Some(Version::HTTP_3) {
            return crate::http3_client::send_http3_request(self).await;
        }

        self.send_http1_2().await
    }

    /// Connect to a WebSocket server
    ///
    /// This uses the same configuration (timeouts, TLS settings, headers) as HTTP requests
    /// but establishes a WebSocket connection instead.
    ///
    /// # Example
    /// ```rust
    /// use orb_client::{RequestBuilder, Url};
    ///
    /// # async fn connect_websocket_example() -> Result<(), Box<dyn std::error::Error>> {
    /// let stream = RequestBuilder::new(Url::parse("wss://example.com/ws").unwrap())
    ///     .header("Authorization", "Bearer token")
    ///     .connect_websocket()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_websocket(
        self,
    ) -> Result<crate::websocket_client::WebSocketStream, OrbError> {
        use crate::websocket_client::{WebSocketConfig, connect};

        // Convert headers from HeaderMap to Vec<(String, String)>
        let headers: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let mut config = WebSocketConfig::new(self.url);

        if let Some(timeout) = self.connect_timeout {
            config = config.connect_timeout(timeout);
        }
        if let Some(max_time) = self.max_time {
            config = config.max_time(max_time);
        }
        config = config.insecure(self.insecure);
        config = config.use_system_cert_store(self.use_system_cert_store);
        config = config.dns_overrides(self.dns_overrides);

        if let Some(handler) = self.event_handler {
            config = config.event_handler(handler);
        }
        if !self.ca_certs.is_empty() {
            config = config.ca_certs(self.ca_certs);
        }
        if let Some((certs, key)) = self.client_cert {
            config = config.client_cert(certs, key);
        }
        for (name, value) in headers {
            config = config.header(name, value);
        }

        connect(config).await
    }

    /// Send using HTTP/1.1 or HTTP/2
    async fn send_http1_2(mut self) -> Result<Response, OrbError> {
        let connect_timeout = self.connect_timeout.unwrap_or(Duration::from_secs(30));
        let insecure = self.insecure;
        let use_system_cert_store = self.use_system_cert_store;
        let max_time = self.max_time;
        let http_version = self.http_version;

        // Clone event handler for the connector, keep original for request events
        let event_handler_for_connector = self.event_handler.clone();
        let dns_overrides = std::mem::take(&mut self.dns_overrides);
        let ca_certs = std::mem::take(&mut self.ca_certs);
        let client_cert = self.client_cert.take();

        let mut builder = HttpClient::builder()
            .connect_timeout(connect_timeout)
            .insecure(insecure)
            .use_system_cert_store(use_system_cert_store)
            .dns_overrides(dns_overrides)
            .ca_certs(ca_certs);

        if let Some(version) = http_version {
            builder = builder.http_version(version);
        }

        if let Some(handler) = event_handler_for_connector {
            builder = builder.event_handler(handler);
        }

        if let Some((certs, key)) = client_cert {
            builder = builder.client_cert(certs, key);
        }

        let client = builder.build();

        if let Some(max_time) = max_time {
            match timeout(max_time, client.execute(self)).await {
                Ok(result) => result,
                Err(_) => Err(OrbError::Timeout { timeout: max_time }),
            }
        } else {
            client.execute(self).await
        }
    }
}

fn boxed_empty() -> BoxBody {
    Empty::new().map_err(|_| unreachable!()).boxed()
}

fn boxed_full(bytes: Bytes) -> BoxBody {
    Full::new(bytes).map_err(|_| unreachable!()).boxed()
}

/// Check if two URIs point to different hosts (scheme + host + port)
fn is_cross_host(original: &http::Uri, redirect: &http::Uri) -> bool {
    let orig_scheme = original.scheme_str().unwrap_or("https");
    let redir_scheme = redirect.scheme_str().unwrap_or("https");

    if orig_scheme != redir_scheme {
        return true;
    }

    let orig_host = original.host().unwrap_or("");
    let redir_host = redirect.host().unwrap_or("");

    if !orig_host.eq_ignore_ascii_case(redir_host) {
        return true;
    }

    let default_port = if orig_scheme == "https" { 443 } else { 80 };
    let orig_port = original.port_u16().unwrap_or(default_port);
    let redir_port = redirect.port_u16().unwrap_or(default_port);

    orig_port != redir_port
}

/// Clone headers but remove the Authorization header
fn strip_sensitive_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();
    for (key, value) in headers.iter() {
        if key == http::header::AUTHORIZATION {
            continue;
        }
        filtered.append(key.clone(), value.clone());
    }
    filtered
}

/// Resolve a redirect Location header into an absolute URI
pub(crate) fn resolve_redirect_uri(
    current: &http::Uri,
    location: &str,
) -> Result<http::Uri, OrbError> {
    if location.starts_with("http://") || location.starts_with("https://") {
        location
            .parse()
            .map_err(|_| OrbError::InvalidRedirectLocation)
    } else if location.starts_with('/') {
        let scheme = current.scheme_str().unwrap_or("https");
        let authority = current.authority().map(|a| a.as_str()).unwrap_or("");
        format!("{}://{}{}", scheme, authority, location)
            .parse()
            .map_err(|_| OrbError::InvalidRedirectLocation)
    } else {
        let scheme = current.scheme_str().unwrap_or("https");
        let authority = current.authority().map(|a| a.as_str()).unwrap_or("");
        let current_path = current.path();
        let base_path = current_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        format!("{}://{}{}/{}", scheme, authority, base_path, location)
            .parse()
            .map_err(|_| OrbError::InvalidRedirectLocation)
    }
}

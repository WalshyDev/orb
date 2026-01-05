use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// TLS certificate information for verbose logging
#[derive(Debug, Clone)]
pub struct TlsCertInfo {
    /// Subject of the certificate (e.g., "CN=example.com")
    pub subject: String,
    /// Issuer of the certificate (e.g., "CN=Let's Encrypt Authority X3")
    pub issuer: String,
    /// Not valid before (ISO 8601 format)
    pub not_before: String,
    /// Not valid after (ISO 8601 format)
    pub not_after: String,
}

/// Events that can occur during HTTP client operations
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// DNS resolution started
    DnsResolutionStarted { host: String },
    /// DNS resolution completed successfully
    DnsResolutionCompleted {
        host: String,
        ip: IpAddr,
        duration: Duration,
    },
    /// DNS resolution failed
    DnsResolutionFailed { host: String, duration: Duration },
    /// Connection override applied
    ConnectToOverride {
        from_host: String,
        from_port: u16,
        to_host: String,
        to_port: u16,
    },
    /// Request info stored before hyper call (for HTTP/1+2, printed after DNS)
    PrepareRequest {
        scheme: String,
        method: String,
        host: String,
        path: String,
        headers: Vec<(String, String)>,
    },
    /// Request is being sent (emitted after connection, before response - used by HTTP/3)
    RequestSent {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
    },
    /// QUIC connection attempt started
    QuicConnectionStarted { host: String, port: u16 },
    /// QUIC connection established successfully
    QuicConnectionEstablished {
        host: String,
        port: u16,
        duration: Duration,
    },
    /// QUIC connection failed
    QuicConnectionFailed {
        host: String,
        port: u16,
        error: String,
    },
    /// HTTP/3 response headers received
    Http3ResponseReceived { status: u16, duration: Duration },

    /// TLS handshake completed (for HTTPS connections)
    TlsHandshakeCompleted {
        /// TLS protocol version (e.g., "TLSv1.3")
        version: String,
        /// Cipher suite (e.g., "TLS_AES_256_GCM_SHA384")
        cipher: Option<String>,
        /// ALPN protocol negotiated (e.g., "h2", "http/1.1")
        alpn: Option<String>,
        /// Server certificate info
        cert: Option<TlsCertInfo>,
    },

    // WebSocket events
    /// WebSocket connection attempt started
    WebSocketConnecting {
        host: String,
        port: u16,
        is_secure: bool,
    },
    /// WebSocket connection established
    WebSocketConnected {
        host: String,
        port: u16,
        duration: Duration,
    },
    /// WebSocket connection failed
    WebSocketConnectionFailed {
        host: String,
        port: u16,
        error: String,
    },
    /// WebSocket message sent
    WebSocketMessageSent { message_type: String, size: usize },
    /// WebSocket message received
    WebSocketMessageReceived { message_type: String, size: usize },
    /// WebSocket connection closed
    WebSocketClosed {
        code: Option<u16>,
        reason: Option<String>,
    },
}

/// A trait for handling client events
pub trait EventHandler: Send + Sync {
    fn on_event(&self, event: ClientEvent);
}

/// A no-op event handler that ignores all events
#[derive(Clone)]
pub struct NoOpEventHandler;

impl EventHandler for NoOpEventHandler {
    fn on_event(&self, _event: ClientEvent) {}
}

/// Type alias for boxed event handler
pub type BoxedEventHandler = Arc<dyn EventHandler>;

/// Helper to create a no-op event handler
pub fn noop_handler() -> BoxedEventHandler {
    Arc::new(NoOpEventHandler)
}

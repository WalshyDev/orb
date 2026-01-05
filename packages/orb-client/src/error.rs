use std::fmt;
use std::time::Duration;

/// Custom error type for orb client
#[derive(Debug)]
pub enum OrbError {
    /// Connection error
    Connect(String),
    /// DNS lookup failed
    DnsLookupFailed,
    /// TLS/SSL error
    Tls(String),
    TlsExpiredCert,
    TlsUnknownIssuer,
    TlsInvalidForName,
    /// Request building error
    RequestBuild(String),
    /// General request error
    Request(String),
    /// Body read error
    BodyRead(String),
    /// Timeout error
    Timeout {
        timeout: Duration,
    },
    /// Too many redirects
    TooManyRedirects {
        count: usize,
        url: String,
    },
    /// Missing Location header in redirect response
    MissingRedirectLocation,
    /// Invalid redirect location
    InvalidRedirectLocation,
    /// DNS resolution error
    Dns(String),
    /// IO error
    Io(std::io::Error),
    /// QUIC connection error
    QuicConnect(String),
    /// HTTP/3 protocol error
    Http3Protocol(String),
    /// HTTP/3 not supported by server
    Http3NotSupported,

    // WebSocket errors
    /// WebSocket connection error
    WebSocketConnect(String),
    /// WebSocket protocol error
    WebSocketProtocol(String),
    /// WebSocket send error
    WebSocketSend(String),
    /// WebSocket receive error
    WebSocketReceive(String),
    /// WebSocket connection closed unexpectedly
    WebSocketClosed {
        code: Option<u16>,
        reason: Option<String>,
    },
}

impl fmt::Display for OrbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrbError::Connect(msg) => write!(f, "Connection error: {}", msg),
            OrbError::DnsLookupFailed => write!(f, "DNS lookup failed"),
            OrbError::Tls(msg) => write!(f, "TLS error: {}", msg),
            OrbError::TlsExpiredCert => write!(f, "TLS error: expired certificate"),
            OrbError::TlsUnknownIssuer => write!(f, "TLS error: unknown issuer"),
            OrbError::TlsInvalidForName => {
                write!(f, "TLS error: certificate not valid for target name")
            }
            OrbError::RequestBuild(msg) => write!(f, "Request build error: {}", msg),
            OrbError::Request(msg) => write!(f, "Request error: {}", msg),
            OrbError::BodyRead(msg) => write!(f, "Body read error: {}", msg),
            OrbError::Timeout { timeout } => {
                write!(f, "Request timed out after {:?}", timeout)
            }
            OrbError::TooManyRedirects { count, url } => {
                write!(f, "Too many redirects ({}) to {}", count, url)
            }
            OrbError::MissingRedirectLocation => {
                write!(f, "Redirect response missing Location header")
            }
            OrbError::InvalidRedirectLocation => {
                write!(f, "Invalid redirect location")
            }
            OrbError::Dns(msg) => write!(f, "DNS resolution error: {}", msg),
            OrbError::Io(err) => write!(f, "IO error: {}", err),
            OrbError::QuicConnect(msg) => write!(f, "QUIC connection error: {}", msg),
            OrbError::Http3Protocol(msg) => write!(f, "HTTP/3 protocol error: {}", msg),
            OrbError::Http3NotSupported => write!(f, "HTTP/3 not supported by server"),
            OrbError::WebSocketConnect(msg) => write!(f, "WebSocket connection error: {}", msg),
            OrbError::WebSocketProtocol(msg) => write!(f, "WebSocket protocol error: {}", msg),
            OrbError::WebSocketSend(msg) => write!(f, "WebSocket send error: {}", msg),
            OrbError::WebSocketReceive(msg) => write!(f, "WebSocket receive error: {}", msg),
            OrbError::WebSocketClosed { code, reason } => {
                if let (Some(c), Some(r)) = (code, reason) {
                    write!(f, "WebSocket connection closed: {} {}", c, r)
                } else if let Some(c) = code {
                    write!(f, "WebSocket connection closed with code {}", c)
                } else {
                    write!(f, "WebSocket connection closed")
                }
            }
        }
    }
}

impl std::error::Error for OrbError {}

impl From<std::io::Error> for OrbError {
    fn from(err: std::io::Error) -> Self {
        OrbError::Io(err)
    }
}

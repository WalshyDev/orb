//! # Mock HTTP Server
//!
//! A unified mock HTTP server supporting HTTP/1.1, HTTP/2, and HTTP/3 for testing.
//!
//! ## Example
//!
//! ```rust
//! use orb_mockhttp::{TestServerBuilder, ResponseBuilder, HttpProtocol};
//!
//! // HTTP/1.1 only (no TLS)
//! let server = TestServerBuilder::new().build();
//!
//! // HTTPS with HTTP/1.1 + HTTP/2 + HTTP/3 (all on same port!)
//! let server = TestServerBuilder::new()
//!     .with_tls()
//!     .build();
//!
//! // Only HTTP/1.1 over TLS
//! let server = TestServerBuilder::new()
//!     .with_tls()
//!     .with_protocols(&[HttpProtocol::Http1])
//!     .build();
//!
//! // Only HTTP/2
//! let server = TestServerBuilder::new()
//!     .with_tls()
//!     .with_protocols(&[HttpProtocol::Http2])
//!     .build();
//!
//! server.on_request("/test")
//!     .expect_method("GET")
//!     .respond_with(200, "Hello, world!");
//!
//! // Single URL works for all protocols:
//! // - HTTP/1.1 and HTTP/2 over TCP
//! // - HTTP/3 over QUIC/UDP
//! let url = server.url("/test");  // https://127.0.0.1:PORT/test
//! ```

mod handlers;
mod request;
mod response;
mod route;
mod server;
mod tls;

pub use handlers::ReceivedWebSocketMessage;
pub use handlers::websocket::{EchoHandler, NoOpHandler, WebSocketHandler};
pub use request::Request;
pub use response::{Response, ResponseBuilder};
pub use route::{Route, RouteBuilder};
pub use server::{TestServer, WebSocketServer};
pub use tls::TlsConfig;

use std::collections::HashSet;
use std::path::PathBuf;

/// Supported HTTP protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpProtocol {
    /// HTTP/1.1
    Http1,
    /// HTTP/2
    Http2,
    /// HTTP/3
    Http3,
}

impl HttpProtocol {
    /// Get all protocols
    pub fn all() -> &'static [HttpProtocol] {
        &[
            HttpProtocol::Http1,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ]
    }
}

/// Builder for creating a test server with specific configuration
pub struct TestServerBuilder {
    tls_enabled: bool,
    tls_config: Option<TlsConfig>,
    protocols: Option<HashSet<HttpProtocol>>,
}

impl TestServerBuilder {
    /// Create a new builder with default settings (HTTP/1.1 only, no TLS)
    pub fn new() -> Self {
        Self {
            tls_enabled: false,
            tls_config: None,
            protocols: None,
        }
    }

    /// Enable TLS (HTTPS)
    ///
    /// This enables all protocols on the same port:
    /// - HTTP/1.1 over TLS (TCP)
    /// - HTTP/2 over TLS (TCP, via ALPN negotiation)
    /// - HTTP/3 over QUIC (UDP, same port number)
    ///
    /// Certificates are auto-generated for localhost/127.0.0.1.
    pub fn with_tls(mut self) -> Self {
        self.tls_enabled = true;
        self
    }

    /// Specify which protocols the server should support
    ///
    /// By default:
    /// - Without TLS: HTTP/1.1 only
    /// - With TLS: HTTP/1.1, HTTP/2, and HTTP/3
    ///
    /// Use this to limit which protocols are available.
    ///
    /// Note: HTTP/2 and HTTP/3 require TLS. If you specify these without
    /// calling `with_tls()`, TLS will be automatically enabled.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use orb_mockhttp::{TestServerBuilder, HttpProtocol};
    ///
    /// // Only HTTP/1.1 over TLS
    /// let server = TestServerBuilder::new()
    ///     .with_tls()
    ///     .with_protocols(&[HttpProtocol::Http1])
    ///     .build();
    ///
    /// // HTTP/2 only (TLS auto-enabled)
    /// let server = TestServerBuilder::new()
    ///     .with_protocols(&[HttpProtocol::Http2])
    ///     .build();
    /// ```
    pub fn with_protocols(mut self, protocols: &[HttpProtocol]) -> Self {
        self.protocols = Some(protocols.iter().copied().collect());
        // Auto-enable TLS if HTTP/2 or HTTP/3 is requested
        if protocols.contains(&HttpProtocol::Http2) || protocols.contains(&HttpProtocol::Http3) {
            self.tls_enabled = true;
        }
        self
    }

    /// Use custom TLS certificates instead of auto-generated ones
    pub fn with_certs(mut self, cert_path: PathBuf, key_path: PathBuf) -> Self {
        self.tls_config =
            Some(TlsConfig::from_files(cert_path, key_path).expect("Failed to load certificates"));
        self.tls_enabled = true;
        self
    }

    /// Use a specific TLS configuration
    pub fn with_tls_config(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self.tls_enabled = true;
        self
    }

    /// Build and start the test server
    pub fn build(self) -> TestServer {
        let tls_config = if self.tls_enabled {
            Some(self.tls_config.unwrap_or_else(TlsConfig::generate))
        } else {
            None
        };

        // Determine protocols
        let protocols = match self.protocols {
            Some(p) => p,
            None => {
                if self.tls_enabled {
                    // TLS: all protocols by default
                    HttpProtocol::all().iter().copied().collect()
                } else {
                    // No TLS: HTTP/1.1 only
                    let mut set = HashSet::new();
                    set.insert(HttpProtocol::Http1);
                    set
                }
            }
        };

        TestServer::new(self.tls_enabled, tls_config, protocols)
    }
}

impl Default for TestServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

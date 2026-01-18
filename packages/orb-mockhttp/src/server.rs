//! Test server implementation with runtime management

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use tokio::sync::watch;

use crate::handlers::websocket::WebSocketHandler;
use crate::handlers::{ServerState, WebSocketState};
use crate::route::RouteBuilder;
use crate::tls::TlsConfig;
use crate::{HttpProtocol, Response};

/// A test server that supports HTTP/1.1, HTTP/2, and HTTP/3
///
/// When TLS is enabled:
/// - HTTP/1.1 and HTTP/2 are served over TCP (same port, ALPN negotiation)
/// - HTTP/3 is served over UDP/QUIC (same port number as TCP)
///
/// This allows a single URL to work transparently for all protocols.
pub struct TestServer {
    /// Server port (used for both TCP and UDP when TLS is enabled)
    port: u16,
    /// Whether TLS is enabled (and thus HTTP/2 and HTTP/3)
    tls_enabled: bool,
    /// TLS configuration
    tls_config: Option<TlsConfig>,
    /// Enabled protocols
    protocols: HashSet<HttpProtocol>,
    /// Shared server state
    state: Arc<ServerState>,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Background thread handle
    thread_handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Create and start a new test server
    pub(crate) fn new(
        tls_enabled: bool,
        tls_config: Option<TlsConfig>,
        protocols: HashSet<HttpProtocol>,
    ) -> Self {
        // Install crypto provider
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let state = Arc::new(ServerState::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Channel to receive port from the runtime thread
        let (port_tx, port_rx) = mpsc::channel();

        let tls_clone = tls_config.clone();
        let state_clone = Arc::clone(&state);
        let protocols_clone = protocols.clone();

        let thread_handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime");

            rt.block_on(async move {
                run_servers(
                    tls_enabled,
                    tls_clone,
                    protocols_clone,
                    state_clone,
                    shutdown_rx,
                    port_tx,
                )
                .await;
            });
        });

        // Wait for port
        let port = port_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("Failed to receive server port");

        TestServer {
            port,
            tls_enabled,
            tls_config,
            protocols,
            state,
            shutdown_tx,
            thread_handle: Some(thread_handle),
        }
    }

    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Get the server port
    ///
    /// When TLS is enabled, this port is used for:
    /// - TCP: HTTP/1.1 and HTTP/2 (via ALPN)
    /// - UDP: HTTP/3 (via QUIC)
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if TLS is enabled
    ///
    /// When TLS is enabled, the server supports HTTP/1.1, HTTP/2, and HTTP/3.
    pub fn is_tls(&self) -> bool {
        self.tls_enabled
    }

    /// Check if a specific protocol is enabled
    pub fn supports_protocol(&self, protocol: HttpProtocol) -> bool {
        self.protocols.contains(&protocol)
    }

    /// Get all enabled protocols
    pub fn protocols(&self) -> &HashSet<HttpProtocol> {
        &self.protocols
    }

    /// Get the URL for the given path
    ///
    /// Returns http:// if TLS is disabled, https:// if TLS is enabled.
    ///
    /// When TLS is enabled, this URL works transparently for:
    /// - HTTP/1.1 and HTTP/2 (over TCP)
    /// - HTTP/3 (over QUIC/UDP)
    pub fn url(&self, path: &str) -> String {
        let scheme = if self.tls_enabled { "https" } else { "http" };
        format!("{}://127.0.0.1:{}{}", scheme, self.port, path)
    }

    /// Get the TLS certificate as PEM (for client trust)
    pub fn cert_pem(&self) -> Option<String> {
        self.tls_config.as_ref().map(|c| c.cert_pem())
    }

    /// Get the TLS certificate as DER bytes
    pub fn cert_der(&self) -> Option<&[u8]> {
        self.tls_config.as_ref().map(|c| c.cert_der())
    }

    /// Register a route with a builder pattern
    pub fn on_request<S: Into<String>>(&self, path: S) -> RouteBuilder {
        RouteBuilder::new(path).with_state(Arc::clone(&self.state))
    }

    /// Register a route with a closure handler
    pub fn on_request_fn<S, F>(&self, path: S, handler: F) -> &Self
    where
        S: Into<String>,
        F: Fn(&crate::Request) -> Response + Send + Sync + 'static,
    {
        let route = crate::route::Route::new(
            path.into(),
            None,
            Arc::new(crate::route::FnHandler(handler)),
            Vec::new(),
        );
        self.state.add_route(Arc::new(route));
        self
    }

    /// Clear all registered routes
    pub fn clear_routes(&self) {
        self.state.clear_routes();
    }

    /// Assert that exactly one request was received
    pub fn assert_one_request(&self) {
        self.state.assert_requests(1);
    }

    /// Assert that the expected number of requests were received
    pub fn assert_requests(&self, expected_count: usize) {
        self.state.assert_requests(expected_count);
    }

    /// Get the raw request data of the last logged request, if any
    /// This is logged in HTTP/1.1 format
    pub fn get_raw_request(&self) -> Option<String> {
        self.state.get_raw_request()
    }

    /// Get the raw request data of all logged requests, if any
    /// This is logged in HTTP/1.1 format
    pub fn get_raw_requests(&self) -> Vec<String> {
        self.state.get_raw_requests()
    }

    /// Shutdown the server
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
        // Wait for the server thread to finish
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Run all enabled protocol servers
async fn run_servers(
    tls_enabled: bool,
    tls_config: Option<TlsConfig>,
    protocols: HashSet<HttpProtocol>,
    state: Arc<ServerState>,
    shutdown_rx: watch::Receiver<bool>,
    port_tx: mpsc::Sender<u16>,
) {
    use tokio::net::TcpListener;

    let mut tasks = Vec::new();

    if tls_enabled {
        // TLS enabled: start requested protocols
        if let Some(ref tls) = tls_config {
            // First, bind TCP to get a port
            let tcp_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind TCP listener");
            let port = tcp_listener.local_addr().unwrap().port();

            // Send the port back
            port_tx.send(port).expect("Failed to send port");

            // Determine which TCP protocols to support via ALPN
            let has_http1 = protocols.contains(&HttpProtocol::Http1);
            let has_http2 = protocols.contains(&HttpProtocol::Http2);
            let has_http3 = protocols.contains(&HttpProtocol::Http3);

            // Start TCP server if HTTP/1.1 or HTTP/2 is enabled
            if has_http1 || has_http2 {
                let tls_server_config = tls.build_alpn_server_config(has_http1, has_http2);
                let state_tcp = Arc::clone(&state);
                let shutdown_tcp = shutdown_rx.clone();
                tasks.push(tokio::spawn(async move {
                    crate::handlers::http2::run_http2_server(
                        tcp_listener,
                        tls_server_config,
                        state_tcp,
                        shutdown_tcp,
                    )
                    .await;
                }));
            }

            // Start HTTP/3 handler (UDP/QUIC) if enabled
            if has_http3 {
                let udp_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
                let quic_config = tls.build_quic_server_config();
                let quic_endpoint = quinn::Endpoint::server(quic_config, udp_addr)
                    .expect("Failed to create QUIC endpoint on same port");

                let state_quic = Arc::clone(&state);
                let shutdown_quic = shutdown_rx.clone();
                tasks.push(tokio::spawn(async move {
                    crate::handlers::http3::run_http3_server(
                        quic_endpoint,
                        state_quic,
                        shutdown_quic,
                    )
                    .await;
                }));
            }
        }
    } else {
        // No TLS: HTTP/1.1 only
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind TCP listener");
        let port = listener.local_addr().unwrap().port();
        port_tx.send(port).expect("Failed to send port");

        let state = Arc::clone(&state);
        let shutdown = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            crate::handlers::http1::run_http1_server(listener, state, shutdown).await;
        }));
    }

    // Wait for all tasks to complete
    futures_util::future::join_all(tasks).await;
}

/// A WebSocket test server
///
/// This is separate from TestServer because WebSocket uses a different protocol
/// and has different configuration needs.
pub struct WebSocketServer {
    /// Server port
    port: u16,
    /// Whether TLS is enabled
    tls_enabled: bool,
    /// TLS configuration
    tls_config: Option<TlsConfig>,
    /// Shared WebSocket state for message tracking
    state: Arc<WebSocketState>,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Background thread handle
    thread_handle: Option<JoinHandle<()>>,
}

impl WebSocketServer {
    /// Create a new WebSocket server with an echo handler
    pub fn echo() -> Self {
        Self::with_handler(Box::new(crate::handlers::websocket::EchoHandler))
    }

    /// Create a new WebSocket server with TLS and an echo handler
    pub fn echo_tls() -> Self {
        Self::with_handler_tls(Box::new(crate::handlers::websocket::EchoHandler))
    }

    /// Create a new WebSocket server with a custom handler
    pub fn with_handler(handler: Box<dyn WebSocketHandler>) -> Self {
        Self::new(false, None, handler)
    }

    /// Create a new WebSocket server with TLS and a custom handler
    pub fn with_handler_tls(handler: Box<dyn WebSocketHandler>) -> Self {
        let tls_config = TlsConfig::generate();
        Self::new(true, Some(tls_config), handler)
    }

    fn new(
        tls_enabled: bool,
        tls_config: Option<TlsConfig>,
        handler: Box<dyn WebSocketHandler>,
    ) -> Self {
        let state = Arc::new(WebSocketState::new(handler));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Channel to receive port from the runtime thread
        let (port_tx, port_rx) = mpsc::channel();

        let tls_clone = tls_config.clone();
        let state_clone = Arc::clone(&state);

        let thread_handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime");

            rt.block_on(async move {
                run_websocket_server(tls_enabled, tls_clone, state_clone, shutdown_rx, port_tx)
                    .await;
            });
        });

        // Wait for port
        let port = port_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("Failed to receive server port");

        WebSocketServer {
            port,
            tls_enabled,
            tls_config,
            state,
            shutdown_tx,
            thread_handle: Some(thread_handle),
        }
    }

    /// Get the server port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if TLS is enabled
    pub fn is_tls(&self) -> bool {
        self.tls_enabled
    }

    /// Get the URL for the given path
    ///
    /// Returns ws:// if TLS is disabled, wss:// if TLS is enabled.
    pub fn url(&self, path: &str) -> String {
        let scheme = if self.tls_enabled { "wss" } else { "ws" };
        format!("{}://127.0.0.1:{}{}", scheme, self.port, path)
    }

    /// Get the TLS certificate as PEM (for client trust)
    pub fn cert_pem(&self) -> Option<String> {
        self.tls_config.as_ref().map(|c| c.cert_pem())
    }

    /// Assert that the expected number of messages were received
    pub fn assert_messages(&self, expected_count: usize) {
        self.state.assert_messages(expected_count);
    }

    /// Get the number of received messages
    pub fn message_count(&self) -> usize {
        self.state.message_count()
    }

    /// Get all received messages
    pub fn get_messages(&self) -> Vec<crate::handlers::ReceivedWebSocketMessage> {
        self.state.get_messages()
    }

    /// Get all received text messages as strings
    pub fn get_text_messages(&self) -> Vec<String> {
        self.state.get_text_messages()
    }

    /// Clear all logged messages
    pub fn clear_messages(&self) {
        self.state.clear_messages();
    }

    /// Shutdown the server
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for WebSocketServer {
    fn drop(&mut self) {
        self.shutdown();
        // Wait for the server thread to finish
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Run WebSocket server
async fn run_websocket_server(
    tls_enabled: bool,
    tls_config: Option<TlsConfig>,
    state: Arc<WebSocketState>,
    shutdown_rx: watch::Receiver<bool>,
    port_tx: mpsc::Sender<u16>,
) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind TCP listener");
    let port = listener.local_addr().unwrap().port();
    port_tx.send(port).expect("Failed to send port");

    if tls_enabled {
        if let Some(ref tls) = tls_config {
            let tls_acceptor = tls.build_tls_acceptor();
            crate::handlers::websocket::run_websocket_tls_server(
                listener,
                tls_acceptor,
                state,
                shutdown_rx,
            )
            .await;
        }
    } else {
        crate::handlers::websocket::run_websocket_server(listener, state, shutdown_rx).await;
    }
}

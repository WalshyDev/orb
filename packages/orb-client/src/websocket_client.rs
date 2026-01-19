//! WebSocket client implementation using tokio-tungstenite

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::protocol::CloseFrame as TungsteniteCloseFrame;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream as TungsteniteStream};
use url::Url;

use crate::dns::{OverrideRule, apply_dns_overrides, resolve_address};
use crate::error::OrbError;
use crate::events::{BoxedEventHandler, ClientEvent};
use crate::tls::build_client_tls_config;

/// Configuration for a WebSocket connection
pub struct WebSocketConfig {
    pub url: Url,
    pub connect_timeout: Option<Duration>,
    pub max_time: Option<Duration>,
    pub insecure: bool,
    pub use_system_cert_store: bool,
    pub dns_overrides: Vec<OverrideRule>,
    pub event_handler: Option<BoxedEventHandler>,
    pub ca_certs: Vec<CertificateDer<'static>>,
    pub client_cert: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    pub headers: Vec<(String, String)>,
}

impl WebSocketConfig {
    pub fn new(url: Url) -> Self {
        Self {
            url,
            connect_timeout: None,
            max_time: None,
            insecure: false,
            use_system_cert_store: false,
            dns_overrides: Vec::new(),
            event_handler: None,
            ca_certs: Vec::new(),
            client_cert: None,
            headers: Vec::new(),
        }
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

    pub fn dns_overrides(mut self, rules: Vec<OverrideRule>) -> Self {
        self.dns_overrides = rules;
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

    pub fn client_cert(
        mut self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.client_cert = Some((certs, key));
        self
    }

    pub fn header(mut self, name: String, value: String) -> Self {
        self.headers.push((name, value));
        self
    }
}

/// WebSocket message types
#[derive(Debug, Clone)]
pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<CloseFrame>),
}

/// Close frame with code and reason
#[derive(Debug, Clone)]
pub struct CloseFrame {
    pub code: u16,
    pub reason: String,
}

// Internal enum to hold either plain or TLS WebSocket streams
enum WebSocketInner {
    Plain(Box<TungsteniteStream<TcpStream>>),
    Tls(Box<TungsteniteStream<MaybeTlsStream<TcpStream>>>),
}

/// A connected WebSocket stream
pub struct WebSocketStream {
    inner: WebSocketInner,
    event_handler: Option<BoxedEventHandler>,
    url: Url,
}

impl WebSocketStream {
    /// Get the URL this stream is connected to
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Send a text message
    pub async fn send_text(&mut self, message: &str) -> Result<(), OrbError> {
        let size = message.len();
        let msg = Message::Text(message.to_string().into());

        match &mut self.inner {
            WebSocketInner::Plain(stream) => {
                stream
                    .send(msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
            WebSocketInner::Tls(stream) => {
                stream
                    .send(msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
        }

        if let Some(ref handler) = self.event_handler {
            handler.on_event(ClientEvent::WebSocketMessageSent {
                message_type: "text".to_string(),
                size,
            });
        }
        Ok(())
    }

    /// Send a binary message
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), OrbError> {
        let size = data.len();
        let msg = Message::Binary(data.to_vec().into());

        match &mut self.inner {
            WebSocketInner::Plain(stream) => {
                stream
                    .send(msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
            WebSocketInner::Tls(stream) => {
                stream
                    .send(msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
        }

        if let Some(ref handler) = self.event_handler {
            handler.on_event(ClientEvent::WebSocketMessageSent {
                message_type: "binary".to_string(),
                size,
            });
        }
        Ok(())
    }

    /// Send a ping
    pub async fn send_ping(&mut self, data: &[u8]) -> Result<(), OrbError> {
        let msg = Message::Ping(data.to_vec().into());

        match &mut self.inner {
            WebSocketInner::Plain(stream) => {
                stream
                    .send(msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
            WebSocketInner::Tls(stream) => {
                stream
                    .send(msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
        }

        if let Some(ref handler) = self.event_handler {
            handler.on_event(ClientEvent::WebSocketMessageSent {
                message_type: "ping".to_string(),
                size: data.len(),
            });
        }
        Ok(())
    }

    /// Receive the next message
    pub async fn recv(&mut self) -> Result<Option<WebSocketMessage>, OrbError> {
        let msg_result = match &mut self.inner {
            WebSocketInner::Plain(stream) => stream.next().await,
            WebSocketInner::Tls(stream) => stream.next().await,
        };

        match msg_result {
            Some(Ok(msg)) => {
                let ws_msg = self.process_message(msg).await?;
                Ok(Some(ws_msg))
            }
            Some(Err(e)) => Err(OrbError::WebSocketReceive(e.to_string())),
            None => Ok(None),
        }
    }

    async fn process_message(&mut self, msg: Message) -> Result<WebSocketMessage, OrbError> {
        match msg {
            Message::Text(text) => {
                let size = text.len();
                if let Some(ref handler) = self.event_handler {
                    handler.on_event(ClientEvent::WebSocketMessageReceived {
                        message_type: "text".to_string(),
                        size,
                    });
                }
                Ok(WebSocketMessage::Text(text.to_string()))
            }
            Message::Binary(data) => {
                let size = data.len();
                if let Some(ref handler) = self.event_handler {
                    handler.on_event(ClientEvent::WebSocketMessageReceived {
                        message_type: "binary".to_string(),
                        size,
                    });
                }
                Ok(WebSocketMessage::Binary(data.to_vec()))
            }
            Message::Ping(data) => {
                if let Some(ref handler) = self.event_handler {
                    handler.on_event(ClientEvent::WebSocketMessageReceived {
                        message_type: "ping".to_string(),
                        size: data.len(),
                    });
                }
                // Auto-respond with pong
                let pong = Message::Pong(data.clone());
                match &mut self.inner {
                    WebSocketInner::Plain(stream) => {
                        let _ = stream.send(pong).await;
                    }
                    WebSocketInner::Tls(stream) => {
                        let _ = stream.send(pong).await;
                    }
                }
                Ok(WebSocketMessage::Ping(data.to_vec()))
            }
            Message::Pong(data) => {
                if let Some(ref handler) = self.event_handler {
                    handler.on_event(ClientEvent::WebSocketMessageReceived {
                        message_type: "pong".to_string(),
                        size: data.len(),
                    });
                }
                Ok(WebSocketMessage::Pong(data.to_vec()))
            }
            Message::Close(frame) => {
                let close_frame = frame.map(|f| CloseFrame {
                    code: f.code.into(),
                    reason: f.reason.to_string(),
                });
                if let Some(ref handler) = self.event_handler {
                    handler.on_event(ClientEvent::WebSocketClosed {
                        code: close_frame.as_ref().map(|f| f.code),
                        reason: close_frame.as_ref().map(|f| f.reason.clone()),
                    });
                }
                Ok(WebSocketMessage::Close(close_frame))
            }
            Message::Frame(_) => {
                // Raw frames are not exposed in the API
                // Return a ping as placeholder (will be filtered by caller if needed)
                Ok(WebSocketMessage::Ping(vec![]))
            }
        }
    }

    /// Close the connection gracefully
    pub async fn close(mut self) -> Result<(), OrbError> {
        let close_msg = Message::Close(Some(TungsteniteCloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "".into(),
        }));

        match &mut self.inner {
            WebSocketInner::Plain(stream) => {
                stream
                    .send(close_msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
            WebSocketInner::Tls(stream) => {
                stream
                    .send(close_msg)
                    .await
                    .map_err(|e| OrbError::WebSocketSend(e.to_string()))?;
            }
        }

        if let Some(ref handler) = self.event_handler {
            handler.on_event(ClientEvent::WebSocketClosed {
                code: Some(1000),
                reason: None,
            });
        }
        Ok(())
    }
}

/// Connect to a WebSocket server
pub async fn connect(config: WebSocketConfig) -> Result<WebSocketStream, OrbError> {
    let url = &config.url;
    let is_secure = url.scheme() == "wss";
    let host = url
        .host_str()
        .ok_or_else(|| OrbError::WebSocketConnect("No host in URL".to_string()))?;
    let default_port = if is_secure { 443 } else { 80 };
    let port = url.port().unwrap_or(default_port);

    // Apply DNS overrides if any
    let (target_host, target_port) =
        apply_dns_overrides(host, port, &config.dns_overrides, &config.event_handler);

    // Emit connection start event
    if let Some(ref handler) = config.event_handler {
        handler.on_event(ClientEvent::WebSocketConnecting {
            host: target_host.clone(),
            port: target_port,
            is_secure,
        });
    }

    let connect_start = Instant::now();

    // Resolve the target address
    let addr = resolve_address(&target_host, target_port)?;

    // Connect timeout
    let connect_timeout_duration = config.connect_timeout.unwrap_or(Duration::from_secs(30));

    // Connect TCP socket
    let tcp_stream = match timeout(connect_timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            if let Some(ref handler) = config.event_handler {
                handler.on_event(ClientEvent::WebSocketConnectionFailed {
                    host: target_host.clone(),
                    port: target_port,
                    error: e.to_string(),
                });
            }
            return Err(OrbError::WebSocketConnect(e.to_string()));
        }
        Err(_) => {
            if let Some(ref handler) = config.event_handler {
                handler.on_event(ClientEvent::WebSocketConnectionFailed {
                    host: target_host.clone(),
                    port: target_port,
                    error: "Connection timed out".to_string(),
                });
            }
            return Err(OrbError::Timeout {
                timeout: connect_timeout_duration,
            });
        }
    };

    // Build WebSocket request
    // tokio-tungstenite requires a full URI with ws:// or wss:// scheme
    let ws_uri = {
        let path_and_query = if let Some(query) = url.query() {
            format!("{}?{}", url.path(), query)
        } else if url.path().is_empty() {
            "/".to_string()
        } else {
            url.path().to_string()
        };

        if is_secure {
            format!("wss://{}:{}{}", host, port, path_and_query)
        } else {
            format!("ws://{}:{}{}", host, port, path_and_query)
        }
    };

    let mut request_builder = Request::builder()
        .uri(&ws_uri)
        .header("Host", format!("{}:{}", host, port))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key());

    // Add custom headers
    for (name, value) in &config.headers {
        request_builder = request_builder.header(name.as_str(), value.as_str());
    }

    let request = request_builder
        .body(())
        .map_err(|e| OrbError::WebSocketConnect(format!("Failed to build request: {}", e)))?;

    // Connect with or without TLS
    let inner = if is_secure {
        // Build TLS config
        let tls_config = build_client_tls_config(
            config.insecure,
            config.use_system_cert_store,
            &config.ca_certs,
            config.client_cert.as_ref(),
        )?;

        let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));

        match tokio_tungstenite::client_async_tls_with_config(
            request,
            tcp_stream,
            None,
            Some(connector),
        )
        .await
        {
            Ok((stream, _response)) => WebSocketInner::Tls(Box::new(stream)),
            Err(e) => {
                if let Some(ref handler) = config.event_handler {
                    handler.on_event(ClientEvent::WebSocketConnectionFailed {
                        host: target_host.clone(),
                        port: target_port,
                        error: e.to_string(),
                    });
                }
                return Err(OrbError::WebSocketConnect(e.to_string()));
            }
        }
    } else {
        match tokio_tungstenite::client_async(request, tcp_stream).await {
            Ok((stream, _response)) => WebSocketInner::Plain(Box::new(stream)),
            Err(e) => {
                if let Some(ref handler) = config.event_handler {
                    handler.on_event(ClientEvent::WebSocketConnectionFailed {
                        host: target_host.clone(),
                        port: target_port,
                        error: e.to_string(),
                    });
                }
                return Err(OrbError::WebSocketConnect(e.to_string()));
            }
        }
    };

    let connect_duration = connect_start.elapsed();

    // Emit connection established event
    if let Some(ref handler) = config.event_handler {
        handler.on_event(ClientEvent::WebSocketConnected {
            host: target_host,
            port: target_port,
            duration: connect_duration,
        });
    }

    Ok(WebSocketStream {
        inner,
        event_handler: config.event_handler,
        url: config.url,
    })
}

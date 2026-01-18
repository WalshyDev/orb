//! WebSocket handler for testing WebSocket connections

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::Message;

use super::{ReceivedWebSocketMessage, WebSocketState};

/// Run a WebSocket server (non-TLS)
pub async fn run_websocket_server(
    listener: TcpListener,
    state: Arc<WebSocketState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Abort all connection tasks on shutdown
                    connection_tasks.abort_all();
                    break;
                }
            }

            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        connection_tasks.spawn(async move {
                            if let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await {
                                handle_websocket_connection(ws_stream, state).await;
                            }
                        });
                    }
                    Err(_) => continue,
                }
            }
        }
    }
}

/// Run a WebSocket server over TLS
pub async fn run_websocket_tls_server(
    listener: TcpListener,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<WebSocketState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Abort all connection tasks on shutdown
                    connection_tasks.abort_all();
                    break;
                }
            }

            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        let state = Arc::clone(&state);
                        connection_tasks.spawn(async move {
                            // Perform TLS handshake
                            if let Ok(tls_stream) = tls_acceptor.accept(stream).await {
                                // Upgrade to WebSocket
                                if let Ok(ws_stream) = tokio_tungstenite::accept_async(tls_stream).await {
                                    handle_websocket_connection(ws_stream, state).await;
                                }
                            }
                        });
                    }
                    Err(_) => continue,
                }
            }
        }
    }
}

/// Handle a single WebSocket connection
async fn handle_websocket_connection<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    state: Arc<WebSocketState>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut write, mut read) = ws_stream.split();

    while let Some(msg_result) = read.next().await {
        match msg_result {
            Ok(msg) => {
                // Log the message (skip ping/pong/close for logging purposes)
                match &msg {
                    Message::Text(text) => {
                        state.log_message(ReceivedWebSocketMessage {
                            text: Some(text.to_string()),
                            binary: None,
                            is_binary: false,
                        });
                    }
                    Message::Binary(data) => {
                        state.log_message(ReceivedWebSocketMessage {
                            text: None,
                            binary: Some(data.clone()),
                            is_binary: true,
                        });
                    }
                    _ => {}
                }

                // Get response while holding lock, then release before await
                let response = {
                    let handler = state.handler.read();
                    handler.handle_message(&msg)
                };

                if let Some(response) = response
                    && write.send(response).await.is_err()
                {
                    break;
                }

                // Close message received - stop processing
                if matches!(msg, Message::Close(_)) {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Try to close gracefully
    let _ = write.close().await;
}

/// Trait for handling WebSocket messages
pub trait WebSocketHandler: Send + Sync {
    /// Handle an incoming message, optionally returning a response
    fn handle_message(&self, message: &Message) -> Option<Message>;
}

/// Echo handler - echoes all text and binary messages back
pub struct EchoHandler;

impl WebSocketHandler for EchoHandler {
    fn handle_message(&self, message: &Message) -> Option<Message> {
        match message {
            Message::Text(text) => Some(Message::Text(text.clone())),
            Message::Binary(data) => Some(Message::Binary(data.clone())),
            Message::Ping(data) => Some(Message::Pong(data.clone())),
            Message::Pong(_) => None,
            Message::Close(frame) => Some(Message::Close(frame.clone())),
            Message::Frame(_) => None,
        }
    }
}

/// No-op handler - accepts connections but doesn't respond to messages
pub struct NoOpHandler;

impl WebSocketHandler for NoOpHandler {
    fn handle_message(&self, message: &Message) -> Option<Message> {
        match message {
            Message::Ping(data) => Some(Message::Pong(data.clone())),
            Message::Close(frame) => Some(Message::Close(frame.clone())),
            _ => None,
        }
    }
}

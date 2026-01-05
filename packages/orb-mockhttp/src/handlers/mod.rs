//! Protocol handlers for HTTP/1.1, HTTP/2, HTTP/3, and WebSocket

pub mod http1;
pub mod http2;
pub mod http3;
pub mod websocket;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use parking_lot::RwLock;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio_stream::Stream;

use crate::request::Request;
use crate::response::Response;
use crate::route::Route;

/// A body type that can be streamed with delays between chunks (for hyper-based handlers)
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// Stream that yields body chunks with optional delays between them.
/// Used by HTTP/1.1 and HTTP/2 handlers for chunked streaming responses.
pub struct DelayedChunkStream {
    body: Bytes,
    chunk_size: usize,
    delay: Duration,
    position: usize,
    pending_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl DelayedChunkStream {
    pub fn new(body: Bytes, chunk_size: usize, delay: Duration) -> Self {
        Self {
            body,
            chunk_size,
            delay,
            position: 0,
            pending_delay: None,
        }
    }
}

impl Stream for DelayedChunkStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // If we're done, return None
        if self.position >= self.body.len() {
            return Poll::Ready(None);
        }

        // Handle delay between chunks (skip delay for first chunk)
        if self.position > 0 {
            if let Some(ref mut sleep) = self.pending_delay {
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => {
                        self.pending_delay = None;
                    }
                }
            } else {
                // Start a new delay
                self.pending_delay = Some(Box::pin(tokio::time::sleep(self.delay)));
                return self.poll_next(cx);
            }
        }

        // Calculate chunk boundaries
        let end = std::cmp::min(self.position + self.chunk_size, self.body.len());
        let chunk = self.body.slice(self.position..end);
        self.position = end;

        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }
}

/// Build a hyper response from our Response type, with optional streaming.
/// Used by HTTP/1.1 and HTTP/2 handlers.
pub fn build_hyper_response(response: Response) -> hyper::Response<BoxBody> {
    let mut builder = hyper::Response::builder().status(response.status());

    // Copy headers
    for (key, value) in response.headers().iter() {
        builder = builder.header(key, value);
    }

    // Set content-length if not already set
    if !response
        .headers()
        .contains_key(http::header::CONTENT_LENGTH)
    {
        builder = builder.header(http::header::CONTENT_LENGTH, response.body().len());
    }

    // Create the body - streaming or full
    let body: BoxBody = if let Some(delay) = response.chunk_delay() {
        // Use streaming body with delays
        let stream = DelayedChunkStream::new(response.body().clone(), response.chunk_size(), delay);
        BodyExt::boxed(StreamBody::new(stream))
    } else {
        // Use full body (no streaming)
        BodyExt::boxed(Full::new(response.body().clone()))
    };

    builder.body(body).unwrap_or_else(|_| {
        hyper::Response::builder()
            .status(500)
            .body(BodyExt::boxed(Full::new(Bytes::from_static(
                b"Internal Server Error",
            ))))
            .unwrap()
    })
}

/// Shared state for all protocol handlers
pub struct ServerState {
    /// Registered routes
    routes: RwLock<Vec<Arc<Route>>>,
    /// Default response when no route matches
    default_response: Response,
    logged_requests: RwLock<Vec<Request>>,
}

impl ServerState {
    /// Create a new server state
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(Vec::new()),
            default_response: Response::not_found(),
            logged_requests: RwLock::new(Vec::new()),
        }
    }

    /// Add a route to the server
    pub fn add_route(&self, route: Arc<Route>) {
        self.routes.write().push(route);
    }

    /// Find a matching route and handle the request
    pub fn handle_request(&self, request: &Request) -> Response {
        self.logged_requests.write().push(request.clone());

        let routes = self.routes.read();
        for route in routes.iter() {
            if route.matches(request) {
                return route.handle(request);
            }
        }
        self.default_response.clone()
    }

    /// Set the default response for unmatched requests
    #[allow(dead_code)]
    pub fn set_default_response(&self, response: Response) {
        // Note: This requires interior mutability, but for simplicity
        // we'll just handle unmatched routes with 404
        let _ = response;
    }

    /// Get all registered routes
    #[allow(dead_code)]
    pub fn routes(&self) -> Vec<Arc<Route>> {
        self.routes.read().clone()
    }

    /// Clear all routes
    pub fn clear_routes(&self) {
        self.routes.write().clear();
    }

    pub fn assert_requests(&self, expected_count: usize) {
        let logged_requests = self.logged_requests.read();
        assert_eq!(
            logged_requests.len(),
            expected_count,
            "Expected {} requests, but got {}",
            expected_count,
            logged_requests.len()
        );
    }

    pub fn get_raw_request(&self) -> Option<String> {
        let logged_requests = self.logged_requests.read();
        if logged_requests.is_empty() {
            None
        } else {
            Some(self.get_raw_requests().into_iter().last().unwrap())
        }
    }

    pub fn get_raw_requests(&self) -> Vec<String> {
        let logged_requests = self.logged_requests.read();
        let mut logs = Vec::new();

        for request in logged_requests.iter() {
            let log = format!(
                "{} {} {:?}\r\n{}\r\n\r\n{}",
                request.method().as_str(),
                request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/"),
                request.version(),
                request
                    .headers()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                    .collect::<Vec<String>>()
                    .join("\r\n"),
                String::from_utf8_lossy(request.body())
            );
            logs.push(log);
        }

        logs
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// A received WebSocket message with metadata
#[derive(Debug, Clone)]
pub struct ReceivedWebSocketMessage {
    /// The message content as a string
    pub text: Option<String>,
    pub binary: Option<Bytes>,
    /// Whether this was a binary message (vs text)
    pub is_binary: bool,
}

/// Shared state for WebSocket handlers
pub struct WebSocketState {
    /// The message handler
    pub handler: RwLock<Box<dyn websocket::WebSocketHandler>>,
    /// Logged messages received from clients
    logged_messages: RwLock<Vec<ReceivedWebSocketMessage>>,
}

impl WebSocketState {
    /// Create a new WebSocket state with the given handler
    pub fn new(handler: Box<dyn websocket::WebSocketHandler>) -> Self {
        Self {
            handler: RwLock::new(handler),
            logged_messages: RwLock::new(Vec::new()),
        }
    }

    /// Log a received message
    pub fn log_message(&self, message: ReceivedWebSocketMessage) {
        self.logged_messages.write().push(message);
    }

    /// Assert that the expected number of messages were received
    pub fn assert_messages(&self, expected_count: usize) {
        let logged = self.logged_messages.read();
        assert_eq!(
            logged.len(),
            expected_count,
            "Expected {} WebSocket messages, but got {}",
            expected_count,
            logged.len()
        );
    }

    /// Get the number of received messages
    pub fn message_count(&self) -> usize {
        self.logged_messages.read().len()
    }

    /// Get all received messages
    pub fn get_messages(&self) -> Vec<ReceivedWebSocketMessage> {
        self.logged_messages.read().clone()
    }

    /// Get all received text messages as strings
    pub fn get_text_messages(&self) -> Vec<String> {
        self.logged_messages
            .read()
            .iter()
            .filter(|m| !m.is_binary)
            .map(|m| m.text.clone().unwrap())
            .collect()
    }

    /// Clear all logged messages
    pub fn clear_messages(&self) {
        self.logged_messages.write().clear();
    }
}

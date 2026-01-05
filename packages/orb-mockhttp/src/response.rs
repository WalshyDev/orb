//! HTTP response types for the mock server

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::time::Duration;

/// Represents an HTTP response to send back to the client
#[derive(Debug, Clone)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    /// Optional delay before sending the response
    initial_delay: Option<Duration>,
    /// Optional delay between chunks when streaming
    chunk_delay: Option<Duration>,
    /// Size of each chunk when streaming (defaults to 1024)
    chunk_size: usize,
}

impl Response {
    /// Create a new response with the given status code
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            initial_delay: None,
            chunk_delay: None,
            chunk_size: 1024,
        }
    }

    /// Create a 200 OK response
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Create a 404 Not Found response
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND)
    }

    /// Create a 500 Internal Server Error response
    pub fn internal_error() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Get the status code
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the headers
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get the body
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Get the initial delay before sending response
    pub fn initial_delay(&self) -> Option<Duration> {
        self.initial_delay
    }

    /// Get the chunk delay (if streaming)
    pub fn chunk_delay(&self) -> Option<Duration> {
        self.chunk_delay
    }

    /// Get the chunk size
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Check if this response should be streamed with delays
    pub fn is_streaming(&self) -> bool {
        self.chunk_delay.is_some()
    }
}

/// Builder for constructing HTTP responses fluently
pub struct ResponseBuilder {
    response: Response,
}

impl ResponseBuilder {
    /// Create a new response builder (defaults to 200 OK)
    pub fn new() -> Self {
        Self {
            response: Response::ok(),
        }
    }

    /// Set the status code
    pub fn status(mut self, status: u16) -> Self {
        self.response.status =
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        self
    }

    /// Set a header
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        if let (Ok(k), Ok(v)) = (key.try_into(), value.try_into()) {
            self.response.headers.insert(k, v);
        }
        self
    }

    /// Set multiple headers
    pub fn headers<I, K, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        for (key, value) in headers {
            if let (Ok(k), Ok(v)) = (key.try_into(), value.try_into()) {
                self.response.headers.insert(k, v);
            }
        }
        self
    }

    /// Set the body from bytes
    pub fn body<B: Into<Bytes>>(mut self, body: B) -> Self {
        self.response.body = body.into();
        self
    }

    /// Set a text body with Content-Type: text/plain
    pub fn text<S: Into<String>>(mut self, text: S) -> Self {
        self.response.body = Bytes::from(text.into());
        self.response.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        self
    }

    /// Set a JSON body with Content-Type: application/json
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => {
                self.response.body = Bytes::from(bytes);
                self.response.headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
            }
            Err(_) => {
                self.response.status = StatusCode::INTERNAL_SERVER_ERROR;
                self.response.body = Bytes::from_static(b"Failed to serialize JSON");
            }
        }
        self
    }

    /// Set an HTML body with Content-Type: text/html
    pub fn html<S: Into<String>>(mut self, html: S) -> Self {
        self.response.body = Bytes::from(html.into());
        self.response.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        self
    }

    /// Set a delay before sending the response
    ///
    /// This causes the server to wait before sending any response data.
    /// Useful for testing timeouts or slow server scenarios.
    pub fn delay(mut self, delay: Duration) -> Self {
        self.response.initial_delay = Some(delay);
        self
    }

    /// Set a delay between chunks when streaming the response
    ///
    /// This causes the response body to be sent in chunks with the specified
    /// delay between each chunk. Useful for testing progress bars or streaming.
    pub fn chunk_delay(mut self, delay: Duration) -> Self {
        self.response.chunk_delay = Some(delay);
        self
    }

    /// Set the size of each chunk when streaming (default: 1024 bytes)
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.response.chunk_size = size;
        self
    }

    /// Build the response
    pub fn build(self) -> Response {
        self.response
    }
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ResponseBuilder> for Response {
    fn from(builder: ResponseBuilder) -> Self {
        builder.build()
    }
}

/// Quick helper to create a simple text response
#[allow(dead_code)]
pub fn text_response<S: Into<String>>(status: u16, body: S) -> Response {
    ResponseBuilder::new().status(status).text(body).build()
}

/// Quick helper to create a JSON response
#[allow(dead_code)]
pub fn json_response<T: serde::Serialize>(status: u16, value: &T) -> Response {
    ResponseBuilder::new().status(status).json(value).build()
}

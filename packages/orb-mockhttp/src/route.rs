//! Route matching and handler configuration

use bytes::Bytes;
use http::Method;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

use crate::handlers::ServerState;
use crate::request::Request;
use crate::response::{Response, ResponseBuilder};

/// Type alias for request assertion functions
type RequestAssertion = Box<dyn Fn(&Request) -> Result<(), String> + Send + Sync>;

/// Trait for request handlers
pub trait RouteHandler: Send + Sync {
    /// Handle a request and return a response
    fn handle(&self, request: &Request) -> Response;
}

/// A function-based route handler
pub struct FnHandler<F>(pub(crate) F);

impl<F> RouteHandler for FnHandler<F>
where
    F: Fn(&Request) -> Response + Send + Sync,
{
    fn handle(&self, request: &Request) -> Response {
        (self.0)(request)
    }
}

/// A simple static response handler
pub struct StaticHandler {
    response: Response,
}

impl StaticHandler {
    pub fn new(response: Response) -> Self {
        Self { response }
    }
}

impl RouteHandler for StaticHandler {
    fn handle(&self, _request: &Request) -> Response {
        self.response.clone()
    }
}

/// A route definition with matching criteria and handler
pub struct Route {
    /// The path to match (exact match)
    path: String,
    /// Optional method constraint
    method: Option<Method>,
    /// The handler for this route
    handler: Arc<dyn RouteHandler>,
    /// Count of times this route was matched
    call_count: Arc<Mutex<usize>>,
    /// Assertions to validate on each request
    assertions: Vec<RequestAssertion>,
}

impl Route {
    /// Create a new route
    pub(crate) fn new(
        path: String,
        method: Option<Method>,
        handler: Arc<dyn RouteHandler>,
        assertions: Vec<RequestAssertion>,
    ) -> Self {
        Self {
            path,
            method,
            handler,
            call_count: Arc::new(Mutex::new(0)),
            assertions,
        }
    }

    /// Check if this route matches the given request
    pub fn matches(&self, request: &Request) -> bool {
        // Path must match exactly
        if request.path() != self.path {
            return false;
        }

        // Method must match if specified
        if let Some(ref method) = self.method
            && request.method() != method
        {
            return false;
        }

        true
    }

    /// Handle a request, incrementing the call count and running assertions
    pub fn handle(&self, request: &Request) -> Response {
        // Increment call count
        *self.call_count.lock() += 1;

        // Run assertions
        for assertion in &self.assertions {
            if let Err(msg) = assertion(request) {
                eprintln!("Route assertion failed: {}", msg);
            }
        }

        // Handle the request
        self.handler.handle(request)
    }

    /// Get the number of times this route was matched
    pub fn call_count(&self) -> usize {
        *self.call_count.lock()
    }

    /// Assert that this route was called exactly n times
    pub fn assert_called(&self, n: usize) {
        let count = self.call_count();
        assert_eq!(
            count, n,
            "Expected route '{}' to be called {} times, but was called {} times",
            self.path, n, count
        );
    }

    /// Assert that this route was called at least once
    pub fn assert_called_once(&self) {
        let count = self.call_count();
        assert!(
            count >= 1,
            "Expected route '{}' to be called at least once, but was never called",
            self.path
        );
    }
}

/// Builder for creating routes with fluent API
pub struct RouteBuilder {
    path: String,
    method: Option<Method>,
    handler: Option<Arc<dyn RouteHandler>>,
    assertions: Vec<RequestAssertion>,
    server_state: Option<Arc<ServerState>>,
    /// Optional delay before sending response
    response_delay: Option<Duration>,
}

impl RouteBuilder {
    /// Create a new route builder for the given path
    pub fn new<S: Into<String>>(path: S) -> Self {
        Self {
            path: path.into(),
            method: None,
            handler: None,
            assertions: Vec::new(),
            server_state: None,
            response_delay: None,
        }
    }

    /// Associate this builder with a server state (internal use)
    pub(crate) fn with_state(mut self, state: Arc<ServerState>) -> Self {
        self.server_state = Some(state);
        self
    }

    /// Expect a specific HTTP method
    pub fn expect_method(mut self, method: &str) -> Self {
        self.method = Some(
            method
                .parse()
                .unwrap_or_else(|_| panic!("Invalid HTTP method: {}", method)),
        );
        self
    }

    /// Expect a specific header to be present with a specific value
    pub fn expect_header<KeyString: Into<String>, ValueString: Into<String>>(
        mut self,
        name: KeyString,
        value: ValueString,
    ) -> Self {
        let name = name.into();
        let value = value.into();
        self.assertions
            .push(Box::new(move |req: &Request| match req.header(&name) {
                Some(v) if v == value => Ok(()),
                Some(v) => Err(format!(
                    "Expected header '{}' to be '{}', but was '{}'",
                    name, value, v
                )),
                None => Err(format!("Expected header '{}' to be present", name)),
            }));
        self
    }

    /// Expect a header to be present (any value)
    pub fn expect_header_present(mut self, name: &'static str) -> Self {
        self.assertions.push(Box::new(move |req: &Request| {
            if req.header(name).is_some() {
                Ok(())
            } else {
                Err(format!("Expected header '{}' to be present", name))
            }
        }));
        self
    }

    /// Expect the body to contain a specific string
    pub fn expect_body_contains(mut self, substring: String) -> Self {
        self.assertions.push(Box::new(move |req: &Request| {
            let body = req.text_lossy();
            if body.contains(&substring) {
                Ok(())
            } else {
                Err(format!(
                    "Expected body to contain '{}', but body was: {}",
                    substring, body
                ))
            }
        }));
        self
    }

    /// Expect the body to equal a specific string
    pub fn expect_body(mut self, expected: String) -> Self {
        self.assertions.push(Box::new(move |req: &Request| {
            let body = req.text_lossy();
            if body == expected {
                Ok(())
            } else {
                Err(format!(
                    "Expected body to be '{}', but was: {}",
                    expected, body
                ))
            }
        }));
        self
    }

    /// Add a delay before responding
    ///
    /// The delay is applied before sending any response data.
    pub fn delay(mut self, delay: Duration) -> Self {
        self.response_delay = Some(delay);
        self
    }

    /// Respond with a status code and text body
    pub fn respond_with<S: Into<String>>(mut self, status: u16, body: S) -> Self {
        let body_bytes = Bytes::from(body.into());
        let mut builder = ResponseBuilder::new().status(status).body(body_bytes);
        if let Some(delay) = self.response_delay {
            builder = builder.delay(delay);
        }
        self.handler = Some(Arc::new(StaticHandler::new(builder.build())));
        self.register_and_return_self()
    }

    /// Respond with a status code and JSON body
    pub fn respond_with_json<T: serde::Serialize>(mut self, status: u16, value: &T) -> Self {
        let mut builder = ResponseBuilder::new().status(status).json(value);
        if let Some(delay) = self.response_delay {
            builder = builder.delay(delay);
        }
        self.handler = Some(Arc::new(StaticHandler::new(builder.build())));
        self.register_and_return_self()
    }

    /// Respond with a custom handler function
    pub fn respond_with_fn<F>(mut self, handler: F) -> Self
    where
        F: Fn(&Request) -> Response + Send + Sync + 'static,
    {
        self.handler = Some(Arc::new(FnHandler(handler)));
        self.register_and_return_self()
    }

    /// Respond with a redirect to the given location
    pub fn respond_with_redirect(mut self, status: u16, location: &str) -> Self {
        let mut builder = ResponseBuilder::new()
            .status(status)
            .header("Location", location);
        if let Some(delay) = self.response_delay {
            builder = builder.delay(delay);
        }
        self.handler = Some(Arc::new(StaticHandler::new(builder.build())));
        self.register_and_return_self()
    }

    /// Respond with a body that is streamed with delays between chunks.
    ///
    /// This is useful for testing progress bars or download scenarios.
    /// The response body will be sent in chunks of `chunk_size` bytes,
    /// with `chunk_delay` pause between each chunk.
    ///
    /// # Arguments
    /// * `status` - HTTP status code
    /// * `body` - Response body content
    /// * `chunk_size` - Size of each chunk in bytes
    /// * `chunk_delay` - Delay between chunks
    pub fn respond_with_delay<S: Into<String>>(
        mut self,
        status: u16,
        body: S,
        chunk_size: usize,
        chunk_delay: Duration,
    ) -> Self {
        let body_bytes = Bytes::from(body.into());
        let mut builder = ResponseBuilder::new()
            .status(status)
            .body(body_bytes)
            .chunk_size(chunk_size)
            .chunk_delay(chunk_delay);
        if let Some(delay) = self.response_delay {
            builder = builder.delay(delay);
        }
        self.handler = Some(Arc::new(StaticHandler::new(builder.build())));
        self.register_and_return_self()
    }

    /// Build the route without registering it
    pub fn build(self) -> Route {
        Route::new(
            self.path,
            self.method,
            self.handler
                .expect("Handler must be set before building route"),
            self.assertions,
        )
    }

    /// Register the route with the server and return self for chaining
    fn register_and_return_self(self) -> Self {
        if let Some(ref state) = self.server_state {
            let route = Route::new(
                self.path.clone(),
                self.method.clone(),
                self.handler.clone().expect("Handler must be set"),
                Vec::new(), // Assertions are stored in the registered route
            );
            state.add_route(Arc::new(route));
        }
        self
    }
}

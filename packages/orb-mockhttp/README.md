# orb-mockhttp

A mock HTTP server for testing, with native support for HTTP/1.1, HTTP/2, and HTTP/3.

## Features

- **Multi-protocol**: HTTP/1.1, HTTP/2, and HTTP/3 on the same port
- **Auto-generated TLS**: No certificate setup required
- **Fluent API**: Builder pattern for routes and responses
- **Request assertions**: Validate headers, body, and method
- **Response delays**: Test timeouts and slow connections
- **WebSocket support**: Mock WebSocket endpoints

## Why orb-mockhttp over httpmock?

| Feature | orb-mockhttp | httpmock |
|---------|--------------|----------|
| HTTP/3 support | Native | No |
| HTTP/2 support | Native | No |
| Same port for all protocols | Yes | N/A |
| Auto-generated TLS certs | Yes | Manual setup |
| WebSocket mocking | Yes | No |
| Dependencies | Minimal | Minimal |

orb-mockhttp is designed for testing modern HTTP clients that need HTTP/2 and HTTP/3 support.

## Quick Start

```rust
use orb_mockhttp::{TestServerBuilder, ResponseBuilder, HttpProtocol};

#[tokio::test]
async fn test_my_http_client() {
    // Start a server (HTTP/1.1 only, no TLS)
    let server = TestServerBuilder::new().build();

    // Define a route
    server.on_request("/api/users")
        .expect_method("GET")
        .respond_with(200, r#"{"users": []}"#);

    // Use the server URL in your tests
    let url = server.url("/api/users");  // http://127.0.0.1:PORT/api/users

    // Make requests with your HTTP client...
}
```

## Examples

### HTTPS with HTTP/2 and HTTP/3

```rust
// Enable TLS - automatically supports HTTP/1.1, HTTP/2, and HTTP/3
let server = TestServerBuilder::new()
    .with_tls()
    .build();

server.on_request("/test")
    .respond_with(200, "Hello");

// Same URL works for all protocols
let url = server.url("/test");  // https://127.0.0.1:PORT/test
```

### Specific Protocol Only

```rust
// HTTP/2 only
let server = TestServerBuilder::new()
    .with_protocols(&[HttpProtocol::Http2])
    .build();

// HTTP/3 only
let server = TestServerBuilder::new()
    .with_protocols(&[HttpProtocol::Http3])
    .build();
```

### Request Assertions

```rust
server.on_request("/api/users")
    .expect_method("POST")
    .expect_header("Content-Type", "application/json")
    .expect_header("Authorization", "Bearer token123")
    .expect_body_contains("name")
    .respond_with(201, "Created");
```

### JSON Responses

```rust
use serde_json::json;

server.on_request("/api/user/1")
    .respond_with_json(200, &json!({
        "id": 1,
        "name": "Alice",
        "email": "alice@example.com"
    }));
```

### Dynamic Responses

```rust
use orb_mockhttp::ResponseBuilder;

server.on_request_fn("/echo", |req| {
    ResponseBuilder::new()
        .status(200)
        .header("X-Request-Method", req.method().as_str())
        .text(format!("You sent: {}", req.text_lossy()))
        .build()
});
```

### Response Delays

```rust
use std::time::Duration;

// Delay before responding (for timeout testing)
server.on_request("/slow")
    .delay(Duration::from_secs(5))
    .respond_with(200, "Finally!");

// Chunked response with delays (for progress bar testing)
server.on_request("/download")
    .respond_with_delay(200, large_body, 1024, Duration::from_millis(100));
```

### Redirects

```rust
server.on_request("/old-path")
    .respond_with_redirect(301, "/new-path");

server.on_request("/new-path")
    .respond_with(200, "You made it!");
```

### Call Counting

```rust
let route = server.on_request("/api/data")
    .respond_with(200, "OK");

// After making requests...
route.assert_called(3);      // Exactly 3 times
route.assert_called_once();  // At least once
```

## Response Builder

Build responses with full control:

```rust
use orb_mockhttp::ResponseBuilder;
use std::time::Duration;

let response = ResponseBuilder::new()
    .status(201)
    .header("X-Custom", "value")
    .header("Set-Cookie", "session=abc123")
    .json(&json!({"created": true}))
    .delay(Duration::from_millis(100))
    .build();
```

## WebSocket Support

```rust
use orb_mockhttp::{TestServerBuilder, EchoHandler};

let server = TestServerBuilder::new()
    .with_tls()
    .build();

// Echo all messages back
server.websocket("/ws", EchoHandler);

// Or use a custom handler
server.websocket_fn("/chat", |message| {
    Some(format!("Server received: {}", message))
});
```

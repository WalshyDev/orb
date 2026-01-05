# orb 🟠

[![CI](https://github.com/WalshyDev/orb/workflows/CI/badge.svg)](https://github.com/WalshyDev/orb/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🟠 **Your powerful HTTP CLI** - A powerful cURL alternative built in Rust

> *Requests that orbit around your APIs* 🌐

**orb** supports HTTP/1.1, HTTP/2, HTTP/3, WebSockets, and multiple modern compression algorithms (zstd, brotli, gzip, deflate).

📚 **[Documentation](https://orb-tools.com)** · 📦 **[Download](https://orb-tools.com/getting-started/installation)** · 🐙 **[Releases](https://github.com/WalshyDev/orb/releases)**

```bash
orb https://api.example.com
```

> [!TIP]
> **For Contributors**: See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
>
> **For AI Agents**: See [AGENTS.md](AGENTS.md) for architecture and development guide

## Workspace

This repository is organized as a Cargo workspace:

| Package                               | Description                                             |
|---------------------------------------|---------------------------------------------------------|
| [orb-cli](packages/orb-cli)           | The orb command-line tool                               |
| [orb-mockhttp](packages/orb-mockhttp) | Mock HTTP server for testing (HTTP/1.1, HTTP/2, HTTP/3) |
| [orb-client](packages/orb-client)     | Internal HTTP client library                            |

# orb-cli

## Features

- **Multiple HTTP Versions**: Support for HTTP/1.1, HTTP/2, and HTTP/3
- **WebSocket Support**: Full WebSocket (ws://) and Secure WebSocket (wss://) support with interactive mode
- **Compression**: Built-in support for zstd, brotli, gzip, and deflate compression
- **Authentication**: Basic and Bearer token authentication
- **Custom Headers**: Add any custom headers to your requests
- **File Upload**: Multipart form data support
- **Redirects**: Follow redirects with configurable limits
- **Timeouts**: Connection and request timeouts
- **SSL/TLS**: Certificate validation with option to skip verification
- **Proxy Support**: HTTP/HTTPS proxy configuration
- **Cookie Management**: Send and save cookies
- **Verbose Output**: Detailed request/response information
- **Cross-Platform**: Works on macOS, Linux, and Windows

## cURL comparison

| Feature                     | orb   | cURL   |
|-----------------------------|-------|--------|
| HTTP/1.1, HTTP/2, HTTP/3    | ✅     | 🟧[^1] |
| WebSocket Support           | ✅     | ❌     |
| Compression (zstd, brotli)  | ✅     | 🟧[^2] |
| Other protocols (FTP, SMTP) | ❌[^3] | ✅     |

[^1]: cURL supports HTTP/2 but not HTTP/3 natively. This can be built manually.
[^2]: cURL supports deflate, gzip and brotli but not zstd natively. This can be built manually.
[^3]: orb focuses on HTTP and WebSocket protocols only. For other protocols, use cURL or other specialized tools.

## HTTP Usage

```bash
# Basic GET request
$ orb https://example.com/

$ # POST request with JSON body
$ orb https://api.example.com/data -X POST --json '{"name": "orb", "type": "cli"}'

# PUT request with form data
$ orb https://api.example.com/update -X PUT --form "field1=value1" --form "field2=value2"

# Verbose output
$ orb https://example.com/ -v

# Connect to a different IP/port
$ orb https://example.com/ -v --connect-to example.com:443:127.0.0.1:8443

# and a lot more!
```

## WebSocket Usage

orb supports WebSocket connections for real-time bidirectional communication.

### Basic WebSocket Connection

WebSocket mode is automatically detected from the URL scheme (ws:// or wss://).

```bash
# WebSocket connection (auto-detected)
orb ws://localhost:8080/ws

# Secure WebSocket connection
orb wss://echo.websocket.org
```

### Send a Single Message

```bash
# Send a message and exit after receiving response
orb ws://localhost:8080/ws --ws-message "Hello WebSocket"
```

### Interactive Mode

When no `--ws-message` is provided, orb enters interactive mode where you can:
- Type messages to send them to the server
- Type `/ping` to send a ping frame
- Type `/close` or `/quit` to close the connection
- Press Ctrl+C to exit

```bash
# Interactive WebSocket session
orb ws://localhost:8080/chat -v

# With custom headers
orb wss://api.example.com/ws \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value"
```

### WebSocket with Options

```bash
# Verbose output to see connection details
orb ws://localhost:8080/ws -v

# Silent mode (no output)
orb ws://localhost:8080/ws -s

# With connection timeout
orb ws://localhost:8080/ws --connect-timeout 10

# Allow insecure SSL/TLS connections
orb wss://self-signed.local/ws --insecure
```

## Building for Distribution

### macOS Universal Binary

Builds a universal binary for macOS (x86_64 + arm64):
```bash
make build-macos
```

### Linux

```bash
make build-linux
```

### Windows

```bash
make build-windows
```

## Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make coverage
```

# orb-mockhttp

orb-mockhttp allows easy local testing of HTTP requests, supporting HTTP/1.1, HTTP/2, HTTP/3 and WebSockets.

## Usage

```rust
#[tokio::test]
async fn test_basic_request_response() {
    // Setup server to respond to /test with a 200
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");

    // Send a request with orb-client
    let response = RequestBuilder::new(Url::parse(&server.url("/echo")).unwrap())
      .send()
      .await
      .unwrap();

    // Assert we got a 200
    assert_eq!(response.status(), 200);

    // Assert server received 1 request
    server.assert_one_request();
}

#[tokio::test]
async fn test_more_complicated_example() {
    // Setup server with custom logic
    // Responds with "Hello, {name}!" where name is a query parameter
    let server = TestServerBuilder::new().build();
    server.on_request_fn("/dynamic", |req| {
        let binding = "Guest".to_string();
        let name = req.query_param("name").unwrap_or(&binding);
        ResponseBuilder::new()
            .status(200)
            .body(format!("Hello, {}!", name))
            .build()
    });

    // Send request with query parameter
    let response = RequestBuilder::new(Url::parse(&server.url("/dynamic?name=orb")).unwrap())
      .send()
      .await
      .unwrap();

    // Assert response body
    let body = response.text().await.unwrap();
    assert_eq!(body, "Hello, orb!");

    // Assert server received 1 request
    server.assert_requests(1);
}

#[tokio::test]
async fn test_websocket_echo() {
    // Setup WebSocket echo server
    let server = WebSocketServer::echo();

    // Send request with query parameter
    let mut socket = RequestBuilder::new(Url::parse(&server.url("/ws")).unwrap())
      .connect_websocket()
      .await
      .unwrap();

    socket.send_text("Echo echo echo echo").await.expect("Failed to send text");

    let message = socket.recv().await.unwrap().unwrap();
    match message {
        WebSocketMessage::Text(text) => assert_eq!(text, "Echo echo echo echo"),
        _ => assert!(false, "Expected text message"),
    }
}
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Code style guidelines
- Testing requirements
- Pull request process

**Quick Start for Contributors:**
```bash
git clone <your-fork>
cd orb
cargo build
cargo test
cargo clippy
```

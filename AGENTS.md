# Orb - HTTP Client

Orb is a powerful HTTP client CLI tool written in Rust, designed as a modern alternative to cURL. It features a custom HTTP client built on hyper with support for HTTP/1.1, HTTP/2, and HTTP/3.

## Architecture Overview

The project is organized as a Cargo workspace with three packages:

```
packages/
├── orb-cli/       - CLI application (the `orb` binary)
├── orb-client/    - HTTP client library (internal)
└── orb-mockhttp/  - Mock HTTP server library (HTTP/1.1, HTTP/2, HTTP/3)
```

**Important:** `orb-client` is the HTTP client library used by the CLI. While internal for now, it is designed as a standalone library. Keep these concerns separated - the client should have no knowledge of CLI-specific code.

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Layer (orb-cli)                      │
│  main.rs → cli.rs → request.rs → output.rs                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                HTTP Client Library (orb-client)             │
│    lib.rs           - Public exports, Response type        │
│    http_client.rs   - HttpClient & RequestBuilder          │
│    http3_client.rs  - HTTP/3 client implementation         │
│    dns.rs           - DNS resolver & connector             │
│    body.rs          - Request/Response body types          │
│    events.rs        - Event system for callbacks           │
│    error.rs         - Error types                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Mock HTTP Server (orb-mockhttp)                │
│    lib.rs           - Public exports, TestServerBuilder    │
│    server.rs        - TestServer implementation            │
│    route.rs         - Route & RouteBuilder                 │
│    request.rs       - Request type for handlers            │
│    response.rs      - Response & ResponseBuilder           │
│    tls.rs           - TLS configuration & cert generation  │
│    handlers/        - Protocol handlers (HTTP/1, 2, 3)     │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
packages/
  orb-cli/
    src/
      main.rs           - Entry point, argument validation, orchestration
      cli.rs            - CLI argument definitions (clap) and validation functions
      request.rs        - Request building from CLI args
      output.rs         - Response output handling
      headers.rs        - Header building utilities
      cookie.rs         - Cookie jar implementation (Netscape format)
      error.rs          - Error types and user-friendly error handling
      verbose_events.rs - CLI-specific event handler for verbose mode
      utils.rs          - Utility macros (fatal!)
    tests/
      fundamental.rs    - Core functionality tests
      options.rs        - CLI option tests (comprehensive)
      validation.rs     - Input validation tests
      testutils/        - TestServer, sanitize helpers, h3_server
      testdata/         - Test fixture files (certs, cookies, etc.)

  orb-client/
    src/
      lib.rs            - Public API exports, Response type
      http_client.rs    - HttpClient, HttpClientBuilder, RequestBuilder
      http3_client.rs   - HTTP/3 over QUIC implementation
      dns.rs            - OrbDnsResolver, OrbConnector, OverrideRule
      body.rs           - RequestBody, ResponseBody
      events.rs         - ClientEvent enum, EventHandler trait
      error.rs          - OrbError type

  orb-mockhttp/
    src/
      lib.rs            - Public exports, TestServerBuilder, HttpProtocol
      server.rs         - TestServer implementation
      route.rs          - Route, RouteBuilder for request matching
      request.rs        - Request type for handlers
      response.rs       - Response, ResponseBuilder
      tls.rs            - TlsConfig, auto-generated certificates
      handlers/
        mod.rs          - Handler traits
        http1.rs        - HTTP/1.1 handler
        http2.rs        - HTTP/2 handler
        http3.rs        - HTTP/3 handler
    tests/
      edge_cases.rs     - Edge case tests
      http_methods.rs   - HTTP method tests
      lifecycle.rs      - Server lifecycle tests
      protocols.rs      - Multi-protocol tests
      request.rs        - Request matching tests
      response.rs       - Response building tests
      routes.rs         - Route matching tests
      tls.rs            - TLS tests
```

## Key Design Principles

### 1. Client/CLI Separation

The HTTP client (`orb-client`) must be usable as a standalone library. It should:
- Have no dependencies on CLI-specific code
- Use the event system for extensibility (not direct printing)
- Provide a clean builder API

**Event-based architecture for verbose logging:**
```rust
// In orb-client events.rs
pub enum ClientEvent {
    DnsResolutionStarted { host: String },
    DnsResolutionCompleted { host: String, ip: IpAddr, duration: Duration },
    ConnectToOverride { from_host: String, from_port: u16, to_host: String, to_port: u16 },
    // ... more events
}

pub trait EventHandler: Send + Sync {
    fn on_event(&self, event: ClientEvent);
}

// CLI implements its own handler in verbose_events.rs
pub struct VerboseEventHandler;
impl EventHandler for VerboseEventHandler {
    fn on_event(&self, event: ClientEvent) {
        match event {
            ClientEvent::DnsResolutionStarted { host } => {
                eprintln!("* Resolving host: {}", host);
            }
            // ...
        }
    }
}
```

### 2. Validation in CLI Layer

All argument validation functions live in `cli.rs` and are called from `main.rs` before making requests:

```rust
// cli.rs
pub fn validate_cert_and_key(cert: Option<&PathBuf>, key: Option<&PathBuf>) {
    if let Some(cert_path) = cert {
        let cert_data = match fs::read(cert_path) {
            Ok(data) => data,
            Err(e) => {
                crate::fatal!(
                    "Failed to read client certificate '{}': {}",
                    cert_path.display(),
                    e
                );
            }
        };
        // ... validation logic
    }
}

// main.rs
fn main() {
    let args = cli::Args::parse();

    validate_connect_to(&args.connect_to);
    validate_cert_and_key(args.cert.as_ref(), args.key.as_ref());
    validate_cacert(args.cacert.as_ref());
    validate_cookie(args.cookie.as_ref());
    validate_proxy(args.proxy.as_ref());

    // ... proceed with request
}
```

### 3. User-Friendly Error Messages

Errors must be helpful and actionable. Use the `fatal!` macro for CLI errors:

```rust
// Error messages should:
// - Explain what went wrong
// - Include the problematic value
// - Suggest how to fix it (when applicable)

crate::fatal!(
    "Invalid --connect-to format '{}'. Expected HOST1:PORT1:HOST2:PORT2",
    rule
);

crate::fatal!(
    "Failed to parse client certificate '{}'. The file must contain both certificate and private key in PEM format, or use --key to specify the key file separately.",
    cert_path.display()
);
```

### 4. Builder Pattern for Client

Both `HttpClientBuilder` and `RequestBuilder` use the builder pattern:

```rust
use orb_client::{HttpClient, RequestBuilder, Url};
use orb_client::body::RequestBody;

let client = HttpClient::builder()
    .connect_timeout(Duration::from_secs(10))
    .dns_overrides(rules)
    .ca_certs(certs)
    .event_handler(Arc::new(handler))
    .build();

let response = RequestBuilder::new(Url::parse("https://example.com").unwrap())
    .method(Method::POST)
    .header("Content-Type", "application/json")
    .body(RequestBody::from_bytes(data))
    .send()
    .await?;
```

## Testing Guidelines

### Building and Testing

```bash
# Use make commands (preferred)
make build          # Debug build
make release        # Release build
make test           # Run all tests
make coverage       # Generate coverage report

# Or use cargo directly
cargo build
cargo test
cargo test test_name
```

### Test Organization

**CLI tests** (`packages/orb-cli/tests/`):
- `fundamental.rs` - Core behavior that must never break
- `options.rs` - Individual CLI options (most tests go here)
- `validation.rs` - Input validation edge cases

**Mock server tests** (`packages/orb-mockhttp/tests/`):
- `http_methods.rs` - HTTP method tests
- `protocols.rs` - Multi-protocol tests (HTTP/1.1, HTTP/2, HTTP/3)
- `request.rs` - Request matching tests
- `response.rs` - Response building tests
- `routes.rs` - Route matching tests
- `edge_cases.rs` - Edge case handling
- `lifecycle.rs` - Server lifecycle tests
- `tls.rs` - TLS configuration tests

### Using orb-mockhttp

The project includes `orb-mockhttp`, a custom mock HTTP server supporting HTTP/1.1, HTTP/2, and HTTP/3:

```rust
use orb_mockhttp::{TestServerBuilder, ResponseBuilder, HttpProtocol};

// HTTP/1.1 only (no TLS)
let server = TestServerBuilder::new().build();

// HTTPS with all protocols (HTTP/1.1 + HTTP/2 + HTTP/3)
let server = TestServerBuilder::new()
    .with_tls()
    .build();

// Only HTTP/2
let server = TestServerBuilder::new()
    .with_tls()
    .with_protocols(&[HttpProtocol::Http2])
    .build();

// Set up routes
server.on_request("/test")
    .expect_method("GET")
    .respond_with(200, "Hello, world!");

// Dynamic responses
server.on_request_fn("/echo", |req| {
    ResponseBuilder::new()
        .status(200)
        .text(format!("Received: {}", req.text_lossy()))
        .build()
});

// Get URL for the server
let url = server.url("/test");  // http://127.0.0.1:PORT/test or https://...
```

### Use `test_case` for Parameterized Tests

**Never create multiple test functions for variations of the same test:**

```rust
#[test_case(
    "tests/testdata/does-not-exist.pem",
    "Failed to read client certificate 'tests/testdata/does-not-exist.pem': No such file or directory (os error 2)\n";
    "cert file not found"
)]
#[test_case(
    "tests/testdata/test_data.txt",
    "Failed to parse client certificate 'tests/testdata/test_data.txt'. The file must contain both certificate and private key in PEM format, or use --key to specify the key file separately.\n";
    "cert invalid pem"
)]
fn test_cert_invalid(cert_path: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://example.com/").arg("--cert").arg(cert_path);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, expected_error);  // Note: includes trailing \n
}
```

### Dynamic Ports in test_case

Use `{PORT}` placeholder for dynamic port values:

```rust
#[test_case(
    "example.com:80:127.0.0.1:{PORT}";
    "basic redirect"
)]
#[test_case(
    "example.com::127.0.0.1:{PORT}";
    "any port match"
)]
fn test_connect_to(pattern: &str) {
    let server = TestServerBuilder::new().build();
    let connect_to = pattern.replace("{PORT}", &server.port().to_string());
    // ...
}
```

### HTTP vs HTTPS in Tests

**Use `http://` for tests without TLS, `https://` for tests with TLS:**

```rust
// HTTP/1.1 without TLS
let server = TestServerBuilder::new().build();
cmd.arg(server.url("/test"));  // http://127.0.0.1:PORT/test

// HTTPS with TLS (required for HTTP/2 and HTTP/3)
let server = TestServerBuilder::new().with_tls().build();
cmd.arg(server.url("/test"))   // https://127.0.0.1:PORT/test
   .arg("--insecure");         // Accept self-signed cert
```

### Test Utilities

`testutils/mod.rs` provides:

- **`TestServer`**: Simple TCP server that captures raw HTTP requests
- **`sanitize_output()`**: Normalizes ports, dates, boundaries
- **`sanitize_error()`**: Normalizes error messages

### Error Message Testing

Error messages must match exactly, including the trailing newline:

```rust
#[test_case(
    "://bad",
    "Invalid proxy URL '://bad'. Expected format: http://host:port or socks5://host:port\n";
    "invalid url format"
)]
fn test_proxy_invalid(proxy_url: &str, expected_error: &str) {
    // ...
    assert_eq!(stderr, expected_error);  // Includes \n
}
```

## Adding New Features

### 1. CLI Argument

Add to `packages/orb-cli/src/cli.rs` following existing patterns:

```rust
/// Description of the option
#[arg(short = 'x', long = "option-name", value_name = "VALUE")]
pub option_name: Option<String>,
```

### 2. Validation (if needed)

Add validation function in `cli.rs`:

```rust
pub fn validate_option_name(value: Option<&String>) {
    if let Some(val) = value {
        if /* invalid */ {
            crate::fatal!("Helpful error message about '{}'", val);
        }
    }
}
```

Call from `main.rs`:

```rust
validate_option_name(args.option_name.as_ref());
```

### 3. Implementation

- **Client-level options** (TLS, timeouts, DNS): Add to `HttpClientBuilder` in `orb-client/src/http_client.rs`
- **Request-level options** (headers, body, auth): Add to `RequestBuilder` or `orb-cli/src/request.rs`
- **Response handling**: Add to `orb-cli/src/output.rs`
- **New error types**: Add to respective `error.rs` files

### 4. Tests

Add tests in `packages/orb-cli/tests/options.rs`:

```rust
// Success case
#[tokio::test]
async fn test_option_name() {
    let server = TestServerBuilder::new().build();

    server.on_request("/test")
        .expect_method("GET")
        .respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("--option-name").arg("value");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
}

// Error cases with test_case
#[test_case("invalid", "Expected error\n"; "descriptive name")]
fn test_option_name_invalid(input: &str, expected_error: &str) {
    // ...
}
```

## Protocol Support

- **HTTP/1.1**: Full support via hyper
- **HTTP/2**: Full support via hyper with ALPN negotiation
- **HTTP/3**: Implemented via quinn/h3 (QUIC)

## Code Style

- Use `rustfmt` formatting (`make fix`)
- Prefer explicit error handling over `.unwrap()` in library code
- Use `fatal!` macro only in CLI layer, not in `orb-client`
- Keep functions focused and small
- Document public APIs with doc comments

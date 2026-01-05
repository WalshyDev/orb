# orb-client

Internal HTTP client library for the orb CLI.

This library provides the HTTP/1.1, HTTP/2, HTTP/3, and WebSocket implementations used by [orb-cli](../orb-cli). It is currently internal and not published to crates.io.

## Features

- HTTP/1.1 and HTTP/2 via hyper
- HTTP/3 via quinn/h3 (QUIC)
- WebSocket support via tokio-tungstenite
- DNS override support for connection routing
- Event-based architecture for extensibility
- Builder pattern API

## Usage

```rust
use orb_client::{HttpClient, RequestBuilder, Url};
use std::time::Duration;

let client = HttpClient::builder()
    .connect_timeout(Duration::from_secs(10))
    .build();

let response = RequestBuilder::new(Url::parse("https://example.com").unwrap())
    .send(&client)
    .await?;

println!("Status: {}", response.status());
println!("Body: {}", response.text().await?);
```

## License

MIT

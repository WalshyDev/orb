# orb-cli

The `orb` command-line HTTP client - a cURL alternative built in Rust.

See the [main README](../../README.md) for full documentation.

## Quick Start

```bash
# Simple GET request
orb https://api.example.com

# POST with JSON
orb https://api.example.com/users --json '{"name": "Alice"}'

# Use HTTP/2 or HTTP/3
orb https://api.example.com --http2
orb https://api.example.com --http3

# WebSocket connection
orb wss://echo.websocket.org
```

## Why orb over cURL?

| Feature | orb | cURL |
|---------|-----|------|
| HTTP/3 support | Native | Requires build flag |
| WebSocket | Built-in interactive mode | Requires external tools |
| Modern compression | zstd, brotli, gzip, deflate | gzip, deflate, brotli |
| Syntax | Familiar cURL-like | - |

orb aims to be a drop-in cURL replacement with modern protocol support out of the box.

## Installation

Download from [Releases](https://github.com/WalshyDev/orb/releases) or build from source:

```bash
cargo install --path packages/orb-cli
```

## License

MIT

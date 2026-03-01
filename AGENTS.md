# Agent Guide for Orb

This file provides guidance specifically for AI agents (and humans) working on this codebase. Read `AGENTS.md` first for full architecture, project structure, and design principles. This file supplements it with practical details, gotchas, and quick references.

## Quick Start

```bash
make build    # Debug build (fast, use for iterating)
make test     # Run all tests
make lint     # Check formatting + clippy (CI runs this)
make fix      # Auto-fix formatting + clippy issues
```

Always run `make lint` before submitting changes. CI will reject PRs that fail lint.

## Rust Edition & Toolchain

- **Edition**: Rust 2024 (`edition = "2024"` in all Cargo.toml files)
- **MSRV**: 1.91 (set in all three package Cargo.toml files)
- **No rust-toolchain.toml** - uses whatever stable/beta toolchain the developer has installed
- **Note**: `CONTRIBUTING.md` says "Rust 1.90 (nightly)" — this is outdated. The actual MSRV is 1.91 from Cargo.toml.

## Workspace Structure

```
Cargo.toml              # Workspace root (resolver = "2")
packages/
  orb-cli/              # Binary: `orb` (publish = false)
  orb-client/           # Library (publish = false, designed as standalone)
  orb-mockhttp/         # Mock server library (publish = true)
```

## Critical Rules

### 1. Client/CLI Separation

`orb-client` must NEVER import from or depend on `orb-cli`. This is the most important architectural constraint.

- **Adding verbose output?** Add a new `ClientEvent` variant in `packages/orb-client/src/events.rs`, then handle it in `packages/orb-cli/src/verbose_events.rs`.
- **Adding error handling?** Use `OrbError` variants in `orb-client`, map to user-friendly messages via `fatal!` in `orb-cli`.
- **Never use `fatal!` in `orb-client`** — it's a CLI macro. Use `OrbError` and propagate with `?`.

### 2. Crypto Provider

Both `orb-client` and `orb-mockhttp` use `aws-lc-rs` as the TLS crypto provider:

```rust
let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
```

The `let _ =` is intentional — subsequent calls return `Err` if already installed, which is fine. **Never `.unwrap()` this call.**

Test dev-dependencies use `ring` for the HTTP/3 test server (`quinn` with `ring` feature). This is an intentional mismatch — don't try to "fix" it.

### 3. Error Messages Include Trailing Newline

The `fatal!` macro uses `eprintln!`, which adds `\n`. All test assertions against stderr must include the trailing newline:

```rust
assert_eq!(stderr, "Failed to read CA certificate 'bad.pem': No such file...\n");
//                                                                          ^^
```

## Common Pitfalls

### 1. TLS Tests Require `--insecure`

Any test using `TestServerBuilder::new().with_tls().build()` needs `--insecure` on the orb command (or the test must provide the server's self-signed cert via `server.cert_pem()`).

### 2. System Cert Store Defaults

`orb-client` defaults to `use_system_cert_store: false` (uses bundled Mozilla roots). The CLI always sets `use_system_cert_store(true)` in `request.rs`. Be aware of this difference when writing library-level vs CLI-level tests.

### 3. RequestBuilder Creates a New HttpClient Per Request

`RequestBuilder::send()` internally calls `HttpClient::builder().build()` each time. This is by design for the CLI (one request per invocation). Don't assume connection pooling.

### 4. Port 0 in Tests

Every `TestServerBuilder::new().build()` binds to port 0 (OS-assigned random port). **Never hardcode ports**. Use `server.port()` and the `{PORT}` placeholder pattern for `test_case`.

### 5. Cross-Platform Error Messages

Error messages from the OS differ between platforms. Use `normalize_os_error()` from `testutils/mod.rs` when testing error output that includes OS-level errors.

### 6. Snapshot Testing with insta

The project uses inline snapshots (not `.snap` files):

```rust
use insta::assert_snapshot;
assert_snapshot!(sanitize_output(&output), @r"
GET / HTTP/1.1
accept: */*
user-agent: orb/0.1.0
host: 127.0.0.1:<PORT>
");
```

Set `INSTA_UPDATE=always` to auto-update snapshots during development.

## Security-Sensitive Code

### Redirect Behavior (`http_client.rs`)

When following redirects cross-host (different scheme, host, or port), these headers are stripped unless `--location-trusted` is used:
- `Authorization`
- `Cookie`
- `Proxy-Authorization`

Status codes 307/308 preserve method and body; 301/302/303 downgrade to GET with empty body.

### Cookie Domain Validation (`cookie.rs`)

The `CookieJar` uses the `psl` (Public Suffix List) crate to:
- Reject cookies with public-suffix domains (e.g., `.com`, `.co.uk`)
- Reject IP address domain attributes
- Require response origin to match cookie domain

The same PSL check runs in `headers.rs` when loading cookies from file.

### TLS (`orb-client/src/tls.rs`)

- `--insecure` mode uses `InsecureServerCertVerifier` (accepts all certs)
- `TlsCapturingConnector` wraps the TLS connector to emit `TlsHandshakeCompleted` events
- Client cert and CA cert validation happens in CLI layer (`cli.rs` validation functions)

## CI/CD

### CI Pipeline (`.github/workflows/ci.yml`)

Triggers on changes to `packages/**`, `Cargo.toml`, `Cargo.lock`, or the workflow file itself.

**Jobs:**
- **Test**: Matrix of `{ubuntu, macos, windows}` x `{stable}` + `ubuntu` x `{beta}`. Runs `make release` then `make test`.
- **Lint**: Ubuntu stable. Runs `make lint` (format check + clippy with `-D warnings`).
- **E2E**: Only on `release/*` branches or manual trigger. Runs `make test-e2e`.

### Release Pipeline (`.github/workflows/release.yml`)

Triggers on `v*` tags. Builds cross-platform binaries and uploads to GitHub Releases + Cloudflare R2.

## Test Utilities Reference (`testutils/mod.rs`)

| Function | Purpose |
|----------|---------|
| `sanitize_output(output)` | Normalizes ports → `<PORT>`, dates → `<DATE>`, boundaries → `<BOUNDARY>`, version → `orb/0.1.0` |
| `sanitize_error(output)` | Normalizes IP:port patterns in error messages |
| `null_device()` | Returns `/dev/null` (Unix) or `NUL` (Windows) |
| `normalize_os_error(error)` | Maps Windows error messages to Unix equivalents |
| `parse_args(input)` | Shell-style arg parsing respecting quotes |
| `test_server()` | Pre-configured server with `/test`, `/echo`, `/raw` routes |

## Adding a New CLI Option (Checklist)

1. Add field to `Args` struct in `packages/orb-cli/src/cli.rs`
2. Add validation function in `cli.rs` if needed
3. Call validator from `packages/orb-cli/src/main.rs`
4. If client-level: add to `HttpClientBuilder` in `packages/orb-client/src/http_client.rs`
5. If request-level: add to `RequestBuilder` or `packages/orb-cli/src/request.rs`
6. If response-level: add to `packages/orb-cli/src/output.rs`
7. Add tests in `packages/orb-cli/tests/options.rs` (use `test_case` for parameterized tests)
8. Run `make lint` before committing

## Adding a New Client Event (Checklist)

1. Add variant to `ClientEvent` in `packages/orb-client/src/events.rs`
2. Emit the event at the appropriate point in `orb-client` code
3. Handle the event in `VerboseEventHandler` in `packages/orb-cli/src/verbose_events.rs`
4. Add tests verifying the verbose output

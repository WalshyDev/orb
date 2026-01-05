//! WebSocket tests for the CLI

mod testutils;

use assert_cmd::cargo::*;
use orb_mockhttp::WebSocketServer;
use std::process::Command;
use test_case::test_case;
use testutils::sanitize_error;

// =============================================================================
// Connection tests
// =============================================================================

#[test]
fn test_websocket_connect_ws() {
    let server = WebSocketServer::echo();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/")).arg("--ws-message").arg("hello");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn test_websocket_connect_wss() {
    let server = WebSocketServer::echo_tls();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"))
        .arg("--ws-message")
        .arg("hello")
        .arg("--insecure");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

// =============================================================================
// Message tests
// =============================================================================

#[test_case("simple message"; "simple message")]
#[test_case("message with spaces"; "message with spaces")]
#[test_case("{\"type\": \"echo\", \"content\": \"test\"}"; "json message")]
#[test_case("unicode: 你好世界 🚀"; "unicode message")]
fn test_ws_message_echo(message: &str) {
    let server = WebSocketServer::echo();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/")).arg("--ws-message").arg(message);

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), message);
}

// =============================================================================
// Unsupported options tests
// =============================================================================

#[test_case("-X POST", "WebSocket connections only support GET method. Remove -X/--request option.\n"; "method not GET")]
#[test_case("-d 'data'", "WebSocket connections don't support -d/--data. Use --ws-message to send a message.\n"; "data option")]
#[test_case("--json '{}'", "WebSocket connections don't support --json. Use --ws-message to send a message.\n"; "json option")]
#[test_case("-F 'field=value'", "WebSocket connections don't support -F/--form. Use --ws-message to send a message.\n"; "form option")]
#[test_case("-o output.txt", "WebSocket connections don't support -o/--output.\n"; "output option")]
#[test_case("-i", "WebSocket connections don't support -i/--include.\n"; "include option")]
#[test_case("-I", "WebSocket connections don't support -I/--head.\n"; "head option")]
#[test_case("-L", "WebSocket connections don't support -L/--location.\n"; "location option")]
#[test_case("--compressed", "WebSocket connections don't support --compressed.\n"; "compressed option")]
#[test_case("--http1.1", "WebSocket connections don't support HTTP version flags. WebSocket uses its own protocol.\n"; "http1.1 flag")]
#[test_case("--http2", "WebSocket connections don't support HTTP version flags. WebSocket uses its own protocol.\n"; "http2 flag")]
#[test_case("--http3", "WebSocket connections don't support HTTP version flags. WebSocket uses its own protocol.\n"; "http3 flag")]
#[test_case("-b cookie.txt", "WebSocket connections don't support -b/--cookie.\n"; "cookie option")]
#[test_case("-c cookie-jar.txt", "WebSocket connections don't support -c/--cookie-jar.\n"; "cookie jar option")]
#[test_case("-u user:pass", "WebSocket connections don't support -u/--user.\n"; "user option")]
#[test_case("--bearer token", "WebSocket connections don't support --bearer.\n"; "bearer option")]
#[test_case("-e http://example.com", "WebSocket connections don't support -e/--referer.\n"; "referer option")]
#[test_case("--proxy http://proxy:8080", "WebSocket connections don't support --proxy (yet).\n"; "proxy option")]
#[test_case("--progress", "WebSocket connections don't support --progress.\n"; "progress option")]
#[test_case("-w", "WebSocket connections don't support -w/--write-out.\n"; "write out option")]
fn test_websocket_unsupported_options(args: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("ws://example.com/ws");

    // Parse and add the arguments
    for arg in testutils::parse_args(args) {
        cmd.arg(arg);
    }

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.as_ref(), expected_error);
}

// =============================================================================
// Supported options tests
// =============================================================================

#[test]
fn test_websocket_with_verbose() {
    let server = WebSocketServer::echo();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"))
        .arg("--ws-message")
        .arg("test")
        .arg("-v");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);

    // Verbose should output connection info to stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Connecting to") || stderr.contains("WebSocket connected"),
        "Expected verbose output, got: {}",
        stderr
    );
}

#[test]
fn test_websocket_with_silent() {
    let server = WebSocketServer::echo();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"))
        .arg("--ws-message")
        .arg("test")
        .arg("-s");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);

    // Silent should suppress stdout (except the actual response)
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "test");

    // Silent should suppress stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "Expected no stderr, got: {}", stderr);
}

#[test]
fn test_websocket_with_user_agent() {
    let server = WebSocketServer::echo();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"))
        .arg("--ws-message")
        .arg("test")
        .arg("-A")
        .arg("CustomAgent/1.0");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);
}

#[test]
fn test_websocket_with_custom_header() {
    let server = WebSocketServer::echo();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"))
        .arg("--ws-message")
        .arg("test")
        .arg("-H")
        .arg("X-Custom-Header: CustomValue");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);
}

#[test]
fn test_websocket_with_connect_to() {
    let server = WebSocketServer::echo();

    // Use --connect-to to redirect example.com to our local server
    let connect_to = format!("example.com:80:127.0.0.1:{}", server.port());

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("ws://example.com/")
        .arg("--ws-message")
        .arg("hello")
        .arg("--connect-to")
        .arg(connect_to);

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn test_websocket_with_insecure() {
    let server = WebSocketServer::echo_tls();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"))
        .arg("--ws-message")
        .arg("test")
        .arg("-k");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);
}

// =============================================================================
// Error tests
// =============================================================================

#[test]
fn test_websocket_connection_refused() {
    // Use a port that's unlikely to be in use
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("ws://127.0.0.1:59999/")
        .arg("--ws-message")
        .arg("test");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = sanitize_error(&String::from_utf8_lossy(&output.stderr));
    assert!(
        stderr.contains("Failed to connect") || stderr.contains("Connection refused"),
        "Expected connection error, got: {}",
        stderr
    );
}

#[test]
fn test_websocket_tls_without_insecure() {
    let server = WebSocketServer::echo_tls();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/")).arg("--ws-message").arg("test");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TLS error") || stderr.contains("certificate"),
        "Expected TLS error, got: {}",
        stderr
    );
}

#[test]
fn test_websocket_invalid_url() {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("ws://[invalid/").arg("--ws-message").arg("test");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid URL"),
        "Expected invalid URL error, got: {}",
        stderr
    );
}

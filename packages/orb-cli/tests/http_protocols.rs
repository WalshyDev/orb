//! HTTP protocol version tests
//!
//! These tests verify correct HTTP/1.1 and HTTP/2 behavior, particularly around
//! ALPN negotiation and header handling. These tests exist to prevent regressions
//! like the HTTP/2 failure with Google that was caused by:
//! 1. ALPN always advertising both protocols regardless of --http1.1/--http2 flags
//! 2. Explicit Host header conflicting with HTTP/2's :authority pseudo-header

mod testutils;

use assert_cmd::cargo::*;
use orb_mockhttp::{HttpProtocol, TestServerBuilder};
use std::process::Command;
use test_case::test_case;

/// Test that HTTP/2 works correctly when the server supports it.
/// This is a regression test for the ALPN/Host header issue.
#[test]
fn test_http2_with_tls_server() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http2])
        .build();
    server
        .on_request("/")
        .respond_with(200, "Hello from HTTP/2");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--insecure")
        .arg("-i")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/2 request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HTTP/2"),
        "Expected HTTP/2 response, got: {}",
        stdout
    );
    assert!(
        stdout.contains("Hello from HTTP/2"),
        "Expected body in response, got: {}",
        stdout
    );

    server.assert_requests(1);
}

/// Test that --http1.1 flag forces HTTP/1.1 even when server supports HTTP/2.
/// This verifies ALPN is correctly configured to only advertise HTTP/1.1.
#[test]
fn test_http1_1_flag_forces_http1_1_alpn() {
    // Server supports both HTTP/1.1 and HTTP/2
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1, HttpProtocol::Http2])
        .build();
    server.on_request("/").respond_with(200, "OK");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--http1.1")
        .arg("--insecure")
        .arg("-i")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/1.1 request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HTTP/1.1"),
        "Expected HTTP/1.1 response when --http1.1 flag is used, got: {}",
        stdout
    );

    server.assert_requests(1);
}

/// Test that --http2 flag forces HTTP/2 when server supports it.
/// This verifies ALPN is correctly configured to only advertise HTTP/2.
#[test]
fn test_http2_flag_forces_http2_alpn() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1, HttpProtocol::Http2])
        .build();
    server.on_request("/").respond_with(200, "OK");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--http2")
        .arg("--insecure")
        .arg("-i")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/2 request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HTTP/2"),
        "Expected HTTP/2 response when --http2 flag is used, got: {}",
        stdout
    );

    server.assert_requests(1);
}

/// Test that default behavior (no version flag) works with HTTP/2 servers.
/// Server chooses HTTP/2 via ALPN and the request succeeds.
#[test]
fn test_default_uses_alpn_negotiation() {
    // Server prefers HTTP/2
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http2, HttpProtocol::Http1])
        .build();
    server.on_request("/").respond_with(200, "ALPN worked");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--insecure")
        .arg("-i")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Default ALPN negotiation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Server should have chosen HTTP/2 since it's listed first
    assert!(
        stdout.contains("HTTP/2"),
        "Expected HTTP/2 via ALPN negotiation, got: {}",
        stdout
    );

    server.assert_requests(1);
}

/// Test HTTP/2 with custom headers to ensure headers are properly handled.
/// This is a regression test for the Host header conflict issue.
#[test]
fn test_http2_with_custom_headers() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http2])
        .build();

    server.on_request_fn("/headers", |req| {
        // Echo back the headers received
        let headers: Vec<String> = req
            .headers()
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("<binary>")))
            .collect();
        orb_mockhttp::ResponseBuilder::new()
            .status(200)
            .text(headers.join("\n"))
            .build()
    });

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/headers"))
        .arg("--insecure")
        .arg("-H")
        .arg("X-Custom-Header: custom-value")
        .arg("-H")
        .arg("Accept: application/json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/2 with custom headers failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("x-custom-header: custom-value"),
        "Custom header not received: {}",
        stdout
    );
    assert!(
        stdout.contains("accept: application/json"),
        "Accept header not received: {}",
        stdout
    );

    server.assert_requests(1);
}

/// Test HTTP/2 with POST body to ensure body handling works correctly.
#[test]
fn test_http2_with_post_body() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http2])
        .build();

    server.on_request_fn("/echo", |req| {
        let body = req.text().unwrap_or_default();
        orb_mockhttp::ResponseBuilder::new()
            .status(200)
            .text(format!("Received: {}", body))
            .build()
    });

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/echo"))
        .arg("--insecure")
        .arg("-X")
        .arg("POST")
        .arg("-d")
        .arg("test data")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/2 POST failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Received: test data"),
        "POST body not echoed correctly: {}",
        stdout
    );

    server.assert_requests(1);
}

/// Test verbose output shows correct ALPN negotiation for HTTP/2.
#[test]
fn test_http2_verbose_shows_alpn() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http2])
        .build();
    server.on_request("/").respond_with(200, "OK");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--insecure")
        .arg("-v")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/2 verbose request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ALPN: h2"),
        "Expected ALPN: h2 in verbose output, got: {}",
        stderr
    );

    server.assert_requests(1);
}

/// Test that HTTP/1.1 verbose output does NOT show ALPN h2.
#[test]
fn test_http1_1_verbose_no_h2_alpn() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1, HttpProtocol::Http2])
        .build();
    server.on_request("/").respond_with(200, "OK");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--http1.1")
        .arg("--insecure")
        .arg("-v")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/1.1 verbose request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // When --http1.1 is used, ALPN should not negotiate h2
    assert!(
        !stderr.contains("ALPN: h2"),
        "Should not show ALPN: h2 when --http1.1 is used, got: {}",
        stderr
    );

    server.assert_requests(1);
}

/// Test multiple sequential HTTP/2 requests to ensure connection handling is stable.
#[test]
fn test_http2_multiple_requests() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http2])
        .build();
    server.on_request("/1").respond_with(200, "Response 1");
    server.on_request("/2").respond_with(200, "Response 2");
    server.on_request("/3").respond_with(200, "Response 3");

    for i in 1..=3 {
        let output = Command::new(cargo_bin!("orb"))
            .arg(server.url(&format!("/{}", i)))
            .arg("--insecure")
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "HTTP/2 request {} failed: {}",
            i,
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("Response {}", i)),
            "Expected Response {} in output, got: {}",
            i,
            stdout
        );
    }

    server.assert_requests(3);
}

/// Test that HTTP/2 works with redirects.
#[test]
fn test_http2_with_redirects() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http2])
        .build();

    server
        .on_request("/redirect")
        .respond_with_redirect(302, "/final");
    server
        .on_request("/final")
        .respond_with(200, "Final destination");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/redirect"))
        .arg("--insecure")
        .arg("-L")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/2 redirect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Final destination"),
        "Expected final response after redirect, got: {}",
        stdout
    );

    server.assert_requests(2);
}

/// Parameterized test for HTTP version flags with different paths.
#[test_case("--http1.1", "HTTP/1.1"; "http1.1 flag")]
#[test_case("--http2", "HTTP/2"; "http2 flag")]
fn test_http_version_flags(flag: &str, expected_version: &str) {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1, HttpProtocol::Http2])
        .build();
    server.on_request("/test").respond_with(200, "OK");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/test"))
        .arg(flag)
        .arg("--insecure")
        .arg("-i")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{} request failed: {}",
        flag,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(expected_version),
        "Expected {} in response with {} flag, got: {}",
        expected_version,
        flag,
        stdout
    );

    server.assert_requests(1);
}

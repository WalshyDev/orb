//! End-to-end tests against real internet servers.
//!
//! These tests are marked with #[ignore] by default since they require internet access.
//! Run them with: cargo test --test e2e -- --ignored
//!
//! These tests validate that orb works correctly with real-world HTTP/2 servers,
//! which may have stricter requirements than mock servers (e.g., Google's HTTP/2
//! implementation is particularly strict about header handling).

use assert_cmd::cargo::*;
use std::process::Command;
use test_case::test_case;

/// Helper to run orb and return (success, stdout, stderr)
fn run_orb(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(cargo_bin!("orb"))
        .args(args)
        .output()
        .expect("Failed to execute orb");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// =============================================================================
// Basic Connectivity Tests (parameterized)
// =============================================================================

/// Test that sites work with default settings.
#[test_case("https://www.google.com/"; "google")]
#[test_case("https://www.cloudflare.com/"; "cloudflare")]
#[test_case("https://httpbin.org/get"; "httpbin")]
#[test_case("https://example.com/"; "example")]
#[test_case("https://test.walshy.dev/"; "personal test site")]
#[ignore = "requires internet access"]
fn test_e2e_default(url: &str) {
    let (success, stdout, stderr) = run_orb(&[url, "-L"]);

    assert!(
        success,
        "Request to {} failed.\nstderr: {}\nstdout: {}",
        url, stderr, stdout
    );
}

/// Test HTTP/2 support across sites.
#[test_case("https://www.google.com/"; "google")]
#[test_case("https://www.cloudflare.com/"; "cloudflare")]
#[test_case("https://httpbin.org/get"; "httpbin")]
#[test_case("https://example.com/"; "example")]
#[test_case("https://test.walshy.dev/"; "personal test site")]
#[ignore = "requires internet access"]
fn test_e2e_http2(url: &str) {
    let (success, stdout, stderr) = run_orb(&[url, "--http2", "-i", "-L"]);

    assert!(
        success,
        "HTTP/2 request to {} failed.\nstderr: {}\nstdout: {}",
        url, stderr, stdout
    );
    assert!(
        stdout.contains("HTTP/2"),
        "Expected HTTP/2 response from {}, got:\nstdout: {}",
        url,
        stdout
    );
}

/// Test HTTP/1.1 fallback across sites.
#[test_case("https://www.google.com/"; "google")]
#[test_case("https://www.cloudflare.com/"; "cloudflare")]
#[test_case("https://example.com/"; "example")]
#[test_case("https://test.walshy.dev/"; "personal test site")]
#[ignore = "requires internet access"]
fn test_e2e_http1_1(url: &str) {
    let (success, stdout, stderr) = run_orb(&[url, "--http1.1", "-i", "-L"]);

    assert!(
        success,
        "HTTP/1.1 request to {} failed.\nstderr: {}\nstdout: {}",
        url, stderr, stdout
    );
    assert!(
        stdout.contains("HTTP/1.1"),
        "Expected HTTP/1.1 response from {}, got:\nstdout: {}",
        url,
        stdout
    );
}

/// Test HTTP/3 (QUIC) support across sites that support it.
#[test_case("https://www.google.com/"; "google")]
#[test_case("https://www.cloudflare.com/"; "cloudflare")]
#[ignore = "requires internet access"]
fn test_e2e_http3(url: &str) {
    let (success, stdout, stderr) = run_orb(&[url, "--http3", "-i", "-L", "--max-time", "10"]);

    assert!(
        success,
        "HTTP/3 request to {} failed.\nstderr: {}\nstdout: {}",
        url, stderr, stdout
    );
    assert!(
        stdout.contains("HTTP/3"),
        "Expected HTTP/3 response from {}, got:\nstdout: {}",
        url,
        stdout
    );
}

// =============================================================================
// e2e feature validation
// =============================================================================

/// Test custom headers are sent correctly.
#[test]
#[ignore = "requires internet access"]
fn test_e2e_test_site_headers() {
    let (success, stdout, stderr) = run_orb(&[
        "https://test.walshy.dev/reqinfo",
        "-H",
        "X-Test-Header: test-value",
    ]);

    assert!(
        success,
        "test site headers request failed.\nstderr: {}\nstdout: {}",
        stderr, stdout
    );
    assert!(
        stdout.contains("X-Test-Header") || stdout.contains("x-test-header"),
        "Custom header not reflected by httpbin, got:\nstdout: {}",
        stdout
    );
}

/// Test POST with body data.
#[test]
#[ignore = "requires internet access"]
fn test_e2e_test_site_post() {
    let (success, stdout, stderr) = run_orb(&[
        "https://test.walshy.dev/reqinfo",
        "-X",
        "POST",
        "-d",
        "test=data",
    ]);

    assert!(
        success,
        "httpbin POST request failed.\nstderr: {}\nstdout: {}",
        stderr, stdout
    );
    assert!(
        stdout.contains("test=data") || stdout.contains("\"data\""),
        "POST data not reflected by httpbin, got:\nstdout: {}",
        stdout
    );
}

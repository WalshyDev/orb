//! TLS-related tests

use orb_mockhttp::TestServerBuilder;
use test_case::test_case;

// =============================================================================
// TLS CONFIGURATION TESTS
// =============================================================================

#[test]
fn test_tls_enabled() {
    let server = TestServerBuilder::new().with_tls().build();

    assert!(server.is_tls());
    assert!(server.url("/test").starts_with("https://"));
}

#[test]
fn test_tls_disabled() {
    let server = TestServerBuilder::new().build();

    assert!(!server.is_tls());
    assert!(server.url("/test").starts_with("http://"));
}

// =============================================================================
// CERTIFICATE TESTS
// =============================================================================

#[test]
fn test_tls_cert_pem_available() {
    let server = TestServerBuilder::new().with_tls().build();

    let cert_pem = server.cert_pem();
    assert!(cert_pem.is_some());

    let pem = cert_pem.unwrap();
    assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("-----END CERTIFICATE-----"));
}

#[test]
fn test_tls_cert_der_available() {
    let server = TestServerBuilder::new().with_tls().build();

    let cert_der = server.cert_der();
    assert!(cert_der.is_some());

    let der = cert_der.unwrap();
    // DER-encoded certificates start with 0x30 (SEQUENCE tag)
    assert!(!der.is_empty());
    assert_eq!(der[0], 0x30);
}

#[test]
fn test_no_tls_no_cert() {
    let server = TestServerBuilder::new().build();

    assert!(server.cert_pem().is_none());
    assert!(server.cert_der().is_none());
}

// =============================================================================
// PORT TESTS
// =============================================================================

#[test]
fn test_tls_same_port_for_all_protocols() {
    let server = TestServerBuilder::new().with_tls().build();

    // When TLS is enabled, the same port is used for:
    // - TCP: HTTP/1.1 and HTTP/2 (via ALPN)
    // - UDP: HTTP/3 (via QUIC)
    let port = server.port();
    let url = server.url("/test");

    assert!(url.contains(&format!(":{}", port)));
    assert!(port > 0);
}

// =============================================================================
// URL SCHEME TESTS
// =============================================================================

#[test_case("/", "https://127.0.0.1:"; "root path tls")]
#[test_case("/api", "https://127.0.0.1:"; "api path tls")]
#[test_case("/api/v1/users", "https://127.0.0.1:"; "nested path tls")]
fn test_tls_url_format(path: &str, expected_prefix: &str) {
    let server = TestServerBuilder::new().with_tls().build();

    let url = server.url(path);
    assert!(url.starts_with(expected_prefix));
    assert!(url.ends_with(path));
}

#[test_case("/", "http://127.0.0.1:"; "root path no tls")]
#[test_case("/api", "http://127.0.0.1:"; "api path no tls")]
fn test_no_tls_url_format(path: &str, expected_prefix: &str) {
    let server = TestServerBuilder::new().build();

    let url = server.url(path);
    assert!(url.starts_with(expected_prefix));
    assert!(url.ends_with(path));
}

// =============================================================================
// MULTIPLE TLS SERVERS
// =============================================================================

#[test]
fn test_multiple_tls_servers_different_ports() {
    let server1 = TestServerBuilder::new().with_tls().build();
    let server2 = TestServerBuilder::new().with_tls().build();
    let server3 = TestServerBuilder::new().with_tls().build();

    // Each server should get a different port
    assert_ne!(server1.port(), server2.port());
    assert_ne!(server2.port(), server3.port());
    assert_ne!(server1.port(), server3.port());

    // All should be TLS
    assert!(server1.is_tls());
    assert!(server2.is_tls());
    assert!(server3.is_tls());
}

#[test]
fn test_different_certs_per_server() {
    let server1 = TestServerBuilder::new().with_tls().build();
    let server2 = TestServerBuilder::new().with_tls().build();

    // Each server generates its own certificate
    let cert1 = server1.cert_pem().unwrap();
    let cert2 = server2.cert_pem().unwrap();

    // Certificates should be different (different key pairs)
    assert_ne!(cert1, cert2);
}

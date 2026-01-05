//! Protocol selection and configuration tests
use http::Version;
use orb_client::{CertificateDer, RequestBuilder, Url};
use orb_mockhttp::{HttpProtocol, TestServerBuilder};
use rustls::pki_types::pem::PemObject;
use test_case::test_case;

// =============================================================================
// DEFAULT PROTOCOL TESTS
// =============================================================================

#[test]
fn test_default_no_tls_only_http1() {
    let server = TestServerBuilder::new().build();

    // Without TLS, only HTTP/1.1 is available
    assert!(server.supports_protocol(HttpProtocol::Http1));
    assert!(!server.supports_protocol(HttpProtocol::Http2));
    assert!(!server.supports_protocol(HttpProtocol::Http3));

    assert_eq!(server.protocols().len(), 1);
    assert!(server.protocols().contains(&HttpProtocol::Http1));
}

#[test]
fn test_default_with_tls_all_protocols() {
    let server = TestServerBuilder::new().with_tls().build();

    // With TLS, all protocols are available by default
    assert!(server.supports_protocol(HttpProtocol::Http1));
    assert!(server.supports_protocol(HttpProtocol::Http2));
    assert!(server.supports_protocol(HttpProtocol::Http3));

    assert_eq!(server.protocols().len(), 3);
}

// =============================================================================
// SINGLE PROTOCOL TESTS
// =============================================================================

#[test]
fn test_http1_only_with_tls() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1])
        .build();

    assert!(server.supports_protocol(HttpProtocol::Http1));
    assert!(!server.supports_protocol(HttpProtocol::Http2));
    assert!(!server.supports_protocol(HttpProtocol::Http3));
    assert!(server.is_tls());
}

#[test]
fn test_http2_only() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http2])
        .build();

    assert!(!server.supports_protocol(HttpProtocol::Http1));
    assert!(server.supports_protocol(HttpProtocol::Http2));
    assert!(!server.supports_protocol(HttpProtocol::Http3));

    // HTTP/2 auto-enables TLS
    assert!(server.is_tls());
}

#[test]
fn test_http3_only() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http3])
        .build();

    assert!(!server.supports_protocol(HttpProtocol::Http1));
    assert!(!server.supports_protocol(HttpProtocol::Http2));
    assert!(server.supports_protocol(HttpProtocol::Http3));

    // HTTP/3 auto-enables TLS
    assert!(server.is_tls());
}

// =============================================================================
// PROTOCOL COMBINATION TESTS
// =============================================================================

#[test]
fn test_http1_and_http2() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http1, HttpProtocol::Http2])
        .build();

    assert!(server.supports_protocol(HttpProtocol::Http1));
    assert!(server.supports_protocol(HttpProtocol::Http2));
    assert!(!server.supports_protocol(HttpProtocol::Http3));
    assert!(server.is_tls());
}

#[test]
fn test_http1_and_http3() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http1, HttpProtocol::Http3])
        .build();

    assert!(server.supports_protocol(HttpProtocol::Http1));
    assert!(!server.supports_protocol(HttpProtocol::Http2));
    assert!(server.supports_protocol(HttpProtocol::Http3));
    assert!(server.is_tls());
}

#[test]
fn test_http2_and_http3() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http2, HttpProtocol::Http3])
        .build();

    assert!(!server.supports_protocol(HttpProtocol::Http1));
    assert!(server.supports_protocol(HttpProtocol::Http2));
    assert!(server.supports_protocol(HttpProtocol::Http3));
    assert!(server.is_tls());
}

#[test]
fn test_all_protocols_explicit() {
    let server = TestServerBuilder::new()
        .with_protocols(&[
            HttpProtocol::Http1,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ])
        .build();

    assert!(server.supports_protocol(HttpProtocol::Http1));
    assert!(server.supports_protocol(HttpProtocol::Http2));
    assert!(server.supports_protocol(HttpProtocol::Http3));
    assert!(server.is_tls());
    assert_eq!(server.protocols().len(), 3);
}

// =============================================================================
// AUTO-ENABLE TLS TESTS
// =============================================================================

#[test_case(HttpProtocol::Http2; "http2 auto enables tls")]
#[test_case(HttpProtocol::Http3; "http3 auto enables tls")]
fn test_protocol_auto_enables_tls(protocol: HttpProtocol) {
    let server = TestServerBuilder::new().with_protocols(&[protocol]).build();

    // These protocols require TLS, so it should be auto-enabled
    assert!(server.is_tls());
    assert!(server.cert_pem().is_some());
}

#[test]
fn test_http1_alone_does_not_enable_tls() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http1])
        .build();

    // HTTP/1.1 alone doesn't require TLS
    assert!(!server.is_tls());
    assert!(server.cert_pem().is_none());
}

#[test]
fn test_http1_with_explicit_tls() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1])
        .build();

    // Explicit TLS + HTTP/1.1 only
    assert!(server.is_tls());
    assert!(server.supports_protocol(HttpProtocol::Http1));
    assert!(!server.supports_protocol(HttpProtocol::Http2));
}

// =============================================================================
// SERVER PROTOCOLS ACCESSOR TESTS
// =============================================================================

#[test]
fn test_protocols_returns_correct_set() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http1, HttpProtocol::Http3])
        .build();

    let protocols = server.protocols();

    assert_eq!(protocols.len(), 2);
    assert!(protocols.contains(&HttpProtocol::Http1));
    assert!(protocols.contains(&HttpProtocol::Http3));
    assert!(!protocols.contains(&HttpProtocol::Http2));
}

// =============================================================================
// FUNCTIONAL PROTOCOL TESTS (HTTP/1.1)
// =============================================================================

#[tokio::test]
async fn test_http1_server_responds() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/test")
        .respond_with(200, "HTTP/1.1 works!");

    let response = RequestBuilder::new(Url::parse(&server.url("/test")).unwrap())
        .send()
        .await
        .unwrap();

    response.headers();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.unwrap(), "HTTP/1.1 works!");
}

#[tokio::test]
async fn test_http1_over_tls_responds() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1])
        .build();

    server
        .on_request("/test")
        .respond_with(200, "HTTP/1.1 over TLS!");

    // We need a client that trusts our self-signed cert
    let cert = server.cert_pem().unwrap();
    let cert_der = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();

    let response = RequestBuilder::new(Url::parse(&server.url("/test")).unwrap())
        .add_root_certificate(cert_der)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.unwrap(), "HTTP/1.1 over TLS!");
}

// =============================================================================
// BUILDER ORDER TESTS
// =============================================================================

#[test_case(
    vec![HttpProtocol::Http1],
    false;
    "http1 unsecure only"
)]
#[test_case(
    vec![HttpProtocol::Http1],
    true;
    "http1 secure only"
)]
#[test_case(
    vec![HttpProtocol::Http2],
    true;
    "http2 only"
)]
#[test_case(
    vec![HttpProtocol::Http3],
    true;
    "http3 only"
)]
#[test_case(
    vec![HttpProtocol::Http2, HttpProtocol::Http3],
    true;
    "http2 and http3 only"
)]
#[tokio::test]
async fn test_with_protocols(protocols: Vec<HttpProtocol>, tls: bool) {
    let mut server_builder = TestServerBuilder::new().with_protocols(&protocols);
    if tls {
        server_builder = server_builder.with_tls();
    }
    let server = server_builder.build();

    server.on_request("/").respond_with(200, "Hello!");

    for protocol in &protocols {
        assert!(server.supports_protocol(*protocol));
    }

    let mut builder = RequestBuilder::new(Url::parse(&server.url("/")).unwrap());

    if tls {
        let cert = server.cert_pem().unwrap();
        let cert_der = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        builder = builder.add_root_certificate(cert_der);
    }

    if protocols.contains(&HttpProtocol::Http3) {
        builder = builder.http_version(Version::HTTP_3);
    }

    let response = builder.send().await.unwrap();
    assert_eq!(response.status(), 200);
}

#[test]
fn test_with_protocols_then_with_tls() {
    // Order shouldn't matter
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http1])
        .with_tls()
        .build();

    assert!(server.is_tls());
    assert!(server.supports_protocol(HttpProtocol::Http1));
}

#[test]
fn test_with_tls_then_with_protocols() {
    let server = TestServerBuilder::new()
        .with_tls()
        .with_protocols(&[HttpProtocol::Http1])
        .build();

    assert!(server.is_tls());
    assert!(server.supports_protocol(HttpProtocol::Http1));
}

// =============================================================================
// MULTIPLE SERVERS WITH DIFFERENT PROTOCOLS
// =============================================================================

#[test]
fn test_multiple_servers_different_protocols() {
    let http1_server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http1])
        .build();

    let http2_server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http2])
        .build();

    let http3_server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http3])
        .build();

    // Each server has different protocols
    assert!(http1_server.supports_protocol(HttpProtocol::Http1));
    assert!(!http1_server.supports_protocol(HttpProtocol::Http2));

    assert!(!http2_server.supports_protocol(HttpProtocol::Http1));
    assert!(http2_server.supports_protocol(HttpProtocol::Http2));

    assert!(!http3_server.supports_protocol(HttpProtocol::Http1));
    assert!(http3_server.supports_protocol(HttpProtocol::Http3));

    // Different ports
    assert_ne!(http1_server.port(), http2_server.port());
    assert_ne!(http2_server.port(), http3_server.port());
}

#[test]
fn test_all_protocols_server_and_http1_only_server() {
    let all_server = TestServerBuilder::new().with_tls().build();

    let http1_server = TestServerBuilder::new().build();

    // All protocols server
    assert!(all_server.supports_protocol(HttpProtocol::Http1));
    assert!(all_server.supports_protocol(HttpProtocol::Http2));
    assert!(all_server.supports_protocol(HttpProtocol::Http3));
    assert!(all_server.is_tls());

    // HTTP/1.1 only server
    assert!(http1_server.supports_protocol(HttpProtocol::Http1));
    assert!(!http1_server.supports_protocol(HttpProtocol::Http2));
    assert!(!http1_server.supports_protocol(HttpProtocol::Http3));
    assert!(!http1_server.is_tls());
}

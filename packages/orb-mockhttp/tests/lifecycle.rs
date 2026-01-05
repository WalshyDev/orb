//! Server lifecycle tests (startup, shutdown, ports)

use orb_client::{RequestBuilder, Url};
use orb_mockhttp::TestServerBuilder;
use std::thread;
use std::time::Duration;

// =============================================================================
// PORT ALLOCATION TESTS
// =============================================================================

#[test]
fn test_server_gets_random_port() {
    let server = TestServerBuilder::new().build();

    let port = server.port();
    assert!(port > 0);
}

#[test]
fn test_multiple_servers_different_ports() {
    let server1 = TestServerBuilder::new().build();
    let server2 = TestServerBuilder::new().build();
    let server3 = TestServerBuilder::new().build();

    assert_ne!(server1.port(), server2.port());
    assert_ne!(server2.port(), server3.port());
    assert_ne!(server1.port(), server3.port());
}

#[test]
fn test_url_contains_port() {
    let server = TestServerBuilder::new().build();

    let port = server.port();
    let url = server.url("/test");

    assert!(url.contains(&format!(":{}", port)));
}

// =============================================================================
// URL FORMAT TESTS
// =============================================================================

#[test]
fn test_url_format_http() {
    let server = TestServerBuilder::new().build();

    let url = server.url("/api/v1/users");
    assert!(url.starts_with("http://127.0.0.1:"));
    assert!(url.ends_with("/api/v1/users"));
}

#[test]
fn test_url_format_https() {
    let server = TestServerBuilder::new().with_tls().build();

    let url = server.url("/api/v1/users");
    assert!(url.starts_with("https://127.0.0.1:"));
    assert!(url.ends_with("/api/v1/users"));
}

#[test]
fn test_url_various_paths() {
    let server = TestServerBuilder::new().build();

    assert!(server.url("/").ends_with("/"));
    assert!(server.url("/a").ends_with("/a"));
    assert!(server.url("/a/b/c").ends_with("/a/b/c"));
}

// =============================================================================
// SHUTDOWN TESTS
// =============================================================================

#[tokio::test]
async fn test_explicit_shutdown() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let url = server.url("/test");

    // Should work before shutdown
    let response = RequestBuilder::new(Url::parse(&url).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Shutdown
    server.shutdown();

    // Give time to shut down
    thread::sleep(Duration::from_millis(50));

    // Should fail after shutdown
    let result = RequestBuilder::new(Url::parse(&url).unwrap())
        .connect_timeout(Duration::from_millis(500))
        .send()
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_drop_triggers_shutdown() {
    let url;
    {
        let server = TestServerBuilder::new().build();
        server.on_request("/test").respond_with(200, "OK");
        url = server.url("/test");

        let response = RequestBuilder::new(Url::parse(&url).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
    }
    // Server dropped here

    // Give time to shut down
    thread::sleep(Duration::from_millis(50));

    // Should fail after drop
    let result = RequestBuilder::new(Url::parse(&url).unwrap())
        .connect_timeout(Duration::from_millis(500))
        .send()
        .await;
    assert!(result.is_err());
}

#[test]
fn test_shutdown_is_idempotent() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    // Multiple shutdowns should not panic
    server.shutdown();
    server.shutdown();
    server.shutdown();
}

// =============================================================================
// SERVER STATE TESTS
// =============================================================================

#[test]
fn test_is_tls_false() {
    let server = TestServerBuilder::new().build();
    assert!(!server.is_tls());
}

#[test]
fn test_is_tls_true() {
    let server = TestServerBuilder::new().with_tls().build();
    assert!(server.is_tls());
}

// =============================================================================
// ROUTE PERSISTENCE TESTS
// =============================================================================

#[tokio::test]
async fn test_routes_persist_across_requests() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/persistent")
        .respond_with(200, "Still here");

    // Multiple requests to same route
    for _ in 0..10 {
        let response = RequestBuilder::new(Url::parse(&server.url("/persistent")).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.text().await.unwrap(), "Still here");
    }
}

#[tokio::test]
async fn test_routes_cleared_properly() {
    let server = TestServerBuilder::new().build();

    server.on_request("/route1").respond_with(200, "Route 1");
    server.on_request("/route2").respond_with(200, "Route 2");

    // Both routes work
    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/route1")).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/route2")).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Clear and re-register only one
    server.clear_routes();
    server
        .on_request("/route1")
        .respond_with(200, "New Route 1");

    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/route1")).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/route2")).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
}

// =============================================================================
// BUILDER PATTERN TESTS
// =============================================================================

#[test]
fn test_default_builder() {
    let server = TestServerBuilder::new().build();

    assert!(!server.is_tls());
    assert!(server.port() > 0);
}

#[test]
fn test_builder_with_tls() {
    let server = TestServerBuilder::new().with_tls().build();

    assert!(server.is_tls());
    assert!(server.cert_pem().is_some());
}

#[test]
fn test_builder_chaining() {
    // Verify that chained building works
    let server = TestServerBuilder::new().with_tls().build();

    assert!(server.is_tls());
}

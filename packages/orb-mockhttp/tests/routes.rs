//! Route matching and assertion tests

use http::Method;
use orb_client::{RequestBuilder, Url};
use orb_mockhttp::{ResponseBuilder, TestServerBuilder};
use test_case::test_case;

// =============================================================================
// PATH MATCHING TESTS
// =============================================================================

#[test_case("/", "Root"; "root path")]
#[test_case("/api", "API"; "simple path")]
#[test_case("/api/v1", "API v1"; "nested path")]
#[test_case("/a/b/c/d/e", "Deep"; "deep path")]
#[test_case("/with-dash", "Dash"; "path with dash")]
#[test_case("/with_underscore", "Underscore"; "path with underscore")]
#[tokio::test]
async fn test_path_matching(path: &str, response_body: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request(path).respond_with(200, response_body);

    let response = RequestBuilder::new(Url::parse(&server.url(path)).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.unwrap(), response_body);
}

#[tokio::test]
async fn test_path_case_sensitive() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/CaseSensitive")
        .respond_with(200, "Upper");
    server
        .on_request("/casesensitive")
        .respond_with(200, "Lower");

    let upper_response = RequestBuilder::new(Url::parse(&server.url("/CaseSensitive")).unwrap())
        .send()
        .await
        .unwrap();
    let upper = upper_response.text().await.unwrap();

    let lower_response = RequestBuilder::new(Url::parse(&server.url("/casesensitive")).unwrap())
        .send()
        .await
        .unwrap();
    let lower = lower_response.text().await.unwrap();

    assert_eq!(upper, "Upper");
    assert_eq!(lower, "Lower");
}

#[tokio::test]
async fn test_trailing_slash_distinction() {
    let server = TestServerBuilder::new().build();

    server.on_request("/path/").respond_with(200, "With slash");
    server
        .on_request("/path")
        .respond_with(200, "Without slash");

    let with_slash_response = RequestBuilder::new(Url::parse(&server.url("/path/")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(with_slash_response.text().await.unwrap(), "With slash");

    let without_slash_response = RequestBuilder::new(Url::parse(&server.url("/path")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        without_slash_response.text().await.unwrap(),
        "Without slash"
    );
}

// =============================================================================
// METHOD MATCHING TESTS
// =============================================================================

#[test_case("GET"; "get method")]
#[test_case("POST"; "post method")]
#[test_case("PUT"; "put method")]
#[test_case("DELETE"; "delete method")]
#[test_case("PATCH"; "patch method")]
#[tokio::test]
async fn test_expect_method(method: &str) {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/test")
        .expect_method(method)
        .respond_with(200, "OK");

    let response = RequestBuilder::new(Url::parse(&server.url("/test")).unwrap())
        .method(method.parse().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn test_same_path_different_methods() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/resource")
        .expect_method("GET")
        .respond_with(200, "GET");

    server
        .on_request("/resource")
        .expect_method("POST")
        .respond_with(201, "POST");

    server
        .on_request("/resource")
        .expect_method("DELETE")
        .respond_with(204, "");

    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/resource")).unwrap())
            .method(Method::GET)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/resource")).unwrap())
            .method(Method::POST)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        201
    );
    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/resource")).unwrap())
            .method(Method::DELETE)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        204
    );
}

#[tokio::test]
async fn test_method_not_matched_returns_404() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/only-get")
        .expect_method("GET")
        .respond_with(200, "OK");

    // GET should work
    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/only-get")).unwrap())
            .method(Method::GET)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    // POST should 404
    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/only-get")).unwrap())
            .method(Method::POST)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
}

// =============================================================================
// HEADER ASSERTION TESTS
// =============================================================================

#[tokio::test]
async fn test_expect_header_value() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/auth")
        .expect_header("authorization", "Bearer secret")
        .respond_with(200, "OK");

    let response = RequestBuilder::new(Url::parse(&server.url("/auth")).unwrap())
        .header("Authorization", "Bearer secret")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn test_expect_header_present() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/check")
        .expect_header_present("x-api-key")
        .respond_with(200, "Valid");

    let response = RequestBuilder::new(Url::parse(&server.url("/check")).unwrap())
        .header("X-API-Key", "any-value")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

// =============================================================================
// BODY ASSERTION TESTS
// =============================================================================

#[tokio::test]
async fn test_expect_body_exact() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/echo")
        .expect_body("exact match".to_string())
        .respond_with(200, "Matched");

    let response = RequestBuilder::new(Url::parse(&server.url("/echo")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes("exact match"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn test_expect_body_contains() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/search")
        .expect_body_contains("needle".to_string())
        .respond_with(200, "Found");

    let response = RequestBuilder::new(Url::parse(&server.url("/search")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes(
            "haystack with needle inside",
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

// =============================================================================
// MULTIPLE ROUTES TESTS
// =============================================================================

#[tokio::test]
async fn test_multiple_routes_different_paths() {
    let server = TestServerBuilder::new().build();

    server.on_request("/a").respond_with(200, "A");
    server.on_request("/b").respond_with(200, "B");
    server.on_request("/c").respond_with(200, "C");

    let a_response = RequestBuilder::new(Url::parse(&server.url("/a")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(a_response.text().await.unwrap(), "A");

    let b_response = RequestBuilder::new(Url::parse(&server.url("/b")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(b_response.text().await.unwrap(), "B");

    let c_response = RequestBuilder::new(Url::parse(&server.url("/c")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(c_response.text().await.unwrap(), "C");
}

#[tokio::test]
async fn test_chained_route_registration() {
    let server = TestServerBuilder::new().build();

    server
        .on_request_fn("/first", |_| {
            ResponseBuilder::new().status(200).text("1").build()
        })
        .on_request_fn("/second", |_| {
            ResponseBuilder::new().status(200).text("2").build()
        })
        .on_request_fn("/third", |_| {
            ResponseBuilder::new().status(200).text("3").build()
        });

    let first_response = RequestBuilder::new(Url::parse(&server.url("/first")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(first_response.text().await.unwrap(), "1");

    let second_response = RequestBuilder::new(Url::parse(&server.url("/second")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(second_response.text().await.unwrap(), "2");

    let third_response = RequestBuilder::new(Url::parse(&server.url("/third")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(third_response.text().await.unwrap(), "3");
}

#[tokio::test]
async fn test_clear_routes() {
    let server = TestServerBuilder::new().build();

    server.on_request("/test").respond_with(200, "OK");

    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/test")).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    server.clear_routes();

    assert_eq!(
        RequestBuilder::new(Url::parse(&server.url("/test")).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
}

// =============================================================================
// 404 TESTS
// =============================================================================

#[tokio::test]
async fn test_404_for_unregistered_route() {
    let server = TestServerBuilder::new().build();

    server.on_request("/exists").respond_with(200, "OK");

    let response = RequestBuilder::new(Url::parse(&server.url("/does-not-exist")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn test_404_no_routes() {
    let server = TestServerBuilder::new().build();

    let response = RequestBuilder::new(Url::parse(&server.url("/anything")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 404);
}

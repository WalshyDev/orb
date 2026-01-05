//! HTTP method tests for the mock server

use http::Method;
use orb_client::{RequestBuilder, Url};
use orb_mockhttp::{ResponseBuilder, TestServerBuilder};
use test_case::test_case;

#[test_case("GET", 200, "GET response"; "get request")]
#[test_case("POST", 201, "Created"; "post request")]
#[test_case("PUT", 200, "Updated"; "put request")]
#[test_case("DELETE", 204, ""; "delete request")]
#[test_case("PATCH", 200, "Patched"; "patch request")]
#[tokio::test]
async fn test_http_method(method: &str, expected_status: u16, expected_body: &str) {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/test")
        .expect_method(method)
        .respond_with(expected_status, expected_body);

    let response = RequestBuilder::new(Url::parse(&server.url("/test")).unwrap())
        .method(method.parse().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), expected_status);
    assert_eq!(response.text().await.unwrap(), expected_body);
}

#[tokio::test]
async fn test_http_head_request() {
    let server = TestServerBuilder::new().build();

    server
        .on_request("/head")
        .expect_method("HEAD")
        .respond_with_fn(|_| {
            ResponseBuilder::new()
                .status(200)
                .header("X-Custom-Header", "head-value")
                .header("Content-Length", "100")
                .build()
        });

    let response = RequestBuilder::new(Url::parse(&server.url("/head")).unwrap())
        .method(Method::HEAD)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers().get("X-Custom-Header").unwrap(),
        "head-value"
    );
    // HEAD responses should not have a body
    assert!(response.text().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_http_options_request() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/options", |req| {
        assert!(req.is_method("OPTIONS"));
        ResponseBuilder::new()
            .status(200)
            .header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
            .header("Access-Control-Allow-Origin", "*")
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/options")).unwrap())
        .method(Method::OPTIONS)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers().get("Allow").unwrap(),
        "GET, POST, PUT, DELETE, OPTIONS"
    );
}

#[tokio::test]
async fn test_method_with_body() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/echo", |req| {
        ResponseBuilder::new()
            .status(200)
            .text(format!("{}: {}", req.method(), req.text_lossy()))
            .build()
    });

    let post = RequestBuilder::new(Url::parse(&server.url("/echo")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes("post data"))
        .send()
        .await
        .unwrap();
    assert_eq!(post.text().await.unwrap(), "POST: post data");

    let put = RequestBuilder::new(Url::parse(&server.url("/echo")).unwrap())
        .method(Method::PUT)
        .body(orb_client::body::RequestBody::from_bytes("put data"))
        .send()
        .await
        .unwrap();
    assert_eq!(put.text().await.unwrap(), "PUT: put data");

    let patch = RequestBuilder::new(Url::parse(&server.url("/echo")).unwrap())
        .method(Method::PATCH)
        .body(orb_client::body::RequestBody::from_bytes("patch data"))
        .send()
        .await
        .unwrap();
    assert_eq!(patch.text().await.unwrap(), "PATCH: patch data");
}

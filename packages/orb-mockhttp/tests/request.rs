//! Request feature tests (headers, body, query strings)

use http::Method;
use orb_client::{RequestBuilder, Url};
use orb_mockhttp::{ResponseBuilder, TestServerBuilder};
use serde_json::json;
use test_case::test_case;

// =============================================================================
// HEADER TESTS
// =============================================================================

#[test_case("authorization", "Bearer token123"; "authorization header")]
#[test_case("x-api-key", "secret-key"; "api key header")]
#[test_case("x-request-id", "req-12345"; "request id header")]
#[test_case("accept", "application/json"; "accept header")]
#[tokio::test]
async fn test_request_header_access(header_name: &str, header_value: &str) {
    let server = TestServerBuilder::new().build();
    let name = header_name.to_string();

    server.on_request_fn("/headers", move |req| {
        let value = req.header(&name).unwrap_or("missing");
        ResponseBuilder::new().status(200).text(value).build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/headers")).unwrap())
        .header(header_name, header_value)
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), header_value);
}

#[tokio::test]
async fn test_request_multiple_headers() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/multi", |req| {
        let auth = req.header("authorization").unwrap_or("none");
        let content_type = req.content_type().unwrap_or("none");
        ResponseBuilder::new()
            .status(200)
            .text(format!("auth={},ct={}", auth, content_type))
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/multi")).unwrap())
        .header("Authorization", "Bearer xyz")
        .header("Content-Type", "text/plain")
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(body.contains("auth=Bearer xyz"));
    assert!(body.contains("ct=text/plain"));
}

#[tokio::test]
async fn test_request_user_agent() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/ua", |req| {
        let ua = req.header("user-agent").unwrap_or("unknown");
        ResponseBuilder::new().status(200).text(ua).build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/ua")).unwrap())
        .header("User-Agent", "CustomAgent/2.0")
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), "CustomAgent/2.0");
}

// =============================================================================
// BODY TESTS
// =============================================================================

#[test_case("Hello, World!"; "simple text")]
#[test_case(""; "empty body")]
#[test_case("Line1\nLine2\nLine3"; "multiline")]
#[test_case("Special chars: <>&\"'"; "special characters")]
#[tokio::test]
async fn test_request_text_body(body_content: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/echo", |req| {
        ResponseBuilder::new()
            .status(200)
            .text(req.text_lossy())
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/echo")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes(
            body_content.to_string(),
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), body_content);
}

#[tokio::test]
async fn test_request_json_body() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/json", |req| {
        let data: serde_json::Value = req.json().unwrap_or(json!({}));
        let name = data["name"].as_str().unwrap_or("unknown");
        let age = data["age"].as_i64().unwrap_or(0);
        ResponseBuilder::new()
            .status(200)
            .text(format!("name={},age={}", name, age))
            .build()
    });

    let json_data = serde_json::to_string(&json!({"name": "Alice", "age": 30})).unwrap();
    let response = RequestBuilder::new(Url::parse(&server.url("/json")).unwrap())
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .body(orb_client::body::RequestBody::from_bytes(json_data))
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), "name=Alice,age=30");
}

#[test_case(&[0x00, 0x01, 0x02]; "small binary")]
#[test_case(&[0xFF, 0xFE, 0xFD, 0xFC]; "high bytes")]
#[test_case(&[0x00; 100]; "null bytes")]
#[tokio::test]
async fn test_request_binary_body(data: &[u8]) {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/binary", |req| {
        let bytes = req.body();
        ResponseBuilder::new()
            .status(200)
            .text(format!("{}", bytes.len()))
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/binary")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes(data.to_vec()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), data.len().to_string());
}

#[tokio::test]
async fn test_request_content_length() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/len", |req| {
        let len = req.content_length().unwrap_or(0);
        let actual = req.body().len();
        ResponseBuilder::new()
            .status(200)
            .text(format!("header={},actual={}", len, actual))
            .build()
    });

    let body = "12345678901234567890"; // 20 bytes
    let response = RequestBuilder::new(Url::parse(&server.url("/len")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes(body))
        .send()
        .await
        .unwrap();

    let text = response.text().await.unwrap();
    assert!(text.contains("actual=20"));
}

// =============================================================================
// QUERY STRING TESTS
// =============================================================================

#[test_case("q=rust", "q=rust"; "single param")]
#[test_case("q=rust&page=1", "q=rust"; "multiple params")]
#[test_case("empty=", "empty="; "empty value")]
#[tokio::test]
async fn test_query_string(query: &str, expected_contains: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/search", |req| {
        let query = req.query().unwrap_or("");
        ResponseBuilder::new().status(200).text(query).build()
    });

    let url = format!("{}?{}", server.url("/search"), query);
    let response = RequestBuilder::new(Url::parse(&url).unwrap())
        .send()
        .await
        .unwrap();

    assert!(response.text().await.unwrap().contains(expected_contains));
}

#[tokio::test]
async fn test_query_string_none() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/no-query", |req| {
        let has_query = req.query().is_some();
        ResponseBuilder::new()
            .status(200)
            .text(format!("{}", has_query))
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/no-query")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), "false");
}

#[tokio::test]
async fn test_uri_access() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/path/to/resource", |req| {
        let uri = req.uri().to_string();
        let path = req.path().to_string();
        ResponseBuilder::new()
            .status(200)
            .text(format!("uri={},path={}", uri, path))
            .build()
    });

    let response =
        RequestBuilder::new(Url::parse(&server.url("/path/to/resource?foo=bar")).unwrap())
            .send()
            .await
            .unwrap();

    let body = response.text().await.unwrap();
    assert!(body.contains("path=/path/to/resource"));
}

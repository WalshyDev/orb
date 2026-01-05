//! Response feature tests (status codes, headers, body)

use futures_util::StreamExt;
use orb_client::{RequestBuilder, Url};
use orb_mockhttp::{ResponseBuilder, TestServerBuilder};
use serde_json::json;
use test_case::test_case;

// Helper function to read response body as bytes
async fn read_bytes(response: orb_client::Response) -> Vec<u8> {
    let mut body_stream = response.into_body_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = body_stream.next().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    bytes
}

// =============================================================================
// STATUS CODE TESTS
// =============================================================================

#[test_case(200, "OK"; "200 ok")]
#[test_case(201, "Created"; "201 created")]
#[test_case(202, "Accepted"; "202 accepted")]
#[test_case(204, ""; "204 no content")]
#[test_case(400, "Bad Request"; "400 bad request")]
#[test_case(401, "Unauthorized"; "401 unauthorized")]
#[test_case(403, "Forbidden"; "403 forbidden")]
#[test_case(404, "Not Found"; "404 not found")]
#[test_case(405, "Method Not Allowed"; "405 method not allowed")]
#[test_case(500, "Internal Server Error"; "500 internal error")]
#[test_case(502, "Bad Gateway"; "502 bad gateway")]
#[test_case(503, "Service Unavailable"; "503 unavailable")]
#[tokio::test]
async fn test_response_status(status: u16, body: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request("/status").respond_with(status, body);

    let response = RequestBuilder::new(Url::parse(&server.url("/status")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.text().await.unwrap(), body);
}

#[tokio::test]
async fn test_redirect_response() {
    let server = TestServerBuilder::new().build();

    server.on_request("/old").respond_with_fn(|_| {
        ResponseBuilder::new()
            .status(301)
            .header("Location", "/new")
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/old")).unwrap())
        .follow_redirects(false)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 301);
    assert_eq!(response.headers().get("Location").unwrap(), "/new");
}

// =============================================================================
// RESPONSE HEADER TESTS
// =============================================================================

#[test_case("X-Request-Id", "abc123"; "request id")]
#[test_case("X-Rate-Limit", "100"; "rate limit")]
#[test_case("Cache-Control", "no-cache"; "cache control")]
#[test_case("X-Custom", "custom-value"; "custom header")]
#[tokio::test]
async fn test_response_header(header_name: &str, header_value: &str) {
    let server = TestServerBuilder::new().build();
    let name = header_name.to_string();
    let value = header_value.to_string();

    server.on_request("/headers").respond_with_fn(move |_| {
        ResponseBuilder::new()
            .status(200)
            .header(name.as_str(), value.as_str())
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/headers")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.headers().get(header_name).unwrap(), header_value);
}

#[tokio::test]
async fn test_response_multiple_headers() {
    let server = TestServerBuilder::new().build();

    server.on_request("/multi").respond_with_fn(|_| {
        ResponseBuilder::new()
            .status(200)
            .header("X-One", "1")
            .header("X-Two", "2")
            .header("X-Three", "3")
            .text("OK")
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/multi")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.headers().get("X-One").unwrap(), "1");
    assert_eq!(response.headers().get("X-Two").unwrap(), "2");
    assert_eq!(response.headers().get("X-Three").unwrap(), "3");
}

// =============================================================================
// CONTENT TYPE TESTS
// =============================================================================

#[test_case("text", "text/plain"; "text content type")]
#[test_case("html", "text/html"; "html content type")]
#[test_case("json", "application/json"; "json content type")]
#[tokio::test]
async fn test_response_content_type(method: &str, expected_ct: &str) {
    let server = TestServerBuilder::new().build();

    match method {
        "text" => {
            server.on_request("/content").respond_with_fn(|_| {
                ResponseBuilder::new()
                    .status(200)
                    .text("plain text")
                    .build()
            });
        }
        "html" => {
            server.on_request("/content").respond_with_fn(|_| {
                ResponseBuilder::new()
                    .status(200)
                    .html("<html></html>")
                    .build()
            });
        }
        "json" => {
            server
                .on_request("/content")
                .respond_with_json(200, &json!({"key": "value"}));
        }
        _ => panic!("Unknown method"),
    }

    let response = RequestBuilder::new(Url::parse(&server.url("/content")).unwrap())
        .send()
        .await
        .unwrap();

    let ct = response
        .headers()
        .get("Content-Type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains(expected_ct));
}

// =============================================================================
// JSON RESPONSE TESTS
// =============================================================================

#[tokio::test]
async fn test_json_object_response() {
    let server = TestServerBuilder::new().build();

    let data = json!({
        "id": 1,
        "name": "Test",
        "active": true,
        "tags": ["a", "b", "c"]
    });

    server.on_request("/data").respond_with_json(200, &data);

    let response = RequestBuilder::new(Url::parse(&server.url("/data")).unwrap())
        .send()
        .await
        .unwrap();
    let body_text = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();

    assert_eq!(body["id"], 1);
    assert_eq!(body["name"], "Test");
    assert_eq!(body["active"], true);
    assert_eq!(body["tags"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_json_array_response() {
    let server = TestServerBuilder::new().build();

    let data = json!([
        {"id": 1, "name": "First"},
        {"id": 2, "name": "Second"},
        {"id": 3, "name": "Third"}
    ]);

    server.on_request("/list").respond_with_json(200, &data);

    let response = RequestBuilder::new(Url::parse(&server.url("/list")).unwrap())
        .send()
        .await
        .unwrap();
    let body_text = response.text().await.unwrap();
    let body: Vec<serde_json::Value> = serde_json::from_str(&body_text).unwrap();

    assert_eq!(body.len(), 3);
    assert_eq!(body[0]["id"], 1);
    assert_eq!(body[2]["name"], "Third");
}

#[tokio::test]
async fn test_struct_json_response() {
    #[derive(serde::Serialize)]
    struct User {
        id: u32,
        name: String,
        email: String,
    }

    let server = TestServerBuilder::new().build();

    let user = User {
        id: 42,
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };

    server.on_request("/user").respond_with_json(200, &user);

    let response = RequestBuilder::new(Url::parse(&server.url("/user")).unwrap())
        .send()
        .await
        .unwrap();
    let body_text = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();

    assert_eq!(body["id"], 42);
    assert_eq!(body["name"], "Alice");
    assert_eq!(body["email"], "alice@example.com");
}

#[tokio::test]
async fn test_nested_json_response() {
    let server = TestServerBuilder::new().build();

    let data = json!({
        "user": {
            "profile": {
                "name": "Bob",
                "settings": {
                    "theme": "dark"
                }
            }
        }
    });

    server.on_request("/nested").respond_with_json(200, &data);

    let response = RequestBuilder::new(Url::parse(&server.url("/nested")).unwrap())
        .send()
        .await
        .unwrap();
    let body_text = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();

    assert_eq!(body["user"]["profile"]["name"], "Bob");
    assert_eq!(body["user"]["profile"]["settings"]["theme"], "dark");
}

// =============================================================================
// BODY TESTS
// =============================================================================

#[tokio::test]
async fn test_empty_response_body() {
    let server = TestServerBuilder::new().build();

    server.on_request("/empty").respond_with(200, "");

    let response = RequestBuilder::new(Url::parse(&server.url("/empty")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert!(response.text().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_binary_response_body() {
    let server = TestServerBuilder::new().build();

    let binary_data = vec![0x00u8, 0x01, 0xFF, 0xFE];
    let expected = binary_data.clone();

    server.on_request_fn("/binary", move |_| {
        ResponseBuilder::new()
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .body(bytes::Bytes::from(binary_data.clone()))
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/binary")).unwrap())
        .send()
        .await
        .unwrap();
    let body = read_bytes(response).await;

    assert_eq!(body.as_slice(), expected.as_slice());
}

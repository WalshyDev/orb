//! Edge case tests (unicode, large bodies, concurrency, special chars)

use http::Method;
use orb_client::{RequestBuilder, Url};
use orb_mockhttp::{ResponseBuilder, TestServerBuilder};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use test_case::test_case;

// =============================================================================
// UNICODE TESTS
// =============================================================================

#[test_case("Hello, 世界!"; "chinese")]
#[test_case("Привет мир!"; "russian")]
#[test_case("مرحبا بالعالم"; "arabic")]
#[test_case("🚀🎉🔥💯"; "emojis")]
#[test_case("Ñoño España"; "spanish accents")]
#[test_case("日本語テスト"; "japanese")]
#[tokio::test]
async fn test_unicode_in_body(text: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/unicode", |req| {
        ResponseBuilder::new()
            .status(200)
            .text(req.text_lossy())
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/unicode")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes(text.to_string()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), text);
}

#[tokio::test]
async fn test_unicode_in_path_encoded() {
    let server = TestServerBuilder::new().build();

    // URL-encoded path for "世界" (world in Chinese)
    server
        .on_request("/data/%E4%B8%96%E7%95%8C")
        .respond_with(200, "World");

    let response =
        RequestBuilder::new(Url::parse(&server.url("/data/%E4%B8%96%E7%95%8C")).unwrap())
            .send()
            .await
            .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

// =============================================================================
// SPECIAL CHARACTERS TESTS
// =============================================================================

#[test_case("hello%20world", "hello%20world"; "url encoded space")]
#[test_case("a%3Db", "a%3Db"; "url encoded equals")]
#[test_case("foo%26bar", "foo%26bar"; "url encoded ampersand")]
#[tokio::test]
async fn test_special_chars_in_query(query: &str, expected_contains: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/search", |req| {
        let query = req.query().unwrap_or("");
        ResponseBuilder::new().status(200).text(query).build()
    });

    let url = format!("{}?q={}", server.url("/search"), query);
    let response = RequestBuilder::new(Url::parse(&url).unwrap())
        .send()
        .await
        .unwrap();

    assert!(response.text().await.unwrap().contains(expected_contains));
}

#[tokio::test]
async fn test_special_chars_in_body() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/special", |req| {
        ResponseBuilder::new()
            .status(200)
            .text(req.text_lossy())
            .build()
    });

    let special_body = "Special: <>&\"'`~!@#$%^&*()[]{}|\\";
    let response = RequestBuilder::new(Url::parse(&server.url("/special")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes(special_body))
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), special_body);
}

// =============================================================================
// LARGE BODY TESTS
// =============================================================================

#[test_case(1024, "1KB"; "1kb body")]
#[test_case(10 * 1024, "10KB"; "10kb body")]
#[test_case(100 * 1024, "100KB"; "100kb body")]
#[test_case(1024 * 1024, "1MB"; "1mb body")]
#[tokio::test]
async fn test_large_request_body(size: usize, _label: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/large", |req| {
        let len = req.body().len();
        ResponseBuilder::new()
            .status(200)
            .text(format!("{}", len))
            .build()
    });

    let large_body = "x".repeat(size);
    let response = RequestBuilder::new(Url::parse(&server.url("/large")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes(large_body))
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), size.to_string());
}

#[test_case(1024, "1KB"; "1kb response")]
#[test_case(10 * 1024, "10KB"; "10kb response")]
#[test_case(100 * 1024, "100KB"; "100kb response")]
#[test_case(1024 * 1024, "1MB"; "1mb response")]
#[tokio::test]
async fn test_large_response_body(size: usize, _label: &str) {
    let server = TestServerBuilder::new().build();

    let response_body = "y".repeat(size);
    let expected_len = response_body.len();

    server.on_request_fn("/large-response", move |_| {
        ResponseBuilder::new()
            .status(200)
            .body(bytes::Bytes::from(response_body.clone()))
            .build()
    });

    let response = RequestBuilder::new(Url::parse(&server.url("/large-response")).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap().len(), expected_len);
}

// =============================================================================
// CONCURRENCY TESTS
// =============================================================================

#[test_case(5, "5 concurrent"; "5 threads")]
#[test_case(10, "10 concurrent"; "10 threads")]
#[test_case(20, "20 concurrent"; "20 threads")]
#[tokio::test]
async fn test_concurrent_requests(num_threads: usize, _label: &str) {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/concurrent", |_| {
        thread::sleep(Duration::from_millis(5));
        ResponseBuilder::new().status(200).text("OK").build()
    });

    let url = server.url("/concurrent");
    let mut handles = vec![];

    for _ in 0..num_threads {
        let url = url.clone();
        let handle = tokio::spawn(async move {
            RequestBuilder::new(Url::parse(&url).unwrap())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });
        handles.push(handle);
    }

    for handle in handles {
        assert_eq!(handle.await.unwrap(), 200);
    }
}

#[tokio::test]
async fn test_sequential_requests_same_route() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/seq", |_| {
        ResponseBuilder::new().status(200).text("OK").build()
    });

    let url = server.url("/seq");

    for _ in 0..100 {
        let response = RequestBuilder::new(Url::parse(&url).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
    }
}

// =============================================================================
// DYNAMIC RESPONSE TESTS
// =============================================================================

#[tokio::test]
async fn test_request_counting() {
    let server = TestServerBuilder::new().build();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    server.on_request_fn("/count", move |_| {
        let count = counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
        ResponseBuilder::new()
            .status(200)
            .text(format!("{}", count))
            .build()
    });

    let url = server.url("/count");

    for i in 1..=5 {
        let response = RequestBuilder::new(Url::parse(&url).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), i.to_string());
    }

    assert_eq!(counter.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn test_stateful_responses() {
    use parking_lot::Mutex;

    let server = TestServerBuilder::new().build();
    let state: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // POST to store
    let post_state = Arc::clone(&state);
    server.on_request_fn("/set", move |req| {
        if req.is_method("POST") {
            let body = req.text_lossy();
            if let Some((key, value)) = body.split_once('=') {
                post_state.lock().insert(key.to_string(), value.to_string());
                return ResponseBuilder::new().status(201).build();
            }
        }
        ResponseBuilder::new().status(400).build()
    });

    // GET to retrieve
    let get_state = Arc::clone(&state);
    server.on_request_fn("/get", move |req| {
        let key = req.query().unwrap_or("key=").replace("key=", "");
        let value = get_state.lock().get(&key).cloned().unwrap_or_default();
        ResponseBuilder::new().status(200).text(value).build()
    });

    // Set values
    RequestBuilder::new(Url::parse(&server.url("/set")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes("foo=bar"))
        .send()
        .await
        .unwrap();
    RequestBuilder::new(Url::parse(&server.url("/set")).unwrap())
        .method(Method::POST)
        .body(orb_client::body::RequestBody::from_bytes("baz=qux"))
        .send()
        .await
        .unwrap();

    // Get values
    let foo_response = RequestBuilder::new(Url::parse(&server.url("/get?key=foo")).unwrap())
        .send()
        .await
        .unwrap();
    let foo = foo_response.text().await.unwrap();

    let baz_response = RequestBuilder::new(Url::parse(&server.url("/get?key=baz")).unwrap())
        .send()
        .await
        .unwrap();
    let baz = baz_response.text().await.unwrap();

    assert_eq!(foo, "bar");
    assert_eq!(baz, "qux");
}

#[tokio::test]
async fn test_dynamic_response_from_query() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/greet", |req| {
        let name = req.query().unwrap_or("name=stranger").replace("name=", "");
        ResponseBuilder::new()
            .status(200)
            .text(format!("Hello, {}!", name))
            .build()
    });

    let alice_response = RequestBuilder::new(Url::parse(&server.url("/greet?name=Alice")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(alice_response.text().await.unwrap(), "Hello, Alice!");

    let bob_response = RequestBuilder::new(Url::parse(&server.url("/greet?name=Bob")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(bob_response.text().await.unwrap(), "Hello, Bob!");
}

// =============================================================================
// EMPTY AND EDGE CASES
// =============================================================================

#[tokio::test]
async fn test_empty_path_segment() {
    let server = TestServerBuilder::new().build();

    server.on_request("/a//b").respond_with(200, "Double slash");

    let response = RequestBuilder::new(Url::parse(&server.url("/a//b")).unwrap())
        .send()
        .await
        .unwrap();

    // Behavior may vary - just ensure no panic
    let status = response.status().as_u16();
    assert!((200..300).contains(&status) || status == 404);
}

#[tokio::test]
async fn test_very_long_path() {
    let server = TestServerBuilder::new().build();

    let long_path = format!("/{}", "a".repeat(1000));
    server.on_request(&long_path).respond_with(200, "Long");

    let response = RequestBuilder::new(Url::parse(&server.url(&long_path)).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn test_many_query_params() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/params", |req| {
        let query = req.query().unwrap_or("");
        let count = query.matches('&').count() + 1;
        ResponseBuilder::new()
            .status(200)
            .text(format!("{}", count))
            .build()
    });

    // 50 query parameters
    let params: Vec<String> = (0..50).map(|i| format!("p{}=v{}", i, i)).collect();
    let query_string = params.join("&");

    let url = format!("{}?{}", server.url("/params"), query_string);
    let response = RequestBuilder::new(Url::parse(&url).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.text().await.unwrap(), "50");
}

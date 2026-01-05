//! Tests from README.md examples

use orb_client::{RequestBuilder, Url, WebSocketMessage};
use orb_mockhttp::{ResponseBuilder, TestServerBuilder, WebSocketServer};

#[tokio::test]
async fn test_basic_request_response() {
    // Setup server to respond to /test with a 200
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");

    // Send a request with orb-client
    let response = RequestBuilder::new(Url::parse(&server.url("/test")).unwrap())
        .send()
        .await
        .unwrap();

    // Assert we got a 200
    assert_eq!(response.status(), 200);

    // Assert server received 1 request
    server.assert_one_request();
}

#[tokio::test]
async fn test_more_complicated_example() {
    // Setup server with custom logic
    // Responds with "Hello, {name}!" where name is a query parameter
    let server = TestServerBuilder::new().build();
    server.on_request_fn("/dynamic", |req| {
        let binding = "Guest".to_string();
        let name = req.query_param("name").unwrap_or(&binding);
        ResponseBuilder::new()
            .status(200)
            .body(format!("Hello, {}!", name))
            .build()
    });

    // Send request with query parameter
    let response = RequestBuilder::new(Url::parse(&server.url("/dynamic?name=orb")).unwrap())
        .send()
        .await
        .unwrap();

    // Assert response body
    let body = response.text().await.unwrap();
    assert_eq!(body, "Hello, orb!");

    // Assert server received 1 request
    server.assert_requests(1);
}

#[tokio::test]
async fn test_websocket_echo() {
    // Setup WebSocket echo server
    let server = WebSocketServer::echo();

    // Send request with query parameter
    let mut socket = RequestBuilder::new(Url::parse(&server.url("/ws")).unwrap())
        .connect_websocket()
        .await
        .unwrap();

    socket
        .send_text("Echo echo echo echo")
        .await
        .expect("Failed to send text");

    let message = socket.recv().await.unwrap().unwrap();
    match message {
        WebSocketMessage::Text(text) => assert_eq!(text, "Echo echo echo echo"),
        _ => panic!("Expected text message"),
    }

    // Close the socket so the server processes all messages
    drop(socket);

    // Give the server time to process
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Assert server received 1 message
    server.assert_messages(1);
    assert_eq!(server.get_text_messages(), vec!["Echo echo echo echo"]);
}

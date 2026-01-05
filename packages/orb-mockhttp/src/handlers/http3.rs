//! HTTP/3 protocol handler (over QUIC)

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::BidiStream;
use http::Version;
use quinn::Endpoint;
use std::sync::Arc;
use tokio::sync::watch;

use crate::HttpProtocol;
use crate::handlers::ServerState;
use crate::request::Request;
use crate::response::Response;

/// Run the HTTP/3 server over QUIC
pub async fn run_http3_server(
    endpoint: Endpoint,
    state: Arc<ServerState>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }

            incoming = endpoint.accept() => {
                match incoming {
                    Some(conn) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(conn, state).await {
                                eprintln!("HTTP/3 connection error: {}", e);
                            }
                        });
                    }
                    None => {
                        // Endpoint closed
                        break;
                    }
                }
            }
        }
    }
}

/// Handle a single HTTP/3 connection
async fn handle_connection(
    incoming: quinn::Incoming,
    state: Arc<ServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connection = incoming.await?;
    let quinn_conn = h3_quinn::Connection::new(connection);

    let mut h3_conn = h3::server::Connection::new(quinn_conn).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((request, stream)) => {
                            if let Err(e) = handle_request(request, stream, state).await {
                                eprintln!("HTTP/3 request error: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("HTTP/3 resolve error: {}", e);
                        }
                    }
                });
            }
            Ok(None) => {
                // Connection closed
                break;
            }
            Err(e) => {
                eprintln!("HTTP/3 accept error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP/3 request
async fn handle_request(
    req: http::Request<()>,
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    state: Arc<ServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read body from stream
    let mut body_data = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        body_data.extend_from_slice(chunk.chunk());
    }

    // Build our Request type
    let request = Request::new(
        req.method().clone(),
        req.uri().clone(),
        Version::HTTP_3,
        req.headers().clone(),
        Bytes::from(body_data),
        HttpProtocol::Http3,
    );

    // Get response from state
    let response = state.handle_request(&request);

    // Apply initial delay if configured
    if let Some(delay) = response.initial_delay() {
        tokio::time::sleep(delay).await;
    }

    // Build and send HTTP/3 response
    send_h3_response(stream, response).await
}

/// Build and send an HTTP/3 response, with optional chunked streaming
async fn send_h3_response(
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    response: Response,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut h3_response = http::Response::builder().status(response.status());

    // Copy headers
    for (key, value) in response.headers().iter() {
        h3_response = h3_response.header(key, value);
    }

    // Set content-length if not already set
    if !response
        .headers()
        .contains_key(http::header::CONTENT_LENGTH)
    {
        h3_response = h3_response.header(http::header::CONTENT_LENGTH, response.body().len());
    }

    let h3_response = h3_response.body(())?;

    // Send response headers
    stream.send_response(h3_response).await?;

    // Send response body - with optional chunk delay
    if let Some(delay) = response.chunk_delay() {
        // Stream body in chunks with delays
        let body = response.body();
        let chunk_size = response.chunk_size();
        let mut position = 0;

        while position < body.len() {
            // Delay between chunks (skip for first chunk)
            if position > 0 {
                tokio::time::sleep(delay).await;
            }

            let end = std::cmp::min(position + chunk_size, body.len());
            let chunk = body.slice(position..end);
            stream.send_data(chunk).await?;
            position = end;
        }
    } else {
        // Send body all at once
        stream.send_data(response.body().clone()).await?;
    }

    // Finish the stream
    stream.finish().await?;

    Ok(())
}

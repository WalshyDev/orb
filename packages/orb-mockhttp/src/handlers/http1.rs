//! HTTP/1.1 protocol handler

use http::Version;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::HttpProtocol;
use crate::handlers::{BoxBody, ServerState, build_hyper_response};
use crate::request::Request;

/// Run the HTTP/1.1 server
pub async fn run_http1_server(
    listener: TcpListener,
    state: Arc<ServerState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Abort all connection tasks on shutdown
                    connection_tasks.abort_all();
                    break;
                }
            }

            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        connection_tasks.spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(|req| {
                                handle_request(req, Arc::clone(&state))
                            });

                            if let Err(e) = http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                eprintln!("HTTP/1.1 connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("HTTP/1.1 accept error: {}", e);
                    }
                }
            }
        }
    }
}

/// Handle a single HTTP/1.1 request
async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    state: Arc<ServerState>,
) -> Result<hyper::Response<BoxBody>, Infallible> {
    // Collect the body
    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();

    // Build our Request type
    let request = Request::new(
        parts.method,
        parts.uri,
        Version::HTTP_11,
        parts.headers,
        body_bytes,
        HttpProtocol::Http1,
    );

    // Get response from state
    let response = state.handle_request(&request);

    // Apply initial delay if configured
    if let Some(delay) = response.initial_delay() {
        tokio::time::sleep(delay).await;
    }

    Ok(build_hyper_response(response))
}

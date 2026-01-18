//! HTTP/2 protocol handler (over TLS)

use http::Version;
use http_body_util::BodyExt;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::HttpProtocol;
use crate::handlers::{BoxBody, ServerState, build_hyper_response};
use crate::request::Request;

/// Run the HTTP/2 server over TLS
pub async fn run_http2_server(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    state: Arc<ServerState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(tls_config);
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
                        let acceptor = acceptor.clone();
                        let state = Arc::clone(&state);
                        connection_tasks.spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    // Check negotiated protocol
                                    let alpn = tls_stream.get_ref().1.alpn_protocol();
                                    let is_h2 = alpn.map(|p| p == b"h2").unwrap_or(false);

                                    let io = TokioIo::new(tls_stream);
                                    let service = service_fn(|req| {
                                        handle_request(req, Arc::clone(&state), is_h2)
                                    });

                                    if is_h2 {
                                        // HTTP/2 connection
                                        if let Err(e) = http2::Builder::new(TokioExecutor::new())
                                            .serve_connection(io, service)
                                            .await
                                        {
                                            eprintln!("HTTP/2 connection error: {}", e);
                                        }
                                    } else {
                                        // Fall back to HTTP/1.1 over TLS
                                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                                            .serve_connection(io, service)
                                            .await
                                        {
                                            eprintln!("HTTP/1.1 (TLS) connection error: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("TLS accept error: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("HTTP/2 TCP accept error: {}", e);
                    }
                }
            }
        }
    }
}

/// Handle a single HTTP/2 request
async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    state: Arc<ServerState>,
    is_h2: bool,
) -> Result<hyper::Response<BoxBody>, Infallible> {
    // Collect the body
    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();

    // Determine HTTP version
    let version = if is_h2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };

    // Build our Request type
    let request = Request::new(
        parts.method,
        parts.uri,
        version,
        parts.headers,
        body_bytes,
        HttpProtocol::Http2,
    );

    // Get response from state
    let response = state.handle_request(&request);

    // Apply initial delay if configured
    if let Some(delay) = response.initial_delay() {
        tokio::time::sleep(delay).await;
    }

    Ok(build_hyper_response(response))
}

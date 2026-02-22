//! HTTP/3 client implementation using quinn (QUIC) and h3

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use http::{Request, Version};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use tokio::time::timeout;

use crate::Response;
use crate::body::{RequestBody, ResponseBody};
use crate::dns::{apply_dns_overrides, resolve_address};
use crate::error::OrbError;
use crate::events::ClientEvent;
use crate::http_client::{RequestBuilder, resolve_redirect_uri};
use crate::tls::build_client_tls_config;

/// Establish a QUIC connection and create an HTTP/3 session
async fn connect_h3(
    builder: &RequestBuilder,
    url: &url::Url,
) -> Result<SendRequest<OpenStreams, Bytes>, OrbError> {
    let host = url
        .host_str()
        .ok_or_else(|| OrbError::QuicConnect("No host in URL".to_string()))?;
    let port = url.port().unwrap_or(443);

    // Apply DNS overrides if any
    let (target_host, target_port) =
        apply_dns_overrides(host, port, &builder.dns_overrides, &builder.event_handler);

    // Resolve the target address
    let addr = resolve_address(&target_host, target_port)?;

    // Build TLS config for QUIC
    let mut tls_config = build_client_tls_config(
        builder.insecure,
        builder.use_system_cert_store,
        &builder.ca_certs,
        builder.client_cert.as_ref(),
    )?;

    // Set ALPN for HTTP/3
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    // Emit connection start event
    if let Some(ref handler) = builder.event_handler {
        handler.on_event(ClientEvent::QuicConnectionStarted {
            host: target_host.clone(),
            port: target_port,
        });
    }

    let connect_start = Instant::now();

    // Create QUIC endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| OrbError::QuicConnect(e.to_string()))?;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| OrbError::QuicConnect(e.to_string()))?,
    ));

    // Configure transport
    let mut transport_config = TransportConfig::default();
    if let Some(connect_timeout) = builder.connect_timeout {
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(connect_timeout)
                .map_err(|e| OrbError::QuicConnect(format!("Invalid timeout: {}", e)))?,
        ));
    }
    client_config.transport_config(Arc::new(transport_config));
    endpoint.set_default_client_config(client_config);

    // Connect to the server - use original host for SNI
    let connecting = endpoint
        .connect(addr, host)
        .map_err(|e| OrbError::QuicConnect(e.to_string()))?;

    let max_time = builder.max_time.unwrap_or(Duration::from_secs(30));
    let connection = match timeout(max_time, connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            if let Some(ref handler) = builder.event_handler {
                handler.on_event(ClientEvent::QuicConnectionFailed {
                    host: target_host.clone(),
                    port: target_port,
                    error: e.to_string(),
                });
            }
            return Err(OrbError::QuicConnect(e.to_string()));
        }
        Err(_) => {
            if let Some(ref handler) = builder.event_handler {
                handler.on_event(ClientEvent::QuicConnectionFailed {
                    host: target_host.clone(),
                    port: target_port,
                    error: "Connection timed out".to_string(),
                });
            }
            return Err(OrbError::Timeout { timeout: max_time });
        }
    };

    let connect_duration = connect_start.elapsed();

    // Emit connection established event
    if let Some(ref handler) = builder.event_handler {
        handler.on_event(ClientEvent::QuicConnectionEstablished {
            host: target_host.clone(),
            port: target_port,
            duration: connect_duration,
        });
    }

    // Emit TLS handshake info
    crate::tls::extract_quic_tls_info(&connection, &builder.event_handler);

    // Create HTTP/3 connection
    let quinn_conn = h3_quinn::Connection::new(connection);
    let (mut driver, send_request) = h3::client::new(quinn_conn)
        .await
        .map_err(|e| OrbError::Http3Protocol(e.to_string()))?;

    // Drive the connection in the background
    tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    Ok(send_request)
}

/// Send an HTTP/3 request with redirect handling
pub async fn send_http3_request(builder: RequestBuilder) -> Result<Response, OrbError> {
    let mut current_url = builder.url.clone();
    let mut current_method = builder.method.clone();
    let mut current_body = builder.body.clone();
    let mut redirect_count = 0;

    loop {
        let send_request = connect_h3(&builder, &current_url).await?;
        let response = send_single_h3_request(
            send_request,
            &builder,
            &current_url,
            &current_method,
            &current_body,
        )
        .await?;

        if !response.status.is_redirection() || !builder.follow_redirects {
            return Ok(response);
        }

        redirect_count += 1;
        if redirect_count > builder.max_redirects {
            return Err(OrbError::TooManyRedirects {
                count: builder.max_redirects,
                url: current_url.to_string(),
            });
        }

        let location = response
            .headers
            .get(http::header::LOCATION)
            .ok_or(OrbError::MissingRedirectLocation)?;

        let location_str = location
            .to_str()
            .map_err(|_| OrbError::InvalidRedirectLocation)?
            .trim();

        let current_uri: http::Uri = current_url
            .as_str()
            .parse()
            .map_err(|_| OrbError::InvalidRedirectLocation)?;
        let new_uri = resolve_redirect_uri(&current_uri, location_str)?;

        current_url =
            url::Url::parse(&new_uri.to_string()).map_err(|_| OrbError::InvalidRedirectLocation)?;

        // 307/308: Preserve method and body
        // 301/302/303: Change to GET with no body
        match response.status.as_u16() {
            307 | 308 => {}
            _ => {
                current_method = http::Method::GET;
                current_body = RequestBody::Empty;
            }
        }
    }
}

async fn send_single_h3_request(
    mut send_request: SendRequest<OpenStreams, Bytes>,
    builder: &RequestBuilder,
    url: &url::Url,
    method: &http::Method,
    body: &RequestBody,
) -> Result<Response, OrbError> {
    let uri: http::Uri = url
        .as_str()
        .parse()
        .map_err(|e: http::uri::InvalidUri| OrbError::RequestBuild(e.to_string()))?;

    // Build the request
    let mut req_builder = Request::builder().uri(uri).method(method.clone());

    for (key, value) in builder.headers.iter() {
        // Skip Host header - h3 uses :authority pseudo-header from the URI
        if key == http::header::HOST {
            continue;
        }
        req_builder = req_builder.header(key, value);
    }

    let request = req_builder
        .body(())
        .map_err(|e| OrbError::RequestBuild(e.to_string()))?;

    // Emit RequestSent event
    if let Some(ref handler) = builder.event_handler {
        let headers: Vec<(String, String)> = builder
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
            .collect();
        handler.on_event(ClientEvent::RequestSent {
            method: method.to_string(),
            path: url.path().to_string(),
            headers,
        });
    }

    let request_start = Instant::now();

    // Send the request
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| OrbError::Http3Protocol(e.to_string()))?;

    // Send body if present
    match body {
        RequestBody::Empty => {
            stream
                .finish()
                .await
                .map_err(|e| OrbError::Http3Protocol(e.to_string()))?;
        }
        RequestBody::Bytes(bytes) => {
            stream
                .send_data(bytes.clone())
                .await
                .map_err(|e| OrbError::Http3Protocol(e.to_string()))?;
            stream
                .finish()
                .await
                .map_err(|e| OrbError::Http3Protocol(e.to_string()))?;
        }
    }

    // Receive response
    let response = stream
        .recv_response()
        .await
        .map_err(|e| OrbError::Http3Protocol(e.to_string()))?;

    let request_duration = request_start.elapsed();

    // Emit response received event
    if let Some(ref handler) = builder.event_handler {
        handler.on_event(ClientEvent::Http3ResponseReceived {
            status: response.status().as_u16(),
            duration: request_duration,
        });
    }

    let status = response.status();
    let headers = response.headers().clone();
    let content_length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Collect all body data
    let mut body_data = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| OrbError::Http3Protocol(e.to_string()))?
    {
        body_data.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }

    // Create response body from collected data
    let response_body = ResponseBody::new(futures_util::stream::once(async move {
        Ok(Bytes::from(body_data))
    }));

    Ok(Response::new(
        status,
        Version::HTTP_3,
        headers,
        response_body,
        content_length,
    ))
}

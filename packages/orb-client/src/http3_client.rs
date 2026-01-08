//! HTTP/3 client implementation using quinn (QUIC) and h3

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use http::{Request, Version};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::time::timeout;

use crate::Response;
use crate::body::{RequestBody, ResponseBody};
use crate::dns::OverrideRule;
use crate::error::OrbError;
use crate::events::{BoxedEventHandler, ClientEvent};
use crate::http_client::RequestBuilder;

/// Send an HTTP/3 request
pub async fn send_http3_request(builder: RequestBuilder) -> Result<Response, OrbError> {
    let url = &builder.url;
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
    let tls_config = build_tls_config(
        builder.insecure,
        builder.use_system_cert_store,
        &builder.ca_certs,
        builder.client_cert.as_ref(),
    )?;

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
        // poll_close polls until connection closes
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Send the request
    send_request_h3(send_request, &builder).await
}

async fn send_request_h3(
    mut send_request: SendRequest<OpenStreams, Bytes>,
    builder: &RequestBuilder,
) -> Result<Response, OrbError> {
    let uri: http::Uri = builder
        .url
        .as_str()
        .parse()
        .map_err(|e: http::uri::InvalidUri| OrbError::RequestBuild(e.to_string()))?;

    // Build the request
    let mut req_builder = Request::builder().uri(uri).method(builder.method.clone());

    for (key, value) in builder.headers.iter() {
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
            method: builder.method.to_string(),
            path: builder.url.path().to_string(),
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
    match &builder.body {
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

fn apply_dns_overrides(
    host: &str,
    port: u16,
    overrides: &[OverrideRule],
    event_handler: &Option<BoxedEventHandler>,
) -> (String, u16) {
    for rule in overrides {
        if rule.matches(host, port) {
            if let Some(handler) = event_handler {
                handler.on_event(ClientEvent::ConnectToOverride {
                    from_host: host.to_string(),
                    from_port: port,
                    to_host: rule.to_host.clone(),
                    to_port: rule.to_port,
                });
            }
            return (rule.to_host.clone(), rule.to_port);
        }
    }
    (host.to_string(), port)
}

fn resolve_address(host: &str, port: u16) -> Result<SocketAddr, OrbError> {
    let addr_str = format!("{}:{}", host, port);
    addr_str
        .to_socket_addrs()
        .map_err(|e| OrbError::Dns(e.to_string()))?
        .next()
        .ok_or_else(|| OrbError::Dns(format!("No addresses found for {}", host)))
}

fn build_tls_config(
    insecure: bool,
    use_system_cert_store: bool,
    ca_certs: &[CertificateDer<'static>],
    client_cert: Option<&(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<rustls::ClientConfig, OrbError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();

        if use_system_cert_store {
            // Load certificates from the system's native certificate store
            let native_certs = rustls_native_certs::load_native_certs();
            for cert in native_certs.certs {
                root_store.add(cert).ok();
            }
        } else {
            // Use bundled webpki-roots (Mozilla's root certificates)
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        // Add custom CA certificates if provided
        for cert in ca_certs {
            root_store.add(cert.clone()).ok();
        }

        let config_builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

        // Add client certificate if provided
        if let Some((certs, key)) = client_cert {
            config_builder
                .with_client_auth_cert(certs.clone(), key.clone_key())
                .map_err(|e| OrbError::Tls(e.to_string()))?
        } else {
            config_builder.with_no_client_auth()
        }
    };

    // Set ALPN for HTTP/3
    config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(config)
}

/// A certificate verifier that accepts all certificates (for --insecure mode)
#[derive(Debug)]
struct InsecureServerCertVerifier;

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

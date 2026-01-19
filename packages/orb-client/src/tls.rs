//! TLS utilities for certificate verification and configuration

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_rustls::{HttpsConnector, MaybeHttpsStream};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tower_service::Service;

use crate::dns::OrbConnector;
use crate::error::OrbError;
use crate::events::{BoxedEventHandler, ClientEvent, TlsCertInfo};

/// Inner HttpsConnector type alias
type InnerConnector = HttpsConnector<OrbConnector>;

/// A connector that wraps HttpsConnector and emits TLS handshake events
#[derive(Clone)]
pub struct TlsCapturingConnector {
    inner: InnerConnector,
    event_handler: Option<BoxedEventHandler>,
}

impl TlsCapturingConnector {
    pub fn new(inner: InnerConnector, event_handler: Option<BoxedEventHandler>) -> Self {
        Self {
            inner,
            event_handler,
        }
    }
}

impl Service<http::Uri> for TlsCapturingConnector {
    type Response = <InnerConnector as Service<http::Uri>>::Response;
    type Error = <InnerConnector as Service<http::Uri>>::Error;
    type Future = TlsCapturingFuture<<InnerConnector as Service<http::Uri>>::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let inner_future = self.inner.call(uri);
        TlsCapturingFuture {
            inner: inner_future,
            event_handler: self.event_handler.clone(),
        }
    }
}

/// Future that wraps the HttpsConnector future and emits TLS info on completion
#[pin_project::pin_project]
pub struct TlsCapturingFuture<F> {
    #[pin]
    inner: F,
    event_handler: Option<BoxedEventHandler>,
}

impl<F> Future for TlsCapturingFuture<F>
where
    F: Future<
        Output = Result<
            MaybeHttpsStream<TokioIo<TcpStream>>,
            Box<dyn std::error::Error + Send + Sync>,
        >,
    >,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                if let Ok(ref stream) = result {
                    emit_tls_info(stream, this.event_handler);
                }
                Poll::Ready(result)
            }
        }
    }
}

/// Extract TLS information from a MaybeHttpsStream and emit an event
fn emit_tls_info(
    stream: &MaybeHttpsStream<TokioIo<TcpStream>>,
    event_handler: &Option<BoxedEventHandler>,
) {
    let Some(handler) = event_handler else {
        return;
    };

    let MaybeHttpsStream::Https(tokio_io) = stream else {
        return;
    };

    // Get the inner TlsStream from TokioIo wrapper
    // The type is TlsStream<TokioIo<TokioIo<TcpStream>>> due to hyper-rustls wrapping
    let tls_stream: &TlsStream<TokioIo<TokioIo<TcpStream>>> = tokio_io.inner();

    // Get the ClientConnection from TlsStream
    let (_, client_conn) = tls_stream.get_ref();

    // Extract TLS version
    let version = client_conn
        .protocol_version()
        .map(|v| format!("{:?}", v))
        .unwrap_or_else(|| "Unknown".to_string());

    // Extract cipher suite
    let cipher = client_conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()));

    // Extract ALPN protocol
    let alpn = client_conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());

    // Extract certificate info
    let cert = client_conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| parse_certificate(cert));

    handler.on_event(ClientEvent::TlsHandshakeCompleted {
        version,
        cipher,
        alpn,
        cert,
    });
}

/// Parse a DER-encoded certificate and extract subject/issuer information
fn parse_certificate(cert_der: &CertificateDer) -> Option<TlsCertInfo> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    // Format validity dates
    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();

    Some(TlsCertInfo {
        subject,
        issuer,
        not_before,
        not_after,
    })
}

// TODO: Quinn should probably have a way to get this info directly
/// Extract TLS info from a quinn Connection (for HTTP/3)
pub fn extract_quic_tls_info(
    connection: &quinn::Connection,
    event_handler: &Option<BoxedEventHandler>,
) {
    let Some(handler) = event_handler else {
        return;
    };

    // QUIC always uses TLS 1.3
    let version = "TLS1_3".to_string();

    // ALPN for HTTP/3 is always "h3"
    let alpn = Some("h3".to_string());

    // Extract peer certificates
    let cert = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer>>().ok())
        .and_then(|certs| certs.first().cloned())
        .as_ref()
        .and_then(parse_certificate);

    handler.on_event(ClientEvent::TlsHandshakeCompleted {
        version,
        cipher: None,
        alpn,
        cert,
    });
}

/// Build a TLS client configuration with the specified options.
///
/// This is used by HTTP/3 and WebSocket clients that need to build their own TLS config.
/// HTTP/1.1 and HTTP/2 use hyper-rustls which handles TLS config internally.
pub fn build_client_tls_config(
    insecure: bool,
    use_system_cert_store: bool,
    ca_certs: &[CertificateDer<'static>],
    client_cert: Option<&(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<rustls::ClientConfig, OrbError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = if insecure {
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

    Ok(config)
}

/// Get an Arc to the InsecureServerCertVerifier for use in TLS configs
pub(crate) fn insecure_cert_verifier() -> Arc<dyn ServerCertVerifier> {
    Arc::new(InsecureServerCertVerifier)
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

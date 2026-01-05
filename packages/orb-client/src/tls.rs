//! TLS inspection utilities for extracting certificate and cipher information

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper_rustls::{HttpsConnector, MaybeHttpsStream};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tower_service::Service;

use crate::dns::OrbConnector;
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

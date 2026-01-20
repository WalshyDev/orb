//! TLS certificate configuration and generation

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

/// TLS certificate configuration for the mock server
pub struct TlsConfig {
    /// DER-encoded certificate
    pub(crate) cert: CertificateDer<'static>,
    /// DER-encoded private key (as raw bytes for cloning)
    key_der: Vec<u8>,
}

impl Clone for TlsConfig {
    fn clone(&self) -> Self {
        Self {
            cert: self.cert.clone(),
            key_der: self.key_der.clone(),
        }
    }
}

impl TlsConfig {
    /// Generate a self-signed certificate for localhost/127.0.0.1
    ///
    /// This certificate is valid for:
    /// - localhost (DNS)
    /// - 127.0.0.1 (IP)
    pub fn generate() -> Self {
        // Generate a new key pair
        let key_pair = KeyPair::generate().expect("Failed to generate key pair");

        // Build certificate parameters with proper SANs
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().expect("Invalid DNS name")),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        ];

        // Self-sign the certificate
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to generate self-signed certificate");

        let key_der = key_pair.serialize_der();

        TlsConfig {
            cert: CertificateDer::from(cert.der().to_vec()),
            key_der,
        }
    }

    /// Load certificate and key from PEM files
    pub fn from_files(cert_path: PathBuf, key_path: PathBuf) -> std::io::Result<Self> {
        use rustls_pemfile::{certs, pkcs8_private_keys};

        // Read certificate file
        let cert_file = std::fs::File::open(&cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert = certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .next()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("No certificate found in {:?}", cert_path),
                )
            })?;

        // Read key file
        let key_file = std::fs::File::open(&key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = pkcs8_private_keys(&mut key_reader)
            .filter_map(|r| r.ok())
            .next()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("No PKCS8 private key found in {:?}", key_path),
                )
            })?;

        Ok(TlsConfig {
            cert,
            key_der: key.secret_pkcs8_der().to_vec(),
        })
    }

    /// Get the private key as PrivateKeyDer
    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    /// Get the certificate as a PEM-encoded string
    ///
    /// This is useful for clients that need to trust this certificate
    pub fn cert_pem(&self) -> String {
        let encoded = base64_encode(self.cert.as_ref());
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            encoded
        )
    }

    /// Get the raw DER-encoded certificate bytes
    pub fn cert_der(&self) -> &[u8] {
        self.cert.as_ref()
    }

    /// Build a base rustls ServerConfig (shared by all TLS methods)
    fn build_base_server_config(&self) -> rustls::ServerConfig {
        // Install crypto provider if not already installed
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.private_key())
            .expect("Failed to build rustls server config")
    }

    /// Build a rustls ServerConfig with specific ALPN protocols
    ///
    /// - `http1`: Include HTTP/1.1 in ALPN
    /// - `http2`: Include HTTP/2 in ALPN
    pub(crate) fn build_alpn_server_config(
        &self,
        http1: bool,
        http2: bool,
    ) -> Arc<rustls::ServerConfig> {
        let mut config = self.build_base_server_config();

        // Set ALPN protocols based on what's enabled
        // Order matters: prefer h2 over http/1.1
        let mut alpn = Vec::new();
        if http2 {
            alpn.push(b"h2".to_vec());
        }
        if http1 {
            alpn.push(b"http/1.1".to_vec());
        }
        config.alpn_protocols = alpn;

        Arc::new(config)
    }

    /// Build a TlsAcceptor for WebSocket TLS
    pub(crate) fn build_tls_acceptor(&self) -> tokio_rustls::TlsAcceptor {
        let config = Arc::new(self.build_base_server_config());
        tokio_rustls::TlsAcceptor::from(config)
    }

    /// Build a Quinn ServerConfig for HTTP/3
    pub(crate) fn build_quic_server_config(&self) -> quinn::ServerConfig {
        let mut server_crypto = self.build_base_server_config();

        // Set ALPN protocol for HTTP/3
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .expect("Failed to create QUIC server config"),
        ))
    }
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field("cert_len", &self.cert.as_ref().len())
            .finish()
    }
}

/// Base64 encode bytes for PEM format
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;
    let mut col = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        let n = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[(n >> 18) & 63] as char);
        result.push(ALPHABET[(n >> 12) & 63] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[(n >> 6) & 63] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[n & 63] as char);
        } else {
            result.push('=');
        }

        col += 4;
        // Add line breaks for PEM format (64 chars per line)
        if col >= 64 {
            result.push('\n');
            col = 0;
        }

        i += 3;
    }

    result
}

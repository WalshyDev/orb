pub mod body;
pub mod dns;
pub mod error;
pub mod events;
pub(crate) mod http3_client;
pub mod http_client;
pub(crate) mod tls;
pub mod websocket_client;

pub use error::OrbError;
pub use events::{ClientEvent, EventHandler, TlsCertInfo};
pub use http_client::{HttpClient, HttpClientBuilder, RequestBuilder};
pub use websocket_client::{CloseFrame, WebSocketMessage, WebSocketStream};

// Re-export rustls types needed for certificate handling
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer};
pub use url::Url;

use futures_util::StreamExt;
use http::header::HeaderMap;
use http::{StatusCode, Version};

use crate::body::ResponseBody;

/// Unified response type that works with both HTTP/1.1+2 and HTTP/3 clients
pub struct Response {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    body: ResponseBody,
    content_length: Option<u64>,
}

impl Response {
    pub fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        body: ResponseBody,
        content_length: Option<u64>,
    ) -> Self {
        Self {
            status,
            version,
            headers,
            body,
            content_length,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// Read the response body as text
    pub async fn text(self) -> Result<String, OrbError> {
        let mut body_stream = self.into_body_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = body_stream.next().await {
            bytes.extend_from_slice(&chunk?);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub async fn json(self) -> Result<serde_json::Value, OrbError> {
        let text = self.text().await?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| OrbError::BodyRead(format!("Failed to parse JSON: {}", e)))?;
        Ok(json)
    }

    /// Convert to a byte stream for streaming the body
    pub fn into_body_stream(self) -> ResponseBody {
        self.body
    }
}

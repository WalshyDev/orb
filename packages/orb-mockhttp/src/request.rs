//! HTTP request type for the mock server

use std::collections::HashMap;

use bytes::Bytes;
use http::{HeaderMap, Method, Uri, Version};

use crate::HttpProtocol;

/// Represents an incoming HTTP request captured by the mock server
#[derive(Debug, Clone)]
pub struct Request {
    version: Version,
    method: Method,
    uri: Uri,
    query_params: HashMap<String, String>,
    headers: HeaderMap,
    body: Bytes,
    protocol: HttpProtocol,
}

impl Request {
    /// Create a new request
    pub(crate) fn new(
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        protocol: HttpProtocol,
    ) -> Self {
        let mut query_params = HashMap::new();
        if let Some(query) = uri.query() {
            for pair in query.split('&') {
                let mut iter = pair.splitn(2, '=');
                let key = iter.next().unwrap_or("").to_string();
                let value = iter.next().unwrap_or("").to_string();
                query_params.insert(key, value);
            }
        };

        Self {
            version,
            method,
            uri,
            query_params,
            headers,
            body,
            protocol,
        }
    }

    /// Get the HTTP method
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Get the request URI
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Get the request path
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// Get the query string (if any)
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// Get the HTTP version
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get all headers
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a specific header value as a string
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Get all query parameters
    pub fn query_params(&self) -> HashMap<String, String> {
        self.query_params.clone()
    }

    /// Get a specific query parameter value
    pub fn query_param(&self, key: &str) -> Option<&String> {
        self.query_params.get(key)
    }

    /// Get the raw body bytes
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Get the body as a UTF-8 string
    pub fn text(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body.to_vec())
    }

    /// Get the body as a UTF-8 string, replacing invalid characters
    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Parse the body as JSON
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Get the protocol used for this request (internal use)
    pub fn protocol(&self) -> HttpProtocol {
        self.protocol
    }

    /// Get the Content-Type header value
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Get the Content-Length header value
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|v| v.parse().ok())
    }

    /// Check if the method matches
    pub fn is_method(&self, method: &str) -> bool {
        self.method.as_str().eq_ignore_ascii_case(method)
    }
}

use std::collections::HashMap;
use std::time::Duration;

use orb_client::RequestBuilder;
use serde::Deserialize;
use url::Url;

use super::UpdateError;

#[derive(Debug, Deserialize)]
pub struct UpdateManifest {
    /// Latest available version
    pub version: String,

    /// Whether this is an urgent/security update
    #[serde(default)]
    pub urgent: bool,

    /// Platform-specific binary information
    pub binaries: HashMap<String, BinaryInfo>,
}

#[derive(Debug, Deserialize)]
pub struct BinaryInfo {
    /// Download URL for the binary
    pub url: String,

    /// SHA256 hash of the binary
    pub sha256: String,
}

impl UpdateManifest {
    /// Fetch the update manifest from the given URL
    pub async fn fetch(manifest_url: &str) -> Result<Self, UpdateError> {
        let url = Url::parse(manifest_url).map_err(|_| UpdateError::InvalidManifestUrl)?;

        let response =
            tokio::time::timeout(Duration::from_secs(10), RequestBuilder::new(url).send())
                .await
                .map_err(|_| UpdateError::Timeout)?
                .map_err(|_| UpdateError::NetworkError)?;

        if !response.status().is_success() {
            return Err(UpdateError::HttpError);
        }

        let body = response
            .text()
            .await
            .map_err(|_| UpdateError::NetworkError)?;

        serde_json::from_str(&body).map_err(|_| UpdateError::InvalidManifest)
    }

    /// Get binary info for the current platform
    pub fn get_binary_for_platform(&self) -> Option<&BinaryInfo> {
        let target = current_target_triple();
        self.binaries.get(target)
    }
}

/// Get the current platform's target triple
pub fn current_target_triple() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    {
        "x86_64-unknown-linux-musl"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        "x86_64-pc-windows-msvc"
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "musl"),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "windows"),
    )))]
    {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orb_mockhttp::TestServerBuilder;

    fn sample_manifest_json() -> String {
        r#"{
            "version": "0.3.0",
            "urgent": false,
            "binaries": {
                "x86_64-apple-darwin": {
                    "url": "https://example.com/orb-x86_64-apple-darwin",
                    "sha256": "abc123"
                },
                "aarch64-apple-darwin": {
                    "url": "https://example.com/orb-aarch64-apple-darwin",
                    "sha256": "def456"
                },
                "x86_64-unknown-linux-gnu": {
                    "url": "https://example.com/orb-x86_64-unknown-linux-gnu",
                    "sha256": "ghi789"
                }
            }
        }"#
        .to_string()
    }

    #[test]
    fn test_parse_manifest() {
        let json = sample_manifest_json();
        let manifest: UpdateManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.version, "0.3.0");
        assert!(!manifest.urgent);
        assert_eq!(manifest.binaries.len(), 3);

        let darwin = manifest.binaries.get("x86_64-apple-darwin").unwrap();
        assert_eq!(darwin.url, "https://example.com/orb-x86_64-apple-darwin");
        assert_eq!(darwin.sha256, "abc123");
    }

    #[test]
    fn test_parse_manifest_urgent() {
        let json = r#"{
            "version": "0.3.1",
            "urgent": true,
            "binaries": {}
        }"#;
        let manifest: UpdateManifest = serde_json::from_str(json).unwrap();

        assert_eq!(manifest.version, "0.3.1");
        assert!(manifest.urgent);
    }

    #[test]
    fn test_parse_manifest_urgent_default() {
        let json = r#"{
            "version": "0.3.0",
            "binaries": {}
        }"#;
        let manifest: UpdateManifest = serde_json::from_str(json).unwrap();

        assert!(!manifest.urgent); // defaults to false
    }

    #[test]
    fn test_get_binary_for_platform() {
        let json = sample_manifest_json();
        let manifest: UpdateManifest = serde_json::from_str(&json).unwrap();

        let binary = manifest.get_binary_for_platform();
        // Should find the binary for the current platform (if it's in our test data)
        let target = current_target_triple();
        if manifest.binaries.contains_key(target) {
            assert!(binary.is_some());
        }
    }

    #[test]
    fn test_current_target_triple() {
        let triple = current_target_triple();
        // Should not be empty and should contain dashes
        assert!(!triple.is_empty());
        assert!(triple.contains('-') || triple == "unknown");
    }

    #[tokio::test]
    async fn test_fetch_manifest_success() {
        let server = TestServerBuilder::new().build();
        server
            .on_request("/update/manifest.json")
            .respond_with(200, sample_manifest_json());

        let manifest = UpdateManifest::fetch(&server.url("/update/manifest.json"))
            .await
            .unwrap();

        assert_eq!(manifest.version, "0.3.0");
        assert_eq!(manifest.binaries.len(), 3);
    }

    #[tokio::test]
    async fn test_fetch_manifest_not_found() {
        let server = TestServerBuilder::new().build();
        server
            .on_request("/update/manifest.json")
            .respond_with(404, "Not Found");

        let result = UpdateManifest::fetch(&server.url("/update/manifest.json")).await;

        assert!(matches!(result, Err(UpdateError::HttpError)));
    }

    #[tokio::test]
    async fn test_fetch_manifest_invalid_json() {
        let server = TestServerBuilder::new().build();
        server
            .on_request("/update/manifest.json")
            .respond_with(200, "not valid json");

        let result = UpdateManifest::fetch(&server.url("/update/manifest.json")).await;

        assert!(matches!(result, Err(UpdateError::InvalidManifest)));
    }

    #[tokio::test]
    async fn test_fetch_manifest_invalid_url() {
        let result = UpdateManifest::fetch("not-a-valid-url").await;

        assert!(matches!(result, Err(UpdateError::InvalidManifestUrl)));
    }
}

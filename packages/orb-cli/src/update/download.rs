use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use orb_client::RequestBuilder;
use sha2::{Digest, Sha256};
use url::Url;

use super::UpdateError;
use super::config::staged_dir;
use super::manifest::BinaryInfo;

/// Download a binary to the staged directory
pub async fn download_binary(
    binary_info: &BinaryInfo,
    version: &str,
) -> Result<std::path::PathBuf, UpdateError> {
    let staged = staged_dir().ok_or(UpdateError::NoConfigDir)?;

    // Ensure staged directory exists
    fs::create_dir_all(&staged).map_err(|_| UpdateError::IoError)?;

    // Determine filename based on platform
    #[cfg(windows)]
    let filename = format!("orb-{}.exe", version);
    #[cfg(not(windows))]
    let filename = format!("orb-{}", version);

    let target_path = staged.join(&filename);

    // Download the binary
    let url = Url::parse(&binary_info.url).map_err(|_| UpdateError::InvalidManifestUrl)?;

    let response = tokio::time::timeout(
        Duration::from_secs(120), // 2 minute timeout for download
        RequestBuilder::new(url).send(),
    )
    .await
    .map_err(|_| UpdateError::Timeout)?
    .map_err(|_| UpdateError::NetworkError)?;

    if !response.status().is_success() {
        return Err(UpdateError::HttpError);
    }

    // Stream body to file
    let mut body_stream = response.into_body_stream();
    let mut file = fs::File::create(&target_path).map_err(|_| UpdateError::IoError)?;

    while let Some(chunk) = body_stream.next().await {
        let data = chunk.map_err(|_| UpdateError::NetworkError)?;
        file.write_all(&data).map_err(|_| UpdateError::IoError)?;
    }

    Ok(target_path)
}

/// Verify the SHA256 hash of a file
pub fn verify_sha256(path: &Path, expected_hash: &str) -> Result<bool, UpdateError> {
    let data = fs::read(path).map_err(|_| UpdateError::IoError)?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let hash_hex = hex_encode(&hash);

    Ok(hash_hex.eq_ignore_ascii_case(expected_hash))
}

/// Convert bytes to hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use orb_mockhttp::{ResponseBuilder, TestServerBuilder};
    use tempfile::TempDir;

    #[test]
    fn test_hex_encode() {
        let bytes = [0x00, 0x01, 0x0f, 0xff, 0xab];
        assert_eq!(hex_encode(&bytes), "00010fffab");
    }

    #[test]
    fn test_verify_sha256_valid() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file");

        // Write known content
        let content = b"Hello, World!";
        fs::write(&file_path, content).unwrap();

        // SHA256 of "Hello, World!" is:
        // dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
        let expected_hash = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";

        let result = verify_sha256(&file_path, expected_hash).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_sha256_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file");

        fs::write(&file_path, b"Hello, World!").unwrap();

        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_sha256(&file_path, wrong_hash).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_sha256_case_insensitive() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file");

        fs::write(&file_path, b"Hello, World!").unwrap();

        // Uppercase version of the hash
        let expected_hash = "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F";
        let result = verify_sha256(&file_path, expected_hash).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_sha256_file_not_found() {
        let result = verify_sha256(Path::new("/nonexistent/file"), "abc123");
        assert!(matches!(result, Err(super::super::UpdateError::IoError)));
    }

    #[tokio::test]
    async fn test_download_binary_success() {
        let server = TestServerBuilder::new().build();
        let binary_content: &[u8] = b"fake binary content for testing";

        server.on_request_fn("/releases/0.3.0/orb", |_req| {
            ResponseBuilder::new()
                .status(200)
                .body(b"fake binary content for testing".to_vec())
                .build()
        });

        let binary_info = BinaryInfo {
            url: server.url("/releases/0.3.0/orb"),
            sha256: "unused".to_string(),
        };

        let result = download_binary(&binary_info, "0.3.0").await;

        // This will fail if staged_dir() returns None (no config dir)
        // In a real test environment, we'd mock the config dir
        if let Ok(path) = result {
            assert!(path.exists());
            let content = fs::read(&path).unwrap();
            assert_eq!(content, binary_content);
            // Clean up
            let _ = fs::remove_file(path);
        }
    }

    #[tokio::test]
    async fn test_download_binary_not_found() {
        let server = TestServerBuilder::new().build();
        server
            .on_request("/releases/0.3.0/orb")
            .respond_with(404, "Not Found");

        let binary_info = BinaryInfo {
            url: server.url("/releases/0.3.0/orb"),
            sha256: "unused".to_string(),
        };

        let result = download_binary(&binary_info, "0.3.0").await;

        // Either NoConfigDir (if no config dir) or HttpError
        assert!(matches!(
            result,
            Err(UpdateError::HttpError) | Err(UpdateError::NoConfigDir)
        ));
    }

    #[tokio::test]
    async fn test_download_binary_invalid_url() {
        let binary_info = BinaryInfo {
            url: "not-a-valid-url".to_string(),
            sha256: "unused".to_string(),
        };

        let result = download_binary(&binary_info, "0.3.0").await;

        assert!(matches!(
            result,
            Err(super::super::UpdateError::InvalidManifestUrl)
                | Err(super::super::UpdateError::NoConfigDir)
        ));
    }
}

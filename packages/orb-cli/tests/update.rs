mod testutils;

use assert_cmd::cargo::*;
use orb_mockhttp::{ResponseBuilder, TestServerBuilder};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Convert a path to a JSON-safe string (forward slashes work on all platforms)
fn path_to_json_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Generate an urgent manifest
fn urgent_manifest_json(version: &str, binary_url: &str, sha256: &str) -> String {
    format!(
        r#"{{
            "version": "{version}",
            "urgent": true,
            "binaries": {{
                "x86_64-apple-darwin": {{
                    "url": "{binary_url}",
                    "sha256": "{sha256}"
                }},
                "aarch64-apple-darwin": {{
                    "url": "{binary_url}",
                    "sha256": "{sha256}"
                }},
                "x86_64-unknown-linux-gnu": {{
                    "url": "{binary_url}",
                    "sha256": "{sha256}"
                }},
                "aarch64-unknown-linux-gnu": {{
                    "url": "{binary_url}",
                    "sha256": "{sha256}"
                }}
            }}
        }}"#
    )
}

/// Compute SHA256 hash of data
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Create a config file that points to our mock server
fn create_test_config(dir: &std::path::Path, manifest_url: &str) {
    let config_content = format!(
        r#"[update]
enabled = true
check_interval_hours = 0
manifest_url = "{manifest_url}"
"#
    );
    fs::write(dir.join("config.toml"), config_content).unwrap();
}

/// Create a state file indicating we haven't checked recently
fn create_fresh_state(dir: &std::path::Path) {
    let state_content = r#"{"last_check": null, "staged": null}"#;
    fs::write(dir.join("state.json"), state_content).unwrap();
}

#[test]
fn test_update_check_does_not_block_cli() {
    // Verify that even when the update server is slow or unreachable,
    // the CLI still responds quickly
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"));

    let start = std::time::Instant::now();
    let output = cmd.output().unwrap();
    let elapsed = start.elapsed();

    assert!(output.status.success());
    // Should complete quickly (within 5 seconds) even if update check fails
    assert!(elapsed.as_secs() < 5, "CLI took too long: {:?}", elapsed);
}

#[test]
fn test_cli_works_without_update_server() {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello from test");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"));

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Hello from test");
}

#[test]
fn test_update_messages_go_to_stderr_not_stdout() {
    // Set up a temp config directory
    let temp_dir = TempDir::new().unwrap();
    let server = TestServerBuilder::new().build();

    // Create fake binary content
    let fake_binary = b"#!/bin/bash\necho 'I am orb 99.0.0'\n";
    let binary_hash = sha256_hex(fake_binary);

    // Set up mock server with manifest and binary
    let manifest = urgent_manifest_json("99.0.0", &server.url("/releases/orb"), &binary_hash);
    server
        .on_request("/update/manifest.json")
        .respond_with(200, &manifest);
    server.on_request_fn("/releases/orb", move |_req| {
        ResponseBuilder::new()
            .status(200)
            .body(b"#!/bin/bash\necho 'I am orb 99.0.0'\n".to_vec())
            .build()
    });

    // Set up test endpoint
    server
        .on_request("/api/data")
        .respond_with(200, r#"{"result": "success"}"#);

    // Create config pointing to our mock server
    create_test_config(temp_dir.path(), &server.url("/update/manifest.json"));
    create_fresh_state(temp_dir.path());
    fs::create_dir_all(temp_dir.path().join("staged")).unwrap();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.env("ORB_CONFIG_DIR", temp_dir.path())
        .arg(server.url("/api/data"));

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // stdout should ONLY contain the response body - no update messages
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, r#"{"result": "success"}"#);

    // stderr may contain update notification (for urgent updates)
    // but stdout must be clean for piping
}

#[test]
fn test_staged_update_is_applied_on_next_run() {
    let temp_dir = TempDir::new().unwrap();
    let server = TestServerBuilder::new().build();

    // Create a fake "new binary" - just a shell script for testing
    let fake_binary = b"#!/bin/bash\necho 'Updated!'\n";
    let binary_hash = sha256_hex(fake_binary);

    // Create staged directory and put the "new binary" there
    let staged_dir = temp_dir.path().join("staged");
    fs::create_dir_all(&staged_dir).unwrap();
    let staged_binary_path = staged_dir.join("orb-99.0.0");
    fs::write(&staged_binary_path, fake_binary).unwrap();

    // Create state file with staged update info
    let state_content = format!(
        r#"{{
            "last_check": "2024-01-01T00:00:00Z",
            "staged": {{
                "version": "99.0.0",
                "path": "{}",
                "sha256": "{}"
            }}
        }}"#,
        path_to_json_string(&staged_binary_path),
        binary_hash
    );
    fs::write(temp_dir.path().join("state.json"), state_content).unwrap();

    // Set up a simple test endpoint
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.env("ORB_CONFIG_DIR", temp_dir.path())
        .env("ORB_UPDATE_DRY_RUN", "1") // Don't actually replace the test binary
        .arg(server.url("/test"));

    let output = cmd.output().unwrap();

    // The update detection should still work and print the message
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("* Updated orb to version 99.0.0"),
        "Expected update message in stderr, got: {}",
        stderr
    );

    // The CLI should still work (dry-run doesn't actually replace the binary)
    assert!(output.status.success());
}

#[test]
fn test_update_disabled_via_config() {
    let temp_dir = TempDir::new().unwrap();

    // Use separate servers: one for the test endpoint, one for the manifest
    let test_server = TestServerBuilder::new().build();
    let manifest_server = TestServerBuilder::new().build();

    // Create config with updates disabled but pointing to manifest server
    let config_content = format!(
        r#"[update]
enabled = false
manifest_url = "{}"
"#,
        manifest_server.url("/update/manifest.json")
    );
    fs::write(temp_dir.path().join("config.toml"), config_content).unwrap();

    // Set up manifest endpoint - should NOT be called
    manifest_server
        .on_request("/update/manifest.json")
        .respond_with(200, r#"{"version": "99.0.0", "binaries": {}}"#);

    test_server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.env("ORB_CONFIG_DIR", temp_dir.path())
        .arg(test_server.url("/test"));

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Give a moment for background task to potentially run
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify: test_server received the test request, manifest_server received nothing
    test_server.assert_requests(1);
    manifest_server.assert_requests(0);
}

#[test]
fn test_update_check_respects_interval() {
    let temp_dir = TempDir::new().unwrap();

    // Use separate servers: one for the test endpoint, one for the manifest
    let test_server = TestServerBuilder::new().build();
    let manifest_server = TestServerBuilder::new().build();

    // Create config with 24 hour interval
    let config_content = format!(
        r#"[update]
enabled = true
check_interval_hours = 24
manifest_url = "{}"
"#,
        manifest_server.url("/update/manifest.json")
    );
    fs::write(temp_dir.path().join("config.toml"), config_content).unwrap();

    // Create state file indicating we just checked
    let state_content = format!(
        r#"{{"last_check": "{}", "staged": null}}"#,
        chrono::Utc::now().to_rfc3339()
    );
    fs::write(temp_dir.path().join("state.json"), state_content).unwrap();

    // Set up manifest endpoint - should NOT be called due to interval
    manifest_server
        .on_request("/update/manifest.json")
        .respond_with(200, r#"{"version": "99.0.0", "binaries": {}}"#);

    test_server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.env("ORB_CONFIG_DIR", temp_dir.path())
        .arg(test_server.url("/test"));

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Give a moment for background task to potentially run
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify: test_server received the test request, manifest_server received nothing
    test_server.assert_requests(1);
    manifest_server.assert_requests(0);
}

#[test]
fn test_sha256_verification_prevents_bad_binary() {
    let temp_dir = TempDir::new().unwrap();
    let server = TestServerBuilder::new().build();

    // Create staged directory with a binary that has WRONG hash in state
    let staged_dir = temp_dir.path().join("staged");
    fs::create_dir_all(&staged_dir).unwrap();
    let staged_binary_path = staged_dir.join("orb-99.0.0");
    fs::write(&staged_binary_path, b"fake binary content").unwrap();

    // Create state file with WRONG hash (doesn't match actual file)
    let state_content = format!(
        r#"{{
            "last_check": "2024-01-01T00:00:00Z",
            "staged": {{
                "version": "99.0.0",
                "path": "{}",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }}
        }}"#,
        path_to_json_string(&staged_binary_path)
    );
    fs::write(temp_dir.path().join("state.json"), state_content).unwrap();

    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.env("ORB_CONFIG_DIR", temp_dir.path())
        .arg(server.url("/test"));

    let output = cmd.output().unwrap();

    // CLI should still work - bad hash means update is skipped
    assert!(output.status.success());

    // Assert binary is cleaned up
    assert!(!fs::exists(&staged_binary_path).unwrap_or(false));
}

#[test]
fn test_missing_staged_binary_is_handled() {
    let temp_dir = TempDir::new().unwrap();
    let server = TestServerBuilder::new().build();

    // Create state file pointing to non-existent staged binary
    let state_content = r#"{
        "last_check": "2024-01-01T00:00:00Z",
        "staged": {
            "version": "99.0.0",
            "path": "/nonexistent/path/orb-99.0.0",
            "sha256": "abc123"
        }
    }"#;
    fs::write(temp_dir.path().join("state.json"), state_content).unwrap();

    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.env("ORB_CONFIG_DIR", temp_dir.path())
        .arg(server.url("/test"));

    let output = cmd.output().unwrap();

    // CLI should work fine - missing staged binary is handled gracefully
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "OK");
}

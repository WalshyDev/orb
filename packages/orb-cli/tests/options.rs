mod testutils;

use assert_cmd::cargo::*;
use async_compression::tokio::bufread::{BrotliEncoder, DeflateEncoder, GzipEncoder, ZstdEncoder};
use insta::{allow_duplicates, assert_snapshot};
use orb_mockhttp::{HttpProtocol, ResponseBuilder, TestServerBuilder};
use std::process::Command;
use std::time::Duration;
use test_case::test_case;
use testutils::{normalize_os_error, null_device, parse_args, sanitize_error, sanitize_output};
use tokio::io::AsyncReadExt;

use crate::testutils::test_server;

/// Helper to compress data using async-compression
async fn compress_data(data: &[u8], encoding: &str) -> Vec<u8> {
    let data = data.to_vec();
    let cursor = std::io::Cursor::new(data);
    let buf_reader = tokio::io::BufReader::new(cursor);

    let mut output = Vec::new();
    match encoding {
        "gzip" => {
            let mut encoder = GzipEncoder::new(buf_reader);
            encoder.read_to_end(&mut output).await.unwrap();
        }
        "deflate" => {
            let mut encoder = DeflateEncoder::new(buf_reader);
            encoder.read_to_end(&mut output).await.unwrap();
        }
        "br" => {
            let mut encoder = BrotliEncoder::new(buf_reader);
            encoder.read_to_end(&mut output).await.unwrap();
        }
        "zstd" => {
            let mut encoder = ZstdEncoder::new(buf_reader);
            encoder.read_to_end(&mut output).await.unwrap();
        }
        _ => panic!("Unsupported encoding: {}", encoding),
    }
    output
}

#[test]
fn test_url() {
    let server = test_server();

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-v");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "OK");

    server.assert_requests(1);
}

#[test_case("GET"; "GET")]
#[test_case("HEAD"; "HEAD")]
#[test_case("POST"; "POST")]
#[test_case("PATCH"; "PATCH")]
#[test_case("PUT"; "PUT")]
#[test_case("DELETE"; "DELETE")]
#[test_case("OPTIONS"; "OPTIONS")]
#[test_case("TRACE"; "TRACE")]
#[test_case("NON-SPEC-COMPLIANT"; "NON-SPEC-COMPLIANT")]
fn test_method(method: &str) {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .expect_method(method)
        .expect_header("User-Agent", concat!("orb/", env!("CARGO_PKG_VERSION")))
        .expect_header("Accept", "*/*")
        .expect_header("Host", server.address().to_string())
        .respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-X").arg(method);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    server.assert_requests(1);
}

#[test_case(vec!["Custom-Header: Value"]; "single header")]
#[test_case(vec!["Custom-Header: Value", "Another-Header: Another-Value"]; "multiple headers")]
#[test_case(vec!["Accept: plain/text", "User-Agent: CustomAgent"]; "override default headers")]
#[test_case(vec!["Accept-Encoding: zstd"]; "Can override Accept-Encoding")]
#[test_case(vec![]; "no custom headers")]
fn test_headers(headers: Vec<&str>) {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"));

    for header in &headers {
        cmd.arg("-H").arg(header);
    }

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Verify headers were sent correctly
    let request = server.get_raw_request().unwrap();
    assert!(request.contains("host:"), "Expected host header");
    for header in &headers {
        if let Some((key, value)) = header.split_once(":") {
            let key_lower = key.trim().to_lowercase();
            let value_trimmed = value.trim();
            assert!(
                request.to_lowercase().contains(&format!(
                    "{}: {}",
                    key_lower,
                    value_trimmed.to_lowercase()
                )),
                "Expected header '{}' with value '{}' in request: {}",
                key.trim(),
                value_trimmed,
                request
            );
        }
    }
    server.assert_requests(1);
}

#[test_case("simple data", "simple data"; "simple data")]
#[test_case("@tests/testdata/test_data.txt", "This is test data from file"; "data from file")]
fn test_data(data: &str, expected_body: &str) {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-d").arg(data);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request.contains(expected_body),
        "Expected body '{}' in request: {}",
        expected_body,
        request
    );
    server.assert_requests(1);
}

#[test_case(
    "@tests/testdata/does-not-exist.txt",
    "Failed to read data from file 'tests/testdata/does-not-exist.txt': No such file or directory (os error 2)\n";
    "file does not exist"
)]
fn test_data_invalid(data: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://127.0.0.1:0/test")
        .arg("-X")
        .arg("POST")
        .arg("-d")
        .arg(data);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(normalize_os_error(&stderr), expected_error);
}

#[test_case("POST", "simple data", "simple data"; "POST simple data")]
#[test_case("POST", "@tests/testdata/test_data.txt", "This is test data from file"; "POST data from file")]
#[test_case("PATCH", "simple data", "simple data"; "PATCH simple data")]
#[test_case("PATCH", "@tests/testdata/test_data.txt", "This is test data from file"; "PATCH data from file")]
#[test_case("PUT", "simple data", "simple data"; "PUT simple data")]
#[test_case("PUT", "@tests/testdata/test_data.txt", "This is test data from file"; "PUT data from file")]
fn test_data_explicit_method(method: &str, data: &str, expected_body: &str) {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("-X")
        .arg(method)
        .arg("-d")
        .arg(data);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request.starts_with(&format!("{} /test", method)),
        "Expected {} method but got: {}",
        method,
        request
    );
    assert!(
        request.contains(expected_body),
        "Expected body '{}' in request: {}",
        expected_body,
        request
    );
    server.assert_requests(1);
}

#[test]
fn test_data_user_content_type_not_overridden() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("-X")
        .arg("POST")
        .arg("-d")
        .arg(r#"{"foo": true}"#)
        .arg("-H")
        .arg("Content-Type: application/json");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("content-type: application/json"),
        "Expected user-specified Content-Type: application/json, got: {}",
        request
    );
    assert!(
        !request
            .to_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"),
        "User Content-Type should not be overridden by -d default, got: {}",
        request
    );
    server.assert_requests(1);
}

#[test]
fn test_json() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("-X")
        .arg("POST")
        .arg("--json")
        .arg(r#"{"key":"value"}"#);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("content-type: application/json"),
        "Expected Content-Type: application/json header in request: {}",
        request
    );
    assert!(
        request.contains(r#"{"key":"value"}"#),
        "Expected JSON body in request: {}",
        request
    );
    server.assert_requests(1);
}

#[test_case(
    "-F field1=value1",
    "--<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field1\"\n\
    \n\
    value1\n\
    --<BOUNDARY>--";
    "single form field"
)]
#[test_case(
    "-F field1=value1 -F field2=value2",
    "--<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field1\"\n\
    \n\
    value1\n\
    --<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field2\"\n\
    \n\
    value2\n\
    --<BOUNDARY>--";
    "multiple form fields"
)]
#[test_case(
    "-F field1=@tests/testdata/test_data.txt",
    "--<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field1\"; filename=\"test_data.txt\"\n\
    Content-Type: text/plain\n\
    \n\
    This is test data from file\n\
    \n\
    --<BOUNDARY>--";
    "form file upload"
)]
#[test_case(
    "-F field1=@tests/testdata/test_data.txt -F field2=@tests/testdata/more_test_data.txt",
    "--<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field1\"; filename=\"test_data.txt\"\n\
    Content-Type: text/plain\n\
    \n\
    This is test data from file\n\
    \n\
    --<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field2\"; filename=\"more_test_data.txt\"\n\
    Content-Type: text/plain\n\
    \n\
    More test data in another file\n\
    \n\
    --<BOUNDARY>--";
    "form multiple file upload"
)]
#[test_case(
    "-F field1=value1 -F field2=@tests/testdata/test_data.txt",
    "--<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field1\"\n\
    \n\
    value1\n\
    --<BOUNDARY>\n\
    Content-Disposition: form-data; name=\"field2\"; filename=\"test_data.txt\"\n\
    Content-Type: text/plain\n\
    \n\
    This is test data from file\n\
    \n\
    --<BOUNDARY>--";
    "form mixed fields"
)]
fn test_form(options: &str, expected_body: &str) {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-X").arg("POST");

    for arg in options.split_whitespace() {
        cmd.arg(arg);
    }

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    let output = sanitize_output(&request);

    assert!(output.contains(expected_body));
    server.assert_requests(1);
}

#[test]
fn test_include_headers() {
    let server = TestServerBuilder::new().build();
    server.on_request_fn("/test", |_req| {
        ResponseBuilder::new()
            .status(200)
            .header("X-Custom-Header", "custom-value")
            .body("Response body")
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-i");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check essential parts of the response
    assert!(
        stdout.contains("HTTP/1.1 200"),
        "Expected HTTP/1.1 200 in response"
    );
    assert!(
        stdout.contains("x-custom-header: custom-value"),
        "Expected custom header"
    );
    assert!(stdout.contains("Response body"), "Expected response body");

    server.assert_requests(1);
}

#[test]
fn test_head_only() {
    let server = TestServerBuilder::new().build();
    server.on_request_fn("/test", |_req| {
        ResponseBuilder::new()
            .status(200)
            .header("X-Custom-Header", "custom-value")
            .body("Response body that should not appear")
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-I");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_snapshot!(
        sanitize_output(&stdout),
        @r"
    HTTP/1.1 200 OK
    x-custom-header: custom-value
    content-length: 36
    date: <DATE>
    "
    );

    // Assert the request was sent as HEAD
    let request = server.get_raw_request().unwrap();
    assert_snapshot!(
        sanitize_output(&request),
        @r"
    HEAD /test HTTP/1.1
    accept: */*
    user-agent: orb/0.1.0
    host: 127.0.0.1:<PORT>
    "
    );

    server.assert_requests(1);
}

#[test_case("GET"; "GET")]
#[test_case("HEAD"; "HEAD")]
#[test_case("POST"; "POST")]
#[test_case("PATCH"; "PATCH")]
#[test_case("PUT"; "PUT")]
#[test_case("DELETE"; "DELETE")]
#[test_case("OPTIONS"; "OPTIONS")]
#[test_case("TRACE"; "TRACE")]
#[test_case("NON-SPEC-COMPLIANT"; "NON-SPEC-COMPLIANT")]
fn test_head_only_with_explicit_method(method: &str) {
    // When -X POST is combined with -I, the explicit method should be preserved
    let server = TestServerBuilder::new().build();
    server.on_request_fn("/test", |_req| {
        ResponseBuilder::new()
            .status(200)
            .header("X-Custom-Header", "custom-value")
            .body("Response body that should not appear")
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-I").arg("-X").arg(method);

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain headers
    assert!(
        stdout.contains("HTTP/1.1 200"),
        "Expected HTTP/1.1 200 in response"
    );
    assert!(
        stdout.contains("x-custom-header: custom-value"),
        "Expected custom header"
    );

    // Should NOT contain body
    assert!(!stdout.contains("Response body that should not appear"));

    // -X {METHOD} should take precedence over -I's implicit HEAD
    let request = server.get_raw_request().unwrap();
    assert!(
        request.starts_with(&format!("{} /test", method)),
        "Expected {} method but got: {}",
        method,
        request
    );

    server.assert_requests(1);
}

#[test_case(
    "",
    "";
    "no verbose"
)]
#[test_case(
    "-v",
    "> GET /test\n\
    > accept: */*\n\
    > user-agent: orb/0.1.0\n\
    > host: 127.0.0.1:<PORT>\n\
    >\n\
    < HTTP/1.1 200 OK\n\
    < content-length: 2\n\
    < date: <DATE>\n\
    <\n\
    ";
    "default verbose"
)]
#[test_case(
    "-v -H 'Custom-Header: CustomValue'",
    "> GET /test\n\
    > accept: */*\n\
    > user-agent: orb/0.1.0\n\
    > host: 127.0.0.1:<PORT>\n\
    > custom-header: CustomValue\n\
    >\n\
    < HTTP/1.1 200 OK\n\
    < content-length: 2\n\
    < date: <DATE>\n\
    <\n\
    ";
    "verbose with custom header"
)]
#[test_case(
    "-v -H 'Accept: text/plain'",
    "> GET /test\n\
    > accept: text/plain\n\
    > user-agent: orb/0.1.0\n\
    > host: 127.0.0.1:<PORT>\n\
    >\n\
    < HTTP/1.1 200 OK\n\
    < content-length: 2\n\
    < date: <DATE>\n\
    <\n\
    ";
    "verbose overriding default header"
)]
#[test_case(
    "-v -A 'CustomAgent/1.0'",
    "> GET /test\n\
    > accept: */*\n\
    > user-agent: CustomAgent/1.0\n\
    > host: 127.0.0.1:<PORT>\n\
    >\n\
    < HTTP/1.1 200 OK\n\
    < content-length: 2\n\
    < date: <DATE>\n\
    <\n\
    ";
    "verbose with user agent"
)]
#[test_case(
    "-v -u user:password",
    "> GET /test\n\
    > accept: */*\n\
    > user-agent: orb/0.1.0\n\
    > host: 127.0.0.1:<PORT>\n\
    > authorization: Basic dXNlcjpwYXNzd29yZA==\n\
    >\n\
    < HTTP/1.1 200 OK\n\
    < content-length: 2\n\
    < date: <DATE>\n\
    <\n\
    ";
    "verbose with basic auth"
)]
#[test_case(
    "-v --bearer my-token",
    "> GET /test\n\
    > accept: */*\n\
    > user-agent: orb/0.1.0\n\
    > host: 127.0.0.1:<PORT>\n\
    > authorization: Bearer my-token\n\
    >\n\
    < HTTP/1.1 200 OK\n\
    < content-length: 2\n\
    < date: <DATE>\n\
    <\n\
    ";
    "verbose with bearer auth"
)]
#[test_case(
    "-v -e 'https://example.com/page'",
    "> GET /test\n\
    > accept: */*\n\
    > user-agent: orb/0.1.0\n\
    > host: 127.0.0.1:<PORT>\n\
    > referer: https://example.com/page\n\
    >\n\
    < HTTP/1.1 200 OK\n\
    < content-length: 2\n\
    < date: <DATE>\n\
    <\n\
    ";
    "verbose with referer"
)]
fn test_verbose(options: &str, expected_output: &str) {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"));

    for arg in parse_args(options) {
        cmd.arg(arg);
    }

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(stdout, "OK");
    assert_eq!(sanitize_output(&stderr), expected_output);

    server.assert_requests(1);
}

// Test verbose mode with TLS shows certificate and cipher info
#[test]
fn test_verbose_tls_handshake_info() {
    let server = TestServerBuilder::new().with_tls().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-v").arg("--insecure"); // Accept self-signed cert

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_snapshot!(
        sanitize_output(&stderr),
        @r"
    * TLS handshake completed
    *   Version: TLSv1_3
    *   Cipher: TLS13_AES_256_GCM_SHA384
    *   ALPN: h2
    *   Server certificate:
    *     Subject: CN=rcgen self signed cert
    *     Issuer: CN=rcgen self signed cert
    *     Valid from: <DATE>
    *     Valid until: <DATE>
    > GET /test
    > accept: */*
    > user-agent: orb/0.1.0
    > host: 127.0.0.1:<PORT>
    >
    < HTTP/2.0 200 OK
    < content-length: 2
    < date: <DATE>
    <
    "
    );

    server.assert_requests(1);
}

// Test --silent suppresses error messages
#[test]
fn test_silent_suppresses_errors() {
    // Request to a non-existent host should fail with no output
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://self-signed.badssl.com/").arg("-s");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "Silent mode should suppress error messages, got: {}",
        stderr
    );
}

// Test --silent still outputs response body
#[test]
fn test_silent_outputs_body() {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-s");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Hello, World!");

    server.assert_requests(1);
}

// Test --silent suppresses verbose output
#[test]
fn test_silent_suppresses_verbose() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-v").arg("-s");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "Silent mode should suppress verbose output, got: {}",
        stderr
    );

    server.assert_requests(1);
}

// Test --silent suppresses write-out stats
#[test]
fn test_silent_suppresses_write_out() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-w").arg("-s");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "Silent mode should suppress write-out stats, got: {}",
        stderr
    );

    server.assert_requests(1);
}

#[test]
fn test_output_file() {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "File content here");

    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("orb_test_output.txt");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-o").arg(&output_file);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Stdout should be empty (output went to file)
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty());

    // File should contain the response
    let file_content = std::fs::read_to_string(&output_file).unwrap();
    assert_eq!(file_content, "File content here");

    // Cleanup
    std::fs::remove_file(&output_file).ok();

    server.assert_requests(1);
}

#[test]
fn test_follow_redirects() {
    let server = TestServerBuilder::new().build();
    let final_url = server.url("/final");

    server
        .on_request("/redirect")
        .respond_with_redirect(302, &final_url);
    server
        .on_request("/final")
        .respond_with(200, "Final destination");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect")).arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Final destination");

    server.assert_requests(2);
}

#[test]
fn test_no_follow_redirects() {
    let server = TestServerBuilder::new().build();
    let final_url = server.url("/final");

    server
        .on_request("/redirect")
        .respond_with_redirect(302, &final_url);

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect"));

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty());

    server.assert_requests(1);
}

#[test]
fn test_max_redirects() {
    let server = TestServerBuilder::new().build();
    let port = server.port();

    // Create a chain of redirects longer than the max
    for i in 0..5 {
        let next_path = if i == 4 {
            "/final".to_string()
        } else {
            format!("/redirect{}", i + 1)
        };
        let location = format!("http://127.0.0.1:{}{}", port, next_path);
        let current_path = format!("/redirect{}", i);
        server
            .on_request(&current_path)
            .respond_with_redirect(302, &location);
    }

    server
        .on_request("/final")
        .respond_with(200, "Final destination");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect0"))
        .arg("--max-redirs")
        .arg("3")
        .arg("-L");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        sanitize_error(&stderr),
        "Maximum redirect limit (3) reached while going to 'http://127.0.0.1:<PORT>/redirect3'. Use --location (-L) to follow redirects.\n"
    );
}

/// Test that 301/302/303 redirects change POST to GET (standard behavior)
#[test_case(301; "301")]
#[test_case(302; "302")]
#[test_case(303; "303")]
fn test_redirect_post_becomes_get(status_code: u16) {
    let server = TestServerBuilder::new().build();
    let final_url = server.url("/final");

    server
        .on_request("/redirect")
        .respond_with_redirect(status_code, &final_url);
    server.on_request_fn("/final", |req| {
        // Verify the method changed to GET
        let method = req.method().to_string();
        ResponseBuilder::new()
            .status(200)
            .body(format!("Redirected with {}", method))
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect"))
        .arg("-X")
        .arg("POST")
        .arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Redirected with GET");

    server.assert_requests(2);
}

/// Test that 307/308 redirects preserve POST method
#[test_case(307; "307")]
#[test_case(308; "308")]
fn test_redirect_preserves_method(status_code: u16) {
    let server = TestServerBuilder::new().build();
    let final_url = server.url("/final");

    server
        .on_request("/redirect")
        .respond_with_redirect(status_code, &final_url);
    server.on_request_fn("/final", |req| {
        // Verify the method is still POST
        let method = req.method().to_string();
        ResponseBuilder::new()
            .status(200)
            .body(format!("Redirected with {}", method))
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect"))
        .arg("-X")
        .arg("POST")
        .arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Redirected with POST");

    server.assert_requests(2);
}

/// Test that 307/308 redirects preserve request body
#[test_case(307; "307")]
#[test_case(308; "308")]
fn test_redirect_preserves_body(status_code: u16) {
    let server = TestServerBuilder::new().build();
    let final_url = server.url("/final");

    server
        .on_request("/redirect")
        .respond_with_redirect(status_code, &final_url);
    server.on_request_fn("/final", |req| {
        // Verify body was preserved
        let body = req.text_lossy();
        if body == "test body content" {
            ResponseBuilder::new()
                .status(200)
                .body("Body received")
                .build()
        } else {
            ResponseBuilder::new()
                .status(400)
                .body(format!("Wrong body: {}", body))
                .build()
        }
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect"))
        .arg("-X")
        .arg("POST")
        .arg("-d")
        .arg("test body content")
        .arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Body received");

    server.assert_requests(2);
}

/// Test redirect Location header formats
#[test_case("/redirect", "/final", "/final", "absolute path"; "absolute_path")]
#[test_case("/subdir/redirect", "final", "/subdir/final", "relative path"; "relative_path")]
fn test_redirect_location_format(
    initial_path: &str,
    location: &str,
    expected_path: &str,
    _desc: &str,
) {
    let server = TestServerBuilder::new().build();
    let location_owned = location.to_string();
    let expected_path_owned = expected_path.to_string();

    server
        .on_request(initial_path)
        .respond_with_redirect(302, &location_owned);
    server
        .on_request(&expected_path_owned)
        .respond_with(200, "Redirect worked");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url(initial_path)).arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Redirect worked");

    server.assert_requests(2);
}

/// Test redirect with absolute URL in Location header
#[test]
fn test_redirect_absolute_url() {
    let server = TestServerBuilder::new().build();
    let final_url = server.url("/final");

    server
        .on_request("/redirect")
        .respond_with_redirect(302, &final_url);
    server
        .on_request("/final")
        .respond_with(200, "Absolute redirect worked");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect")).arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Absolute redirect worked");

    server.assert_requests(2);
}

/// Test multiple redirects in a chain
#[test]
fn test_redirect_chain() {
    let server = TestServerBuilder::new().build();
    let second_url = server.url("/second");
    let third_url = server.url("/third");

    server
        .on_request("/first")
        .respond_with_redirect(302, &second_url);
    server
        .on_request("/second")
        .respond_with_redirect(302, &third_url);
    server
        .on_request("/third")
        .respond_with(200, "Chain complete");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/first")).arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Chain complete");

    server.assert_requests(3);
}

/// Test that headers are preserved across redirects
#[test]
fn test_redirect_preserves_headers() {
    let server = TestServerBuilder::new().build();
    let final_url = server.url("/final");

    server
        .on_request("/redirect")
        .respond_with_redirect(302, &final_url);
    server.on_request_fn("/final", |req| {
        // Check if custom header was preserved
        let has_header = req
            .headers()
            .get("x-custom-header")
            .map(|v| v == "custom-value")
            .unwrap_or(false);
        if has_header {
            ResponseBuilder::new()
                .status(200)
                .body("Headers preserved")
                .build()
        } else {
            ResponseBuilder::new()
                .status(400)
                .body("Header not preserved")
                .build()
        }
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect"))
        .arg("-H")
        .arg("X-Custom-Header: custom-value")
        .arg("-L");

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "Headers preserved");

    server.assert_requests(2);
}

#[test]
fn test_redirect_without_location_header() {
    let server = TestServerBuilder::new().build();

    server.on_request_fn("/redirect", |_req| {
        ResponseBuilder::new()
            .status(302)
            .body("Redirecting...")
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/redirect")).arg("-L");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    let error_count = stderr.matches("missing").count() + stderr.matches("Missing").count();
    assert_eq!(
        error_count, 1,
        "BUG: Error printed {} times instead of 1:\n{}",
        error_count, stderr
    );
}

#[test]
fn test_connect_timeout() {
    // Use a non-routable address to test timeout behavior
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://10.255.255.1")
        .arg("--connect-timeout")
        .arg("1");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let sanitized = sanitize_error(&stderr);
    // Can be either a connect error or a timeout depending on network conditions
    assert!(
        sanitized
            == "Failed to connect to 'http://10.255.255.1' (10.255.255.1:<PORT>). Please check the URL and your network connection.\n"
            || sanitized
                == "Request to 'http://10.255.255.1' timed out. Consider setting a timeout with --max-time.\n",
        "Unexpected error: {}",
        sanitized
    );
}

// Note: test_max_time requires delay support which orb-mockhttp doesn't have yet.
// This test uses a slow external resource for now.
#[test]
fn test_max_time() {
    // Use a TCP endpoint that accepts connections but never responds
    // 10.255.255.1 is a non-routable address that will cause the connection to hang
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://10.255.255.1/test")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("1");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should timeout with either connect or overall timeout
    assert!(
        stderr.contains("timed out") || stderr.contains("Failed to connect"),
        "Expected timeout or connect failure, got: {}",
        stderr
    );
}

#[test]
fn test_user_agent() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("-A")
        .arg("CustomAgent/1.0");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("user-agent: customagent/1.0"),
        "Expected User-Agent: CustomAgent/1.0 in request: {}",
        request
    );
    server.assert_requests(1);
}

#[test_case("user:password", "dXNlcjpwYXNzd29yZA=="; "with password")]
#[test_case("user", "dXNlcjo="; "without password")]
fn test_basic_auth(user_arg: &str, expected_header: &str) {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-u").arg(user_arg);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    let expected = format!("authorization: Basic {}", expected_header);
    assert!(
        request.to_lowercase().contains(&expected.to_lowercase()),
        "Expected '{}' in request: {}",
        expected,
        request
    );
    server.assert_requests(1);
}

#[test]
fn test_bearer_auth() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("--bearer")
        .arg("my-secret-token");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer my-secret-token"),
        "Expected Authorization: Bearer my-secret-token in request: {}",
        request
    );
    server.assert_requests(1);
}

#[test_case("deflate"; "deflate")]
#[test_case("gzip"; "gzip")]
#[test_case("br"; "brotli")]
#[test_case("zstd"; "zstd")]
#[tokio::test]
async fn test_compressed(encoding: &str) {
    let original = "Hello, World!";
    let compressed = compress_data(original.as_bytes(), encoding).await;
    let encoding_owned = encoding.to_string();

    let server = TestServerBuilder::new().build();
    server.on_request_fn("/test", move |_req| {
        orb_mockhttp::ResponseBuilder::new()
            .status(200)
            .header("content-encoding", encoding_owned.as_str())
            .body(compressed.clone())
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("--compressed");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // With --compressed, the response should be decompressed
    let body = String::from_utf8_lossy(&output.stdout);
    assert_eq!(body, original);
    server.assert_requests(1);
}

#[test_case("gzip", "gzip"; "gzip")]
#[test_case("deflate", "deflate"; "deflate")]
#[test_case("brotli", "br"; "brotli")]
#[test_case("zstd", "zstd"; "zstd")]
fn test_compress_algo(algo: &str, expected_encoding: &str) {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("--compress-algo")
        .arg(algo);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    // When --compress-algo is used, Accept-Encoding should include only the specified algorithm
    assert!(
        request.contains("accept-encoding:"),
        "Expected accept-encoding header in request: {}",
        request
    );
    assert!(
        request.contains(expected_encoding),
        "Expected {} in accept-encoding: {}",
        expected_encoding,
        request
    );
    server.assert_requests(1);
}

#[test_case("gzip", "gzip"; "gzip")]
#[test_case("deflate", "deflate"; "deflate")]
#[test_case("brotli", "br"; "brotli")]
#[test_case("zstd", "zstd"; "zstd")]
#[tokio::test]
async fn test_compress_algo_decompresses(algo: &str, encoding: &str) {
    let original = "Hello, World!";
    let compressed = compress_data(original.as_bytes(), encoding).await;
    let encoding_owned = encoding.to_string();

    let server = TestServerBuilder::new().build();
    server.on_request_fn("/test", move |_req| {
        ResponseBuilder::new()
            .status(200)
            .header("content-encoding", encoding_owned.as_str())
            .body(compressed.clone())
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("--compress-algo")
        .arg(algo);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // With --compress-algo, the response should be decompressed
    let body = String::from_utf8_lossy(&output.stdout);
    assert_eq!(body, original);
    server.assert_requests(1);
}

#[tokio::test]
async fn test_manual_accept_encoding_returns_raw_compressed() {
    let original = "Hello, World!";
    let compressed = compress_data(original.as_bytes(), "gzip").await;

    let server = TestServerBuilder::new().build();
    let compressed_clone = compressed.clone();
    server.on_request_fn("/test", move |_req| {
        orb_mockhttp::ResponseBuilder::new()
            .status(200)
            .header("content-encoding", "gzip")
            .body(compressed_clone.clone())
            .build()
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("-H")
        .arg("Accept-Encoding: gzip");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Without --compressed, the response should be raw compressed bytes
    // It should NOT equal the original (decompressed) content
    let body = output.stdout;
    assert_eq!(body, compressed);
    assert_ne!(body, original.as_bytes());
    server.assert_requests(1);
}

#[test]
fn test_compressed_with_identity_encoding() {
    // Server returns uncompressed content (no Content-Encoding header)
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("--compressed");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Should work fine without any decompression needed
    let body = String::from_utf8_lossy(&output.stdout);
    assert_eq!(body, "Hello, World!");
    server.assert_requests(1);
}

// Testing SSL certificate validation against badssl.com
#[test_case(
    "",
    "https://expired.badssl.com/",
    false,
    "SSL certificate for 'https://expired.badssl.com/' has expired. Use --insecure (-k) to ignore certificate errors.\n";
    "should error on expired cert"
)]
#[test_case(
    "",
    "https://wrong.host.badssl.com/",
    false,
    "SSL certificate is not valid for 'https://wrong.host.badssl.com/'. Use --insecure (-k) to ignore certificate errors.\n";
    "should error on wrong host cert"
)]
#[test_case(
    "",
    "https://self-signed.badssl.com/",
    false,
    "SSL certificate for 'https://self-signed.badssl.com/' has an unknown issuer (likely self-signed). Use --insecure (-k) to ignore certificate errors.\n";
    "should error on self-signed cert"
)]
#[test_case(
    "",
    "https://untrusted-root.badssl.com/",
    false,
    "SSL certificate for 'https://untrusted-root.badssl.com/' has an unknown issuer (likely self-signed). Use --insecure (-k) to ignore certificate errors.\n";
    "should error on untrusted root cert"
)]
#[test_case(
    "-k",
    "https://self-signed.badssl.com/",
    true,
    "";
    "insecure flag accepts self-signed cert"
)]
#[test_case(
    "-k",
    "https://expired.badssl.com/",
    true,
    "";
    "insecure flag accepts expired cert"
)]
#[test_case(
    "--insecure",
    "https://self-signed.badssl.com/",
    true,
    "";
    "insecure long flag accepts self-signed cert"
)]
fn test_insecure(flag: &str, host: &str, should_succeed: bool, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(host);
    if !flag.is_empty() {
        cmd.arg(flag);
    }

    let output = cmd.output().unwrap();
    assert_eq!(output.status.success(), should_succeed);
    if !should_succeed {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            sanitize_error(&stderr).contains(expected_error),
            "Expected error to contain '{}', got '{}'",
            expected_error,
            sanitize_error(&stderr)
        );
    }
}

#[test]
fn test_http1_1() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("--http1.1").arg("-i");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HTTP/1.1"),
        "Expected HTTP/1.1 in response, got: {}",
        stdout
    );

    server.assert_requests(1);
}

#[test]
fn test_http2() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http2])
        .build();
    server.on_request("/").respond_with(200, "Hello, World!");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--http2")
        .arg("-I")
        .arg("--insecure")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HTTP/2"),
        "Expected HTTP/2 in response, got: {}",
        stdout
    );

    server.assert_requests(1);
}

#[test]
fn test_http3() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http3])
        .build();
    server.on_request("/").respond_with(200, "Hello, World!");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/"))
        .arg("--http3")
        .arg("-I")
        .arg("--insecure")
        .arg("--max-time")
        .arg("10")
        .arg("-v")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "Command failed: {}", stderr);

    assert!(
        stdout.contains("HTTP/3"),
        "Expected HTTP/3 in response, got: {}",
        stdout
    );
    server.assert_requests(1);
}

#[test]
fn test_http3_with_body() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http3])
        .build();
    server.on_request_fn("/echo", |req| {
        let body = req.text().unwrap();
        let response_body = format!(
            "Method: {}\nHeaders:\n{}\n\nBody:\n{}",
            req.method(),
            req.headers()
                .iter()
                .map(|(k, v)| format!("{}: {:?}", k, v))
                .collect::<Vec<String>>()
                .join("\n"),
            body,
        );
        ResponseBuilder::new()
            .status(200)
            .body(response_body)
            .build()
    });

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/echo"))
        .arg("--http3")
        .arg("--insecure")
        .arg("--max-time")
        .arg("10")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Method: GET"),
        "Expected body content, got: {}",
        stdout
    );
    server.assert_requests(1);
}

#[test]
fn test_http3_follows_redirects() {
    let server = TestServerBuilder::new()
        .with_protocols(&[HttpProtocol::Http3])
        .build();

    server
        .on_request("/redirect")
        .respond_with_redirect(302, "/final");
    server
        .on_request("/final")
        .respond_with(200, "Final destination");

    let output = Command::new(cargo_bin!("orb"))
        .arg(server.url("/redirect"))
        .arg("--http3")
        .arg("--insecure")
        .arg("--max-time")
        .arg("10")
        .arg("-L")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "HTTP/3 redirect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Final destination"),
        "Expected final response after redirect, got: {}",
        stdout
    );

    server.assert_requests(2);
}

// Test HTTP/3 against a server that doesn't support it
#[test]
fn test_http3_not_supported() {
    // Use a regular HTTPS server without HTTP/3 support
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://example.com/")
        .arg("--http3")
        .arg("-I")
        .arg("--max-time")
        .arg("3");

    let output = cmd.output().unwrap();
    // Should fail since example.com doesn't support HTTP/3
    assert!(
        !output.status.success(),
        "Expected HTTP/3 to fail against non-H3 server"
    );
}

// Test --cacert with a CA certificate
// Uses badssl.com's untrusted-root endpoint which fails without --cacert
// but succeeds when we provide their untrusted root CA
#[test]
fn test_cacert() {
    // First verify the request fails WITHOUT --cacert
    let mut cmd_fail = Command::new(cargo_bin!("orb"));
    cmd_fail.arg("https://untrusted-root.badssl.com/");

    let output_fail = cmd_fail.output().unwrap();
    assert!(
        !output_fail.status.success(),
        "Request should fail without --cacert: {}",
        String::from_utf8_lossy(&output_fail.stdout)
    );

    // Now verify it succeeds WITH --cacert
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://untrusted-root.badssl.com/")
        .arg("--cacert")
        .arg("tests/testdata/badssl-untrusted-root.crt");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test_case(
    "tests/testdata/does-not-exist.pem",
    "Failed to read CA certificate 'tests/testdata/does-not-exist.pem': No such file or directory (os error 2)\n";
    "cacert file not found"
)]
#[test_case(
    "tests/testdata/test_data.txt",
    "Failed to parse CA certificate 'tests/testdata/test_data.txt'. Ensure the file is a valid PEM-encoded certificate.\n";
    "cacert invalid pem"
)]
fn test_cacert_invalid(cacert_path: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://example.com/")
        .arg("--cacert")
        .arg(cacert_path);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(normalize_os_error(&stderr), expected_error);
}

// Test --cert with a valid client certificate (cert + key combined)
// Uses badssl.com client cert against their client auth endpoint
#[test]
fn test_cert() {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://client.badssl.com/")
        .arg("--cert")
        .arg("tests/testdata/badssl-client-cert.pem");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// Test --cert with --key (separate cert and key files)
// Uses badssl.com client cert against their client auth endpoint
#[test]
fn test_cert_with_key() {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://client.badssl.com/")
        .arg("--cert")
        .arg("tests/testdata/badssl-client-cert-only.pem")
        .arg("--key")
        .arg("tests/testdata/badssl-client-key.pem");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test_case(
    "tests/testdata/does-not-exist.pem",
    "Failed to read client certificate 'tests/testdata/does-not-exist.pem': No such file or directory (os error 2)\n";
    "cert file not found"
)]
#[test_case(
    "tests/testdata/test_data.txt",
    "Failed to parse client certificate 'tests/testdata/test_data.txt'. The file must contain both certificate and private key in PEM format, or use --key to specify the key file separately.\n";
    "cert invalid pem"
)]
fn test_cert_invalid(cert_path: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://example.com/").arg("--cert").arg(cert_path);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(normalize_os_error(&stderr), expected_error);
}

#[test_case(
    "tests/testdata/does-not-exist.pem",
    "Failed to read client key 'tests/testdata/does-not-exist.pem': No such file or directory (os error 2)\n";
    "key file not found"
)]
fn test_key_invalid(key_path: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("https://example.com/")
        .arg("--cert")
        .arg("tests/testdata/badssl-client-cert-only.pem")
        .arg("--key")
        .arg(key_path);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(normalize_os_error(&stderr), expected_error);
}

#[test]
fn test_referer() {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test"))
        .arg("-e")
        .arg("https://example.com/page");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("referer: https://example.com/page"),
        "Expected Referer header in request: {}",
        request
    );
    server.assert_requests(1);
}

#[test_case("session=abc123", "session=abc123"; "single cookie")]
#[test_case("session=abc123; user=john", "session=abc123; user=john"; "multiple cookies")]
fn test_cookie(cookie_arg: &str, expected_cookie: &str) {
    let server = TestServerBuilder::new().build();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-b").arg(cookie_arg);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let request = server.get_raw_request().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains(&format!("cookie: {}", expected_cookie.to_lowercase())),
        "Expected Cookie header with '{}' in request: {}",
        expected_cookie,
        request
    );
    server.assert_requests(1);
}

// Test --cookie loading from Netscape cookie file
// The cookies.txt file has cookies for .example.com domain
// We use --connect-to to redirect example.com to our mock server
#[test]
fn test_cookie_from_file() {
    let server = TestServerBuilder::new().build();
    let port = server.port();
    server.on_request("/test").respond_with(200, "OK");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(format!("http://example.com:{}/test", port))
        .arg("-b")
        .arg("@tests/testdata/cookies.txt")
        .arg("--connect-to")
        .arg(format!("example.com:{}:127.0.0.1:{}", port, port));

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let request = server.get_raw_request().unwrap();
    assert!(
        request.to_lowercase().contains("cookie:"),
        "Expected Cookie header in request: {}",
        request
    );
    server.assert_requests(1);
}

#[test_case(
    "abc",
    "Invalid cookie format 'abc'. Expected 'NAME=VALUE' or '@filename' for cookie file.\n";
    "invalid cookie format"
)]
#[test_case(
    "@tests/testdata/does-not-exist.txt",
    "Failed to read cookie file 'tests/testdata/does-not-exist.txt': No such file or directory (os error 2)\n";
    "file not found"
)]
fn test_cookie_invalid(cookie_arg: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://example.com/").arg("-b").arg(cookie_arg);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(normalize_os_error(&stderr), expected_error);
}

#[test]
fn test_cookie_jar() {
    let server = TestServerBuilder::new().build();
    server.on_request_fn("/test", |_req| {
        ResponseBuilder::new()
            .status(200)
            .header("Set-Cookie", "newcookie=value123; Path=/")
            .body("OK")
            .build()
    });

    let temp_dir = std::env::temp_dir();
    let cookie_jar = temp_dir.join("orb_test_cookies.txt");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-c").arg(&cookie_jar);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Check that cookie jar file was created
    assert!(cookie_jar.exists(), "Cookie jar file should be created");

    // Read and verify the cookie jar contains header info
    let content = std::fs::read_to_string(&cookie_jar).unwrap();
    assert!(
        content.contains("# Netscape HTTP Cookie File"),
        "Cookie jar should have Netscape header, got: {}",
        content
    );

    // Cleanup
    std::fs::remove_file(&cookie_jar).ok();

    server.assert_requests(1);
}

#[test]
fn test_cookie_jar_sends_cookies() {
    let server = TestServerBuilder::new().build();

    // First request: server sets a cookie
    server.on_request_fn("/set", |_req| {
        ResponseBuilder::new()
            .status(200)
            .header("Set-Cookie", "session=abc123; Path=/")
            .body("Cookie set")
            .build()
    });

    // Second request: verify client sends the cookie back
    server.on_request_fn("/get", |req| {
        let has_cookie = req
            .headers()
            .get("cookie")
            .map(|v| v.to_str().unwrap_or("").contains("session=abc123"))
            .unwrap_or(false);
        if has_cookie {
            ResponseBuilder::new()
                .status(200)
                .body("Cookie received")
                .build()
        } else {
            ResponseBuilder::new()
                .status(400)
                .body("Cookie not found")
                .build()
        }
    });

    let temp_dir = std::env::temp_dir();
    let cookie_jar = temp_dir.join("orb_test_cookies_roundtrip.txt");

    // Ensure clean state
    std::fs::remove_file(&cookie_jar).ok();

    // First request - sets the cookie
    let mut cmd1 = Command::new(cargo_bin!("orb"));
    cmd1.arg(server.url("/set")).arg("-c").arg(&cookie_jar);

    let output1 = cmd1.output().unwrap();
    assert!(
        output1.status.success(),
        "First request failed: {}",
        String::from_utf8_lossy(&output1.stderr)
    );

    // Verify cookie jar was created
    assert!(cookie_jar.exists(), "Cookie jar file should be created");

    // Second request - should send the cookie from jar
    let mut cmd2 = Command::new(cargo_bin!("orb"));
    cmd2.arg(server.url("/get")).arg("-c").arg(&cookie_jar);

    let output2 = cmd2.output().unwrap();
    assert!(
        output2.status.success(),
        "Second request failed: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

    let stdout = String::from_utf8_lossy(&output2.stdout);
    assert_eq!(stdout, "Cookie received");

    // Cleanup
    std::fs::remove_file(&cookie_jar).ok();

    server.assert_requests(2);
}

#[test_case(
    "://bad",
    "Invalid proxy URL '://bad'. Expected format: http://host:port or socks5://host:port\n";
    "invalid url format"
)]
fn test_proxy_invalid(proxy_url: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://example.com/").arg("--proxy").arg(proxy_url);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, expected_error);
}

#[test_case(
    "example.com:80:127.0.0.1:{PORT}";
    "basic redirect"
)]
#[test_case(
    "example.com::127.0.0.1:{PORT}";
    "any port match"
)]
#[test_case(
    "::127.0.0.1:{PORT}";
    "any host and port match"
)]
fn test_connect_to(connect_to_pattern: &str) {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");
    let port = server.port();

    let connect_to = connect_to_pattern.replace("{PORT}", &port.to_string());

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://example.com/test")
        .arg("--connect-to")
        .arg(&connect_to)
        .arg("--max-time")
        .arg("5")
        .arg("-v");

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "Command failed: {:?}", output);

    let request = server.get_raw_request().unwrap();
    allow_duplicates! {
        assert_snapshot!(sanitize_output(&request), @r"
        GET /test HTTP/1.1
        accept: */*
        user-agent: orb/0.1.0
        host: example.com:<PORT>
        ");
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "* Connecting to 127.0.0.1:{} (overriden from example.com:80)",
            port
        )),
        "Expected connect-to override log in stderr, got: {}",
        stderr,
    );
}

#[test_case(
    "example.com",
    "Invalid --connect-to format 'example.com'. Expected HOST1:PORT1:HOST2:PORT2 (IPv6 addresses must be in brackets, e.g., [::1])";
    "missing parts"
)]
#[test_case(
    "example.com:80::8080",
    "Invalid --connect-to format 'example.com:80::8080'. HOST2 cannot be empty";
    "empty host2"
)]
#[test_case(
    "example.com:abc:127.0.0.1:8080",
    "Invalid --connect-to format 'example.com:abc:127.0.0.1:<PORT>'. PORT1 or PORT2 is not a valid port number";
    "invalid port1"
)]
#[test_case(
    "example.com:80:127.0.0.1:abc",
    "Invalid --connect-to format 'example.com:80:127.0.0.1:abc'. PORT1 or PORT2 is not a valid port number";
    "invalid port2"
)]
#[test_case(
    "example.com:80:127.0.0.1",
    "Invalid --connect-to format 'example.com:80:127.0.0.1'. PORT2 is required";
    "missing port2"
)]
#[test_case(
    "::1:80:127.0.0.1:8080",
    "Invalid --connect-to format '::1:80:127.0.0.1:<PORT>'. IPv6 addresses must be enclosed in brackets, e.g., [::1]:80:[::1]:8080";
    "ipv6 no bracket"
)]
#[test_case(
    "[::1:80:127.0.0.1:8080",
    "Invalid --connect-to format '[::1:80:127.0.0.1:<PORT>'. Unclosed bracket in IPv6 address";
    "unclosed ipv6 bracket"
)]
fn test_connect_to_invalid(connect_to: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://example.com/test")
        .arg("--connect-to")
        .arg(connect_to);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(sanitize_error(&stderr), format!("{}\n", expected_error));
}

#[test]
fn test_write_out() {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/test")
        .respond_with(200, "Hello, World!");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-w");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("http_code: 200"),
        "Expected http_code in output, got: {}",
        stderr
    );
    assert!(
        stderr.contains("size_download: 13 bytes"),
        "Expected size_download in output, got: {}",
        stderr
    );
    assert!(
        stderr.contains("time_starttransfer:"),
        "Expected time_starttransfer (TTFB) in output, got: {}",
        stderr
    );
    assert!(
        stderr.contains("time_total:"),
        "Expected time_total (TTLB) in output, got: {}",
        stderr
    );

    server.assert_requests(1);
}

// Test --write-out with different status codes
#[test]
fn test_write_out_status_code() {
    let server = TestServerBuilder::new().build();
    server
        .on_request("/not-found")
        .respond_with(404, "Not Found");

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/not-found")).arg("-w");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("http_code: 404"),
        "Expected http_code: 404 in output, got: {}",
        stderr
    );

    server.assert_requests(1);
}

/// Test that progress bar is shown when --progress flag is used
/// Uses delayed streaming response to give the progress bar time to render
#[test]
fn test_progress() {
    let server = TestServerBuilder::new().build();

    // Create a 10KB body
    let body = "X".repeat(10 * 1024);

    // Set up a delayed response: 1KB chunks with 50ms delay between chunks
    // This means ~500ms total for the 10 chunks
    server
        .on_request("/download")
        .delay(Duration::from_millis(50))
        .respond_with(200, body.clone());

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/download"))
        .arg("--progress")
        .arg("-o")
        .arg(null_device())
        // Force progress bar output even when stderr is not a TTY (for testing)
        .env("ORB_FORCE_PROGRESS", "1");

    let output = cmd.output().unwrap();

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify progress bar was displayed
    // With ORB_FORCE_PROGRESS, the progress bar renders even when stderr is not a TTY
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr, "[progress-bar-started]\n",
        "Expected progress bar output in stderr, got: {:?}",
        stderr
    );

    server.assert_requests(1);
}

/// Test that progress bar starts automatically for large downloads
#[test]
fn test_progress_auto_start() {
    let server = TestServerBuilder::new().build();

    let body = "X".repeat(1024 * 1024); // 1 MiB
    let large_body = "Y".repeat(110 * 1024 * 1024); // 110 MiB

    server
        .on_request("/slow-response")
        // Make it send in 1.2 seconds
        .respond_with_delay(
            200,
            body.clone(),
            body.len() / 2,
            Duration::from_millis(1_200),
        );

    server
        .on_request("/large-file")
        .respond_with_fn(move |_req| {
            ResponseBuilder::new()
                .status(200)
                .body(large_body.clone())
                .build()
        });

    // -- Test 1 --
    // Respond slowly to trigger progress bar based on time
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/slow-response"))
        .arg("-o")
        .arg(null_device())
        // Force progress bar output even when stderr is not a TTY (for testing)
        .env("ORB_FORCE_PROGRESS", "1");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify progress bar was displayed
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr, "[progress-bar-started]\n",
        "Expected progress bar output in stderr, got: {:?}",
        stderr
    );

    // -- Test 2 --
    // Respond with large Content-Length to trigger progress bar based on size
    let mut cmd2 = Command::new(cargo_bin!("orb"));
    cmd2.arg(server.url("/large-file"))
        .arg("-o")
        .arg(null_device())
        // Force progress bar output even when stderr is not a TTY (for testing)
        .env("ORB_FORCE_PROGRESS", "1");

    let output2 = cmd2.output().unwrap();
    assert!(
        output2.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

    // Verify progress bar was displayed
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert_eq!(
        stderr2, "[progress-bar-started]\n",
        "Expected progress bar output in stderr, got: {:?}",
        stderr2
    );

    server.assert_requests(2);
}

// fn test_ws_message

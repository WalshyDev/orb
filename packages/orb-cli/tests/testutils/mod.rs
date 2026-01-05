#![allow(dead_code)]

use orb_mockhttp::{ResponseBuilder, TestServer, TestServerBuilder};
use regex::Regex;

pub fn sanitize_output(output: &str) -> String {
    let re_http_newline = Regex::new(r"\r\n").unwrap();
    let re_host = Regex::new(r"host: ([\w\d\.]+)(:\d+)?").unwrap();
    let re_date = Regex::new(r"date: .+").unwrap();
    let re_boundary_header = Regex::new(r"multipart/form-data; boundary=([^\r\n]+)").unwrap();

    // TLS-related patterns
    let re_tls_valid_from = Regex::new(r"\*     Valid from: .+").unwrap();
    let re_tls_valid_until = Regex::new(r"\*     Valid until: .+").unwrap();

    // Extract the boundary value (without any trailing whitespace/CR)
    let boundary = re_boundary_header
        .captures(output)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim())
        .unwrap_or("");

    let output = re_http_newline.replace_all(output, "\n");
    let output = re_host.replace_all(&output, "host: $1:<PORT>");
    let output = re_date.replace_all(&output, "date: <DATE>");
    let output =
        re_boundary_header.replace_all(&output, "multipart/form-data; boundary=<BOUNDARY>");

    // Sanitize TLS certificate validity dates
    let output = re_tls_valid_from.replace_all(&output, "*     Valid from: <DATE>");
    let output = re_tls_valid_until.replace_all(&output, "*     Valid until: <DATE>");

    if !boundary.is_empty() {
        // Replace all occurrences of the boundary in the body (--boundary and --boundary--)
        let re_boundary_body = Regex::new(&format!(r"--{}", regex::escape(boundary))).unwrap();
        re_boundary_body
            .replace_all(&output, "--<BOUNDARY>")
            .to_string()
    } else {
        output.to_string()
    }
}

pub fn sanitize_error(output: &str) -> String {
    let re_port = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+").unwrap();
    let output = re_port.replace_all(output, "$1:<PORT>");

    output.to_string()
}

/// Returns the platform-appropriate null device path.
/// On Unix: `/dev/null`
/// On Windows: `NUL`
pub fn null_device() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

/// Normalizes OS error messages for cross-platform testing.
/// Windows uses different error message text than Unix for the same error codes.
pub fn normalize_os_error(error: &str) -> String {
    error
        // "file not found" errors (os error 2)
        .replace(
            "The system cannot find the file specified.",
            "No such file or directory",
        )
        // "path not found" errors (os error 3)
        .replace(
            "The system cannot find the path specified.",
            "No such file or directory",
        )
}

/// Parse a shell-style argument string, respecting single and double quotes.
/// e.g. "-v -H 'Custom-Header: CustomValue'" -> ["-v", "-H", "Custom-Header: CustomValue"]
pub fn parse_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let chars = input.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    for c in chars {
        match c {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

pub fn test_server() -> TestServer {
    let server = TestServerBuilder::new().build();
    let address = server.address();

    server
        .on_request("/test")
        .expect_header("User-Agent", concat!("orb/", env!("CARGO_PKG_VERSION")))
        .expect_header("Accept", "*/*")
        .expect_header("Host", address)
        .respond_with(200, "OK");
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
    server.on_request_fn("/raw", |req| {
        let response_body = format!(
            "{} {} {:?}\r\n{}\r\n\r\n{}",
            req.method().as_str(),
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
            req.version(),
            req.headers()
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<String>>()
                .join("\r\n"),
            String::from_utf8_lossy(req.body()),
        );
        ResponseBuilder::new()
            .status(200)
            .body(response_body)
            .build()
    });

    server
}

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::cli::Args;

/// Build all request headers, merging defaults with user-specified overrides.
/// Returns the final HeaderMap that will be sent.
pub fn build_headers(args: &Args, url: &Url) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // Start with defaults
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static(concat!("orb/", env!("CARGO_PKG_VERSION"))),
    );
    let host_header = build_host_header(url);
    headers.insert(header::HOST, HeaderValue::from_str(&host_header).unwrap());

    // Accept-Encoding (compression)
    if args.compressed {
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("zstd, br, gzip, deflate"),
        );
    } else if let Some(ref algo) = args.compress_algo {
        let encoding = algo.as_str();
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_str(encoding).unwrap(),
        );
    }

    // User-Agent
    if let Some(ref user_agent) = args.user_agent
        && let Ok(value) = HeaderValue::from_str(user_agent)
    {
        headers.insert(header::USER_AGENT, value);
    }

    // Referer
    if let Some(ref referer) = args.referer
        && let Ok(value) = HeaderValue::from_str(referer)
    {
        headers.insert(header::REFERER, value);
    }

    // Auth headers (--user, --bearer)
    if let Some(ref user) = args.user {
        let auth_value = if let Some((username, password)) = user.split_once(':') {
            format!("{}:{}", username, password)
        } else {
            format!("{}:", user)
        };
        let encoded = BASE64.encode(auth_value.as_bytes());
        if let Ok(value) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
            headers.insert(header::AUTHORIZATION, value);
        }
    } else if let Some(ref token) = args.bearer
        && let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token))
    {
        headers.insert(header::AUTHORIZATION, value);
    }

    // Cookie - combine cookies from -b (cookie) and -c (cookie-jar)
    let mut all_cookies = Vec::new();

    // Load cookies from -b flag
    if let Some(ref cookie_arg) = args.cookie {
        let cookie_value = get_cookie_header_value(cookie_arg, url);
        if !cookie_value.is_empty() {
            all_cookies.push(cookie_value);
        }
    }

    // Load cookies from cookie jar file (-c) if it exists
    if let Some(ref cookie_jar_path) = args.cookie_jar
        && cookie_jar_path.exists()
    {
        let jar_cookies = get_cookie_header_value(&format!("@{}", cookie_jar_path.display()), url);
        if !jar_cookies.is_empty() {
            all_cookies.push(jar_cookies);
        }
    }

    // Set cookie header if we have any cookies
    if !all_cookies.is_empty() {
        let cookie_header_value = all_cookies.join("; ");
        if let Ok(value) = HeaderValue::from_str(&cookie_header_value) {
            headers.insert(header::COOKIE, value);
        }
    }

    // Finally, custom headers can override any of the above
    for header_str in &args.headers {
        if let Some((key, value)) = header_str.split_once(":")
            && let Ok(header_name) = key.trim().parse::<HeaderName>()
            && let Ok(header_value) = HeaderValue::from_str(value.trim())
        {
            headers.insert(header_name, header_value);
        }
    }

    headers
}

fn build_host_header(url: &Url) -> String {
    let mut host = url.host_str().unwrap_or("").to_string();
    if url.scheme() == "http" && url.port().is_some_and(|p| p != 80)
        || url.scheme() == "https" && url.port().is_some_and(|p| p != 443)
    {
        host = format!("{}:{}", host, url.port().unwrap());
    }
    host
}

/// Get the cookie header value from the --cookie argument
/// Handles both inline cookies ("name=value") and file references ("@filename")
fn get_cookie_header_value(cookie_arg: &str, url: &Url) -> String {
    if let Some(file_path) = cookie_arg.strip_prefix('@') {
        // Load from file and extract cookies for this URL
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let mut cookies = Vec::new();
            for line in content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                if let Some(cookie) = parse_netscape_line_for_url(line, url) {
                    cookies.push(cookie);
                }
            }
            if cookies.is_empty() {
                // Not Netscape format, treat as raw cookie
                content.trim().to_string()
            } else {
                cookies.join("; ")
            }
        } else {
            String::new()
        }
    } else {
        // Inline cookie string
        cookie_arg.to_string()
    }
}

/// Parse a Netscape cookie line and return the "name=value" if it matches the URL
fn parse_netscape_line_for_url(line: &str, url: &Url) -> Option<String> {
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() < 7 {
        return None;
    }

    let domain = parts[0];
    let path = parts[2];
    let secure = parts[3] == "TRUE";
    let name = parts[5];
    let value = parts[6];

    // Check if cookie matches the URL
    let url_host = url.host_str().unwrap_or("");
    let url_path = url.path();
    let is_https = url.scheme() == "https";

    // Domain matching: cookie domain should match or be a suffix of URL host
    let domain_matches = if domain.starts_with('.') {
        url_host.ends_with(domain) || url_host == &domain[1..]
    } else {
        url_host == domain
    };

    // Path matching: URL path should start with cookie path
    let path_matches = url_path.starts_with(path);

    // Secure matching: if cookie requires secure, URL must be https
    let secure_matches = !secure || is_https;

    if domain_matches && path_matches && secure_matches {
        Some(format!("{}={}", name, value))
    } else {
        None
    }
}

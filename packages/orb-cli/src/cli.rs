use clap::{Parser, ValueEnum};
use std::fmt;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::str::FromStr;

use orb_client::dns::OverrideRule;

/// Wrapper around http::Method for clap parsing
#[derive(Debug, Clone, Default)]
pub struct HttpMethod(pub http::Method);

impl FromStr for HttpMethod {
    type Err = http::method::InvalidMethod;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        http::Method::from_str(s).map(HttpMethod)
    }
}

impl std::ops::Deref for HttpMethod {
    type Target = http::Method;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version, display_name = "orb", about = "🟠 Your powerful HTTP client", long_about = None)]
pub struct Args {
    /// URL to request
    #[arg(value_name = "URL")]
    pub url: String,

    /// HTTP method to use
    #[arg(
        short = 'X',
        long = "request",
        value_name = "METHOD",
        default_value = "GET"
    )]
    pub method: HttpMethod,

    /// Custom headers (can be used multiple times)
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// Request body data
    #[arg(short = 'd', long = "data", value_name = "DATA", conflicts_with_all = &["json", "form"])]
    pub data: Option<String>,

    /// JSON data (automatically sets Content-Type: application/json)
    #[arg(long = "json", value_name = "JSON", conflicts_with_all = &["data", "form"])]
    pub json: Option<String>,

    /// File to upload
    #[arg(short = 'F', long = "form", value_name = "FORM", conflicts_with_all = &["data", "json"])]
    pub form: Vec<String>,

    /// Output file (instead of stdout)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Include response headers in output
    #[arg(short = 'i', long = "include")]
    pub include_headers: bool,

    /// Show only response headers
    #[arg(short = 'I', long = "head")]
    pub head_only: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Silent mode
    #[arg(short = 's', long = "silent")]
    pub silent: bool,

    /// Follow redirects
    #[arg(short = 'L', long = "location")]
    pub follow_redirects: bool,

    /// Maximum number of redirects
    #[arg(long = "max-redirs", value_name = "NUM", default_value = "10")]
    pub max_redirects: usize,

    /// Connection timeout in seconds
    #[arg(long = "connect-timeout", value_name = "SECONDS", default_value = "10")]
    pub connect_timeout: u64,

    /// Maximum time allowed for transfer in seconds
    #[arg(short = 'm', long = "max-time", value_name = "SECONDS")]
    pub max_time: Option<u64>,

    /// User agent string
    #[arg(short = 'A', long = "user-agent", value_name = "STRING")]
    pub user_agent: Option<String>,

    /// HTTP basic authentication (user:password)
    #[arg(short = 'u', long = "user", value_name = "USER:PASSWORD")]
    pub user: Option<String>,

    /// Bearer token authentication
    #[arg(long = "bearer", value_name = "TOKEN")]
    pub bearer: Option<String>,

    /// Accept compressed response
    #[arg(long = "compressed")]
    pub compressed: bool,

    /// Specify compression algorithm
    #[arg(long = "compress-algo", value_name = "ALGORITHM")]
    pub compress_algo: Option<CompressionAlgorithm>,

    /// Insecure - allow insecure SSL connections
    #[arg(short = 'k', long = "insecure")]
    pub insecure: bool,

    /// Use HTTP/1.1
    #[arg(long = "http1.1", conflicts_with_all = &["http2", "http3"])]
    pub http1_1: bool,

    /// Use HTTP/2
    #[arg(long = "http2", conflicts_with_all = &["http1_1", "http3"])]
    pub http2: bool,

    /// Use HTTP/3
    #[arg(long = "http3", conflicts_with_all = &["http1_1", "http2"])]
    pub http3: bool,

    /// CA certificate to verify peer against
    #[arg(long = "cacert", value_name = "FILE")]
    pub cacert: Option<PathBuf>,

    /// Client certificate file
    #[arg(long = "cert", value_name = "FILE")]
    pub cert: Option<PathBuf>,

    /// Client certificate key file
    #[arg(long = "key", value_name = "FILE")]
    pub key: Option<PathBuf>,

    /// Referer URL
    #[arg(short = 'e', long = "referer", value_name = "URL")]
    pub referer: Option<String>,

    /// Cookie string or file to read cookies from
    #[arg(short = 'b', long = "cookie", value_name = "DATA")]
    pub cookie: Option<String>,

    /// File to write cookies to
    #[arg(short = 'c', long = "cookie-jar", value_name = "FILE")]
    pub cookie_jar: Option<PathBuf>,

    /// Proxy URL
    #[arg(short = 'x', long = "proxy", value_name = "URL")]
    pub proxy: Option<String>,

    /// Connect to HOST2:PORT2 instead of HOST1:PORT1 (format: HOST1:PORT1:HOST2:PORT2)
    #[arg(long = "connect-to", value_name = "HOST1:PORT1:HOST2:PORT2")]
    pub connect_to: Vec<String>,

    /// Show response time
    #[arg(short = 'w', long = "write-out")]
    pub write_out: bool,

    /// Show download progress bar
    #[arg(short = '#', long = "progress")]
    pub progress: bool,

    /// Send a single WebSocket message and exit (for ws:// or wss:// URLs)
    #[arg(long = "ws-message", value_name = "MESSAGE")]
    pub ws_message: Option<String>,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CompressionAlgorithm {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl CompressionAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zstd",
        }
    }
}

/// Validate --cacert argument if provided
pub fn validate_cacert(cacert: Option<&PathBuf>) {
    if let Some(cacert_path) = cacert {
        // Check if the file exists and can be read
        let cacert_data = match fs::read(cacert_path) {
            Ok(data) => data,
            Err(e) => {
                crate::fatal!(
                    "Failed to read CA certificate '{}': {}",
                    cacert_path.display(),
                    e
                );
            }
        };

        // Try to parse as PEM certificate
        let mut reader = BufReader::new(cacert_data.as_slice());
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            crate::fatal!(
                "Failed to parse CA certificate '{}'. Ensure the file is a valid PEM-encoded certificate.",
                cacert_path.display()
            );
        }
    }
}

/// Validate --cert and --key arguments if provided
pub fn validate_cert_and_key(cert: Option<&PathBuf>, key: Option<&PathBuf>) {
    if let Some(cert_path) = cert {
        // First, check if the cert file exists and can be read
        let cert_data = match fs::read(cert_path) {
            Ok(data) => data,
            Err(e) => {
                crate::fatal!(
                    "Failed to read client certificate '{}': {}",
                    cert_path.display(),
                    e
                );
            }
        };

        // If --key is provided separately, we just need to verify the cert file has a certificate
        if let Some(key_path) = key {
            // Verify key file exists and can be read
            if let Err(e) = fs::read(key_path) {
                crate::fatal!("Failed to read client key '{}': {}", key_path.display(), e);
            }

            // Try to parse certificate from cert file
            let mut cert_reader = BufReader::new(cert_data.as_slice());
            let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
                .filter_map(|r| r.ok())
                .collect();

            if certs.is_empty() {
                crate::fatal!(
                    "Failed to parse client certificate '{}'. No valid certificate found in PEM file.",
                    cert_path.display()
                );
            }

            // Try to parse key from key file
            let key_data = fs::read(key_path).unwrap(); // Already verified it exists above
            let mut key_reader = BufReader::new(key_data.as_slice());
            let key = rustls_pemfile::private_key(&mut key_reader).ok().flatten();

            if key.is_none() {
                crate::fatal!(
                    "Failed to parse client key '{}'. No valid private key found in PEM file.",
                    key_path.display()
                );
            }
        } else {
            // No --key provided, cert file must contain both cert and key
            let mut cert_reader = BufReader::new(cert_data.as_slice());
            let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
                .filter_map(|r| r.ok())
                .collect();

            // Re-read for key parsing
            let mut key_reader = BufReader::new(cert_data.as_slice());
            let key = rustls_pemfile::private_key(&mut key_reader).ok().flatten();

            if certs.is_empty() || key.is_none() {
                crate::fatal!(
                    "Failed to parse client certificate '{}'. The file must contain both certificate and private key in PEM format, or use --key to specify the key file separately.",
                    cert_path.display()
                );
            }
        }
    }
}

/// Validate --connect-to arguments and exit with error if invalid
pub fn validate_connect_to(connect_to: &[String]) {
    for rule in connect_to {
        let parts: Vec<&str> = rule.split(':').collect();

        if parts.len() < 4 {
            if parts.len() == 3 {
                crate::fatal!("Invalid --connect-to format '{}'. PORT2 is required", rule);
            } else {
                crate::fatal!(
                    "Invalid --connect-to format '{}'. Expected HOST1:PORT1:HOST2:PORT2",
                    rule
                );
            }
        }

        let _host1 = parts[0]; // Can be empty for wildcard
        let port1_str = parts[1]; // Can be empty for wildcard
        let host2 = parts[2];
        let port2_str = parts[3];

        // Validate PORT1 (empty is valid - means any port)
        if !port1_str.is_empty() && port1_str.parse::<u16>().is_err() {
            crate::fatal!(
                "Invalid --connect-to format '{}'. PORT1 '{}' is not a valid port number",
                rule,
                port1_str
            );
        }

        // Validate HOST2 (must be specified)
        if host2.is_empty() {
            crate::fatal!(
                "Invalid --connect-to format '{}'. HOST2 cannot be empty",
                rule
            );
        }

        // Validate PORT2 (must be a valid port)
        if port2_str.parse::<u16>().is_err() {
            crate::fatal!(
                "Invalid --connect-to format '{}'. PORT2 '{}' is not a valid port number",
                rule,
                port2_str
            );
        }

        // Validate that the rule can be parsed
        if OverrideRule::parse(rule).is_none() {
            crate::fatal!("Invalid --connect-to format '{}'", rule);
        }
    }
}

/// Validate --cookie argument if provided
pub fn validate_cookie(cookie: Option<&String>) {
    if let Some(cookie_arg) = cookie {
        if let Some(file_path) = cookie_arg.strip_prefix('@') {
            // It's a file reference, check if file exists
            if let Err(e) = fs::read(file_path) {
                crate::fatal!("Failed to read cookie file '{}': {}", file_path, e);
            }
        } else if !cookie_arg.contains('=') {
            // Not a file and not in NAME=VALUE format
            crate::fatal!(
                "Invalid cookie format '{}'. Expected 'NAME=VALUE' or '@filename' for cookie file.",
                cookie_arg
            );
        }
    }
}

/// Validate --proxy argument if provided
pub fn validate_proxy(proxy: Option<&String>) {
    if let Some(proxy_url) = proxy {
        // Try to parse as URL
        if url::Url::parse(proxy_url).is_err() {
            crate::fatal!(
                "Invalid proxy URL '{}'. Expected format: http://host:port or socks5://host:port",
                proxy_url
            );
        }
    }
}

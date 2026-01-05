use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http::Version;
use http::header::{CONTENT_TYPE, HeaderValue};
use orb_client::body::RequestBody;
use orb_client::dns::OverrideRule;
use orb_client::{CertificateDer, PrivateKeyDer, RequestBuilder};
use url::Url;

use crate::cli::Args;
use crate::headers::build_headers;
use crate::verbose_events::VerboseEventHandler;

/// Build the HTTP request based on CLI args
pub async fn build_request(builder: RequestBuilder, args: &Args, url: &Url) -> RequestBuilder {
    let mut builder = builder
        .method(args.method.0.clone())
        .follow_redirects(args.follow_redirects)
        .max_redirects(args.max_redirects)
        .connect_timeout(Duration::from_secs(args.connect_timeout))
        .insecure(args.insecure)
        .dns_overrides(parse_connect_to_rules(&args.connect_to));

    // Add event handler for verbose mode (silent suppresses verbose)
    if args.verbose && !args.silent {
        builder = builder.event_handler(Arc::new(VerboseEventHandler::new()));
    }

    if let Some(max_time) = args.max_time {
        builder = builder.max_time(Duration::from_secs(max_time));
    }

    let headers = build_headers(args, url);
    builder = builder.headers(headers);

    // Set HTTP version
    builder = set_http_version(builder, args);

    // Build body
    let (body, content_type) = build_body(args).await;
    if let Some(ct) = content_type {
        builder = builder.header(CONTENT_TYPE, ct);
    }

    // Load CA certificates if provided
    if let Some(ref cacert_path) = args.cacert {
        let ca_certs = load_ca_certs(cacert_path);
        builder = builder.ca_certs(ca_certs);
    }

    // Load client certificate if provided
    if let Some(ref cert_path) = args.cert {
        let (certs, key) = load_client_cert(cert_path, args.key.as_ref());
        builder = builder.client_cert(certs, key);
    }

    builder.body(body)
}

fn set_http_version(builder: RequestBuilder, args: &Args) -> RequestBuilder {
    if args.http3 {
        builder.http_version(Version::HTTP_3)
    } else if args.http2 {
        builder.http_version(Version::HTTP_2)
    } else if args.http1_1 {
        builder.http_version(Version::HTTP_11)
    } else {
        builder
    }
}

/// Returns (body, optional Content-Type)
async fn build_body(args: &Args) -> (RequestBody, Option<HeaderValue>) {
    // -d/--data: raw body data
    if let Some(ref data) = args.data {
        return (
            build_data_body(data),
            Some(HeaderValue::from_static(
                "application/x-www-form-urlencoded",
            )),
        );
    }

    // --json: JSON body
    if let Some(ref json_data) = args.json {
        return (
            RequestBody::from_bytes(json_data.clone()),
            Some(HeaderValue::from_static("application/json")),
        );
    }

    // -F/--form: multipart form data
    if !args.form.is_empty() {
        return build_multipart_body(&args.form).await;
    }

    (RequestBody::empty(), None)
}

fn build_data_body(data: &str) -> RequestBody {
    if let Some(file_path) = data.strip_prefix('@') {
        let file_content = std::fs::read(file_path).unwrap_or_else(|err| {
            fatal!("Failed to read data from file '{}': {}", file_path, err);
        });
        RequestBody::from_bytes(file_content)
    } else {
        RequestBody::from_bytes(data.to_string())
    }
}

/// Build multipart body and return with the Content-Type header value
async fn build_multipart_body(form_fields: &[String]) -> (RequestBody, Option<HeaderValue>) {
    let boundary = uuid::Uuid::new_v4().simple().to_string();
    let mut body = Vec::new();

    for field in form_fields {
        if let Some((key, value)) = field.split_once('=') {
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());

            if let Some(file_path) = value.strip_prefix('@') {
                // File upload
                let path = Path::new(file_path);
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
                let content = std::fs::read(file_path).unwrap_or_else(|err| {
                    fatal!("Failed to read form file '{}': {}", file_path, err);
                });
                let mime = mime_guess::from_path(file_path)
                    .first_or_octet_stream()
                    .to_string();

                body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                        key, filename
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", mime).as_bytes());
                body.extend_from_slice(&content);
            } else {
                // Text field
                body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{}\"\r\n\r\n{}",
                        key, value
                    )
                    .as_bytes(),
                );
            }
            body.extend_from_slice(b"\r\n");
        } else {
            fatal!("Invalid form field format: {}", field);
        }
    }

    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let content_type = format!("multipart/form-data; boundary={}", boundary);
    let header_value = HeaderValue::from_str(&content_type).ok();

    (RequestBody::from_bytes(body), header_value)
}

pub fn parse_connect_to_rules(rules: &[String]) -> Vec<OverrideRule> {
    let mut overrides = Vec::new();
    for rule in rules {
        match OverrideRule::parse(rule) {
            Some(override_rule) => overrides.push(override_rule),
            None => fatal!("Invalid --connect-to rule format: {}", rule),
        }
    }
    overrides
}

pub fn load_ca_certs(path: &PathBuf) -> Vec<CertificateDer<'static>> {
    let data = fs::read(path).unwrap_or_else(|err| {
        fatal!(
            "Failed to read CA certificate '{}': {}",
            path.display(),
            err
        );
    });

    let mut reader = BufReader::new(data.as_slice());
    rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect()
}

pub fn load_client_cert(
    cert_path: &PathBuf,
    key_path: Option<&PathBuf>,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_data = fs::read(cert_path).unwrap_or_else(|err| {
        fatal!(
            "Failed to read client certificate '{}': {}",
            cert_path.display(),
            err
        );
    });

    let mut cert_reader = BufReader::new(cert_data.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    let key = if let Some(key_path) = key_path {
        // Key is in a separate file
        let key_data = fs::read(key_path).unwrap_or_else(|err| {
            fatal!(
                "Failed to read client key '{}': {}",
                key_path.display(),
                err
            );
        });
        let mut key_reader = BufReader::new(key_data.as_slice());
        rustls_pemfile::private_key(&mut key_reader)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                fatal!(
                    "Failed to parse client key '{}'. No valid private key found in PEM file.",
                    key_path.display()
                );
            })
    } else {
        // Key is in the same file as the cert
        let mut key_reader = BufReader::new(cert_data.as_slice());
        rustls_pemfile::private_key(&mut key_reader)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                fatal!(
                    "Failed to parse client certificate '{}'. The file must contain both certificate and private key in PEM format, or use --key to specify the key file separately.",
                    cert_path.display()
                );
            })
    };

    (certs, key)
}

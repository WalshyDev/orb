use crate::cli::Args;

// Re-export OrbError from orb_client
pub use orb_client::OrbError;

/// Handle errors with user-friendly messages
pub fn handle_request_error(err: OrbError, args: &Args) -> ! {
    match err {
        OrbError::TooManyRedirects { count, url } => {
            silent_fatal!(
                args.silent,
                "Maximum redirect limit ({}) reached while going to '{}'. Use --location (-L) to follow redirects.",
                count,
                url
            );
        }
        OrbError::Connect(msg) => {
            silent_fatal!(
                args.silent,
                "Failed to connect to '{}'. Please check the URL and your network connection.\nDetails: {}",
                args.url,
                msg
            );
        }
        OrbError::Timeout { timeout } => {
            if timeout.as_secs() == 0 {
                // Connect timeout (duration not known from error)
                silent_fatal!(
                    args.silent,
                    "Request to '{}' timed out. Consider setting a timeout with --max-time.",
                    args.url
                );
            } else if args.http3 {
                silent_fatal!(
                    args.silent,
                    "Request to '{}' timed out ({} seconds). The server may not support HTTP/3. Try without --http3.",
                    args.url,
                    timeout.as_secs()
                );
            } else {
                silent_fatal!(
                    args.silent,
                    "Request to '{}' timed out ({} seconds). Consider increasing the timeout with --max-time.",
                    args.url,
                    timeout.as_secs()
                );
            }
        }
        OrbError::Tls(msg) => {
            let msg_lower = msg.to_lowercase();
            if msg_lower.contains("not valid for")
                || msg_lower.contains("notvalidforname")
                || msg_lower.contains("certificatenotvalidforname")
                || msg_lower.contains("invalid for target")
            {
                silent_fatal!(
                    args.silent,
                    "SSL certificate is not valid for '{}'. Use --insecure (-k) to ignore certificate errors.",
                    args.url
                );
            } else {
                silent_fatal!(
                    args.silent,
                    "TLS error for '{}': {}. Use --insecure (-k) to ignore certificate errors.",
                    args.url,
                    msg
                );
            }
        }
        OrbError::TlsExpiredCert => {
            silent_fatal!(
                args.silent,
                "SSL certificate for '{}' has expired. Use --insecure (-k) to ignore certificate errors.",
                args.url
            );
        }
        OrbError::TlsUnknownIssuer => {
            silent_fatal!(
                args.silent,
                "SSL certificate for '{}' has an unknown issuer (likely self-signed). Use --insecure (-k) to ignore certificate errors.",
                args.url
            );
        }
        OrbError::TlsInvalidForName => {
            silent_fatal!(
                args.silent,
                "SSL certificate is not valid for '{}'. Use --insecure (-k) to ignore certificate errors.",
                args.url
            );
        }
        OrbError::Dns(msg) => {
            silent_fatal!(
                args.silent,
                "Failed to resolve hostname for '{}': {}",
                args.url,
                msg
            );
        }
        OrbError::QuicConnect(msg) => {
            silent_fatal!(
                args.silent,
                "Failed to establish QUIC connection to '{}': {}. The server may not support HTTP/3.",
                args.url,
                msg
            );
        }
        OrbError::Http3Protocol(msg) => {
            silent_fatal!(
                args.silent,
                "HTTP/3 protocol error for '{}': {}",
                args.url,
                msg
            );
        }
        OrbError::Http3NotSupported => {
            silent_fatal!(
                args.silent,
                "Server '{}' does not support HTTP/3. Try without --http3.",
                args.url
            );
        }
        _ => {
            if !args.silent {
                eprintln!("Error: {:?}", err);
            }
            silent_fatal!(args.silent, "Error sending request: {}", err);
        }
    }
}

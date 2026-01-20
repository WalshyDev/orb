//! WebSocket handling for the CLI

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use orb_client::{OrbError, RequestBuilder, WebSocketMessage, WebSocketStream};
use url::Url;

use crate::cli::Args;
use crate::request::{load_ca_certs, load_client_cert, parse_connect_to_rules};
use crate::verbose_events::VerboseEventHandler;

// ANSI color codes for terminal output
mod color {
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const RED: &str = "\x1b[31m";
    pub const CYAN: &str = "\x1b[36m";
    pub const DIM: &str = "\x1b[2m";
    pub const RESET: &str = "\x1b[0m";
}

/// Check if URL is a WebSocket URL
pub fn is_websocket_url(url: &Url) -> bool {
    matches!(url.scheme(), "ws" | "wss")
}

/// Validate that unsupported options are not used with WebSocket
/// Returns an error message if an unsupported option is used
pub fn validate_websocket_options(args: &Args) -> Option<String> {
    // Method must be GET for WebSocket
    if args.method.0 != http::Method::GET {
        return Some(
            "WebSocket connections only support GET method. Remove -X/--request option."
                .to_string(),
        );
    }

    // Data options not supported
    if args.data.is_some() {
        return Some(
            "WebSocket connections don't support -d/--data. Use --ws-message to send a message."
                .to_string(),
        );
    }
    if args.json.is_some() {
        return Some(
            "WebSocket connections don't support --json. Use --ws-message to send a message."
                .to_string(),
        );
    }
    if !args.form.is_empty() {
        return Some(
            "WebSocket connections don't support -F/--form. Use --ws-message to send a message."
                .to_string(),
        );
    }

    // Output options not supported
    if args.output.is_some() {
        return Some("WebSocket connections don't support -o/--output.".to_string());
    }
    if args.include_headers {
        return Some("WebSocket connections don't support -i/--include.".to_string());
    }
    if args.head_only {
        return Some("WebSocket connections don't support -I/--head.".to_string());
    }

    // HTTP-specific options not supported
    if args.follow_redirects {
        return Some("WebSocket connections don't support -L/--location.".to_string());
    }
    if args.compressed {
        return Some("WebSocket connections don't support --compressed.".to_string());
    }
    if args.compress_algo.is_some() {
        return Some("WebSocket connections don't support --compress-algo.".to_string());
    }

    // HTTP version flags not supported
    if args.http1_1 || args.http2 || args.http3 {
        return Some(
            "WebSocket connections don't support HTTP version flags. WebSocket uses its own protocol.".to_string(),
        );
    }

    // Cookie options not supported
    if args.cookie.is_some() {
        return Some("WebSocket connections don't support -b/--cookie.".to_string());
    }
    if args.cookie_jar.is_some() {
        return Some("WebSocket connections don't support -c/--cookie-jar.".to_string());
    }

    // Auth options not supported (could be supported via headers in future)
    if args.user.is_some() {
        return Some("WebSocket connections don't support -u/--user.".to_string());
    }
    if args.bearer.is_some() {
        return Some("WebSocket connections don't support --bearer.".to_string());
    }

    // Other unsupported options
    if args.referer.is_some() {
        return Some("WebSocket connections don't support -e/--referer.".to_string());
    }
    if args.proxy.is_some() {
        return Some("WebSocket connections don't support --proxy (yet).".to_string());
    }
    if args.progress {
        return Some("WebSocket connections don't support --progress.".to_string());
    }
    if args.write_out {
        return Some("WebSocket connections don't support -w/--write-out.".to_string());
    }

    None
}

/// Build a RequestBuilder configured for WebSocket from CLI args
fn build_websocket_request(args: &Args, url: &Url) -> RequestBuilder {
    let mut builder = RequestBuilder::new(url.clone())
        .insecure(args.insecure)
        .connect_timeout(Duration::from_secs(args.connect_timeout));

    // Parse and apply DNS overrides
    let rules = parse_connect_to_rules(&args.connect_to);
    builder = builder.dns_overrides(rules);

    // Apply max time if specified
    if let Some(max_time) = args.max_time {
        builder = builder.max_time(Duration::from_secs(max_time));
    }

    // Add event handler for verbose mode
    if args.verbose && !args.silent {
        builder = builder.event_handler(Arc::new(VerboseEventHandler::new()));
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

    // Add custom User-Agent if specified
    if let Some(ref user_agent) = args.user_agent {
        builder = builder.header("User-Agent", user_agent.as_str());
    }

    // Add custom headers
    for header in &args.headers {
        if let Some((name, value)) = header.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    builder
}

/// Handle WebSocket connection and messaging
pub async fn handle_websocket(args: &Args, url: &Url) {
    let builder = build_websocket_request(args, url);

    // Connect
    let stream = match builder.connect_websocket().await {
        Ok(s) => s,
        Err(err) => {
            handle_websocket_error(err, args);
        }
    };

    // If --ws-message is provided, use single message mode
    if let Some(ref message) = args.ws_message {
        handle_single_message_mode(stream, message, args).await;
        return;
    }

    // Otherwise, interactive mode
    handle_interactive_mode(stream, args).await;
}

/// Single message mode: send one message, receive response, close
async fn handle_single_message_mode(mut stream: WebSocketStream, message: &str, args: &Args) {
    // Send the message
    if let Err(err) = stream.send_text(message).await {
        if !args.silent {
            eprintln!("Failed to send message: {}", err);
        }
        std::process::exit(1);
    }

    // Wait for response
    match stream.recv().await {
        Ok(Some(msg)) => {
            print_received_message(&msg, args);
        }
        Ok(None) => {
            // Connection closed without response
            if !args.silent {
                eprintln!("Connection closed without response");
            }
        }
        Err(err) => {
            if !args.silent {
                eprintln!("Failed to receive message: {}", err);
            }
            std::process::exit(1);
        }
    }

    // Close gracefully (ignore errors on close)
    let _ = stream.close().await;
}

/// Interactive mode: read from stdin, send messages, print received
async fn handle_interactive_mode(mut stream: WebSocketStream, args: &Args) {
    let is_tty = atty::is(atty::Stream::Stdin);

    if is_tty {
        handle_tty_interactive_mode(stream, args).await;
    } else {
        // Non-TTY mode: just show connect/disconnect
        if !args.silent {
            eprintln!("Connected to {}", stream.url());
        }

        // Wait for close or any message
        loop {
            match stream.recv().await {
                Ok(None) => break,
                Ok(Some(WebSocketMessage::Close(_))) => break,
                Ok(Some(_)) => continue, // Discard messages in non-tty mode
                Err(_) => break,
            }
        }

        if !args.silent {
            eprintln!("Disconnected");
        }
    }
}

/// Handle interactive TTY mode with rustyline for line editing
async fn handle_tty_interactive_mode(mut stream: WebSocketStream, args: &Args) {
    use rustyline::DefaultEditor;
    use rustyline::error::ReadlineError;
    use std::io::BufRead;
    use std::thread;

    use color::*;

    let silent = args.silent;
    let url = stream.url().to_string();

    if !silent {
        eprintln!(
            "{}Connected to {}{}\n{}Type messages and press Enter to send. Ctrl+C to exit.{}",
            GREEN, url, RESET, DIM, RESET
        );
    }

    // Channel for stdin -> async task
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // Spawn a thread for stdin reading
    // Try to use rustyline for nice line editing, fall back to basic stdin if it fails
    let stdin_handle = thread::spawn(move || {
        match DefaultEditor::new() {
            Ok(mut rl) => {
                // Use rustyline for line editing with history
                loop {
                    match rl.readline(&format!("{}> {}", GREEN, RESET)) {
                        Ok(line) => {
                            if line.trim().is_empty() {
                                continue;
                            }
                            let _ = rl.add_history_entry(&line);
                            if tx.send(line).is_err() {
                                break;
                            }
                        }
                        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                            // Ctrl+C or Ctrl+D - exit
                            break;
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                // Fall back to basic stdin reading
                eprintln!(
                    "{}Warning: Line editing unavailable, using basic input{}",
                    YELLOW, RESET
                );
                let stdin = std::io::stdin();
                for line in stdin.lock().lines() {
                    match line {
                        Ok(line) => {
                            if line.trim().is_empty() {
                                continue;
                            }
                            if tx.send(line).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    // Main async loop - handle both stdin input and WebSocket messages
    loop {
        tokio::select! {
            biased;

            // Check for incoming WebSocket messages
            result = stream.recv() => {
                match result {
                    Ok(Some(msg)) => {
                        // Clear the current prompt line, print message, then prompt will reappear
                        print_interactive_message(&msg, silent);
                        if matches!(msg, WebSocketMessage::Close(_)) {
                            break;
                        }
                    }
                    Ok(None) => {
                        if !silent {
                            eprintln!("\n{}< Connection closed by server{}", YELLOW, RESET);
                        }
                        break;
                    }
                    Err(err) => {
                        if !silent {
                            eprintln!("\n{}< Error: {}{}", RED, err, RESET);
                        }
                        break;
                    }
                }
            }

            // Check for input from stdin thread
            Some(line) = rx.recv() => {
                // Move cursor up to overwrite the prompt line we just typed on
                print!("\x1b[1A\x1b[2K");
                // Print our sent message with styling
                println!("{}  ➤ {}{}", DIM, line, RESET);

                if let Err(err) = stream.send_text(&line).await {
                    if !silent {
                        eprintln!("{}  ✗ Error sending: {}{}", RED, err, RESET);
                    }
                    break;
                }
            }
        }
    }

    // Close the stream
    let _ = stream.close().await;

    // The stdin thread will exit when the channel is dropped
    drop(rx);
    let _ = stdin_handle.join();

    if !silent {
        eprintln!("{}Disconnected{}", DIM, RESET);
    }
}

/// Print a message received in interactive mode
fn print_interactive_message(msg: &WebSocketMessage, _silent: bool) {
    use color::*;

    match msg {
        WebSocketMessage::Text(text) => {
            // Clear current line and print received message
            print!("\x1b[2K\r");
            println!("{}  ◀ {}{}", CYAN, text, RESET);
        }
        WebSocketMessage::Binary(data) => {
            print!("\x1b[2K\r");
            println!("{}  ◀ [binary: {} bytes]{}", CYAN, data.len(), RESET);
        }
        WebSocketMessage::Ping(_) => {
            // Don't print pings in interactive mode
        }
        WebSocketMessage::Pong(_) => {
            // Don't print pongs in interactive mode
        }
        WebSocketMessage::Close(frame) => {
            print!("\x1b[2K\r");
            if let Some(f) = frame {
                println!("{}  ◀ [closed: {} {}]{}", YELLOW, f.code, f.reason, RESET);
            } else {
                println!("{}  ◀ [closed]{}", YELLOW, RESET);
            }
        }
    }
}

/// Print a received message
fn print_received_message(msg: &WebSocketMessage, args: &Args) {
    match msg {
        WebSocketMessage::Text(text) => {
            println!("{}", text);
        }
        WebSocketMessage::Binary(data) => {
            if !args.silent {
                eprintln!("< Received {} bytes of binary data", data.len());
            }
            // Write binary data to stdout
            let _ = io::stdout().write_all(data);
            let _ = io::stdout().flush();
        }
        WebSocketMessage::Ping(_) => {
            if args.verbose && !args.silent {
                eprintln!("< Ping received (pong sent automatically)");
            }
        }
        WebSocketMessage::Pong(_) => {
            if args.verbose && !args.silent {
                eprintln!("< Pong received");
            }
        }
        WebSocketMessage::Close(frame) => {
            if !args.silent {
                if let Some(f) = frame {
                    eprintln!("< Connection closed: {} {}", f.code, f.reason);
                } else {
                    eprintln!("< Connection closed");
                }
            }
        }
    }
}

/// Handle WebSocket errors with user-friendly messages
fn handle_websocket_error(err: OrbError, args: &Args) -> ! {
    if args.silent {
        std::process::exit(1);
    }

    match err {
        OrbError::WebSocketConnect(msg) => {
            eprintln!("Failed to connect to WebSocket server: {}", msg);
        }
        OrbError::Timeout { timeout } => {
            eprintln!(
                "WebSocket connection timed out ({} seconds)",
                timeout.as_secs()
            );
        }
        OrbError::Tls(msg) => {
            eprintln!("TLS error: {}", msg);
        }
        OrbError::TlsUnknownIssuer => {
            eprintln!(
                "TLS error: unknown certificate issuer. Use --insecure to skip verification."
            );
        }
        OrbError::TlsExpiredCert => {
            eprintln!("TLS error: certificate has expired");
        }
        OrbError::TlsInvalidForName => {
            eprintln!("TLS error: certificate not valid for this host");
        }
        OrbError::Dns(msg) => {
            eprintln!("DNS resolution failed: {}", msg);
        }
        _ => {
            eprintln!("WebSocket error: {}", err);
        }
    }
    std::process::exit(1);
}

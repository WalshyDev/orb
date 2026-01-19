#[macro_use]
mod utils;

mod cli;
mod cookie;
mod error;
mod headers;
mod output;
mod request;
mod update;
mod verbose_events;
mod websocket;

use std::time::Instant;

use clap::Parser;
use orb_client::RequestBuilder;
use url::Url;

use crate::cli::{
    validate_cacert, validate_cert_and_key, validate_connect_to, validate_cookie, validate_proxy,
};
use crate::error::handle_request_error;
use crate::output::handle_response;
use crate::request::build_request;
use crate::websocket::{handle_websocket, is_websocket_url, validate_websocket_options};

#[tokio::main]
async fn main() {
    // Apply any staged update (fast, synchronous check)
    if let Some(version) = update::apply_pending() {
        eprintln!("* Updated orb to version {}", version);
    }

    // Spawn background update check (non-blocking)
    update::init();

    let args = cli::Args::parse();

    let url = Url::parse(&args.url).unwrap_or_else(|err| {
        fatal!("Invalid URL {}", err);
    });

    // Check if this is a WebSocket URL
    if is_websocket_url(&url) {
        // Validate that only supported options are used
        if let Some(error) = validate_websocket_options(&args) {
            fatal!("{}", error);
        }

        // Validate options that ARE supported for WebSocket
        if !args.connect_to.is_empty() {
            validate_connect_to(&args.connect_to);
        }
        validate_cert_and_key(args.cert.as_ref(), args.key.as_ref());
        validate_cacert(args.cacert.as_ref());

        // Handle WebSocket connection
        handle_websocket(&args, &url).await;
        return;
    }

    // HTTP flow: validate all options
    if !args.connect_to.is_empty() {
        validate_connect_to(&args.connect_to);
    }
    validate_cert_and_key(args.cert.as_ref(), args.key.as_ref());
    validate_cacert(args.cacert.as_ref());
    validate_cookie(args.cookie.as_ref());
    validate_proxy(args.proxy.as_ref());

    let builder = RequestBuilder::new(url.clone());
    let builder = build_request(builder, &args, &url).await;

    let start_time = Instant::now();
    let response = match builder.send().await {
        Ok(resp) => resp,
        Err(err) => handle_request_error(err, &args),
    };
    let ttfb = start_time.elapsed();

    handle_response(response, &args, &url, start_time, ttfb).await;
}

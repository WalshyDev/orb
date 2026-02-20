use bytes::Bytes;
use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_compression::tokio::bufread::{BrotliDecoder, DeflateDecoder, GzipDecoder, ZstdDecoder};
use futures_util::{Stream, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use orb_client::{OrbError, Response};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::io::StreamReader;
use url::Url;

use crate::cli::Args;
use crate::cookie::CookieJar;

/// Threshold for auto-enabling progress bar (100 MiB)
const AUTO_PROGRESS_SIZE_THRESHOLD: u64 = 100 * 1024 * 1024;
/// Timeout before first chunk to trigger progress bar (1 second)
const AUTO_PROGRESS_SLOW_START_THRESHOLD: Duration = Duration::from_secs(1);

/// Content-Encoding types we can decompress
#[derive(Debug, Clone, Copy)]
enum ContentEncoding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
    Identity,
}

impl ContentEncoding {
    fn from_header(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "gzip" | "x-gzip" => Self::Gzip,
            "deflate" => Self::Deflate,
            "br" | "brotli" => Self::Brotli,
            "zstd" => Self::Zstd,
            _ => Self::Identity,
        }
    }
}

pin_project! {
    /// A stream that decompresses data from an inner async reader
    struct DecompressStream<R> {
        #[pin]
        reader: R,
        buf: Vec<u8>,
    }
}

impl<R: AsyncRead> DecompressStream<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: vec![0u8; 8192],
        }
    }
}

impl<R: AsyncRead> Stream for DecompressStream<R> {
    type Item = Result<Bytes, OrbError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let mut read_buf = ReadBuf::new(this.buf);

        match this.reader.poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Bytes::copy_from_slice(filled))))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(OrbError::BodyRead(e.to_string())))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Handle the response output (headers and body)
pub async fn handle_response(
    response: Response,
    args: &Args,
    url: &Url,
    start_time: Instant,
    ttfb: Duration,
) {
    // Verbose output shows response status and headers to stderr
    // Silent mode suppresses verbose output
    if args.verbose && !args.silent {
        print_verbose_response(&response);
    }

    if args.include_headers || args.head_only {
        print_headers(&response);
    }

    // Store cookies if cookie jar is specified
    if let Some(ref cookie_jar_path) = args.cookie_jar {
        let uri: http::Uri = url.as_str().parse().unwrap_or_else(|err| {
            crate::fatal!("Invalid URL '{}': {}", url, err);
        });
        let cookie_jar = CookieJar::new(Some(cookie_jar_path.clone()));
        cookie_jar.store_response_cookies(response.headers(), &uri);
        // cookie_jar will save to file when dropped
    }

    // Capture status code before consuming response
    let status_code = response.status().as_u16();
    let content_length = response.content_length();

    // Determine content encoding for decompression
    // Decompress if --compressed or --compress-algo is set
    let content_encoding = if args.compressed || args.compress_algo.is_some() {
        response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(ContentEncoding::from_header)
            .unwrap_or(ContentEncoding::Identity)
    } else {
        ContentEncoding::Identity
    };

    if args.head_only {
        let ttlb = start_time.elapsed();
        // Silent mode suppresses write-out stats
        if args.write_out && !args.silent {
            print_write_out(status_code, 0, ttfb, ttlb);
        }
        return;
    }

    // Determine if we should show progress
    let large_file = content_length.is_some_and(|len| len >= AUTO_PROGRESS_SIZE_THRESHOLD);
    let show_progress = !args.silent && (args.progress || large_file);

    // Stream the response body (with optional decompression)
    let body_size = stream_body(
        response,
        args,
        content_length,
        show_progress,
        content_encoding,
    )
    .await;
    let ttlb = start_time.elapsed(); // Time to last byte (after body is fully read)

    // Silent mode suppresses write-out stats
    if args.write_out && !args.silent {
        print_write_out(status_code, body_size, ttfb, ttlb);
    }
}

/// Type alias for a boxed stream of bytes
type BoxedByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, OrbError>> + Send>>;

/// Create a body stream, optionally wrapped with decompression
fn create_body_stream(response: Response, encoding: ContentEncoding) -> BoxedByteStream {
    let raw_stream = response.into_body_stream();

    match encoding {
        ContentEncoding::Identity => Box::pin(raw_stream),
        ContentEncoding::Gzip => {
            let reader = StreamReader::new(
                raw_stream.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
            );
            let decoder = GzipDecoder::new(tokio::io::BufReader::new(reader));
            Box::pin(DecompressStream::new(decoder))
        }
        ContentEncoding::Deflate => {
            let reader = StreamReader::new(
                raw_stream.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
            );
            let decoder = DeflateDecoder::new(tokio::io::BufReader::new(reader));
            Box::pin(DecompressStream::new(decoder))
        }
        ContentEncoding::Brotli => {
            let reader = StreamReader::new(
                raw_stream.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
            );
            let decoder = BrotliDecoder::new(tokio::io::BufReader::new(reader));
            Box::pin(DecompressStream::new(decoder))
        }
        ContentEncoding::Zstd => {
            let reader = StreamReader::new(
                raw_stream.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
            );
            let decoder = ZstdDecoder::new(tokio::io::BufReader::new(reader));
            Box::pin(DecompressStream::new(decoder))
        }
    }
}

/// Stream the response body to stdout or file, returning the total bytes written
async fn stream_body(
    response: Response,
    args: &Args,
    content_length: Option<u64>,
    show_progress: bool,
    encoding: ContentEncoding,
) -> usize {
    // Create the body stream with optional decompression
    let stream = create_body_stream(response, encoding);

    if let Some(ref output_path) = args.output {
        // Stream to file
        if show_progress {
            stream_to_file_with_progress(stream, output_path, content_length).await
        } else if !args.silent {
            // Auto-progress for slow downloads
            stream_to_file_with_auto_progress(stream, output_path, content_length).await
        } else {
            stream_to_file(stream, output_path).await
        }
    } else {
        // Stream to stdout
        if show_progress {
            stream_to_stdout_with_progress(stream, content_length).await
        } else {
            stream_to_stdout(stream).await
        }
    }
}

/// Stream response body to stdout
async fn stream_to_stdout(mut stream: BoxedByteStream) -> usize {
    let mut total_bytes = 0;
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.unwrap_or_else(|err: OrbError| {
            fatal!("Error reading response body: {}", err);
        });
        total_bytes += chunk.len();
        handle.write_all(&chunk).unwrap_or_else(|err| {
            fatal!("Failed to write to stdout: {}", err);
        });
        // Flush after each chunk for streaming output
        handle.flush().ok();
    }

    total_bytes
}

/// Stream response body to stdout with progress bar on stderr
async fn stream_to_stdout_with_progress(
    mut stream: BoxedByteStream,
    content_length: Option<u64>,
) -> usize {
    let mut total_bytes: u64 = 0;
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let progress_bar = create_progress_bar(content_length, 0);

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.unwrap_or_else(|err: OrbError| {
            fatal!("Error reading response body: {}", err);
        });
        total_bytes += chunk.len() as u64;
        handle.write_all(&chunk).unwrap_or_else(|err| {
            fatal!("Failed to write to stdout: {}", err);
        });
        handle.flush().ok();
        progress_bar.set_position(total_bytes);
    }

    progress_bar.finish_and_clear();

    total_bytes as usize
}

/// Stream response body to file
async fn stream_to_file(mut stream: BoxedByteStream, output_path: &std::path::Path) -> usize {
    let mut total_bytes = 0;

    let mut file = std::fs::File::create(output_path).unwrap_or_else(|err| {
        fatal!("Failed to create file '{}': {}", output_path.display(), err);
    });

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.unwrap_or_else(|err: OrbError| {
            fatal!("Error reading response body: {}", err);
        });
        total_bytes += chunk.len();
        file.write_all(&chunk).unwrap_or_else(|err| {
            fatal!(
                "Failed to write to file '{}': {}",
                output_path.display(),
                err
            );
        });
    }

    total_bytes
}

/// Stream response body to file with progress bar
async fn stream_to_file_with_progress(
    mut stream: BoxedByteStream,
    output_path: &std::path::Path,
    content_length: Option<u64>,
) -> usize {
    let mut total_bytes: u64 = 0;

    let mut file = std::fs::File::create(output_path).unwrap_or_else(|err| {
        fatal!("Failed to create file '{}': {}", output_path.display(), err);
    });

    let progress_bar = create_progress_bar(content_length, 0);

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.unwrap_or_else(|err: OrbError| {
            fatal!("Error reading response body: {}", err);
        });
        total_bytes += chunk.len() as u64;
        file.write_all(&chunk).unwrap_or_else(|err| {
            fatal!(
                "Failed to write to file '{}': {}",
                output_path.display(),
                err
            );
        });
        progress_bar.set_position(total_bytes);
    }

    progress_bar.finish_and_clear();

    total_bytes as usize
}

/// Stream response body to file with auto-progress (shows progress if download is slow)
async fn stream_to_file_with_auto_progress(
    mut stream: BoxedByteStream,
    output_path: &std::path::Path,
    content_length: Option<u64>,
) -> usize {
    let mut total_bytes: u64 = 0;
    let mut progress_bar: Option<ProgressBar> = None;
    let start_time = Instant::now();

    let mut file = std::fs::File::create(output_path).unwrap_or_else(|err| {
        fatal!("Failed to create file '{}': {}", output_path.display(), err);
    });

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.unwrap_or_else(|err: OrbError| {
            fatal!("Error reading response body: {}", err);
        });

        // Show progress bar if download is taking too long
        if progress_bar.is_none() && start_time.elapsed() >= AUTO_PROGRESS_SLOW_START_THRESHOLD {
            progress_bar = Some(create_progress_bar(content_length, total_bytes));
        }

        total_bytes += chunk.len() as u64;
        file.write_all(&chunk).unwrap_or_else(|err| {
            fatal!(
                "Failed to write to file '{}': {}",
                output_path.display(),
                err
            );
        });

        if let Some(ref pb) = progress_bar {
            pb.set_position(total_bytes);
        }
    }

    if let Some(pb) = progress_bar {
        pb.finish_and_clear();
    }

    total_bytes as usize
}

/// Create a progress bar (determinate if content-length known, spinner otherwise)
fn create_progress_bar(content_length: Option<u64>, initial_position: u64) -> ProgressBar {
    let pb = if let Some(total) = content_length {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                .expect("Invalid progress bar template")
                .progress_chars("#>-"),
        );
        pb
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {bytes} ({bytes_per_sec})")
                .expect("Invalid progress bar template"),
        );
        pb
    };

    // Force progress bar output when ORB_FORCE_PROGRESS is set (for testing)
    // By default, indicatif hides progress bars when stderr is not a TTY
    if std::env::var("ORB_FORCE_PROGRESS").is_ok() {
        eprintln!("[progress-bar-started]");
    }

    pb.set_position(initial_position);
    pb
}

/// Print response info in verbose mode (to stderr with < prefix)
fn print_verbose_response(response: &Response) {
    eprintln!("< {:?} {}", response.version(), response.status());

    for (key, value) in response.headers() {
        eprintln!("< {}: {}", key, value.to_str().unwrap_or("<binary>"));
    }

    eprintln!("<");
}

fn print_headers(response: &Response) {
    println!("{:?} {}", response.version(), response.status());

    for (key, value) in response.headers() {
        println!("{}: {}", key, value.to_str().unwrap_or("<binary>"));
    }

    println!();
}

fn print_write_out(status_code: u16, body_size: usize, ttfb: Duration, ttlb: Duration) {
    eprintln!();
    eprintln!("  http_code: {}", status_code);
    eprintln!("  size_download: {} bytes", body_size);
    eprintln!("  time_starttransfer: {:.3}s", ttfb.as_secs_f64()); // TTFB
    eprintln!("  time_total: {:.3}s", ttlb.as_secs_f64()); // TTLB
}

use bytes::Bytes;
use futures_util::Stream;
use http_body::Body;
use hyper::body::Incoming;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::error::OrbError;

/// Wrapper to convert hyper's Incoming body to a Stream
pub struct BodyStream {
    inner: Incoming,
}

impl BodyStream {
    pub fn new(inner: Incoming) -> Self {
        Self { inner }
    }
}

impl futures_util::Stream for BodyStream {
    type Item = Result<Bytes, OrbError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    Poll::Ready(Some(Ok(data)))
                } else {
                    // Skip trailers, poll again
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(e))) => {
                let err: hyper::Error = e;
                Poll::Ready(Some(Err(OrbError::BodyRead(err.to_string()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Request body type
#[derive(Clone, Debug)]
pub enum RequestBody {
    Empty,
    Bytes(Bytes),
}

impl RequestBody {
    pub fn empty() -> Self {
        Self::Empty
    }

    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self::Bytes(bytes.into())
    }
}

/// A stream of response body chunks
pub struct ResponseBody {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, OrbError>> + Send>>,
}

impl ResponseBody {
    pub fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, OrbError>> + Send + 'static,
    {
        Self {
            inner: Box::pin(stream),
        }
    }

    pub fn empty() -> Self {
        Self::new(futures_util::stream::empty())
    }
}

impl Stream for ResponseBody {
    type Item = Result<Bytes, OrbError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

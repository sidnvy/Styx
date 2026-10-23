use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::OwnedSemaphorePermit;
/// Holds admissions through actual SSE/body EOF or drop, not just response headers.
pub(super) struct HeldBody {
    pub inner: BoxBody<Bytes, Infallible>,
    pub until: Pin<Box<tokio::time::Sleep>>,
    pub _permits: Vec<OwnedSemaphorePermit>,
    pub _lifetime: Option<Arc<dyn Send + Sync>>,
    pub ended: bool,
    pub delivery_allowed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}
impl HeldBody {
    pub fn new(
        inner: BoxBody<Bytes, Infallible>,
        permits: Vec<OwnedSemaphorePermit>,
        lifetime: Option<Arc<dyn Send + Sync>>,
    ) -> Self {
        Self {
            inner,
            until: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
            _permits: permits,
            _lifetime: lifetime,
            ended: false,
            delivery_allowed: None,
        }
    }
}
impl Body for HeldBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        use std::future::Future;
        if self.ended {
            return Poll::Ready(None);
        }
        if self
            .delivery_allowed
            .as_ref()
            .is_some_and(|allowed| !allowed())
            || self.until.as_mut().poll(cx).is_ready()
        {
            self.ended = true;
            self.inner = Full::new(Bytes::new()).boxed();
            self._permits.clear();
            self._lifetime = None;
            return Poll::Ready(None);
        }
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(result, Poll::Ready(None)) {
            self.ended = true;
            self.inner = Full::new(Bytes::new()).boxed();
            self._permits.clear();
            self._lifetime = None;
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.ended || self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

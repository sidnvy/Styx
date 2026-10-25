//! Original native session plus original WTS event-source incarnation.
//! Core alone owns grants/operations. All methods run on a retained blocking
//! boundary; shutdown joins the original message thread, never its replacement.
use super::{
    windows_native_observation::{
        NativeObservation, NativeSession, ObservationError, Result, WindowReadEvidence,
    },
    windows_notifications::NotificationWatch,
};
use std::sync::Mutex;
/// Same observation interval and original watcher generation; not a grant.
pub(crate) struct SourceObservation {
    pub(crate) native: NativeObservation,
    pub(crate) epoch: u64,
    pub(crate) windows: WindowReadEvidence,
}
pub(crate) struct WindowsSource {
    native: NativeSession,
    watch: NotificationWatch,
    reader: Mutex<()>,
}
impl WindowsSource {
    pub(crate) fn acquire_current() -> Result<Self> {
        // Subscribe before minting the first point observation, then consume a
        // queue checkpoint. Any event in this interval permanently fences it.
        let watch = NotificationWatch::start_current()?;
        let before = watch.checkpoint()?;
        let native = NativeSession::acquire_current()?;
        if watch.checkpoint()? != before {
            return Err(ObservationError::Fenced);
        }
        Ok(Self {
            native,
            watch,
            reader: Mutex::new(()),
        })
    }
    pub(crate) fn fresh(&self) -> Result<SourceObservation> {
        let _reader = self.reader.lock().map_err(|_| {
            self.watch.fence();
            ObservationError::Fenced
        })?;
        let before = self.watch.checkpoint()?;
        let observed = self.native.observe();
        if observed.is_err() {
            self.watch.fence();
        }
        let value = observed?;
        let windows = self
            .native
            .enumerate_windows(&self.watch.invalidation_token());
        if windows.is_err() {
            self.watch.fence();
        }
        let windows = windows?;
        // Re-read original token/session after the synchronous native query.
        if self.native.observe()? != value {
            self.watch.fence();
            return Err(ObservationError::Changed);
        }
        if self.watch.checkpoint()? != before {
            return Err(ObservationError::Fenced);
        }
        Ok(SourceObservation {
            native: value,
            windows,
            epoch: before,
        })
    }

    pub(crate) fn invalidation_token(&self) -> tokio_util::sync::CancellationToken {
        self.watch.invalidation_token()
    }

    pub(crate) fn stop_and_join(&mut self) -> Result<()> {
        self.watch.stop_and_join()
    }
}

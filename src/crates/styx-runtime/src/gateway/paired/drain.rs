//! Original-transport shutdown only. Retained results are observations of the
//! existing Host owner-cleanup port, never new business or owner authority.
use super::*;
use crate::host::protocol::wire::{HostControl, TRANSPORT_DRAIN_TIMEOUT_MS};
use std::sync::atomic::AtomicU8;

pub(crate) fn cleanup_control(call: &Call) -> bool {
    matches!(
        call,
        Call::OwnerRevoke { .. }
            | Call::OwnerCleanup { .. }
            | Call::EnableTransportDrain
            | Call::TransportDrainResult { .. }
    )
}
#[derive(Default)]
pub(super) struct BindingCleanup {
    started: bool,
    pub(super) result: Option<bool>,
    entry: Option<Arc<Entry>>,
    pub(super) job: Option<tokio::task::JoinHandle<()>>,
}
pub(crate) struct EntryDrain {
    id: RequestId,
    job: Option<tokio::task::JoinHandle<()>>,
    // 0 pending, 1 exact acceptance received, 2 unconfirmed. No authority.
    acceptance: Arc<AtomicU8>,
}
impl RelayHandle {
    /// Final count after original socket tasks join. Distinct from per-binding
    /// owner cleanup and worker failure; local EOF is never an acceptance ACK.
    pub fn unconfirmed_transport_drains(&self) -> usize {
        self.inner.unconfirmed_drains.load(Ordering::Acquire)
    }
    pub(crate) fn begin_transport_drain(
        &self,
        entry: &Arc<Entry>,
        message: HostControl,
    ) -> Result<(), RelayError> {
        let HostControl::TransportDrainV1 {
            drain_id,
            connection_generation,
            host_generation,
            timeout_ms,
        } = message;
        if !entry.drain_enabled
            || connection_generation != entry.host_connection
            || host_generation != entry.host_generation
            || timeout_ms == 0
            || timeout_ms > TRANSPORT_DRAIN_TIMEOUT_MS
        {
            return Err(RelayError::Invalid);
        }
        let until = tokio::time::Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        let mut attempt = entry.drain.lock().map_err(|_| RelayError::Unknown)?;
        if let Some(previous) = attempt.as_ref() {
            return if previous.id == drain_id {
                Ok(())
            } else {
                Err(RelayError::Invalid)
            };
        }
        // Same gate as final binding insertion and actual start_send/delivery.
        // A reserved open is already in this inventory, even if never confirmed.
        let mut admission = entry.admission.lock().map_err(|_| RelayError::Unknown)?;
        *admission = true;
        let cohort = {
            let bindings = self
                .inner
                .bindings
                .lock()
                .map_err(|_| RelayError::Unknown)?;
            let mut cohort = Vec::new();
            for binding in bindings.iter() {
                if self
                    .current_binding_entry(binding, true)
                    .is_ok_and(|current| Arc::ptr_eq(&current, entry))
                {
                    *binding.revoked.lock().map_err(|_| RelayError::Unknown)? = true;
                    cohort.push(binding.clone());
                }
            }
            cohort
        };
        let relay = self.clone();
        let original = entry.clone();
        let id = drain_id.clone();
        let acceptance = Arc::new(AtomicU8::new(0));
        let observed_acceptance = acceptance.clone();
        let job = tokio::spawn(async move {
            // Fencing is synchronous and grants no authority. Read-only Core
            // authentication runs in the original owned job under its original
            // deadline, keeping the socket reader available for all replies.
            let mut complete = matches!(
                tokio::time::timeout_at(until, relay.control_lane(&original)).await,
                Ok(Ok(_))
            );
            if complete {
                for binding in cohort {
                    if !relay.settle_binding(&binding, until, Some(&original)).await {
                        complete = false;
                    }
                }
            }
            // This request goes through the original socket's normal queue and
            // reader. No new connection can finish this attempt.
            let call = Call::TransportDrainResult {
                drain_id: id.clone(),
                host_generation: original.host_generation.clone(),
                complete,
            };
            let result =
                tokio::time::timeout_at(until, relay.exchange(&original, call, None)).await;
            // A lost acceptance leaves this observer unconfirmed. It cannot
            // erase a per-binding Complete that was already actually received.
            let accepted = matches!(result, Ok(Ok(Reply::TransportDrainResultAccepted { drain_id })) if drain_id == id);
            observed_acceptance.store(if accepted { 1 } else { 2 }, Ordering::Release);
        });
        *attempt = Some(EntryDrain {
            id: drain_id,
            job: Some(job),
            acceptance,
        });
        Ok(())
    }
    /// Start at most one original cleanup job per binding. Observers never own
    /// that job's cancellation; a timeout leaves its handles retained here.
    pub(super) async fn settle_binding(
        &self,
        binding: &Arc<Binding>,
        until: tokio::time::Instant,
        exact: Option<&Arc<Entry>>,
    ) -> bool {
        {
            let Ok(mut state) = binding.cleanup.lock() else {
                return false;
            };
            if let Some(result) = state.result {
                return result;
            }
            if !state.started {
                state.started = true;
                let entry = self.current_binding_entry(binding, true).ok();
                if !binding.ready.load(Ordering::Acquire)
                    || entry.is_none()
                    || entry
                        .as_ref()
                        .is_some_and(|e| !e.live.load(Ordering::Acquire) || e.stop.is_cancelled())
                    || exact.is_some_and(|expected| {
                        !entry.as_ref().is_some_and(|e| Arc::ptr_eq(e, expected))
                    })
                    || tokio::time::Instant::now() >= until
                {
                    state.result = Some(false);
                    binding.cleanup_changed.notify_waiters();
                    return false;
                }
                let entry = entry.expect("checked original entry");
                state.entry = Some(entry.clone());
                let relay = self.clone();
                let owned = binding.clone();
                let deadline = until.min(tokio::time::Instant::now() + Duration::from_secs(5));
                state.job = Some(tokio::spawn(async move {
                    let result = relay.cleanup_binding_once(&owned, &entry, deadline).await;
                    owned.cleanup.lock().expect("binding cleanup").result = Some(result);
                    owned.cleanup_changed.notify_waiters();
                }));
            }
        }
        loop {
            let changed = binding.cleanup_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Ok(state) = binding.cleanup.lock() {
                if let Some(result) = state.result {
                    return result;
                }
            } else {
                return false;
            }
            if tokio::time::timeout_at(until, changed).await.is_err() {
                return false;
            }
        }
    }
    async fn cleanup_binding_once(
        &self,
        binding: &Binding,
        entry: &Arc<Entry>,
        until: tokio::time::Instant,
    ) -> bool {
        if !matches!(
            tokio::time::timeout_at(until, self.control_lane(entry)).await,
            Ok(Ok(_))
        ) {
            return false;
        }
        let revoked = tokio::time::timeout_at(
            until,
            self.exchange(
                entry,
                Call::OwnerRevoke {
                    owner: binding.reference.clone(),
                },
                None,
            ),
        )
        .await;
        if !matches!(revoked, Ok(Ok(Reply::OwnerRevoked { owner, fenced: true, .. })) if owner == binding.reference)
        {
            return false;
        }
        let remaining = until
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis()
            .min(5000) as u32;
        if remaining == 0 {
            return false;
        }
        let result = tokio::time::timeout_at(
            until,
            self.exchange(
                entry,
                Call::OwnerCleanup {
                    owner: binding.reference.clone(),
                    timeout_ms: remaining,
                },
                None,
            ),
        )
        .await;
        matches!(result, Ok(Ok(Reply::OwnerCleanup { owner, complete: true })) if owner == binding.reference)
    }
    /// Called by the SAME original socket task before it releases Core leases.
    pub(crate) async fn join_transport_drain(&self, entry: &Arc<Entry>) {
        let original = entry
            .drain
            .lock()
            .expect("transport drain")
            .as_mut()
            .and_then(|d| d.job.take().map(|job| (job, d.acceptance.clone())));
        if let Some((job, acceptance)) = original {
            if job.await.is_err() {
                self.inner.shutdown_failed.store(true, Ordering::Release);
            }
            if acceptance.load(Ordering::Acquire) != 1 {
                acceptance.store(2, Ordering::Release);
                self.inner.unconfirmed_drains.fetch_add(1, Ordering::AcqRel);
                eprintln!("{{\"schema\":1,\"event\":\"transport_drain_acceptance_unconfirmed\"}}");
            }
        }
        let bindings = self.inner.bindings.lock().expect("bindings").clone();
        for binding in bindings {
            let job = {
                let mut cleanup = binding.cleanup.lock().expect("binding cleanup");
                if cleanup
                    .entry
                    .as_ref()
                    .is_some_and(|e| Arc::ptr_eq(e, entry))
                {
                    cleanup.job.take()
                } else {
                    None
                }
            };
            if let Some(job) = job
                && job.await.is_err()
            {
                self.inner.shutdown_failed.store(true, Ordering::Release);
            }
        }
    }
}

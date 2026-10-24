//! Explicit legacy Gateway compatibility. The protected Gateway owns one
//! session authority; the old wire has NO per-chat owner or new Host-token
//! guarantee. No unknown action is replayed and link loss never stops Codex.
mod wire;
use super::{
    coordinator::{
        CoordinatorError, HostAuthority, HostCoordinator, LegacyActionSubmission,
        LegacyStartSubmission,
    },
    link::{HostWssLink, LinkEndpoint},
};
use crate::providers::codex::{
    ActionEvidence, DispatchEvidence, ExecError, LegacyAction, TerminalEvent,
};
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use styx_contracts::{identity::*, operation::ResourceTarget};
use styx_core::operations::OwnerLease;
use wire::*;
const MAX_PROCESSES: usize = 512;
const MAX_WRITES: usize = 1024;
const MAX_ACK_BYTES: usize = 1024;

/// Only protected native configuration selects this explicit legacy mode. An
/// ordinary MCP argument cannot construct or replace the Gateway binding.
pub struct TrustedLegacyGateway {
    pub endpoint: String,
    pub gateway_namespace: GatewayId,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LegacyError {
    #[error("protected legacy Gateway binding does not match Host/link")]
    BootstrapMismatch,
    #[error("legacy frame or initialization is invalid")]
    InvalidFrame,
    #[error("legacy response/notification lost; outcome unknown; never replay")]
    OutcomeUnknown,
    #[error("legacy connection or metadata capacity exhausted")]
    Busy,
}
struct ProcessBinding {
    target: Option<ResourceTarget>,
    digest: Sha256Digest,
}
struct WriteBinding {
    process: String,
    digest: Sha256Digest,
    reply: Option<Box<serde_json::value::RawValue>>,
}
#[derive(Default)]
struct Bindings {
    processes: BTreeMap<String, ProcessBinding>,
    writes: BTreeMap<String, WriteBinding>,
}
/// Must be kept across reconnects with the SAME OwnedExecHost. A fresh object
/// cannot adopt old native process IDs. Authority is borrowed from bootstrap.
pub struct LegacyExecSession<'a> {
    profile: TrustedLegacyGateway,
    coordinator: HostCoordinator,
    _authority: &'a HostAuthority,
    owner: OwnerLease,
    initialization: Value,
    initialized_before: AtomicBool,
    bindings: Mutex<Bindings>,
    connection_slot: tokio::sync::Semaphore,
}
enum Handled {
    Response(Response),
    Unknown,
}
impl ProcessBinding {
    fn duplicate_start(&self, digest: Sha256Digest, id: Id) -> Handled {
        if self.digest != digest {
            // Refuse this changed request without rewriting the original fact.
            reject(id)
        } else {
            // The earlier request may already have effects or a lost ACK.
            // Legacy RpcFault would be mistaken for certain start refusal.
            Handled::Unknown
        }
    }
}
impl<'a> LegacyExecSession<'a> {
    pub fn new(
        profile: TrustedLegacyGateway,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
    ) -> Result<Self, LegacyError> {
        let endpoint =
            LinkEndpoint::parse(&profile.endpoint).map_err(|_| LegacyError::BootstrapMismatch)?;
        let canonical =
            url::Url::parse(&profile.endpoint).map_err(|_| LegacyError::BootstrapMismatch)?;
        let path = canonical.path();
        let legacy_host = path
            .strip_prefix("/styx/hosts/")
            .and_then(|p| p.strip_suffix("/exec"))
            .ok_or(LegacyError::BootstrapMismatch)?;
        if canonical.to_string() != profile.endpoint
            || legacy_host.is_empty()
            || legacy_host.len() > 128
            || !legacy_host.as_bytes()[0].is_ascii_alphanumeric()
            || !legacy_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !coordinator.shares_authority(authority)
        {
            return Err(LegacyError::BootstrapMismatch);
        }
        drop(endpoint);
        let initialization = coordinator
            .legacy_initialization()
            .map_err(|_| LegacyError::BootstrapMismatch)?;
        let owner = authority
            .register_verified_owner(
                format!("legacy-gateway:{}", uuid::Uuid::new_v4())
                    .try_into()
                    .map_err(|_| LegacyError::BootstrapMismatch)?,
                uuid::Uuid::new_v4()
                    .to_string()
                    .try_into()
                    .map_err(|_| LegacyError::BootstrapMismatch)?,
            )
            .map_err(|_| LegacyError::Busy)?;
        Ok(Self {
            profile,
            coordinator,
            _authority: authority,
            owner,
            initialization,
            initialized_before: AtomicBool::new(false),
            bindings: Mutex::new(Bindings::default()),
            connection_slot: tokio::sync::Semaphore::new(1),
        })
    }
    fn initialize(&self, request: &Request, id: Id) -> Response {
        let Ok(params) = request.typed::<Initialize>() else {
            return Response::error(id, -32602, "invalid initialize parameters");
        };
        if !params.valid() {
            return Response::error(id, -32602, "invalid initialize parameters");
        }
        let original = self.initialization["sessionId"].as_str();
        if params
            .resume_session_id
            .as_deref()
            .is_some_and(|resume| Some(resume) != original)
            || (self.initialized_before.load(Ordering::Acquire)
                && params.resume_session_id.as_deref() != original)
        {
            return Response::error(
                id,
                -32600,
                "session resume required or original session mismatch",
            );
        }
        self.initialized_before.store(true, Ordering::Release);
        Response::result(id, self.initialization.clone())
    }
    fn target(&self, process: &str) -> Option<ResourceTarget> {
        self.bindings
            .lock()
            .expect("legacy bindings")
            .processes
            .get(process)
            .and_then(|p| p.target.clone())
    }
    async fn handle(&self, request: Request, id: Id) -> Handled {
        match request.method.as_str() {
            "process/start" => {
                let Ok(spec) = request.typed::<Start>() else {
                    return reject(id);
                };
                if !spec.valid() {
                    return reject(id);
                }
                let Ok(payload) = spec.to_operation_payload() else {
                    return reject(id);
                };
                let process = spec.process_id.clone();
                let digest = Sha256Digest::of_bytes(&payload);
                let submission = {
                    let mut bindings = self.bindings.lock().expect("legacy bindings");
                    if let Some(previous) = bindings.processes.get(&process) {
                        return previous.duplicate_start(digest, id);
                    }
                    if bindings.processes.len() >= MAX_PROCESSES {
                        return busy(id);
                    }
                    // Register before any action byte; retain Unknown on waiter loss.
                    bindings.processes.insert(
                        process.clone(),
                        ProcessBinding {
                            target: None,
                            digest,
                        },
                    );
                    let prepared = match self.coordinator.prepare_legacy_start(&self.owner, &spec) {
                        Ok(v) => v,
                        Err(_) => return busy(id),
                    };
                    let target = ResourceTarget {
                        operation_id: prepared.id,
                        payload_digest: prepared.payload_digest,
                    };
                    bindings
                        .processes
                        .get_mut(&process)
                        .expect("just inserted")
                        .target = Some(target.clone());
                    self.coordinator.dispatch_legacy_start(
                        &self.owner,
                        &target.operation_id,
                        target.payload_digest,
                    )
                };
                match submission {
                    Ok(LegacyStartSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(done) => {
                            let _snapshot = done.snapshot;
                            let _cause = done.cause;
                            match (done.dispatch, done.raw_result) {
                                (DispatchEvidence::Started, Some(value)) => {
                                    Handled::Response(Response::result(id, value))
                                }
                                (DispatchEvidence::NotDispatched, _) => Handled::Response(
                                    Response::error(id, -32001, "start not dispatched"),
                                ),
                                _ => Handled::Unknown,
                            }
                        }
                        Err(_) => Handled::Unknown,
                    },
                    Ok(LegacyStartSubmission::Existing(snapshot)) => {
                        let _ = snapshot;
                        Handled::Unknown
                    }
                    Err(_) => {
                        Handled::Response(Response::error(id, -32001, "start not dispatched"))
                    }
                }
            }
            "process/read" => {
                let Ok(params) = request.typed::<Read>() else {
                    return reject(id);
                };
                if !params.valid() {
                    return reject(id);
                }
                let Some(target) = self.target(&params.process_id) else {
                    return Handled::Response(Response::error(
                        id,
                        -32600,
                        format!("unknown process id {}", params.process_id),
                    ));
                };
                match self
                    .coordinator
                    .read_legacy_raw(
                        &self.owner,
                        &target,
                        params.after_seq,
                        params.max_bytes,
                        Duration::from_millis(params.wait_ms),
                    )
                    .await
                {
                    Ok(page) => Handled::Response(Response::result(id, page.into_native())),
                    Err(CoordinatorError::Executor(ExecError::ProcessLost)) => {
                        Handled::Response(Response::error(
                            id,
                            -32600,
                            format!("unknown process id {}", params.process_id),
                        ))
                    }
                    // A lost raw read response leaves the caller cursor unchanged;
                    // no invented EOF/exit or deterministic error is returned.
                    Err(_) => Handled::Unknown,
                }
            }
            "process/write" => {
                let Ok(params) = request.typed::<wire::Write>() else {
                    return reject(id);
                };
                if !params.valid() {
                    return reject(id);
                }
                let digest = Sha256Digest::of_bytes(params.chunk.as_bytes());
                {
                    let mut bindings = self.bindings.lock().expect("legacy bindings");
                    if let Some(previous) = bindings.writes.get(&params.write_id) {
                        if previous.process != params.process_id || previous.digest != digest {
                            return reject(id);
                        }
                        return match &previous.reply {
                            Some(raw) => Handled::Response(Response::result(
                                id,
                                serde_json::from_str(raw.get()).expect("stored serialized ACK"),
                            )),
                            None => Handled::Unknown,
                        };
                    }
                    if bindings.writes.len() >= MAX_WRITES {
                        return busy(id);
                    }
                    bindings.writes.insert(
                        params.write_id.clone(),
                        WriteBinding {
                            process: params.process_id.clone(),
                            digest,
                            reply: None,
                        },
                    );
                }
                let Some(target) = self.target(&params.process_id) else {
                    return Handled::Response(Response::error(
                        id,
                        -32600,
                        format!("unknown process id {}", params.process_id),
                    ));
                };
                let write_id = params.write_id.clone();
                let action = LegacyAction::Write {
                    process_id: params.process_id,
                    write_id: params.write_id,
                    chunk: params.chunk,
                };
                let result = self.action(id, &target, action).await;
                if let Handled::Response(Response {
                    outcome: Outcome::Result { result: value },
                    ..
                }) = &result
                    && let Ok(raw) = serde_json::value::to_raw_value(value)
                    && raw.get().len() <= MAX_ACK_BYTES
                {
                    self.bindings
                        .lock()
                        .expect("legacy bindings")
                        .writes
                        .get_mut(&write_id)
                        .expect("registered write")
                        .reply = Some(raw);
                }
                result
            }
            "process/terminate" => {
                let Ok(params) = request.typed::<Terminate>() else {
                    return reject(id);
                };
                if !params.valid() {
                    return reject(id);
                }
                let Some(target) = self.target(&params.process_id) else {
                    return Handled::Response(Response::error(
                        id,
                        -32600,
                        format!("unknown process id {}", params.process_id),
                    ));
                };
                self.action(
                    id,
                    &target,
                    LegacyAction::Terminate {
                        process_id: params.process_id,
                    },
                )
                .await
            }
            _ => Handled::Response(Response::error(
                id,
                -32601,
                "method not supported by explicit legacy mode",
            )),
        }
    }
    async fn action(&self, id: Id, target: &ResourceTarget, action: LegacyAction) -> Handled {
        let prepared =
            match self
                .coordinator
                .prepare_legacy_action(&self.owner, target.clone(), &action)
            {
                Ok(v) => v,
                Err(_) => return busy(id),
            };
        let submitted = self.coordinator.dispatch_legacy_action(
            &self.owner,
            &prepared.id,
            prepared.payload_digest,
        );
        match submitted {
            Ok(LegacyActionSubmission::Submitted(ticket)) => match ticket.wait().await {
                Ok(done) => {
                    let _snapshot = done.snapshot;
                    let _retention_pending = done.retention_error;
                    match (done.receipt.evidence, done.raw_result) {
                        (ActionEvidence::Acknowledged, Some(value)) => {
                            Handled::Response(Response::result(id, value))
                        }
                        (ActionEvidence::NotDispatched, _) => {
                            Handled::Response(Response::error(id, -32001, "action not dispatched"))
                        }
                        _ => Handled::Unknown,
                    }
                }
                Err(_) => Handled::Unknown,
            },
            Ok(LegacyActionSubmission::Existing(snapshot)) => {
                let _ = snapshot;
                Handled::Unknown
            }
            Err(_) => Handled::Response(Response::error(id, -32001, "action not dispatched")),
        }
    }
    pub async fn run_connection(&self, link: &mut HostWssLink) -> Result<(), LegacyError> {
        let _slot = self
            .connection_slot
            .try_acquire()
            .map_err(|_| LegacyError::Busy)?;
        if link.endpoint() != self.profile.endpoint {
            return Err(LegacyError::BootstrapMismatch);
        }
        let generation = link.generation().clone();
        let sender = link.sender();
        let mut terminal = self
            .coordinator
            .legacy_terminal()
            .map_err(|_| LegacyError::BootstrapMismatch)?;
        let mut initialized = false;
        let mut handshake_done = false;
        let mut pending: FuturesUnordered<futures_util::future::BoxFuture<'_, Handled>> =
            FuturesUnordered::new();
        loop {
            let handled = tokio::select! {
                done=pending.next(),if !pending.is_empty()=>done.expect("pending nonempty"),
                event=terminal.recv()=>{
                    match event {
                        Ok(TerminalEvent::Frame(frame))=>{
                            if handshake_done&&self.target(&frame.process_id).is_some(){
                                // The original native frame and budget lease stay alive
                                // through send completion; never fabricate terminal facts.
                                sender.send_text(frame.text.to_string(),Duration::from_secs(5)).await.map_err(|_|LegacyError::OutcomeUnknown)?;
                            }
                        }
                        Ok(TerminalEvent::Lost)|Err(_)=>return Err(LegacyError::OutcomeUnknown),
                    }
                    continue;
                }
                frame=link.recv()=>{
                    let Some(frame)=frame else {return if pending.is_empty(){Ok(())}else{Err(LegacyError::OutcomeUnknown)}};
                    if frame.generation!=generation{return Err(LegacyError::InvalidFrame)}
                    let request=Request::parse(frame.as_str()).map_err(|_|LegacyError::InvalidFrame)?;
                    if request.method=="initialized"&&request.id.is_none(){
                        if !initialized||handshake_done||request.typed::<Initialized>().is_err(){return Err(LegacyError::InvalidFrame)}
                        handshake_done=true;continue;
                    }
                    let Some(id)=request.id.clone() else{return Err(LegacyError::InvalidFrame)};
                    if request.method=="initialize" {
                        if initialized||handshake_done{return Err(LegacyError::InvalidFrame)}
                        let response=self.initialize(&request,id);
                        initialized=matches!(response.outcome,Outcome::Result{..});
                        Handled::Response(response)
                    } else if !handshake_done {Handled::Response(Response::error(id,-32600,"initialize and initialized required"))}
                    else if pending.len()>=2 {busy(id)}
                    else {
                        let mut handler: futures_util::future::BoxFuture<'_,Handled>=Box::pin(self.handle(request,id));
                        // Commit admission/Host-owned jobs before observing EOF.
                        match handler.as_mut().now_or_never(){Some(done)=>done,None=>{pending.push(handler);continue;}}
                    }
                }
            };
            match handled {
                Handled::Unknown => return Err(LegacyError::OutcomeUnknown),
                Handled::Response(response) => {
                    let mut bytes = BoundedFrame(Vec::new());
                    serde_json::to_writer(&mut bytes, &response)
                        .map_err(|_| LegacyError::OutcomeUnknown)?;
                    let text =
                        String::from_utf8(bytes.0).map_err(|_| LegacyError::OutcomeUnknown)?;
                    sender
                        .send_text(text, Duration::from_secs(5))
                        .await
                        .map_err(|_| LegacyError::OutcomeUnknown)?;
                }
            }
        }
    }
}
fn reject(id: Id) -> Handled {
    Handled::Response(Response::error(id, -32602, "invalid legacy parameters"))
}
fn busy(id: Id) -> Handled {
    Handled::Response(Response::error(
        id,
        -32001,
        "legacy capacity/admission refused before dispatch",
    ))
}
struct BoundedFrame(Vec<u8>);
impl std::io::Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("legacy frame limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
mod tests;

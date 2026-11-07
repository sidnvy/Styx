//! Closed, non-authoritative native startup fault facts. No native output,
//! target identifiers, paths or credentials can enter this value.
use serde::Serialize;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeStage {
    NativeBeforeBinding,
    NativeBeforeObservation,
    NativeBeforeFinalBinding,
    SessionBinding,
    SessionBeginExchange,
    SessionBeginReply,
    ListWindowsExchange,
    ListWindowsResult,
    ListWindowsRows,
    ReadBindingAfter,
    ReadDeadline,
    NativeAfterBinding,
    NativeAfterObservation,
    NativeAfterFinalBinding,
    ConsoleMatch,
    EvidenceLookup,
    CoordinatorRefresh,
    ObservationMutex,
    ControlMutex,
    AlreadyFenced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeCause {
    NotPublished,
    Unavailable,
    NativeProtocol,
    InvalidHint,
    ImagePin,
    Signature,
    Peer,
    Fenced,
    MutexPoisoned,
    Locked,
    ConsoleChanged,
    Deadline,
    EvidenceMissing,
    EvidenceExpired,
    CoordinatorRefused,
    ReplyJson,
    ReplyRefused,
    ReplyExitCode,
    ReplyMissingResult,
    BeginReplyShape,
    WindowsReplyIsError,
    WindowsArrayMissing,
    WindowsLimit,
    WindowPidInvalid,
    WindowIdInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ProbeDiagnostic {
    pub stage: ProbeStage,
    pub cause: ProbeCause,
    pub elapsed_ms: u64,
    pub deadline_expired: bool,
}
impl ProbeDiagnostic {
    pub(crate) fn observed(
        stage: ProbeStage,
        cause: ProbeCause,
        started: Instant,
        until: Instant,
    ) -> Self {
        Self {
            stage,
            cause,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            deadline_expired: Instant::now() >= until,
        }
    }
}

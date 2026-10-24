//! Selected UWSM association through the original bounded same-image runner.
//! This port has no network input, Agent registration, Desktop Ready or action.
use super::{PinnedWorker, ProbeError, WorkerOutput, run_with};
pub use crate::platform::linux::association::{AssociationError, AssociationInspection};
use crate::platform::linux::{
    LinuxCandidate,
    association::{AssociationFacts, LinuxAssociationLease},
};
use serde::{Deserialize, Serialize};
const SELECTOR_LIMIT: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssociationProbeError {
    #[error("bounded association worker unavailable")]
    Probe(#[from] ProbeError),
    #[error("native association refused")]
    Association(#[from] AssociationError),
}
impl AssociationProbeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Probe(error) => error.code(),
            Self::Association(error) => error.code(),
        }
    }
}
/// Acceptance-only read facade. This executes the original parent runner and
/// consumes only its exact successfully waited worker output. The projection
/// cannot register an Agent or be imported as Core authority.
pub async fn inspect_candidate_association(
    candidate_json: &str,
) -> Result<AssociationInspection, AssociationProbeError> {
    let selected = decode_selector(candidate_json)?;
    let lease = probe_candidate(&selected).await?;
    Ok(lease.inspection())
}
/// Private stdout envelope: observations from this original worker, never a
/// verified flag. Only the parent runner after actual successful wait consumes it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAssociationOutput {
    schema: u16,
    facts: AssociationFacts,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAssociationRefusal {
    schema: u16,
    error: AssociationError,
}
impl WorkerAssociationRefusal {
    pub fn code(&self) -> &'static str {
        self.error.code()
    }
}

/// Hidden CLI operation. Caller performs prepare_worker_limits BEFORE creating
/// Tokio, exactly like __linux-desktop-probe. The selector only identifies a
/// candidate; the worker re-reads login facts and requires exact equality.
pub async fn worker_association(
    candidate_json: &str,
) -> Result<WorkerAssociationOutput, WorkerAssociationRefusal> {
    let result = async {
        let candidate = decode_selector(candidate_json)?;
        let facts = crate::platform::linux::association::collect_uwsm(&candidate).await?;
        Ok(WorkerAssociationOutput { schema: 1, facts })
    }
    .await;
    result.map_err(|error| WorkerAssociationRefusal { schema: 1, error })
}
fn decode_selector(json: &str) -> Result<LinuxCandidate, AssociationError> {
    if json.len() > SELECTOR_LIMIT {
        return Err(AssociationError::Capacity);
    }
    let candidate: LinuxCandidate =
        serde_json::from_str(json).map_err(|_| AssociationError::Untrusted)?;
    // Reuse only shape checks; do not fabricate a discovery/closed fact.
    if !super::candidate_shape(&candidate, nix::unistd::Uid::current().as_raw()) {
        return Err(AssociationError::Untrusted);
    }
    Ok(candidate)
}
/// Trusted runtime-only entry, not an MCP/management facts import. The SAME
/// pinned image, shared single slot, 64KiB reader, exact exit status and wait,
/// deadline, cancellation and retained cleanup ownership are used by discovery.
pub(crate) async fn probe_candidate(
    candidate: &LinuxCandidate,
) -> Result<LinuxAssociationLease, AssociationProbeError> {
    if !super::candidate_shape(candidate, nix::unistd::Uid::current().as_raw()) {
        return Err(ProbeError::InvalidFacts.into());
    }
    let selector = serde_json::to_string(candidate).map_err(|_| ProbeError::InvalidFacts)?;
    decode_selector(&selector)?;
    let mut image = PinnedWorker::current()?;
    image.args = vec![
        "__linux-desktop-association".into(),
        "--candidate".into(),
        selector.into(),
    ];
    let selected = candidate.clone();
    let result = run_with(image, move |output, end| async move {
        let facts = match decode_output(output, &selected)? {
            Ok(facts) => facts,
            Err(error) => return Ok(Err(error)),
        };
        // This function is unreachable from a directly supplied JSON value:
        // run_with produced the output only after this original Child.wait.
        Ok(LinuxAssociationLease::from_owned_collector(facts, end).await)
    })
    .await?;
    result.map_err(AssociationProbeError::Association)
}

fn decode_output(
    output: WorkerOutput,
    selected: &LinuxCandidate,
) -> Result<Result<AssociationFacts, AssociationError>, ProbeError> {
    let WorkerOutput { bytes, status } = output;
    if !status.success() {
        if status.code() == Some(2)
            && let Ok(refusal) = serde_json::from_slice::<WorkerAssociationRefusal>(&bytes)
            && refusal.schema == 1
        {
            return Ok(Err(refusal.error));
        }
        return Err(ProbeError::WorkerFailed);
    }
    let output: WorkerAssociationOutput =
        serde_json::from_slice(&bytes).map_err(|_| ProbeError::InvalidFacts)?;
    if output.schema != 1 || !output.facts.matches_candidate(selected) {
        return Err(ProbeError::InvalidFacts);
    }
    Ok(Ok(output.facts))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    #[test]
    fn selected_association_refusal_requires_exact_schema_and_wait_status() {
        // Synthetic status controls only; actual wait/source/bounds ownership
        // is exercised by the existing shared runner's subprocess aggregate.
        let candidate = LinuxCandidate {
            session_id: "owned".into(),
            uid: nix::unistd::Uid::current().as_raw(),
            seat: Some("seat0".into()),
            leader_pid: 1,
            leader_birth: 1,
            login_timestamp_monotonic: 1,
            backend: "wayland".into(),
            active: true,
            state: "active".into(),
            locked_hint: false,
            compositor_association: crate::platform::linux::Association::Unknown,
            agent_association: crate::platform::linux::Association::Unknown,
        };
        let decode = |bytes: &[u8], code: i32| {
            decode_output(
                WorkerOutput {
                    bytes: bytes.to_vec(),
                    status: std::process::ExitStatus::from_raw(code << 8),
                },
                &candidate,
            )
        };
        assert!(matches!(
            decode(br#"{"schema":1,"error":"ambiguous"}"#, 2),
            Ok(Err(AssociationError::Ambiguous))
        ));
        assert!(matches!(
            decode(br#"{"schema":1,"error":"ambiguous"}"#, 0),
            Err(ProbeError::InvalidFacts)
        ));
        assert!(matches!(
            decode(br#"{"schema":1,"error":"ambiguous"}"#, 3),
            Err(ProbeError::WorkerFailed)
        ));
        assert!(matches!(
            decode(br#"{"schema":2,"error":"ambiguous"}"#, 2),
            Err(ProbeError::WorkerFailed)
        ));
        assert!(matches!(
            decode(br#"{"schema":1,"error":"private arbitrary exception"}"#, 2),
            Err(ProbeError::WorkerFailed)
        ));
        assert!(matches!(
            decode(br#"{"schema":1,"error":"ambiguous","verified":true}"#, 2),
            Err(ProbeError::WorkerFailed)
        ));
        let selector = serde_json::to_string(&candidate).unwrap();
        assert_eq!(decode_selector(&selector).unwrap(), candidate);
        let mut wrong = candidate.clone();
        wrong.uid = wrong.uid.checked_add(1).unwrap();
        assert!(decode_selector(&serde_json::to_string(&wrong).unwrap()).is_err());
        assert!(matches!(
            decode_selector(&" ".repeat(SELECTOR_LIMIT + 1)),
            Err(AssociationError::Capacity)
        ));
    }
}

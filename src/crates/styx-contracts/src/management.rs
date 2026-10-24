//! Versioned C07 management journal intent. Decoding is never authorization,
//! ownership, reader attestation, durability, or permission to apply state.
use crate::identity::{Sha256Digest, TransactionId};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagementIntentError {
    #[error("invalid_transaction_intent")]
    InvalidIntent,
    #[error("transaction_capacity")]
    Capacity,
}
pub const MAX_INTENT_BYTES: usize = 4096;
/// Closed reader contract identifier; a DTO is not runtime reader attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaderContract {
    NativeManagementStateV1,
    /// Explicit reader barrier for an original-identity runtime cutover.
    NativeMigratedStateV1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredStateCommit {
    pub transaction_id: TransactionId,
    /// Writer-scope durable high-water sequence, not a process-local counter.
    pub sequence: u64,
    pub deployment_raw_sha256: Sha256Digest,
    pub before_state_sha256: Sha256Digest,
    pub target_state_sha256: Sha256Digest,
    pub reader: ReaderContract,
}
impl DesiredStateCommit {
    pub fn validate(&self) -> Result<(), ManagementIntentError> {
        if self.sequence == 0 || self.before_state_sha256 == self.target_state_sha256 {
            return Err(ManagementIntentError::InvalidIntent);
        }
        Ok(())
    }
    /// Thin bounded JSON adapter. Parsing a DTO never authorizes a transaction.
    pub fn decode(bytes: &[u8]) -> Result<Self, ManagementIntentError> {
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(ManagementIntentError::Capacity);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| ManagementIntentError::InvalidIntent)?;
        value.validate()?;
        Ok(value)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableStage {
    Planned,
    Prepared,
    Applied,
    Verified,
    Committed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Planned,
    Prepared,
    Applied,
    Verified,
    Committed,
    Recoverable,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalReceipt {
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub stage: DurableStage,
    /// Exact previous durable journal record, None only at Prepared.
    pub previous: Option<Sha256Digest>,
    pub record_sha256: Sha256Digest,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_exact_intent_wire_rejects_extra_fields_and_ambiguous_writes() {
        let intent = DesiredStateCommit {
            transaction_id: "management-1".try_into().unwrap(),
            sequence: 1,
            deployment_raw_sha256: Sha256Digest::of_bytes(b"deployment"),
            before_state_sha256: Sha256Digest::of_bytes(b"before"),
            target_state_sha256: Sha256Digest::of_bytes(b"target"),
            reader: ReaderContract::NativeManagementStateV1,
        };
        let bytes = serde_json::to_vec(&intent).unwrap();
        assert_eq!(DesiredStateCommit::decode(&bytes).unwrap(), intent);
        let mut value = serde_json::to_value(&intent).unwrap();
        value["permission"] = true.into();
        assert_eq!(
            DesiredStateCommit::decode(&serde_json::to_vec(&value).unwrap()),
            Err(ManagementIntentError::InvalidIntent)
        );
        assert_eq!(
            DesiredStateCommit::decode(&vec![b' '; MAX_INTENT_BYTES + 1]),
            Err(ManagementIntentError::Capacity)
        );
    }
}

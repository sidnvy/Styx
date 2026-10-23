//! Native enrollment journal DTOs. They are data, never authenticated proofs.
/// Runtime storage material. References are content-addressed within a typed
/// role; possession of a reference is not device authentication or publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialKind {
    Profile,
    Token,
    Sealed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialRef {
    pub kind: MaterialKind,
    pub digest: Sha256Digest,
}

use crate::identity::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub computer: bool,
    pub browser: bool,
}
impl Grant {
    pub fn subset_of(self, requested: Self) -> bool {
        (!self.computer || requested.computer) && (!self.browser || requested.browser)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingContext {
    pub origin: String,
    pub leaf: Sha256Digest,
    pub ingress_generation: PairingIngressGeneration,
    pub window: Option<PairingWindowId>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueProfileRef(pub Sha256Digest);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef(pub Sha256Digest);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedCredentialRef(pub Sha256Digest);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTarget {
    pub request: RequestId,
    pub device: DeviceId,
    pub fingerprint: Sha256Digest,
    pub profile: OpaqueProfileRef,
    pub pending_facts_digest: Sha256Digest,
}
pub fn join_facts_digest(facts: &JoinFacts) -> Result<Sha256Digest, serde_json::Error> {
    Ok(Sha256Digest::of_bytes(&serde_json::to_vec(facts)?))
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub hash: Sha256Digest,
    pub expires: u64,
    pub scope: Option<PairingContext>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinFacts {
    pub request: RequestId,
    pub device: DeviceId,
    pub fingerprint: Sha256Digest,
    pub invitation_hash: Sha256Digest,
    pub claim_hash: Sha256Digest,
    pub signed_payload_hash: Sha256Digest,
    pub requested: Grant,
    pub profile: OpaqueProfileRef,
    pub pairing: PairingContext,
    pub comparison: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PendingStatus {
    Pending,
    Approved {
        credential: CredentialRef,
        sealed: Option<SealedCredentialRef>,
        claim_expires: u64,
        claimed: bool,
    },
    Revoked,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub facts: JoinFacts,
    pub expires: u64,
    pub status: PendingStatus,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub grant: Grant,
    pub generation: String,
    pub credential: CredentialRef,
    pub credential_hash: Sha256Digest,
    pub profile: OpaqueProfileRef,
    pub revoked: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    Invite {
        invitation: Invitation,
    },
    CloseWindow {
        scope: Option<PairingWindowId>,
    },
    Join {
        pending: Pending,
    },
    Approve {
        request: RequestId,
        target: CredentialTarget,
        device: Device,
        sealed: SealedCredentialRef,
        claim_expires: u64,
    },
    Confirm {
        request: RequestId,
    },
    CollectPending {
        requests: Vec<RequestId>,
    },
    Revoke {
        device: DeviceId,
        fingerprint: Sha256Digest,
    },
    SelfCas {
        device: DeviceId,
        expected_generation: String,
        generation: String,
        grant: Grant,
        signed_payload_hash: Sha256Digest,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentBody {
    pub schema: u8,
    pub gateway_epoch: GatewayEpoch,
    pub transaction: TransactionId,
    pub sequence: u64,
    pub expected_revision: u64,
    pub prepared_at: u64,
    pub required_materials: Vec<MaterialRef>,
    pub mutation: Mutation,
}
pub fn allocated_identity(
    domain: &str,
    epoch: &GatewayEpoch,
    sequence: u64,
    device: Option<&DeviceId>,
) -> Result<Sha256Digest, serde_json::Error> {
    Ok(Sha256Digest::of_bytes(&serde_json::to_vec(&(
        domain, epoch, sequence, device,
    ))?))
}
pub fn encode(body: &IntentBody) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(body)
}
/// Decode only after validating the original bytes/digest. No Value roundtrip is
/// used for authority. Errors expose positions, never copied credential fields.
#[derive(Debug, thiserror::Error)]
pub enum IntentDecodeError {
    #[error("bounded schema-1 enrollment intent required")]
    Unsupported,
    #[error("invalid enrollment intent at {line}:{column}")]
    Invalid { line: usize, column: usize },
}
pub fn decode(bytes: &[u8]) -> Result<IntentBody, IntentDecodeError> {
    if bytes.len() > 16384 {
        return Err(IntentDecodeError::Unsupported);
    }
    let body: IntentBody =
        serde_json::from_slice(bytes).map_err(|e| IntentDecodeError::Invalid {
            line: e.line(),
            column: e.column(),
        })?;
    if body.schema != 1 || body.sequence == 0 || body.required_materials.len() > 8 {
        return Err(IntentDecodeError::Unsupported);
    }
    Ok(body)
}

//! Deterministic enrollment authority. Crypto, durable storage and transport
//! facts arrive only through the trusted bootstrap control, never JSON proofs.
use std::{cell::Cell, collections::BTreeMap, sync::Arc};
use styx_contracts::{
    identity::*,
    legacy::{CapabilityPayload, JoinPayload, PairingComparison},
};

use intent_contract::*;
use styx_contracts::enrollment as intent_contract;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentError {
    Authority,
    Busy,
    Capacity,
    Invalid,
    Expired,
    Conflict,
    Retired,
    Proof,
    NotFound,
    OfflineRequired,
    Clock,
    DurableMismatch,
    Recovering,
}
type Result<T> = std::result::Result<T, EnrollmentError>;
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub invitations: usize,
    pub pending: usize,
    pub devices: usize,
    pub retired: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            invitations: 64,
            pending: 64,
            devices: 1024,
            retired: 4096,
        }
    }
}
// An Arc identity is a process-local authority brand, not a bearer/cryptographic
// credential. Only the trusted bootstrap receives the control handle.
pub struct EnrollmentControl {
    brand: Arc<()>,
}
pub struct EnrollmentAdminAuthority {
    brand: Arc<()>,
}
pub struct ApprovalRequest {
    pub request: RequestId,
    pub fingerprint: Sha256Digest,
    pub comparison: String,
    pub grant: Grant,
}
pub struct PreparedCredential {
    brand: Arc<()>,
    target: CredentialTarget,
    credential: CredentialRef,
    credential_hash: Sha256Digest,
    sealed: SealedCredentialRef,
}
pub struct VerifiedJoin {
    brand: Arc<()>,
    facts: JoinFacts,
}
pub struct DeviceSelfProof {
    brand: Arc<()>,
    device: DeviceId,
    fingerprint: Sha256Digest,
    credential_hash: Sha256Digest,
}
pub struct VerifiedSelfCas {
    auth: DeviceSelfProof,
    generation: String,
    computer: Option<bool>,
    browser: Option<bool>,
    payload_hash: Sha256Digest,
}
pub struct VerifiedClaim {
    brand: Arc<()>,
    request: RequestId,
    hash: Sha256Digest,
}
pub struct VerifiedConfirmation {
    claim: VerifiedClaim,
    device: DeviceId,
    credential: CredentialRef,
}
pub struct DurableConfirmation {
    brand: Arc<()>,
    transaction: TransactionId,
    digest: Sha256Digest,
    receipt_ref: Sha256Digest,
}
pub struct ProvenNotWritten {
    brand: Arc<()>,
    transaction: TransactionId,
    digest: Sha256Digest,
}
macro_rules! redacted { ($($t:ty),*) => {$ (impl std::fmt::Debug for $t { fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result { f.write_str(concat!(stringify!($t), "([redacted])")) } })*}; }
redacted!(
    EnrollmentControl,
    EnrollmentAdminAuthority,
    PreparedCredential,
    VerifiedJoin,
    DeviceSelfProof,
    VerifiedSelfCas,
    VerifiedClaim,
    VerifiedConfirmation,
    DurableConfirmation,
    ProvenNotWritten
);

#[derive(Debug, Clone)]
pub struct PendingIntent {
    body: IntentBody,
    bytes: Arc<[u8]>,
    digest: Sha256Digest,
}
impl PendingIntent {
    pub fn body(&self) -> &IntentBody {
        &self.body
    }
    pub fn original_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}
#[derive(Debug)]
pub struct Committed {
    pub revision: u64,
    pub intent_digest: Sha256Digest,
    pub durable_receipt_ref: Sha256Digest,
    pub projection: Mutation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lane {
    Exec,
    Computer,
    Browser,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum LaneState {
    Offline,
    Connected(ConnectionGeneration),
    Unknown,
    RecoveredUnknown,
}
#[derive(Debug)]
pub struct ConnectionLease {
    brand: Arc<()>,
    device: DeviceId,
    lane: Lane,
    generation: ConnectionGeneration,
    capability_generation: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationTarget {
    pub device: DeviceId,
    pub credential: CredentialRef,
    pub already_confirmed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionObservation {
    Connected,
    Offline,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClaimView {
    Pending,
    Approved {
        credential: CredentialRef,
        sealed: SealedCredentialRef,
        device: DeviceId,
        grant: Grant,
    },
}
pub struct EnrollmentLedger {
    brand: Arc<()>,
    epoch: GatewayEpoch,
    limits: Limits,
    revision: u64,
    sequence: u64,
    time_floor: u64,
    observed_time: Cell<u64>,
    invitations: Vec<Invitation>,
    pending: BTreeMap<RequestId, Pending>,
    devices: BTreeMap<DeviceId, Device>,
    historical_revoked: BTreeMap<DeviceId, HistoricalRevoked>,
    default_device: Option<DeviceId>,
    historical_baseline: Option<HistoricalBaselineRecovery>,
    retired: Vec<Sha256Digest>,
    lanes: BTreeMap<(DeviceId, Lane), LaneState>,
    staged: Option<PendingIntent>,
    recovering: bool,
    recovered_head: Option<Sha256Digest>,
}
fn exact_request(id: &RequestId) -> bool {
    id.as_str().len() == 32
        && id
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn generation(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128
}
impl EnrollmentControl {
    pub fn admin(&self) -> EnrollmentAdminAuthority {
        EnrollmentAdminAuthority {
            brand: self.brand.clone(),
        }
    }
    /// Runtime generated/prepared one credential and sealed THAT credential
    /// to the verified original device key. This is not caller-provided auth.
    pub fn attest_prepared_credential(
        &self,
        target: CredentialTarget,
        credential: CredentialRef,
        credential_hash: Sha256Digest,
        sealed: SealedCredentialRef,
    ) -> Result<PreparedCredential> {
        Ok(PreparedCredential {
            brand: self.brand.clone(),
            target,
            credential,
            credential_hash,
            sealed,
        })
    }
    /// Trusted runtime has verified legacy PSS, key size, SPKI fingerprint, path
    /// schema and actual listener facts BEFORE calling this attestation port.
    pub fn attest_join(
        &self,
        payload: &JoinPayload,
        fingerprint: Sha256Digest,
        request: RequestId,
        claim_hash: Sha256Digest,
        profile: OpaqueProfileRef,
        pairing: PairingContext,
    ) -> Result<VerifiedJoin> {
        let field_bytes = [
            &payload.invitation,
            &payload.label,
            &payload.platform,
            &payload.cwd,
            &payload.shell,
            &payload.public_key_pem,
        ]
        .into_iter()
        .try_fold(0usize, |n, s| n.checked_add(s.len()))
        .ok_or(EnrollmentError::Capacity)?;
        if field_bytes > 16 * 1024 || pairing.origin.len() > 2048 {
            return Err(EnrollmentError::Invalid);
        }
        let bytes = payload
            .signing_bytes()
            .map_err(|_| EnrollmentError::Invalid)?;
        if bytes.len() > 16 * 1024 || !exact_request(&request) {
            return Err(EnrollmentError::Invalid);
        }
        let comparison = PairingComparison {
            gateway_origin: pairing.origin.clone(),
            certificate_sha256: pairing.leaf,
            request_id: request.as_str().to_owned(),
            device_fingerprint: fingerprint,
        }
        .comparison_code()
        .map_err(|_| EnrollmentError::Invalid)?;
        Ok(VerifiedJoin {
            brand: self.brand.clone(),
            facts: JoinFacts {
                request,
                device: payload.device_id.clone(),
                fingerprint,
                invitation_hash: Sha256Digest::of_bytes(payload.invitation.as_bytes()),
                claim_hash,
                signed_payload_hash: Sha256Digest::of_bytes(&bytes),
                requested: Grant {
                    computer: payload.computer_requested,
                    browser: payload.browser_requested == Some(true),
                },
                profile,
                pairing,
                comparison,
            },
        })
    }
    /// Trusted protected-reader authentication, NOT a JSON factory or MCP owner.
    pub fn attest_device(
        &self,
        device: DeviceId,
        fingerprint: Sha256Digest,
        credential_hash: Sha256Digest,
    ) -> DeviceSelfProof {
        DeviceSelfProof {
            brand: self.brand.clone(),
            device,
            fingerprint,
            credential_hash,
        }
    }
    /// PSS signature and exact device bearer checked by trusted runtime first.
    pub fn attest_self_cas(
        &self,
        payload: &CapabilityPayload,
        credential_hash: Sha256Digest,
    ) -> Result<VerifiedSelfCas> {
        let bytes = payload
            .signing_bytes()
            .map_err(|_| EnrollmentError::Invalid)?;
        if !generation(&payload.generation) {
            return Err(EnrollmentError::Invalid);
        }
        Ok(VerifiedSelfCas {
            auth: self.attest_device(
                payload.device_id.clone(),
                payload.fingerprint,
                credential_hash,
            ),
            generation: payload.generation.clone(),
            computer: payload.enable_computer,
            browser: payload.enable_browser,
            payload_hash: Sha256Digest::of_bytes(&bytes),
        })
    }
    pub fn attest_claim(&self, request: RequestId, claim_hash: Sha256Digest) -> VerifiedClaim {
        VerifiedClaim {
            brand: self.brand.clone(),
            request,
            hash: claim_hash,
        }
    }
    /// Runtime has verified HMAC with the SAME persisted credential referenced
    /// by `credential`, over the exact legacy request-id domain.
    pub fn attest_confirmation(
        &self,
        claim: VerifiedClaim,
        device: DeviceId,
        credential: CredentialRef,
    ) -> Result<VerifiedConfirmation> {
        if !Arc::ptr_eq(&self.brand, &claim.brand) {
            return Err(EnrollmentError::Authority);
        }
        Ok(VerifiedConfirmation {
            claim,
            device,
            credential,
        })
    }
    /// This method is ONLY called after a real journal/storage durability proof.
    /// No default implementation, boolean network receipt, or timer invokes it.
    pub fn attest_durable(
        &self,
        intent: &PendingIntent,
        receipt_ref: Sha256Digest,
    ) -> DurableConfirmation {
        DurableConfirmation {
            brand: self.brand.clone(),
            transaction: intent.body.transaction.clone(),
            digest: intent.digest,
            receipt_ref,
        }
    }
    /// Strong pre-I/O/noncommit recovery proof only; ordinary I/O error or
    /// timeout is not evidence sufficient to un-fence a transaction.
    pub fn attest_not_written(&self, intent: &PendingIntent) -> ProvenNotWritten {
        ProvenNotWritten {
            brand: self.brand.clone(),
            transaction: intent.body.transaction.clone(),
            digest: intent.digest,
        }
    }
}
impl EnrollmentLedger {
    /// Production starts closed until the trusted store adapter proves the complete
    /// original journal, material references and clock high-water mark.
    pub fn new_recovering(
        epoch: GatewayEpoch,
        limits: Limits,
    ) -> Result<(Self, EnrollmentControl)> {
        if limits.invitations == 0
            || limits.invitations > 64
            || limits.pending == 0
            || limits.pending > 64
            || limits.devices == 0
            || limits.devices > 4096
            || limits.retired == 0
            || limits.retired > 8192
        {
            return Err(EnrollmentError::Invalid);
        }
        let brand = Arc::new(());
        let control = EnrollmentControl {
            brand: brand.clone(),
        };
        Ok((
            Self {
                brand,
                epoch,
                limits,
                revision: 0,
                sequence: 0,
                time_floor: 0,
                observed_time: Cell::new(0),
                invitations: vec![],
                pending: BTreeMap::new(),
                devices: BTreeMap::new(),
                historical_revoked: BTreeMap::new(),
                default_device: None,
                historical_baseline: None,
                retired: vec![],
                lanes: BTreeMap::new(),
                staged: None,
                recovering: true,
                recovered_head: None,
            },
            control,
        ))
    }
    #[cfg(test)]
    fn new_owned(epoch: GatewayEpoch, limits: Limits) -> Result<(Self, EnrollmentControl)> {
        let (mut ledger, control) = Self::new_recovering(epoch, limits)?;
        ledger.recovering = false;
        Ok((ledger, control))
    }
    fn available(&self) -> Result<()> {
        if self.recovering {
            Err(EnrollmentError::Recovering)
        } else {
            Ok(())
        }
    }
    fn brand(&self, b: &Arc<()>) -> Result<()> {
        if Arc::ptr_eq(&self.brand, b) {
            Ok(())
        } else {
            Err(EnrollmentError::Authority)
        }
    }
    fn observe_time(&self, now: u64) -> Result<()> {
        if now < self.time_floor.max(self.observed_time.get()) {
            return Err(EnrollmentError::Clock);
        }
        self.observed_time.set(now);
        Ok(())
    }
    fn ready(&self, now: u64) -> Result<()> {
        self.available()?;
        self.observe_time(now)?;
        if self.staged.is_some() {
            Err(EnrollmentError::Busy)
        } else {
            Ok(())
        }
    }
    fn next_generation(&self, device: &DeviceId) -> Result<String> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(EnrollmentError::Capacity)?;
        Ok(format!(
            "capability-{}",
            intent_contract::allocated_identity(
                "styx-enrollment-capability-generation-v1",
                &self.epoch,
                next,
                Some(device)
            )
            .map_err(|_| EnrollmentError::Invalid)?
            .to_hex()
        ))
    }
    fn required_materials(&self, mutation: &Mutation) -> Result<Vec<MaterialRef>> {
        let device = match mutation {
            Mutation::SelfCas { device, .. } => {
                Some(self.devices.get(device).ok_or(EnrollmentError::NotFound)?)
            }
            Mutation::Confirm { request } => {
                let pending = self.pending.get(request).ok_or(EnrollmentError::NotFound)?;
                Some(
                    self.devices
                        .get(&pending.facts.device)
                        .ok_or(EnrollmentError::NotFound)?,
                )
            }
            _ => None,
        };
        let mut refs = Vec::new();
        if let Some(device) = device {
            refs.push(MaterialRef {
                kind: MaterialKind::Profile,
                digest: device.profile.0,
            });
            refs.push(MaterialRef {
                kind: MaterialKind::Token,
                digest: device.credential.0,
            });
        }
        match mutation {
            Mutation::Join { pending } => refs.push(MaterialRef {
                kind: MaterialKind::Profile,
                digest: pending.facts.profile.0,
            }),
            Mutation::Approve { device, sealed, .. } => {
                refs.push(MaterialRef {
                    kind: MaterialKind::Profile,
                    digest: device.profile.0,
                });
                refs.push(MaterialRef {
                    kind: MaterialKind::Token,
                    digest: device.credential.0,
                });
                refs.push(MaterialRef {
                    kind: MaterialKind::Sealed,
                    digest: sealed.0,
                });
            }
            _ => {}
        }
        Ok(refs)
    }
    fn stage(&mut self, now: u64, mutation: Mutation) -> Result<PendingIntent> {
        self.ready(now)?;
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(EnrollmentError::Capacity)?;
        self.revision
            .checked_add(1)
            .ok_or(EnrollmentError::Capacity)?;
        let body = IntentBody {
            schema: 1,
            gateway_epoch: self.epoch.clone(),
            transaction: TransactionId::try_from(format!(
                "enrollment-{}",
                intent_contract::allocated_identity(
                    "styx-enrollment-transaction-v1",
                    &self.epoch,
                    next,
                    None
                )
                .map_err(|_| EnrollmentError::Invalid)?
                .to_hex()
            ))
            .map_err(|_| EnrollmentError::Invalid)?,
            sequence: next,
            expected_revision: self.revision,
            prepared_at: now,
            required_materials: self.required_materials(&mutation)?,
            mutation,
        };
        self.validate_historical(&body)?;
        let bytes = intent_contract::encode(&body).map_err(|_| EnrollmentError::Invalid)?;
        if bytes.len() > 16 * 1024 {
            return Err(EnrollmentError::Capacity);
        }
        let intent = PendingIntent {
            digest: Sha256Digest::of_bytes(&bytes),
            bytes: bytes.into(),
            body,
        };
        self.sequence = next;
        self.staged = Some(intent.clone());
        Ok(intent)
    }
    pub fn pending_intent(&self) -> Option<&PendingIntent> {
        self.staged.as_ref()
    }
    pub fn invite(
        &mut self,
        admin: &EnrollmentAdminAuthority,
        hash: Sha256Digest,
        ttl_seconds: u64,
        scope: Option<PairingContext>,
        now: u64,
    ) -> Result<PendingIntent> {
        self.brand(&admin.brand)?;
        self.ready(now)?;
        if !(60..=600).contains(&ttl_seconds) || self.invitations.iter().any(|i| i.hash == hash) {
            return Err(EnrollmentError::Invalid);
        }
        if let Some(s) = &scope {
            if s.window.is_none() || s.origin.len() > 2048 {
                return Err(EnrollmentError::Invalid);
            }
            PairingComparison {
                gateway_origin: s.origin.clone(),
                certificate_sha256: s.leaf,
                request_id: "0123456789abcdef0123456789abcdef".into(),
                device_fingerprint: hash,
            }
            .comparison_code()
            .map_err(|_| EnrollmentError::Invalid)?;
        }
        if self.invitations.iter().filter(|i| i.expires > now).count() >= self.limits.invitations {
            return Err(EnrollmentError::Capacity);
        }
        let expires = now
            .checked_add(ttl_seconds * 1000)
            .ok_or(EnrollmentError::Clock)?;
        self.stage(
            now,
            Mutation::Invite {
                invitation: Invitation {
                    hash,
                    expires,
                    scope,
                },
            },
        )
    }
    pub fn close_window(
        &mut self,
        admin: &EnrollmentAdminAuthority,
        window: Option<PairingWindowId>,
        now: u64,
    ) -> Result<PendingIntent> {
        self.brand(&admin.brand)?;
        self.stage(now, Mutation::CloseWindow { scope: window })
    }
    pub fn join(&mut self, proof: VerifiedJoin, now: u64) -> Result<PendingIntent> {
        self.brand(&proof.brand)?;
        self.ready(now)?;
        let f = proof.facts;
        let invite = self
            .invitations
            .iter()
            .find(|i| i.hash == f.invitation_hash && i.expires > now)
            .ok_or(EnrollmentError::Expired)?;
        if invite.scope.as_ref().is_some_and(|s| s != &f.pairing) {
            return Err(EnrollmentError::Proof);
        }
        if self.retired.contains(&f.fingerprint) {
            return Err(EnrollmentError::Retired);
        }
        if self.pending.contains_key(&f.request)
            || self
                .pending
                .values()
                .any(|p| p.facts.device == f.device || p.facts.fingerprint == f.fingerprint)
            || self.registered_identity_conflict(&f.device, f.fingerprint)
        {
            return Err(EnrollmentError::Conflict);
        }
        // Bound the ENTIRE retained collection, not merely its active subset.
        if self.pending.len() >= self.limits.pending {
            return Err(EnrollmentError::Capacity);
        }
        let expires = now
            .checked_add(15 * 60 * 1000)
            .ok_or(EnrollmentError::Clock)?;
        self.stage(
            now,
            Mutation::Join {
                pending: Pending {
                    facts: f,
                    expires,
                    status: PendingStatus::Pending,
                },
            },
        )
    }
    fn target(pending: &Pending) -> Result<CredentialTarget> {
        let f = &pending.facts;
        Ok(CredentialTarget {
            request: f.request.clone(),
            device: f.device.clone(),
            fingerprint: f.fingerprint,
            profile: f.profile.clone(),
            pending_facts_digest: intent_contract::join_facts_digest(f)
                .map_err(|_| EnrollmentError::Invalid)?,
        })
    }
    /// Opaque references produced asynchronously must carry this exact target.
    pub fn approval_target(
        &self,
        admin: &EnrollmentAdminAuthority,
        request: &RequestId,
    ) -> Result<CredentialTarget> {
        self.available()?;
        self.brand(&admin.brand)?;
        let p = self.pending.get(request).ok_or(EnrollmentError::NotFound)?;
        if p.status != PendingStatus::Pending {
            return Err(EnrollmentError::Proof);
        }
        Self::target(p)
    }
    pub fn approve(
        &mut self,
        admin: &EnrollmentAdminAuthority,
        request: ApprovalRequest,
        prepared: PreparedCredential,
        now: u64,
    ) -> Result<PendingIntent> {
        self.brand(&prepared.brand)?;
        let ApprovalRequest {
            request,
            fingerprint,
            comparison,
            grant,
        } = request;
        let PreparedCredential {
            target,
            credential,
            credential_hash,
            sealed,
            ..
        } = prepared;
        self.brand(&admin.brand)?;
        self.ready(now)?;
        let p = self
            .pending
            .get(&request)
            .ok_or(EnrollmentError::NotFound)?;
        if p.expires <= now {
            return Err(EnrollmentError::Expired);
        }
        if p.status != PendingStatus::Pending
            || p.facts.fingerprint != fingerprint
            || p.facts.comparison != comparison
        {
            return Err(EnrollmentError::Proof);
        }
        if target != Self::target(p)? {
            return Err(EnrollmentError::Proof);
        }
        if !grant.subset_of(p.facts.requested) {
            return Err(EnrollmentError::Invalid);
        }
        // Reserve a retirement slot BEFORE publishing the new credential.
        // Every approved active key must remain revocable at full capacity.
        let active = self.devices.values().filter(|d| !d.revoked).count();
        if self.registered_identity_conflict(&p.facts.device, fingerprint) {
            return Err(EnrollmentError::Conflict);
        }
        if self.retained_device_count() >= self.limits.devices
            || self
                .retired
                .len()
                .checked_add(active)
                .ok_or(EnrollmentError::Capacity)?
                >= self.limits.retired
        {
            return Err(EnrollmentError::Capacity);
        }
        let new_generation = self.next_generation(&p.facts.device)?;
        let device = Device {
            id: p.facts.device.clone(),
            fingerprint,
            grant,
            generation: new_generation,
            credential,
            credential_hash,
            profile: p.facts.profile.clone(),
            revoked: false,
        };
        self.stage(
            now,
            Mutation::Approve {
                request: request.clone(),
                target,
                device,
                sealed,
                claim_expires: now
                    .checked_add(20 * 60 * 1000)
                    .ok_or(EnrollmentError::Clock)?,
            },
        )
    }
    fn verified_claim(&self, proof: &VerifiedClaim, now: u64) -> Result<&Pending> {
        self.available()?;
        self.brand(&proof.brand)?;
        let p = self
            .pending
            .get(&proof.request)
            .filter(|p| p.facts.claim_hash == proof.hash)
            .ok_or(EnrollmentError::Proof)?;
        self.observe_time(now)?;
        if self.fenced(&p.facts.device) {
            return Err(EnrollmentError::Busy);
        }
        Ok(p)
    }
    pub fn claim(&self, proof: &VerifiedClaim, now: u64) -> Result<ClaimView> {
        let p = self.verified_claim(proof, now)?;
        match &p.status {
            PendingStatus::Pending if p.expires > now => Ok(ClaimView::Pending),
            PendingStatus::Approved {
                credential,
                sealed: Some(sealed),
                claim_expires,
                ..
            } if *claim_expires > now => {
                let d = self
                    .devices
                    .get(&p.facts.device)
                    .filter(|d| !d.revoked && d.credential == *credential)
                    .ok_or(EnrollmentError::Proof)?;
                Ok(ClaimView::Approved {
                    credential: credential.clone(),
                    sealed: sealed.clone(),
                    device: d.id.clone(),
                    grant: d.grant,
                })
            }
            _ => Err(EnrollmentError::Expired),
        }
    }
    /// Claim authentication for confirmation also works after a lost successful
    /// confirmation response; it does not re-expose a removed sealed credential.
    pub fn confirmation_target(
        &self,
        proof: &VerifiedClaim,
        now: u64,
    ) -> Result<ConfirmationTarget> {
        let p = self.verified_claim(proof, now)?;
        let PendingStatus::Approved {
            credential,
            claim_expires,
            claimed,
            ..
        } = &p.status
        else {
            return Err(EnrollmentError::Proof);
        };
        if *claim_expires <= now {
            return Err(EnrollmentError::Expired);
        }
        let d = self
            .devices
            .get(&p.facts.device)
            .filter(|d| !d.revoked && d.credential == *credential)
            .ok_or(EnrollmentError::Proof)?;
        Ok(ConfirmationTarget {
            device: d.id.clone(),
            credential: credential.clone(),
            already_confirmed: *claimed,
        })
    }
    pub fn pending_for_admin(
        &self,
        admin: &EnrollmentAdminAuthority,
        now: u64,
    ) -> Result<Vec<Pending>> {
        self.available()?;
        self.brand(&admin.brand)?;
        self.observe_time(now)?;
        Ok(self
            .pending
            .values()
            .filter(|p| p.status == PendingStatus::Pending && p.expires > now)
            .cloned()
            .collect())
    }
    pub fn devices_for_admin(&self, admin: &EnrollmentAdminAuthority) -> Result<Vec<Device>> {
        self.available()?;
        self.brand(&admin.brand)?;
        Ok(self.devices.values().cloned().collect())
    }
    /// Full bounded private boot inventory, never an ordinary MCP/admin DTO.
    pub fn recovery_pending(&self, control: &EnrollmentControl) -> Result<Vec<Pending>> {
        self.brand(&control.brand)?;
        Ok(self.pending.values().cloned().collect())
    }
    /// Protected-reader lookup only. Possession of this DTO is not device auth;
    /// runtime must verify the actual bearer before calling attest_device.
    pub fn authentication_target(
        &self,
        control: &EnrollmentControl,
        id: &DeviceId,
    ) -> Result<Device> {
        self.available()?;
        self.brand(&control.brand)?;
        self.devices
            .get(id)
            .filter(|d| !d.revoked)
            .cloned()
            .ok_or(EnrollmentError::Proof)
    }
    pub fn connection_observations(
        &self,
        proof: &DeviceSelfProof,
    ) -> Result<[ConnectionObservation; 3]> {
        let d = self.device_proof(proof)?;
        Ok([Lane::Exec, Lane::Computer, Lane::Browser].map(|lane| {
            match self.lanes.get(&(d.id.clone(), lane)) {
                Some(LaneState::Connected(_)) => ConnectionObservation::Connected,
                Some(LaneState::Offline) => ConnectionObservation::Offline,
                _ => ConnectionObservation::Unknown,
            }
        }))
    }
    pub fn confirm(&mut self, proof: VerifiedConfirmation, now: u64) -> Result<PendingIntent> {
        self.ready(now)?;
        let p = self.verified_claim(&proof.claim, now)?;
        let PendingStatus::Approved {
            credential,
            claim_expires,
            ..
        } = &p.status
        else {
            return Err(EnrollmentError::Proof);
        };
        if *claim_expires <= now {
            return Err(EnrollmentError::Expired);
        }
        if proof.device != p.facts.device
            || *credential != proof.credential
            || self
                .devices
                .get(&proof.device)
                .is_none_or(|d| d.revoked || d.credential != proof.credential)
        {
            return Err(EnrollmentError::Proof);
        }
        self.stage(
            now,
            Mutation::Confirm {
                request: proof.claim.request,
            },
        )
    }
    fn device_proof(&self, p: &DeviceSelfProof) -> Result<&Device> {
        self.available()?;
        self.brand(&p.brand)?;
        if self.fenced(&p.device) {
            return Err(EnrollmentError::Busy);
        }
        self.devices
            .get(&p.device)
            .filter(|d| {
                !d.revoked
                    && d.fingerprint == p.fingerprint
                    && d.credential_hash == p.credential_hash
            })
            .ok_or(EnrollmentError::Proof)
    }
    pub fn self_device(&self, proof: &DeviceSelfProof) -> Result<&Device> {
        self.device_proof(proof)
    }
    fn fenced(&self, id: &DeviceId) -> bool {
        self.staged
            .as_ref()
            .is_some_and(|s| match &s.body.mutation {
                Mutation::Approve { device, .. } => &device.id == id,
                Mutation::SelfCas { device, .. } | Mutation::Revoke { device, .. } => device == id,
                _ => false,
            })
    }
    pub fn self_cas(&mut self, proof: VerifiedSelfCas, now: u64) -> Result<PendingIntent> {
        self.ready(now)?;
        let d = self.device_proof(&proof.auth)?;
        if d.generation != proof.generation {
            return Err(EnrollmentError::Conflict);
        }
        let new_generation = self.next_generation(&d.id)?;
        if proof.browser.is_some()
            && [Lane::Exec, Lane::Computer, Lane::Browser]
                .into_iter()
                .any(|l| self.lanes.get(&(d.id.clone(), l)) != Some(&LaneState::Offline))
        {
            return Err(EnrollmentError::OfflineRequired);
        }
        let grant = Grant {
            computer: proof.computer.unwrap_or(d.grant.computer),
            browser: proof.browser.unwrap_or(d.grant.browser),
        };
        self.stage(
            now,
            Mutation::SelfCas {
                device: d.id.clone(),
                expected_generation: proof.generation,
                generation: new_generation,
                grant,
                signed_payload_hash: proof.payload_hash,
            },
        )
    }
    /// Persist bounded metadata collection after the original claim window.
    /// Devices/tombstones are never evicted to make room for new identities.
    pub fn collect_pending(
        &mut self,
        admin: &EnrollmentAdminAuthority,
        now: u64,
    ) -> Result<PendingIntent> {
        self.brand(&admin.brand)?;
        self.ready(now)?;
        let requests = self
            .pending
            .iter()
            .filter_map(|(id, p)| {
                let expired = match p.status {
                    PendingStatus::Pending => p.expires <= now,
                    PendingStatus::Approved { claim_expires, .. } => claim_expires <= now,
                    PendingStatus::Revoked => true,
                };
                expired.then(|| id.clone())
            })
            .collect::<Vec<_>>();
        if requests.is_empty() {
            return Err(EnrollmentError::NotFound);
        }
        self.stage(now, Mutation::CollectPending { requests })
    }
    /// Required per accepted frame: queued disconnect is not authorization.
    pub fn authorize_connection(&self, lease: &ConnectionLease) -> Result<&Device> {
        self.available()?;
        self.brand(&lease.brand)?;
        if self.fenced(&lease.device) {
            return Err(EnrollmentError::Busy);
        }
        let d = self
            .devices
            .get(&lease.device)
            .ok_or(EnrollmentError::Proof)?;
        if d.revoked
            || (lease.lane == Lane::Computer && !d.grant.computer)
            || (lease.lane == Lane::Browser && !d.grant.browser)
            || d.generation != lease.capability_generation
        {
            return Err(EnrollmentError::Proof);
        }
        if self.lanes.get(&(lease.device.clone(), lease.lane))
            != Some(&LaneState::Connected(lease.generation.clone()))
        {
            return Err(EnrollmentError::Conflict);
        }
        Ok(d)
    }
    pub fn admit_connection(
        &mut self,
        proof: DeviceSelfProof,
        lane: Lane,
        generation: ConnectionGeneration,
    ) -> Result<ConnectionLease> {
        let d = self.device_proof(&proof)?;
        if (lane == Lane::Computer && !d.grant.computer)
            || (lane == Lane::Browser && !d.grant.browser)
        {
            return Err(EnrollmentError::Proof);
        }
        let capability_generation = d.generation.clone();
        let key = (d.id.clone(), lane);
        if self.lanes.get(&key) != Some(&LaneState::Offline) {
            return Err(EnrollmentError::Conflict);
        }
        self.lanes
            .insert(key, LaneState::Connected(generation.clone()));
        Ok(ConnectionLease {
            brand: self.brand.clone(),
            device: proof.device,
            lane,
            generation,
            capability_generation,
        })
    }
    /// Only the exact admitted generation may report offline/uncertain. An old
    /// socket's close cannot make a new connection look offline.
    pub fn connection_ended(
        &mut self,
        lease: ConnectionLease,
        certainly_closed: bool,
    ) -> Result<()> {
        self.available()?;
        self.brand(&lease.brand)?;
        let key = (lease.device, lease.lane);
        if self.lanes.get(&key) != Some(&LaneState::Connected(lease.generation)) {
            return Err(EnrollmentError::Conflict);
        }
        self.lanes.insert(
            key,
            if certainly_closed {
                LaneState::Offline
            } else {
                LaneState::Unknown
            },
        );
        Ok(())
    }
    pub fn revoke(
        &mut self,
        admin: &EnrollmentAdminAuthority,
        id: &DeviceId,
        now: u64,
    ) -> Result<PendingIntent> {
        self.brand(&admin.brand)?;
        self.ready(now)?;
        let d = self
            .devices
            .get(id)
            .filter(|d| !d.revoked)
            .ok_or(EnrollmentError::NotFound)?;
        if self.retired.len() >= self.limits.retired && !self.retired.contains(&d.fingerprint) {
            return Err(EnrollmentError::Capacity);
        }
        self.stage(
            now,
            Mutation::Revoke {
                device: id.clone(),
                fingerprint: d.fingerprint,
            },
        )
    }
    pub fn confirm_durable(&mut self, proof: DurableConfirmation) -> Result<Committed> {
        self.available()?;
        self.brand(&proof.brand)?;
        let staged = self.staged.as_ref().ok_or(EnrollmentError::NotFound)?;
        if staged.digest != proof.digest
            || staged.body.transaction != proof.transaction
            || staged.body.expected_revision != self.revision
        {
            return Err(EnrollmentError::DurableMismatch);
        }
        // Stage/recover_unresolved already validated this private immutable
        // intent against the unchanged revision. A later durable clock floor
        // must not invalidate settlement of an older Unknown transaction.
        let staged = self.staged.take().ok_or(EnrollmentError::NotFound)?;
        let mutation = staged.body.mutation;
        self.apply_validated(&mutation, staged.body.prepared_at);
        self.revision += 1;
        self.time_floor = self.time_floor.max(staged.body.prepared_at);
        Ok(Committed {
            revision: self.revision,
            intent_digest: staged.digest,
            durable_receipt_ref: proof.receipt_ref,
            projection: mutation,
        })
    }
    // Call only after validate_historical succeeds against unchanged state.
    // Recovery never calls the normal staged/brand path with deserialized proofs.
    fn apply_validated(&mut self, mutation: &Mutation, prepared_at: u64) {
        match &mutation {
            Mutation::Invite { invitation } => {
                self.invitations.retain(|i| i.expires > prepared_at);
                self.invitations.push(invitation.clone());
            }
            Mutation::CloseWindow { scope } => self.invitations.retain(|i| match scope {
                None => i.scope.is_some(),
                Some(window) => i.scope.as_ref().and_then(|s| s.window.as_ref()) != Some(window),
            }),
            Mutation::CollectPending { requests } => {
                for id in requests {
                    self.pending.remove(id);
                }
            }
            Mutation::Join { pending } => {
                self.invitations
                    .retain(|i| i.hash != pending.facts.invitation_hash);
                self.pending
                    .insert(pending.facts.request.clone(), pending.clone());
            }
            Mutation::Approve {
                request,
                device,
                sealed,
                claim_expires,
                ..
            } => {
                if let Some(pending) = self.pending.get_mut(request) {
                    pending.status = PendingStatus::Approved {
                        credential: device.credential.clone(),
                        sealed: Some(sealed.clone()),
                        claim_expires: *claim_expires,
                        claimed: false,
                    };
                }
                for lane in [Lane::Exec, Lane::Computer, Lane::Browser] {
                    self.lanes
                        .insert((device.id.clone(), lane), LaneState::Offline);
                }
                self.devices.insert(device.id.clone(), device.clone());
            }
            Mutation::Confirm { request } => {
                if let Some(Pending {
                    status:
                        PendingStatus::Approved {
                            sealed, claimed, ..
                        },
                    ..
                }) = self.pending.get_mut(request)
                {
                    *sealed = None;
                    *claimed = true;
                }
            }
            Mutation::Revoke {
                device,
                fingerprint,
            } => {
                if self.default_device.as_ref() == Some(device) {
                    self.default_device = None;
                }
                if let Some(d) = self.devices.get_mut(device) {
                    d.revoked = true;
                }
                if !self.retired.contains(fingerprint) {
                    self.retired.push(*fingerprint);
                }
                self.pending.retain(|_, p| &p.facts.device != device);
            }
            Mutation::SelfCas {
                device,
                generation,
                grant,
                ..
            } => {
                if let Some(d) = self.devices.get_mut(device) {
                    d.generation = generation.clone();
                    d.grant = *grant;
                }
            }
        }
    }
    pub fn abort_proven_not_written(&mut self, proof: ProvenNotWritten) -> Result<()> {
        self.available()?;
        self.brand(&proof.brand)?;
        let staged = self.staged.as_ref().ok_or(EnrollmentError::NotFound)?;
        if staged.digest != proof.digest || staged.body.transaction != proof.transaction {
            return Err(EnrollmentError::DurableMismatch);
        }
        self.staged = None;
        Ok(())
    }
}
mod historical;
pub use historical::{HistoricalBaselineRecovery, HistoricalRevoked, validate_historical_baseline};
mod recovery;
pub use recovery::{RecoveredLaneClosure, RecoveryClosure, RecoveryRecord, RecoveryUnresolved};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

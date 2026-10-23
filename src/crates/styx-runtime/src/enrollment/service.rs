//! Synchronous enrollment authority, intended for bounded spawn_blocking callers.
//! Core owns policy; protected journal evidence precedes every publication. No
//! HTTP cancellation/response failure reverses or replays a committed mutation.
use super::{
    profile::{self, VerifiedProfile},
    recovery,
};
use crate::{
    crypto::{ClaimCapability, ClaimConfirmation, EnrollmentRequestId},
    gateway::auth::GatewayBearerPolicy,
    store::enrollment::{JournalError, MaterialKind, MaterialRef, OwnedEnrollmentJournal},
};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{
    HeaderMap, Method,
    header::{AUTHORIZATION, HOST, ORIGIN},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    enrollment::*,
    identity::*,
    legacy::{CapabilityPayload, JoinPayload},
};
use styx_core::enrollment::{
    ConnectionLease, ConnectionObservation, DeviceSelfProof, EnrollmentControl, EnrollmentError,
    EnrollmentLedger, Lane, Limits, PendingIntent,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("{code}")]
pub struct ServiceError {
    status: u16,
    code: &'static str,
}
impl ServiceError {
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    fn new(status: u16, code: &'static str) -> Self {
        Self { status, code }
    }
}
impl From<EnrollmentError> for ServiceError {
    fn from(e: EnrollmentError) -> Self {
        use EnrollmentError::*;
        match e {
            Authority | Proof => Self::new(403, "invalid_identity_proof"),
            Busy => Self::new(409, "enrollment_transaction_unresolved"),
            Capacity => Self::new(429, "enrollment_capacity"),
            Invalid => Self::new(400, "invalid_enrollment"),
            Expired => Self::new(403, "claim_or_invitation_expired"),
            Conflict => Self::new(409, "capability_revision_mismatch"),
            Retired => Self::new(403, "device_identity_retired"),
            NotFound => Self::new(404, "device_or_request_not_found"),
            OfflineRequired => Self::new(409, "browser_capability_all_connections_must_be_offline"),
            Clock => Self::new(503, "enrollment_clock_unproven"),
            DurableMismatch | Recovering => Self::new(503, "enrollment_recovery_required"),
        }
    }
}
impl From<JournalError> for ServiceError {
    fn from(_: JournalError) -> Self {
        Self::new(503, "enrollment_store_unproven")
    }
}
fn invalid() -> ServiceError {
    ServiceError::new(400, "invalid_fields")
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ServiceError> {
    if bytes.len() > 16 * 1024 {
        return Err(ServiceError::new(413, "body_too_large"));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid())
}
fn validate_request(id: &RequestId) -> Result<(), ServiceError> {
    EnrollmentRequestId::parse(id.as_str())
        .map(|_| ())
        .map_err(|_| ServiceError::new(400, "invalid_request_id"))
}
fn validate_claim(id: &RequestId, secret: &str) -> Result<(), ServiceError> {
    validate_request(id)?;
    if !(32..=4096).contains(&secret.len())
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(ServiceError::new(403, "invalid_claim_secret"));
    }
    Ok(())
}
fn join_failure(error: profile::ProfileError) -> ServiceError {
    use profile::ProfileError::*;
    match error {
        Proof => ServiceError::new(403, "invalid_identity_proof"),
        Signature => ServiceError::new(400, "invalid_signature"),
        Size => ServiceError::new(413, "body_too_large"),
        DeviceId => ServiceError::new(400, "invalid_device_id"),
        Invitation => ServiceError::new(400, "invalid_invitation"),
        Label => ServiceError::new(400, "invalid_label"),
        Platform => ServiceError::new(400, "invalid_platform"),
        Cwd => ServiceError::new(400, "invalid_cwd"),
        Shell => ServiceError::new(400, "unsupported_shell"),
        PublicKey | Fingerprint => ServiceError::new(400, "invalid_public_key"),
        Internal => ServiceError::new(503, "profile_validator_unavailable"),
        _ => ServiceError::new(400, "invalid_fields"),
    }
}
fn secret(bytes: usize) -> Result<Zeroizing<String>, ServiceError> {
    let mut raw = Zeroizing::new(vec![0u8; bytes]);
    getrandom::fill(&mut raw).map_err(|_| ServiceError::new(503, "entropy_unavailable"))?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(&*raw)))
}
fn wall_now() -> Result<u64, ServiceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(ServiceError::new(503, "enrollment_clock_unproven"))
}
struct Clock {
    wall: u64,
    origin: u64,
    monotonic: Instant,
}
impl Clock {
    fn new(now: u64) -> Self {
        Self {
            wall: now,
            origin: now,
            monotonic: Instant::now(),
        }
    }
    fn observe(&mut self) -> Result<u64, ServiceError> {
        let wall = wall_now()?;
        if wall < self.wall {
            return Err(ServiceError::new(503, "enrollment_clock_rollback"));
        }
        self.wall = wall;
        let elapsed = u64::try_from(self.monotonic.elapsed().as_millis()).map_err(|_| invalid())?;
        Ok(wall.max(self.origin.checked_add(elapsed).ok_or_else(invalid)?))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invite {
    #[serde(default = "default_ttl")]
    ttl_seconds: u64,
}
fn default_ttl() -> u64 {
    600
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Join {
    invitation: String,
    device_id: DeviceId,
    label: String,
    platform: String,
    cwd: String,
    shell: String,
    computer_requested: bool,
    #[serde(default, deserialize_with = "optional_bool")]
    browser_requested: Option<bool>,
    public_key_pem: String,
    signature: String,
}
fn optional_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(d).map(Some)
}
impl Join {
    fn split(self) -> (JoinPayload, String) {
        (
            JoinPayload {
                invitation: self.invitation,
                device_id: self.device_id,
                label: self.label,
                platform: self.platform,
                cwd: self.cwd,
                shell: self.shell,
                computer_requested: self.computer_requested,
                browser_requested: self.browser_requested,
                public_key_pem: self.public_key_pem,
            },
            self.signature,
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approve {
    request_id: RequestId,
    fingerprint: Sha256Digest,
    #[serde(default)]
    enable_computer: bool,
    #[serde(default)]
    enable_browser: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    request_id: RequestId,
    claim_secret: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirm {
    request_id: RequestId,
    claim_secret: String,
    confirmation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBody {
    device_id: DeviceId,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryBody {
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    generation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    generation: String,
    #[serde(default, deserialize_with = "optional_bool")]
    enable_computer: Option<bool>,
    #[serde(default, deserialize_with = "optional_bool")]
    enable_browser: Option<bool>,
    public_key_pem: String,
    signature: String,
}
impl Capability {
    fn payload(&self) -> CapabilityPayload {
        CapabilityPayload {
            device_id: self.device_id.clone(),
            fingerprint: self.fingerprint,
            generation: self.generation.clone(),
            enable_computer: self.enable_computer,
            enable_browser: self.enable_browser,
        }
    }
}
#[derive(Clone, Copy)]
enum Route {
    Invite,
    Close,
    Pending,
    Devices,
    Join,
    Approve,
    Claim,
    Confirm,
    Revoke,
    Recover,
    AdminCas,
    SelfGet,
    SelfCas,
}
impl Route {
    fn admin(self) -> bool {
        matches!(
            self,
            Self::Invite
                | Self::Close
                | Self::Pending
                | Self::Devices
                | Self::Approve
                | Self::Revoke
                | Self::Recover
                | Self::AdminCas
        )
    }
}
fn device_path(path: &str) -> Option<DeviceId> {
    let id = path
        .strip_prefix("/styx/enroll/self/")?
        .strip_suffix("/capabilities")?;
    let hex = id.strip_prefix("styx-")?;
    (hex.len() == 24
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| DeviceId::try_from(id).ok())
    .flatten()
}
fn route(method: &Method, path: &str) -> Result<Route, ServiceError> {
    let (expected, r) = match path {
        "/styx/enroll/invitations" => (Method::POST, Route::Invite),
        "/styx/enroll/invitations/close" => (Method::POST, Route::Close),
        "/styx/enroll/pending" => (Method::GET, Route::Pending),
        "/styx/enroll/devices" => (Method::GET, Route::Devices),
        "/styx/enroll/join" => (Method::POST, Route::Join),
        "/styx/enroll/approve" => (Method::POST, Route::Approve),
        "/styx/enroll/claim" => (Method::POST, Route::Claim),
        "/styx/enroll/confirm" => (Method::POST, Route::Confirm),
        "/styx/enroll/revoke" => (Method::POST, Route::Revoke),
        "/styx/enroll/recover" => (Method::POST, Route::Recover),
        "/styx/enroll/capabilities" => (Method::POST, Route::AdminCas),
        _ if device_path(path).is_some() => {
            if method == Method::GET {
                return Ok(Route::SelfGet);
            }
            if method == Method::POST {
                return Ok(Route::SelfCas);
            }
            return Err(ServiceError::new(405, "method_not_allowed"));
        }
        _ => return Err(ServiceError::new(404, "not_found")),
    };
    if method != expected {
        return Err(ServiceError::new(405, "method_not_allowed"));
    }
    Ok(r)
}
fn bearer(headers: &HeaderMap) -> Result<&[u8], ServiceError> {
    if headers.get_all(AUTHORIZATION).iter().count() != 1 {
        return Err(ServiceError::new(403, "device_unauthorized"));
    }
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ServiceError::new(403, "device_unauthorized"))?;
    if !(32..=4096).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(ServiceError::new(403, "device_unauthorized"));
    }
    Ok(value.as_bytes())
}
fn capabilities(g: Grant, exec: bool) -> Value {
    json!({"exec":exec,"computer":exec&&g.computer,"browser":exec&&g.browser})
}

/// Opaque trusted runtime. No Deserialize/Clone, public admin factory or token
/// accessor. Existing native journal required; legacy/fresh activation is a
/// separate migration/bootstrap transaction and cannot default to empty here.
pub struct EnrollmentService {
    store: OwnedEnrollmentJournal,
    ledger: EnrollmentLedger,
    control: EnrollmentControl,
    head: Option<Sha256Digest>,
    admin: GatewayBearerPolicy,
    hosts: BTreeSet<String>,
    clock: Clock,
    uncertain: bool,
}
impl EnrollmentService {
    pub fn recover_existing(
        mut store: OwnedEnrollmentJournal,
        admin_token: &[u8],
        ordinary_mcp_digest: Sha256Digest,
        allowed_hosts: Vec<String>,
        limits: Limits,
    ) -> Result<Self, ServiceError> {
        if verify_slices_are_equal(
            Sha256Digest::of_bytes(admin_token).as_bytes(),
            ordinary_mcp_digest.as_bytes(),
        )
        .is_ok()
        {
            return Err(ServiceError::new(500, "admin_mcp_authorities_must_differ"));
        }
        let admin = GatewayBearerPolicy::new(admin_token, allowed_hosts.clone(), vec![])
            .map_err(|_| invalid())?;
        let now = wall_now()?;
        let epoch = GatewayEpoch::try_from(format!("enrollment-service-{}", uuid::Uuid::new_v4()))
            .map_err(|_| invalid())?;
        let recovered = store
            .with_journal(|j| Ok(recovery::recover_journal(j, epoch, limits, now)))?
            .map_err(|_| ServiceError::new(503, "enrollment_recovery_required"))?;
        let mut service = Self {
            store,
            ledger: recovered.ledger,
            control: recovered.control,
            head: recovered.facts.head,
            admin,
            hosts: allowed_hosts.into_iter().collect(),
            clock: Clock::new(now),
            uncertain: false,
        };
        service.verify_profiles()?;
        Ok(service)
    }
    fn healthy(&self) -> Result<(), ServiceError> {
        if self.uncertain {
            Err(ServiceError::new(503, "enrollment_recovery_required"))
        } else {
            Ok(())
        }
    }
    fn time(&mut self) -> Result<u64, ServiceError> {
        let result = (|| {
            let now = self.clock.observe()?;
            self.store.with_journal(|j| j.record_time_floor(now))?;
            Ok(now)
        })();
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
    fn read_material(
        &mut self,
        kind: MaterialKind,
        digest: Sha256Digest,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        match self
            .store
            .with_journal(|j| j.read_material(&MaterialRef { kind, digest }))
        {
            Ok(bytes) => Ok(Zeroizing::new(bytes)),
            Err(error) => {
                self.uncertain = true;
                Err(error.into())
            }
        }
    }
    fn load_profile(
        &mut self,
        reference: &OpaqueProfileRef,
        id: &DeviceId,
        fingerprint: Sha256Digest,
    ) -> Result<VerifiedProfile, ServiceError> {
        let raw = self.read_material(MaterialKind::Profile, reference.0)?;
        let p = VerifiedProfile::from_stored(&raw).map_err(|_| {
            self.uncertain = true;
            ServiceError::new(503, "stored_profile_invalid")
        })?;
        if p.profile().device_id != *id || p.fingerprint() != fingerprint {
            self.uncertain = true;
            return Err(ServiceError::new(503, "stored_profile_binding_invalid"));
        }
        Ok(p)
    }
    fn verify_profiles(&mut self) -> Result<(), ServiceError> {
        let devices = self.ledger.recovery_devices(&self.control)?;
        let pending = self.ledger.recovery_pending(&self.control)?;
        for d in &devices {
            self.load_profile(&d.profile, &d.id, d.fingerprint)?;
            let token = self.read_material(MaterialKind::Token, d.credential.0)?;
            ClaimCapability::from_legacy_token_bytes(&token)
                .map_err(|_| ServiceError::new(503, "stored_credential_invalid"))?;
            if Sha256Digest::of_bytes(&token) != d.credential_hash {
                return Err(ServiceError::new(503, "stored_credential_invalid"));
            }
        }
        for p in pending {
            let profile =
                self.load_profile(&p.facts.profile, &p.facts.device, p.facts.fingerprint)?;
            if let PendingStatus::Approved {
                sealed: Some(sealed),
                ..
            } = p.status
            {
                let bytes = self.read_material(MaterialKind::Sealed, sealed.0)?;
                if bytes.len() != profile.public_key().credential_ciphertext_size() {
                    return Err(ServiceError::new(503, "stored_sealed_credential_invalid"));
                }
            }
        }
        Ok(())
    }
    fn authenticate(&self, id: &DeviceId, token: &[u8]) -> Result<DeviceSelfProof, ServiceError> {
        self.healthy()?;
        if !(32..=4096).contains(&token.len()) {
            return Err(ServiceError::new(403, "device_unauthorized"));
        }
        let d = self
            .ledger
            .authentication_target(&self.control, id)
            .map_err(|_| ServiceError::new(403, "device_unauthorized"))?;
        verify_slices_are_equal(
            Sha256Digest::of_bytes(token).as_bytes(),
            d.credential_hash.as_bytes(),
        )
        .map_err(|_| ServiceError::new(403, "device_unauthorized"))?;
        let p = self
            .control
            .attest_device(d.id, d.fingerprint, d.credential_hash);
        self.ledger.self_device(&p).map_err(|e| {
            if e == EnrollmentError::Busy {
                e.into()
            } else {
                ServiceError::new(403, "device_unauthorized")
            }
        })?;
        Ok(p)
    }
    pub(super) fn preflight(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        pairing: &PairingContext,
    ) -> Result<(), ServiceError> {
        self.healthy()?;
        let r = route(method, path)?;
        if headers.get_all(HOST).iter().count() != 1
            || headers.contains_key(ORIGIN)
            || headers.contains_key("x-styx-tunnel-context")
        {
            return Err(ServiceError::new(403, "host_or_origin_not_allowed"));
        }
        let host = headers
            .get(HOST)
            .and_then(|s| s.to_str().ok())
            .filter(|s| self.hosts.contains(*s))
            .ok_or(ServiceError::new(403, "host_not_allowed"))?;
        if pairing.origin != format!("https://{host}") {
            return Err(ServiceError::new(403, "listener_tls_identity_mismatch"));
        }
        if r.admin() {
            self.admin
                .authorize(headers)
                .map_err(|_| ServiceError::new(401, "unauthorized"))?;
        } else if matches!(r, Route::SelfGet | Route::SelfCas) {
            self.authenticate(&device_path(path).ok_or_else(invalid)?, bearer(headers)?)?;
        } else if headers.contains_key(AUTHORIZATION) {
            return Err(ServiceError::new(401, "unauthorized"));
        }
        Ok(())
    }
    fn persist(
        &mut self,
        intent: PendingIntent,
        materials: &[(MaterialKind, &[u8])],
    ) -> Result<(), ServiceError> {
        let result = (|| {
            let receipt = self.store.with_journal(|j| {
                for (kind, bytes) in materials {
                    j.put_material(*kind, bytes)?;
                }
                let prepared = j.prepare(intent.original_bytes(), self.head)?;
                let committed = j.commit(&prepared)?;
                committed.digest()
            })?;
            self.ledger
                .confirm_durable(self.control.attest_durable(&intent, receipt))?;
            self.head = Some(receipt);
            Ok(())
        })();
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
    fn collect_expired(&mut self, now: u64) -> Result<(), ServiceError> {
        // Bounded expiry maintenance is itself a Core-authorized durable
        // mutation. Never silently retain/drop maps just to admit a new join.
        match self.ledger.collect_pending(&self.control.admin(), now) {
            Ok(intent) => self.persist(intent, &[]),
            Err(EnrollmentError::NotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    pub(super) fn request(
        &mut self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
        pairing: &PairingContext,
    ) -> Result<(u16, Value), ServiceError> {
        self.preflight(method, path, headers, pairing)?;
        let r = route(method, path)?;
        if method == Method::GET && !body.is_empty() {
            return Err(invalid());
        }
        match r {
            Route::Invite => {
                let req: Invite = decode(body)?;
                let code = secret(32)?;
                let now = self.time()?;
                let intent = self.ledger.invite(
                    &self.control.admin(),
                    Sha256Digest::of_bytes(code.as_bytes()),
                    req.ttl_seconds,
                    None,
                    now,
                )?;
                let Mutation::Invite { invitation } = &intent.body().mutation else {
                    return Err(invalid());
                };
                let expires = invitation.expires;
                self.persist(intent, &[])?;
                Ok((
                    200,
                    json!({"invitation":&**code,"expires_at":expires,"one_use":true}),
                ))
            }
            Route::Close => {
                let _: Empty = decode(body)?;
                let now = self.time()?;
                let p = self.ledger.close_window(&self.control.admin(), None, now)?;
                self.persist(p, &[])?;
                Ok((200, json!({"schema":1,"pairing":{"status":"closed"}})))
            }
            Route::Join => {
                let (payload, signature) = decode::<Join>(body)?.split();
                let verified = profile::verify_join(&payload, &signature).map_err(join_failure)?;
                let code = secret(32)?;
                let request_id = RequestId::try_from(uuid::Uuid::new_v4().simple().to_string())
                    .map_err(|_| invalid())?;
                let profile_ref =
                    OpaqueProfileRef(Sha256Digest::of_bytes(verified.raw_profile_bytes()));
                let now = self.time()?;
                self.collect_expired(now)?;
                let proof = self.control.attest_join(
                    &payload,
                    verified.fingerprint(),
                    request_id.clone(),
                    Sha256Digest::of_bytes(code.as_bytes()),
                    profile_ref,
                    pairing.clone(),
                )?;
                let intent = self.ledger.join(proof, now)?;
                let Mutation::Join { pending } = &intent.body().mutation else {
                    return Err(invalid());
                };
                let result = json!({"request_id":request_id,"claim_secret":&**code,"fingerprint":verified.fingerprint(),"status":"pending","expires_at":pending.expires,
                    "comparison_code":pending.facts.comparison,"ingress":{"origin":pairing.origin,"certificate_sha256":pairing.leaf,"generation":pairing.ingress_generation}});
                self.persist(
                    intent,
                    &[(MaterialKind::Profile, verified.raw_profile_bytes())],
                )?;
                Ok((202, result))
            }
            Route::Pending => {
                let now = self.time()?;
                let list = self.ledger.pending_for_admin(&self.control.admin(), now)?;
                let mut result = Vec::with_capacity(list.len());
                for p in list {
                    let profile =
                        self.load_profile(&p.facts.profile, &p.facts.device, p.facts.fingerprint)?;
                    let f = profile.profile();
                    result.push(json!({"request_id":p.facts.request,"device_id":f.device_id,"label":f.label,"platform":f.platform,"cwd":f.cwd,"shell":f.shell,
                        "fingerprint":p.facts.fingerprint,"computer_requested":p.facts.requested.computer,"browser_requested":p.facts.requested.browser,"expires_at":p.expires,
                        "comparison_code":p.facts.comparison,"ingress":{"origin":p.facts.pairing.origin,"certificate_sha256":p.facts.pairing.leaf,"generation":p.facts.pairing.ingress_generation}}));
                }
                Ok((200, Value::Array(result)))
            }
            Route::Approve => {
                let req: Approve = decode(body)?;
                validate_request(&req.request_id)?;
                let now = self.time()?;
                let admin = self.control.admin();
                let target = self.ledger.approval_target(&admin, &req.request_id)?;
                let pending = self
                    .ledger
                    .pending_for_admin(&admin, now)?
                    .into_iter()
                    .find(|p| p.facts.request == req.request_id)
                    .ok_or(ServiceError::new(409, "request_not_pending"))?;
                let profile =
                    self.load_profile(&target.profile, &target.device, target.fingerprint)?;
                let token = secret(48)?;
                let sealed = profile
                    .public_key()
                    .wrap_credential(token.as_bytes())
                    .map_err(|_| ServiceError::new(503, "credential_wrap_failed"))?;
                let digest = Sha256Digest::of_bytes(token.as_bytes());
                let prepared = self.control.attest_prepared_credential(
                    target.clone(),
                    CredentialRef(digest),
                    digest,
                    SealedCredentialRef(Sha256Digest::of_bytes(&sealed)),
                )?;
                let grant = Grant {
                    computer: req.enable_computer,
                    browser: req.enable_browser,
                };
                // Legacy admin approval carries explicit fingerprint but no code
                // field. Bind to this authoritative pending code without claiming
                // a wire proof that the human compared the displayed code.
                let intent = self.ledger.approve(
                    &admin,
                    styx_core::enrollment::ApprovalRequest {
                        request: req.request_id,
                        fingerprint: req.fingerprint,
                        comparison: pending.facts.comparison,
                        grant,
                    },
                    prepared,
                    now,
                )?;
                self.persist(
                    intent,
                    &[
                        (MaterialKind::Token, token.as_bytes()),
                        (MaterialKind::Sealed, &sealed),
                    ],
                )?;
                Ok((
                    200,
                    json!({"device_id":target.device,"status":"approved","fingerprint":target.fingerprint,"approved_capabilities":capabilities(grant,true)}),
                ))
            }
            Route::Claim => {
                let req: Claim = decode(body)?;
                validate_claim(&req.request_id, &req.claim_secret)?;
                let now = self.time()?;
                let proof = self.control.attest_claim(
                    req.request_id,
                    Sha256Digest::of_bytes(req.claim_secret.as_bytes()),
                );
                match self.ledger.claim(&proof, now)? {
                    styx_core::enrollment::ClaimView::Pending => {
                        Ok((202, json!({"status":"pending"})))
                    }
                    styx_core::enrollment::ClaimView::Approved {
                        sealed,
                        device,
                        grant,
                        ..
                    } => {
                        let raw = self.read_material(MaterialKind::Sealed, sealed.0)?;
                        Ok((
                            200,
                            json!({"status":"approved","device_id":device,"encrypted_credential":URL_SAFE_NO_PAD.encode(&*raw),"crypto":"RSA-OAEP-SHA256","approved_capabilities":capabilities(grant,true)}),
                        ))
                    }
                }
            }
            Route::Confirm => {
                let req: Confirm = decode(body)?;
                validate_claim(&req.request_id, &req.claim_secret)?;
                let now = self.time()?;
                let proof = self.control.attest_claim(
                    req.request_id.clone(),
                    Sha256Digest::of_bytes(req.claim_secret.as_bytes()),
                );
                let target = self.ledger.confirmation_target(&proof, now)?;
                let token = self.read_material(MaterialKind::Token, target.credential.0)?;
                let capability = ClaimCapability::from_legacy_token_bytes(&token)
                    .map_err(|_| ServiceError::new(503, "stored_credential_invalid"))?;
                capability
                    .verify(
                        &EnrollmentRequestId::parse(req.request_id.as_str())
                            .map_err(|_| invalid())?,
                        &ClaimConfirmation::from_hex(&req.confirmation).map_err(|_| invalid())?,
                    )
                    .map_err(|_| ServiceError::new(403, "confirmation_failed"))?;
                if !target.already_confirmed {
                    let confirmation = self.control.attest_confirmation(
                        proof,
                        target.device.clone(),
                        target.credential,
                    )?;
                    let p = self.ledger.confirm(confirmation, now)?;
                    self.persist(p, &[])?;
                }
                let d = self
                    .ledger
                    .authentication_target(&self.control, &target.device)?;
                Ok((
                    200,
                    json!({"status":"ready_to_connect","device_id":d.id,"approved_capabilities":capabilities(d.grant,true)}),
                ))
            }
            Route::SelfGet => {
                let id = device_path(path).ok_or_else(invalid)?;
                let proof = self.authenticate(&id, bearer(headers)?)?;
                let d = self.ledger.self_device(&proof)?;
                let states = self
                    .ledger
                    .connection_observations(&proof)?
                    .map(|s| match s {
                        ConnectionObservation::Connected => "connected",
                        ConnectionObservation::Offline => "offline",
                        ConnectionObservation::Unknown => "unknown",
                    });
                Ok((
                    200,
                    json!({"status":"approved","device_id":d.id,"fingerprint":d.fingerprint,"generation":d.generation,"capabilities":capabilities(d.grant,true),"connections":{"exec":states[0],"computer":states[1],"browser":states[2]}}),
                ))
            }
            Route::SelfCas | Route::AdminCas => {
                let req: Capability = decode(body)?;
                if matches!(r, Route::SelfCas) && Some(req.device_id.clone()) != device_path(path) {
                    return Err(ServiceError::new(403, "device_unauthorized"));
                }
                let d = if matches!(r, Route::SelfCas) {
                    let p = self.authenticate(&req.device_id, bearer(headers)?)?;
                    self.ledger.self_device(&p)?.clone()
                } else {
                    self.ledger
                        .authentication_target(&self.control, &req.device_id)?
                };
                let profile = self.load_profile(&d.profile, &d.id, d.fingerprint)?;
                let payload = req.payload();
                profile
                    .verify_capability(&payload, &req.public_key_pem, &req.signature)
                    .map_err(|_| ServiceError::new(403, "invalid_identity_proof"))?;
                let now = self.time()?;
                let proof = self.control.attest_self_cas(&payload, d.credential_hash)?;
                let p = self.ledger.self_cas(proof, now)?;
                let Mutation::SelfCas {
                    generation, grant, ..
                } = &p.body().mutation
                else {
                    return Err(invalid());
                };
                let generation = generation.clone();
                let grant = *grant;
                self.persist(p, &[])?;
                Ok((
                    200,
                    json!({"status":"updated","device_id":d.id,"fingerprint":d.fingerprint,"generation":generation,"capabilities":capabilities(grant,true)}),
                ))
            }
            Route::Revoke | Route::Recover => {
                let id = if matches!(r, Route::Recover) {
                    let req: RecoveryBody = decode(body)?;
                    let d = self
                        .ledger
                        .authentication_target(&self.control, &req.device_id)?;
                    if d.fingerprint != req.fingerprint || d.generation != req.generation {
                        return Err(ServiceError::new(409, "recovery_identity_mismatch"));
                    }
                    req.device_id
                } else {
                    decode::<DeviceBody>(body)?.device_id
                };
                let now = self.time()?;
                let p = self.ledger.revoke(&self.control.admin(), &id, now)?;
                self.persist(p, &[])?;
                let mut result = json!({"device_id":id,"status":"revoked"});
                if matches!(r, Route::Recover) {
                    result["recovery"] = json!("fresh_enrollment_required");
                }
                Ok((200, result))
            }
            Route::Devices => {
                let devices = self.ledger.devices_for_admin(&self.control.admin())?;
                let mut out = Vec::with_capacity(devices.len());
                for d in devices {
                    let profile = self.load_profile(&d.profile, &d.id, d.fingerprint)?;
                    let states = if d.revoked {
                        Some([ConnectionObservation::Offline; 3])
                    } else {
                        let proof = self.control.attest_device(
                            d.id.clone(),
                            d.fingerprint,
                            d.credential_hash,
                        );
                        self.ledger.connection_observations(&proof).ok()
                    };
                    let boolstate = |i: usize| match states.map(|s| s[i]) {
                        Some(ConnectionObservation::Connected) => Some(true),
                        Some(ConnectionObservation::Offline) => Some(false),
                        _ => None,
                    };
                    out.push(json!({"device_id":d.id,"label":profile.profile().label,"platform":profile.profile().platform,"is_default":false,"capabilities":capabilities(d.grant,!d.revoked),
                        "status":if d.revoked{"revoked"}else{"approved"},"generation":d.generation,"fingerprint":d.fingerprint,"online":boolstate(0)==Some(true),"connections":{"exec":boolstate(0),"computer":boolstate(1),"browser":boolstate(2)}}));
                }
                Ok((200, Value::Array(out)))
            }
        }
    }
    pub(crate) fn exec_profiles(&mut self) -> Result<Vec<GatewayExecProfile>, ServiceError> {
        self.healthy()?;
        self.ledger
            .devices_for_admin(&self.control.admin())?
            .into_iter()
            .filter(|d| !d.revoked)
            .map(|d| {
                let verified = self.load_profile(&d.profile, &d.id, d.fingerprint)?;
                let p = verified.profile();
                Ok(GatewayExecProfile {
                    device_id: d.id,
                    capability_generation: d.generation,
                    platform: p.platform.clone(),
                    cwd: p.cwd.clone(),
                    shell: p.shell.clone(),
                    allowed_shells: vec![p.shell.clone()],
                    environment: std::collections::BTreeMap::new(),
                })
            })
            .collect()
    }
    pub(crate) fn profile_is_current(
        &self,
        id: &DeviceId,
        generation: &str,
    ) -> Result<(), ServiceError> {
        self.healthy()?;
        if self
            .ledger
            .devices_for_admin(&self.control.admin())?
            .iter()
            .any(|d| &d.id == id && !d.revoked && d.generation == generation)
        {
            Ok(())
        } else {
            Err(ServiceError::transport_unauthorized())
        }
    }
    pub(crate) fn admit_upgrade(
        &mut self,
        headers: &HeaderMap,
        id: &DeviceId,
        generation: ConnectionGeneration,
    ) -> Result<ConnectionLease, ServiceError> {
        if headers.get_all(HOST).iter().count() != 1
            || headers.contains_key(ORIGIN)
            || headers.contains_key("x-styx-tunnel-context")
            || !headers
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|h| self.hosts.contains(h))
        {
            return Err(ServiceError::new(403, "host_or_origin_not_allowed"));
        }
        let token = bearer(headers)?;
        self.admit_host(id, token, Lane::Exec, generation)
    }
    /// Host transport adapters retain the nonserializable lease and recheck it
    /// per frame. This is not a native operation/owner authorization substitute.
    pub fn admit_host(
        &mut self,
        id: &DeviceId,
        token: &[u8],
        lane: Lane,
        generation: ConnectionGeneration,
    ) -> Result<ConnectionLease, ServiceError> {
        let proof = self.authenticate(id, token)?;
        self.ledger
            .admit_connection(proof, lane, generation)
            .map_err(Into::into)
    }
    pub fn authorize_host_frame(&self, lease: &ConnectionLease) -> Result<(), ServiceError> {
        self.healthy()?;
        self.ledger.authorize_connection(lease)?;
        Ok(())
    }
    pub fn host_connection_ended(
        &mut self,
        lease: ConnectionLease,
        certainly_closed: bool,
    ) -> Result<(), ServiceError> {
        self.ledger
            .connection_ended(lease, certainly_closed)
            .map_err(Into::into)
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "controller_tests.rs"]
mod controller_tests;

/// Verified enrollment metadata; never inferred from Gateway OS/environment.
#[derive(Clone, Debug)]
pub struct GatewayExecProfile {
    pub device_id: DeviceId,
    pub capability_generation: String,
    pub platform: String,
    pub cwd: String,
    pub shell: String,
    pub allowed_shells: Vec<String>,
    pub environment: std::collections::BTreeMap<String, String>,
}

impl ServiceError {
    pub(crate) fn transport_unauthorized() -> Self {
        Self::new(403, "device_unauthorized")
    }
}

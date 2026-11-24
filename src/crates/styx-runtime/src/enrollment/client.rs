//! Host enrollment with platform-owned protected persistence. Desktop and Android
//! use the same signing, short-code authentication and CA-pinned HTTP protocol.
//! A lost join or confirmation response is never permission to repeat that write.
use super::{client_http as http, client_protocol as protocol, pairing_link};
use crate::{
    crypto::DevicePrivateKey,
    tls::{GatewayClientTls, GatewayLeafPin, TrustAnchorPin},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use styx_contracts::identity::{DeviceId, Sha256Digest};
use zeroize::{Zeroize, Zeroizing};

const HTTP_BUDGET: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
#[error("{code}")]
pub struct ClientError {
    pub code: &'static str,
    pub uncertain: bool,
}
impl ClientError {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            uncertain: false,
        }
    }
    fn unknown(code: &'static str) -> Self {
        Self {
            code,
            uncertain: true,
        }
    }
}
impl From<http::JoinHttpError> for ClientError {
    fn from(value: http::JoinHttpError) -> Self {
        Self {
            code: value.code(),
            uncertain: value.certainty == http::JoinHttpCertainty::ResultUnknown,
        }
    }
}
type Result<T> = std::result::Result<T, ClientError>;

/// On Android these methods call the app's AndroidKeyStore-backed encrypted file.
/// Implementations must finish persistence before returning and never log JSON.
pub trait CredentialStore: Send + Sync {
    fn load(&self) -> Result<Option<Zeroizing<String>>>;
    fn save(&self, json: &str) -> Result<()>;
}

/// Only the Host composition receives this material. No Debug/Serialize surface.
pub struct ReadyCredentials {
    pub device_id: DeviceId,
    pub gateway_origin: String,
    pub ca_pem: String,
    pub anchor_sha256: Sha256Digest,
    pub credential: Zeroizing<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    JoinDispatched,
    AwaitingClaim,
    ConfirmDispatched,
    Ready,
    Rejected,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    body: String,
    leaf_sha256: String,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u16,
    identity: protocol::JoinIdentity,
    ca_pem: String,
    anchor_sha256: Sha256Digest,
    private_key_pem: String,
    phase: Phase,
    pending: Option<Pending>,
    credential: Option<String>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
        if let Some(credential) = &mut self.credential {
            credential.zeroize();
        }
    }
}
impl Record {
    fn persist(&self, store: &dyn CredentialStore) -> Result<()> {
        let json = Zeroizing::new(
            serde_json::to_string(self)
                .map_err(|_| ClientError::new("pairing_persistence_encoding_failed"))?,
        );
        store.save(&json)
    }
    fn tls(&self) -> Result<GatewayClientTls> {
        let pin = TrustAnchorPin::parse_hex(&self.anchor_sha256.to_hex())
            .map_err(|_| ClientError::new("pairing_trust_invalid"))?;
        GatewayClientTls::from_pinned_ca_pem(self.ca_pem.as_bytes(), pin, None)
            .map_err(|_| ClientError::new("pairing_trust_invalid"))
    }
    fn ready(&self) -> Result<ReadyCredentials> {
        if self.phase != Phase::Ready {
            return Err(ClientError::new("pairing_not_ready"));
        }
        let credential = self
            .credential
            .as_ref()
            .ok_or_else(|| ClientError::new("pairing_credential_missing"))?;
        Ok(ReadyCredentials {
            device_id: self.identity.device_id.clone(),
            gateway_origin: self.identity.gateway_origin.clone(),
            ca_pem: self.ca_pem.clone(),
            anchor_sha256: self.anchor_sha256,
            credential: Zeroizing::new(credential.clone()),
        })
    }
}
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .ok_or_else(|| ClientError::new("pairing_clock_unavailable"))
}
fn read(store: &dyn CredentialStore) -> Result<Record> {
    let json = store
        .load()?
        .ok_or_else(|| ClientError::new("pairing_not_configured"))?;
    let record: Record =
        serde_json::from_str(&json).map_err(|_| ClientError::new("pairing_credentials_invalid"))?;
    if record.schema != 1 {
        return Err(ClientError::new("pairing_credentials_version_unsupported"));
    }
    record.tls()?;
    Ok(record)
}

/// Existing ready pairing is used directly by the normal WSS authentication.
pub fn load_ready(store: &dyn CredentialStore) -> Result<ReadyCredentials> {
    read(store)?.ready()
}

/// A new invitation enrolls exactly one independent Android identity. The
/// authenticated short code supplies the Gateway CA before any device mutation.
pub async fn pair(
    store: &dyn CredentialStore,
    gateway: &str,
    code: &str,
    label: &str,
) -> Result<ReadyCredentials> {
    if store.load()?.is_some() {
        return Err(ClientError::new("pairing_already_configured"));
    }
    let input = Zeroizing::new(format!("{} {}", gateway.trim(), code.trim()));
    let inspected = pairing_link::resolve(&input, now_ms()?)
        .await
        .map_err(|error| ClientError::new(error.code()))?;
    if !inspected.preapproved {
        return Err(ClientError::new("pairing_short_code_required"));
    }
    let preview = inspected.preview();
    let accepted = inspected
        .approve(&preview.origin, preview.ca_sha256.as_deref(), now_ms()?)
        .map_err(|error| ClientError::new(error.code()))?;
    let (origin, invitation, ca_pem, _) = accepted.into_parts();
    let ca_pem = ca_pem.ok_or_else(|| ClientError::new("pairing_trust_missing"))?;
    let anchor_sha256 = Sha256Digest::try_from(
        preview
            .ca_sha256
            .ok_or_else(|| ClientError::new("pairing_trust_missing"))?,
    )
    .map_err(|_| ClientError::new("pairing_trust_invalid"))?;
    let generated = tokio::task::spawn_blocking(DevicePrivateKey::generate_rsa3072)
        .await
        .map_err(|_| ClientError::new("pairing_identity_generation_failed"))?
        .map_err(|_| ClientError::new("pairing_identity_generation_failed"))?;
    let mut random = [0u8; 12];
    getrandom::fill(&mut random).map_err(|_| ClientError::new("pairing_entropy_unavailable"))?;
    let identity = protocol::JoinIdentity {
        schema: 2,
        gateway_origin: origin.clone(),
        device_id: DeviceId::try_from(format!("styx-{}", hex::encode(random)))
            .map_err(|_| ClientError::new("pairing_identity_invalid"))?,
        fingerprint: Sha256Digest::of_bytes(generated.public_key().spki_der()),
        public_key_pem: generated.public_key_pem().to_owned(),
        label: label.to_owned(),
        platform: "android".into(),
        cwd: String::new(),
        shell: String::new(),
        computer_requested: false,
        browser_requested: false,
    };
    let request = protocol::make_join(&identity, &invitation, generated.private_key())
        .map_err(|error| ClientError::new(error.code()))?;
    let private_key_pem = std::str::from_utf8(generated.protected_pkcs8_pem())
        .map_err(|_| ClientError::new("pairing_identity_invalid"))?
        .to_owned();
    let mut record = Record {
        schema: 1,
        identity,
        ca_pem,
        anchor_sha256,
        private_key_pem,
        phase: Phase::JoinDispatched,
        pending: None,
        credential: None,
    };
    let tls = record.tls()?;
    let origin =
        url::Url::parse(&origin).map_err(|_| ClientError::new("pairing_gateway_invalid"))?;
    record.persist(store)?;
    let response = http::exchange(
        &origin,
        &tls,
        "/styx/enroll/join",
        &request,
        None,
        HTTP_BUDGET,
    )
    .await?;
    if !matches!(response.status, 200 | 202) {
        return Err(ClientError::unknown("pairing_join_response_rejected"));
    }
    protocol::validate_pending(
        &record.identity,
        &response.body,
        &response.leaf_pin,
        now_ms()?,
    )
    .map_err(|error| ClientError::unknown(error.code()))?;
    record.pending = Some(Pending {
        body: std::str::from_utf8(&response.body)
            .map_err(|_| ClientError::unknown("pairing_join_response_invalid"))?
            .to_owned(),
        leaf_sha256: response.leaf_pin.as_hex(),
    });
    record.phase = Phase::AwaitingClaim;
    record.persist(store)?;
    finish(store, record).await
}

/// Continues the retained original enrollment. Never resubmits join/confirm.
pub async fn resume(store: &dyn CredentialStore) -> Result<ReadyCredentials> {
    finish(store, read(store)?).await
}
async fn finish(store: &dyn CredentialStore, mut record: Record) -> Result<ReadyCredentials> {
    match record.phase {
        Phase::Ready => return record.ready(),
        Phase::JoinDispatched => return Err(ClientError::unknown("pairing_join_result_unknown")),
        Phase::Rejected => return Err(ClientError::new("pairing_rejected")),
        Phase::AwaitingClaim | Phase::ConfirmDispatched => {}
    }
    let tls = record.tls()?;
    let origin = url::Url::parse(&record.identity.gateway_origin)
        .map_err(|_| ClientError::new("pairing_gateway_invalid"))?;
    let recorded = record
        .pending
        .as_ref()
        .ok_or_else(|| ClientError::new("pairing_pending_missing"))?;
    let leaf = GatewayLeafPin::parse_hex(&recorded.leaf_sha256)
        .map_err(|_| ClientError::new("pairing_pending_invalid"))?;
    let pending =
        protocol::validate_recorded_pending(&record.identity, recorded.body.as_bytes(), &leaf)
            .map_err(|error| ClientError::new(error.code()))?;
    if record.phase == Phase::AwaitingClaim {
        let body =
            protocol::claim_request(&pending).map_err(|error| ClientError::new(error.code()))?;
        let response = http::exchange(
            &origin,
            &tls,
            "/styx/enroll/claim",
            &body,
            None,
            HTTP_BUDGET,
        )
        .await?;
        if response.status == 202 {
            return Err(ClientError::new("pairing_awaiting_approval"));
        }
        if response.status != 200 {
            return Err(ClientError::new("pairing_claim_rejected"));
        }
        if protocol::rejected_claim(&pending, &response.body)
            .map_err(|error| ClientError::new(error.code()))?
        {
            record.phase = Phase::Rejected;
            record.persist(store)?;
            return Err(ClientError::new("pairing_rejected"));
        }
        let key = DevicePrivateKey::from_pkcs8_pem(record.private_key_pem.as_bytes())
            .map_err(|_| ClientError::new("pairing_identity_invalid"))?;
        let credential = protocol::decrypt_claim(&record.identity, &key, &response.body)
            .map_err(|error| ClientError::new(error.code()))?;
        let confirm = protocol::confirm_request(&pending, &credential)
            .map_err(|error| ClientError::new(error.code()))?;
        record.credential = Some(
            std::str::from_utf8(&credential)
                .map_err(|_| ClientError::new("pairing_credential_invalid"))?
                .to_owned(),
        );
        record.phase = Phase::ConfirmDispatched;
        record.persist(store)?;
        let response = http::exchange(
            &origin,
            &tls,
            "/styx/enroll/confirm",
            &confirm,
            None,
            HTTP_BUDGET,
        )
        .await?;
        if response.status != 200 {
            return Err(ClientError::unknown("pairing_confirmation_result_unknown"));
        }
        protocol::validate_confirmation(&record.identity, &response.body)
            .map_err(|error| ClientError::unknown(error.code()))?;
    }
    let credential = record
        .credential
        .as_ref()
        .ok_or_else(|| ClientError::new("pairing_credential_missing"))?;
    let response = http::exchange_self(
        &origin,
        &tls,
        &record.identity.device_id,
        credential.as_bytes(),
        HTTP_BUDGET,
    )
    .await?;
    if response.status != 200 {
        return Err(ClientError::unknown(
            if matches!(response.status, 401 | 403) {
                "pairing_authentication_refused"
            } else {
                "pairing_self_result_unknown"
            },
        ));
    }
    protocol::validate_self(&record.identity, &response.body)
        .map_err(|error| ClientError::unknown(error.code()))?;
    record.phase = Phase::Ready;
    record.pending = None;
    record.persist(store)?;
    record.ready()
}

#[cfg(all(test, not(target_os = "android")))]
#[path = "client_tests.rs"]
mod tests;

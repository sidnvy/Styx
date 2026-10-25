//! Pure legacy-compatible native join messages. Observations do not grant authority.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use styx_contracts::{
    identity::{DeviceId, Sha256Digest},
    legacy::{JoinPayload, PairingComparison},
    native_host::NativeHostJoinSeed,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        ClaimCapability, DevicePrivateKey, DeviceProofBytes, DevicePublicKey, EnrollmentRequestId,
    },
    tls::GatewayLeafPin,
};

const REQUEST_LIMIT: usize = 16 * 1024;
const RESPONSE_LIMIT: usize = 32 * 1024;

pub(super) struct ProtocolError(&'static str);
impl ProtocolError {
    pub(super) fn code(&self) -> &'static str {
        self.0
    }
}
type Result<T> = std::result::Result<T, ProtocolError>;

pub(super) struct PendingJoin {
    pub(super) request_id: String,
    pub(super) comparison_code: String,
    pub(super) expires_at: u64,
    pub(super) claim_secret: Zeroizing<String>,
}
pub(super) struct ObservedSelf {
    pub(super) generation: String,
    pub(super) computer_approved: bool,
    pub(super) browser_approved: bool,
}

fn parse<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    if raw.is_empty() || raw.len() > RESPONSE_LIMIT {
        return Err(ProtocolError("response_size"));
    }
    serde_json::from_slice(raw).map_err(|_| ProtocolError("response_shape"))
}
fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let raw =
        Zeroizing::new(serde_json::to_vec(value).map_err(|_| ProtocolError("request_encoding"))?);
    if raw.len() > REQUEST_LIMIT {
        return Err(ProtocolError("request_size"));
    }
    Ok(raw)
}
fn token(bytes: &[u8]) -> bool {
    (32..=4096).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}
fn verify_seed_key(seed: &NativeHostJoinSeed, key: &DevicePrivateKey) -> Result<()> {
    let public = DevicePublicKey::from_spki_pem(seed.public_key_pem.as_bytes())
        .map_err(|_| ProtocolError("seed_identity"))?;
    if seed.schema != 1
        || public.spki_der() != key.public_key().spki_der()
        || Sha256Digest::of_bytes(public.spki_der()) != seed.fingerprint
    {
        return Err(ProtocolError("seed_identity"));
    }
    Ok(())
}

pub(super) fn make_join(
    seed: &NativeHostJoinSeed,
    invitation: &str,
    key: &DevicePrivateKey,
) -> Result<Zeroizing<Vec<u8>>> {
    verify_seed_key(seed, key)?;
    if invitation.is_empty() || invitation.len() > 4096 {
        return Err(ProtocolError("invitation"));
    }
    let mut payload = JoinPayload {
        invitation: invitation.to_owned(),
        device_id: seed.device_id.clone(),
        label: seed.label.clone(),
        platform: seed.platform.clone(),
        cwd: seed.cwd.clone(),
        shell: seed.shell.clone(),
        computer_requested: seed.computer_requested,
        public_key_pem: seed.public_key_pem.clone(),
        browser_requested: Some(seed.browser_requested),
    };
    let result = (|| {
        let signing = Zeroizing::new(
            payload
                .signing_bytes()
                .map_err(|_| ProtocolError("join_encoding"))?,
        );
        if signing.len() > REQUEST_LIMIT {
            return Err(ProtocolError("request_size"));
        }
        let signature = URL_SAFE_NO_PAD.encode(
            key.sign(DeviceProofBytes::from_canonical_bytes(&signing))
                .map_err(|_| ProtocolError("join_signature"))?,
        );
        crate::enrollment::validate_local_join(&payload, &signature)
            .map_err(|_| ProtocolError("join_invalid"))?;
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(flatten)]
            payload: &'a JoinPayload,
            signature: &'a str,
        }
        encode(&Wire {
            payload: &payload,
            signature: &signature,
        })
    })();
    payload.invitation.zeroize();
    result
}

fn secret<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
struct Ingress {
    origin: String,
    certificate_sha256: Sha256Digest,
}
#[derive(Deserialize)]
struct PendingResponse {
    status: String,
    request_id: String,
    comparison_code: String,
    expires_at: u64,
    fingerprint: Sha256Digest,
    #[serde(deserialize_with = "secret")]
    claim_secret: Zeroizing<String>,
    ingress: Ingress,
}
pub(super) fn validate_pending(
    seed: &NativeHostJoinSeed,
    raw: &[u8],
    actual_leaf: &GatewayLeafPin,
    now_ms: u64,
) -> Result<PendingJoin> {
    let pending = validate_recorded_pending(seed, raw, actual_leaf)?;
    if now_ms == 0 || pending.expires_at <= now_ms {
        return Err(ProtocolError("pending_expired"));
    }
    Ok(pending)
}
/// Validates persisted ingress/comparison facts only, without claiming current
/// invitation liveness. A current authenticated self response is still required
/// to resolve an already dispatched confirmation or validate an existing Ready.
pub(super) fn validate_recorded_pending(
    seed: &NativeHostJoinSeed,
    raw: &[u8],
    actual_leaf: &GatewayLeafPin,
) -> Result<PendingJoin> {
    let response: PendingResponse = parse(raw)?;
    let comparison = PairingComparison {
        gateway_origin: seed.gateway_origin.clone(),
        certificate_sha256: response.ingress.certificate_sha256,
        request_id: response.request_id.clone(),
        device_fingerprint: seed.fingerprint,
    };
    if response.status != "pending"
        || EnrollmentRequestId::parse(&response.request_id).is_err()
        || !token(response.claim_secret.as_bytes())
        || response.fingerprint != seed.fingerprint
        || response.ingress.origin != seed.gateway_origin
        || response.ingress.certificate_sha256.to_hex() != actual_leaf.as_hex()
        || response.expires_at == 0
        || comparison
            .comparison_code()
            .map_err(|_| ProtocolError("pending_scope"))?
            != response.comparison_code
    {
        return Err(ProtocolError("pending_proof"));
    }
    Ok(PendingJoin {
        request_id: response.request_id,
        comparison_code: response.comparison_code,
        expires_at: response.expires_at,
        claim_secret: response.claim_secret,
    })
}

#[derive(Serialize)]
struct ClaimRequest<'a> {
    request_id: &'a str,
    claim_secret: &'a str,
}
pub(super) fn claim_request(pending: &PendingJoin) -> Result<Zeroizing<Vec<u8>>> {
    encode(&ClaimRequest {
        request_id: &pending.request_id,
        claim_secret: &pending.claim_secret,
    })
}
#[derive(Deserialize)]
struct Capabilities {
    exec: bool,
    computer: bool,
    browser: bool,
}
#[derive(Deserialize)]
struct ClaimResponse {
    status: String,
    device_id: DeviceId,
    crypto: String,
    encrypted_credential: String,
    approved_capabilities: Capabilities,
}
pub(super) fn decrypt_claim(
    seed: &NativeHostJoinSeed,
    key: &DevicePrivateKey,
    raw: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    verify_seed_key(seed, key)?;
    let response: ClaimResponse = parse(raw)?;
    if response.status != "approved"
        || response.device_id != seed.device_id
        || response.crypto != "RSA-OAEP-SHA256"
        || !response.approved_capabilities.exec
        || response.encrypted_credential.len() > 1366
    {
        return Err(ProtocolError("claim_proof"));
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&response.encrypted_credential)
        .map_err(|_| ProtocolError("claim_ciphertext"))?;
    if ciphertext.is_empty()
        || ciphertext.len() > 1024
        || URL_SAFE_NO_PAD.encode(&ciphertext) != response.encrypted_credential
    {
        return Err(ProtocolError("claim_ciphertext"));
    }
    let credential = key
        .unwrap_credential(&ciphertext)
        .map_err(|_| ProtocolError("claim_decryption"))?;
    if !token(&credential) {
        return Err(ProtocolError("credential_shape"));
    }
    Ok(credential)
}
pub(super) fn confirm_request(
    pending: &PendingJoin,
    credential: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if !token(credential) {
        return Err(ProtocolError("credential_shape"));
    }
    let request =
        EnrollmentRequestId::parse(&pending.request_id).map_err(|_| ProtocolError("request_id"))?;
    let confirmation = ClaimCapability::from_legacy_token_bytes(credential)
        .map_err(|_| ProtocolError("credential_shape"))?
        .confirm(&request)
        .to_hex();
    #[derive(Serialize)]
    struct Confirm<'a> {
        request_id: &'a str,
        claim_secret: &'a str,
        confirmation: &'a str,
    }
    encode(&Confirm {
        request_id: &pending.request_id,
        claim_secret: &pending.claim_secret,
        confirmation: &confirmation,
    })
}
#[derive(Deserialize)]
struct Confirmation {
    status: String,
    device_id: DeviceId,
    approved_capabilities: Capabilities,
}
pub(super) fn validate_confirmation(seed: &NativeHostJoinSeed, raw: &[u8]) -> Result<()> {
    let response: Confirmation = parse(raw)?;
    if response.status != "ready_to_connect"
        || response.device_id != seed.device_id
        || !response.approved_capabilities.exec
    {
        return Err(ProtocolError("confirmation_proof"));
    }
    Ok(())
}
#[derive(Deserialize)]
struct SelfResponse {
    status: String,
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    generation: String,
    capabilities: Capabilities,
}
pub(super) fn validate_self(seed: &NativeHostJoinSeed, raw: &[u8]) -> Result<ObservedSelf> {
    let response: SelfResponse = parse(raw)?;
    if response.status != "approved"
        || response.device_id != seed.device_id
        || response.fingerprint != seed.fingerprint
        || !response.capabilities.exec
        || response.generation.is_empty()
        || response.generation.len() > 128
    {
        return Err(ProtocolError("self_proof"));
    }
    Ok(ObservedSelf {
        generation: response.generation,
        computer_approved: response.capabilities.computer,
        browser_approved: response.capabilities.browser,
    })
}

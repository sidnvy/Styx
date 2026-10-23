//! Exact legacy enrollment signing bytes; validation occurs before encoding.
//! Field order and absent-versus-false semantics are authentication contracts.
use crate::identity::{DeviceId, Sha256Digest};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("invalid enrollment scope")]
    InvalidScope,
    #[error("at least one capability approval is required")]
    MissingCapability,
    #[error("enrollment encoding failed")]
    Encoding(#[from] serde_json::Error),
}
fn optional_bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPayload {
    pub invitation: String,
    pub device_id: DeviceId,
    pub label: String,
    pub platform: String,
    pub cwd: String,
    pub shell: String,
    pub computer_requested: bool,
    pub public_key_pem: String,
    #[serde(
        default,
        deserialize_with = "optional_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_requested: Option<bool>,
}
impl JoinPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CodecError> {
        Ok(serde_json::to_vec(self)?)
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPayload {
    pub device_id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub generation: String,
    #[serde(default, deserialize_with = "optional_bool")]
    pub enable_computer: Option<bool>,
    #[serde(default, deserialize_with = "optional_bool")]
    pub enable_browser: Option<bool>,
}
impl CapabilityPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CodecError> {
        if let Some(browser) = self.enable_browser {
            #[derive(Serialize)]
            struct Change {
                browser: bool,
                #[serde(skip_serializing_if = "Option::is_none")]
                computer: Option<bool>,
            }
            Ok(serde_json::to_vec(&(
                "styx-device-capabilities-v2",
                &self.device_id,
                self.fingerprint,
                &self.generation,
                Change {
                    browser,
                    computer: self.enable_computer,
                },
            ))?)
        } else {
            let computer = self.enable_computer.ok_or(CodecError::MissingCapability)?;
            Ok(serde_json::to_vec(&(
                "styx-device-capabilities-v1",
                &self.device_id,
                self.fingerprint,
                &self.generation,
                computer,
            ))?)
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingComparison {
    pub gateway_origin: String,
    pub certificate_sha256: Sha256Digest,
    pub request_id: String,
    pub device_fingerprint: Sha256Digest,
}
impl PairingComparison {
    pub fn comparison_code(&self) -> Result<String, CodecError> {
        let url = url::Url::parse(&self.gateway_origin).map_err(|_| CodecError::InvalidScope)?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != self.gateway_origin
            || self.request_id.len() != 32
            || !self
                .request_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CodecError::InvalidScope);
        }
        let bytes = serde_json::to_vec(&(
            "styx-pairing-comparison-v1",
            &self.gateway_origin,
            self.certificate_sha256,
            &self.request_id,
            self.device_fingerprint,
        ))?;
        let hash = Sha256Digest::of_bytes(&bytes).to_hex().to_ascii_uppercase();
        Ok([&hash[0..4], &hash[4..8], &hash[8..12], &hash[12..16]].join("-"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_generated_public_vectors_match_exact_bytes() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/rust-core-rewrite/LEGACY-WIRE-VECTORS-V1.json"
        ))
        .unwrap();
        for vector in corpus["vectors"].as_array().unwrap() {
            let input = vector["input"].clone();
            match vector["kind"].as_str().unwrap() {
                "join" => assert_eq!(
                    serde_json::from_value::<JoinPayload>(input)
                        .unwrap()
                        .signing_bytes()
                        .unwrap(),
                    vector["payload"].as_str().unwrap().as_bytes(),
                    "{}",
                    vector["id"]
                ),
                "capability" => assert_eq!(
                    serde_json::from_value::<CapabilityPayload>(input)
                        .unwrap()
                        .signing_bytes()
                        .unwrap(),
                    vector["payload"].as_str().unwrap().as_bytes(),
                    "{}",
                    vector["id"]
                ),
                "comparison" => assert_eq!(
                    serde_json::from_value::<PairingComparison>(input)
                        .unwrap()
                        .comparison_code()
                        .unwrap(),
                    vector["value"].as_str().unwrap(),
                    "{}",
                    vector["id"]
                ),
                other => panic!("unreviewed vector kind: {other}"),
            }
        }
    }
    #[test]
    fn absence_is_not_null_or_false() {
        let base = serde_json::json!({"device_id":"fixture", "fingerprint":"a".repeat(64), "generation":"generation"});
        let mut input = base.clone();
        input["enable_browser"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CapabilityPayload>(input).is_err());
        let absent: CapabilityPayload = serde_json::from_value(base.clone()).unwrap();
        assert!(matches!(
            absent.signing_bytes(),
            Err(CodecError::MissingCapability)
        ));
        let mut input = base;
        input["enable_browser"] = false.into();
        let encoded = serde_json::from_value::<CapabilityPayload>(input)
            .unwrap()
            .signing_bytes()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value[0], "styx-device-capabilities-v2");
        assert_eq!(value[4], serde_json::json!({"browser": false}));
    }
    #[test]
    fn comparison_rejects_noncanonical_or_ambiguous_origins() {
        for origin in [
            "http://example.com",
            "https://example.com/",
            "https://EXAMPLE.com",
            "https://example.com:443",
            "https://u:p@example.com",
            "https://example.com/path",
        ] {
            let scope: PairingComparison = serde_json::from_value(serde_json::json!({"gatewayOrigin":origin, "certificateSha256":"a".repeat(64), "requestId":"b".repeat(32), "deviceFingerprint":"c".repeat(64)})).unwrap();
            assert!(scope.comparison_code().is_err(), "{origin}");
        }
    }
    #[test]
    fn untrusted_identity_deserialization_validates_syntax() {
        for raw in ["", "../escape", "with space", "uid\n", "é", "-first"] {
            assert!(serde_json::from_value::<DeviceId>(raw.into()).is_err());
        }
        assert!(serde_json::from_value::<DeviceId>("a".repeat(129).into()).is_err());
        assert!(serde_json::from_value::<Sha256Digest>("A".repeat(64).into()).is_err());
    }
}

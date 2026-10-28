//! The existing schema-1 owner-local pairing link, without persistence/network.
//! Inspection is not approval; secrets have no public Debug/Serialize surface.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
};
use sha2::{Digest, Sha256};
use std::{fmt, io::Cursor};
use zeroize::Zeroizing;

const MAX_LINK: usize = 32_768;
const MAX_CA: usize = 12_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairingLinkError(&'static str);
impl PairingLinkError {
    pub(crate) fn code(self) -> &'static str {
        self.0
    }
}
impl fmt::Display for PairingLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for PairingLinkError {}
type Result<T> = std::result::Result<T, PairingLinkError>;
fn error(code: &'static str) -> PairingLinkError {
    PairingLinkError(code)
}

pub(crate) struct InspectedLink {
    origin: String,
    invitation: Zeroizing<String>,
    expires_ms: u64,
    ca_pem: Option<String>,
    ca_sha256: Option<String>,
}
pub(crate) struct AcceptedLink(InspectedLink);
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkPreview {
    pub(crate) origin: String,
    pub(crate) expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ca_sha256: Option<String>,
    pub(crate) requires_certificate_approval: bool,
}
impl InspectedLink {
    pub(crate) fn preview(&self) -> LinkPreview {
        LinkPreview {
            origin: self.origin.clone(),
            expires_at: self.expires_ms,
            ca_sha256: self.ca_sha256.clone(),
            requires_certificate_approval: self.ca_pem.is_some(),
        }
    }
    pub(crate) fn approve(
        self,
        approved_origin: &str,
        approved_ca: Option<&str>,
        now_ms: u64,
    ) -> Result<AcceptedLink> {
        validate_expiry(self.expires_ms, now_ms)?;
        if normalize_origin(approved_origin).ok().as_deref() != Some(self.origin.as_str()) {
            return Err(error("pairing_gateway_confirmation_mismatch"));
        }
        let current = self
            .ca_pem
            .as_deref()
            .map(|pem| certificate(pem, now_ms))
            .transpose()?;
        if current != self.ca_sha256 || current.as_deref() != approved_ca {
            return Err(error("pairing_certificate_confirmation_mismatch"));
        }
        Ok(AcceptedLink(self))
    }
}
impl AcceptedLink {
    pub(crate) fn into_parts(self) -> (String, Zeroizing<String>, Option<String>, u64) {
        let value = self.0;
        (
            value.origin,
            value.invitation,
            value.ca_pem,
            value.expires_ms,
        )
    }
}
fn normalize_origin(value: &str) -> Result<String> {
    let u = url::Url::parse(value).map_err(|_| error("pairing_gateway_origin_invalid"))?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || !matches!(u.path(), "" | "/")
    {
        return Err(error("pairing_gateway_origin_invalid"));
    }
    Ok(u.origin().ascii_serialization())
}
fn validate_expiry(expires: u64, now_ms: u64) -> Result<()> {
    if now_ms == 0
        || now_ms > MAX_SAFE_INTEGER
        || expires > MAX_SAFE_INTEGER
        || expires <= now_ms
        || now_ms
            .checked_add(600_000)
            .is_none_or(|last| expires > last)
    {
        return Err(error("pairing_link_expired_or_invalid"));
    }
    Ok(())
}
// JS RegExp \s includes BOM but excludes NEL. Match the original PEM suffix.
fn js_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
        | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
fn certificate(pem: &str, now_ms: u64) -> Result<String> {
    let invalid = || error("pairing_certificate_invalid");
    if pem.len() > MAX_CA {
        return Err(invalid());
    }
    let after = pem
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .ok_or_else(invalid)?;
    let body = after
        .strip_prefix("\r\n")
        .or_else(|| after.strip_prefix('\n'))
        .ok_or_else(invalid)?;
    let (encoded, suffix) = body
        .split_once("-----END CERTIFICATE-----")
        .ok_or_else(invalid)?;
    if encoded.is_empty()
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=\r\n".contains(&b))
        || !suffix.chars().all(js_whitespace)
    {
        return Err(invalid());
    }
    let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if certs.len() != 1 {
        return Err(invalid());
    }
    let (_, parsed) = x509_parser::parse_x509_certificate(&certs[0]).map_err(|_| invalid())?;
    let now = i128::from(now_ms);
    if i128::from(parsed.validity().not_before.timestamp()) * 1000 > now
        || i128::from(parsed.validity().not_after.timestamp()) * 1000 <= now
    {
        return Err(error("pairing_certificate_expired"));
    }
    // OpenSSL X509Certificate.raw covers the parsed certificate, not trailing
    // bytes after its ASN.1 sequence. The mature parser supplies that same span.
    Ok(hex::encode(Sha256::digest(parsed.as_raw())))
}

// Only accepted schema fields are scalar. Keep insertion order locally, without
// changing serde_json's global map representation or retaining plaintext tokens.
enum Atom {
    String(Zeroizing<String>),
    Number(serde_json::Number),
    Bool(bool),
    Null,
}
impl Serialize for Atom {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::String(s) => serializer.serialize_str(s),
            Self::Number(n) => n.serialize(serializer),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Null => serializer.serialize_none(),
        }
    }
}
impl<'de> Deserialize<'de> for Atom {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Scalar;
        impl Visitor<'_> for Scalar {
            type Value = Atom;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("pairing scalar")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Atom, E> {
                Ok(Atom::String(Zeroizing::new(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Atom, E> {
                Ok(Atom::String(Zeroizing::new(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Atom, E> {
                Ok(Atom::Number(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Atom, E> {
                Ok(Atom::Number(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Atom, E> {
                serde_json::Number::from_f64(v)
                    .map(Atom::Number)
                    .ok_or_else(|| E::custom("pairing number"))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Atom, E> {
                Ok(Atom::Bool(v))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Atom, E> {
                Ok(Atom::Null)
            }
        }
        deserializer.deserialize_any(Scalar)
    }
}
struct Fields(Vec<(String, Atom)>);
impl Serialize for Fields {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}
impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = Fields;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("pairing object")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Fields, M::Error> {
                let mut fields = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if fields.len() >= 5 || fields.iter().any(|(old, _)| old == &key) {
                        return Err(de::Error::custom("pairing fields"));
                    }
                    fields.push((key, map.next_value::<Atom>()?));
                }
                Ok(Fields(fields))
            }
        }
        deserializer.deserialize_map(Object)
    }
}
impl Fields {
    fn number(&self, name: &str) -> Option<u64> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| match v {
                Atom::Number(n) => n.as_u64(),
                _ => None,
            })
    }
    fn string(&mut self, name: &str) -> Option<Zeroizing<String>> {
        let index = self.0.iter().position(|(k, _)| k == name)?;
        match self.0.swap_remove(index).1 {
            Atom::String(value) => Some(value),
            _ => None,
        }
    }
}
/// Produce the same canonical scalar JSON accepted by inspection. The link is
/// a secret: callers publish it only to a new private file, never a report.
pub(crate) fn build(
    origin: &str,
    invitation: &str,
    expires_ms: u64,
    ca_pem: &str,
    now_ms: u64,
) -> Result<Zeroizing<String>> {
    let fields = Fields(vec![
        ("caPem".into(), Atom::String(Zeroizing::new(ca_pem.into()))),
        ("expiresAt".into(), Atom::Number(expires_ms.into())),
        (
            "invitation".into(),
            Atom::String(Zeroizing::new(invitation.into())),
        ),
        ("origin".into(), Atom::String(Zeroizing::new(origin.into()))),
        ("schema".into(), Atom::Number(1.into())),
    ]);
    let bytes =
        Zeroizing::new(serde_json::to_vec(&fields).map_err(|_| error("pairing_link_invalid"))?);
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
    let link = Zeroizing::new(format!("styx://join#{}", encoded.as_str()));
    inspect(&link, now_ms)?;
    Ok(link)
}

pub(crate) fn inspect(link: &str, now_ms: u64) -> Result<InspectedLink> {
    if link.len() > MAX_LINK {
        return Err(error("pairing_link_size_invalid"));
    }
    let u = url::Url::parse(link).map_err(|_| error("pairing_link_invalid"))?;
    let encoded = u.fragment().ok_or_else(|| error("pairing_link_invalid"))?;
    if u.scheme() != "styx"
        || u.host_str() != Some("join")
        || !u.username().is_empty()
        || u.password().is_some()
        || u.port().is_some()
        || !u.path().is_empty()
        || u.query().is_some()
        || encoded.is_empty()
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(error("pairing_link_invalid"));
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| error("pairing_link_invalid"))?,
    );
    let canonical_encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
    if canonical_encoded.as_str() != encoded {
        return Err(error("pairing_link_invalid"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| error("pairing_link_invalid"))?;
    let mut fields: Fields =
        serde_json::from_str(text).map_err(|_| error("pairing_link_invalid"))?;
    let canonical =
        Zeroizing::new(serde_json::to_vec(&fields).map_err(|_| error("pairing_link_invalid"))?);
    if canonical.as_slice() != bytes.as_slice() {
        return Err(error("pairing_link_noncanonical"));
    }
    if fields.number("schema") != Some(1)
        || fields.0.iter().any(|(k, _)| {
            !matches!(
                k.as_str(),
                "schema" | "origin" | "invitation" | "expiresAt" | "caPem"
            )
        })
    {
        return Err(error("pairing_link_schema_invalid"));
    }
    let expires_ms = fields
        .number("expiresAt")
        .ok_or_else(|| error("pairing_link_expired_or_invalid"))?;
    validate_expiry(expires_ms, now_ms)?;
    let origin = fields
        .string("origin")
        .ok_or_else(|| error("pairing_link_schema_invalid"))?;
    let normalized = normalize_origin(&origin)?;
    if origin.as_str() != normalized {
        return Err(error("pairing_link_schema_invalid"));
    }
    let invitation = fields
        .string("invitation")
        .ok_or_else(|| error("pairing_invitation_invalid"))?;
    if invitation.len() != 43
        || !invitation
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(error("pairing_invitation_invalid"));
    }
    let invitation_bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(invitation.as_bytes())
            .map_err(|_| error("pairing_invitation_invalid"))?,
    );
    let invitation_canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(invitation_bytes.as_slice()));
    if invitation_canonical.as_str() != invitation.as_str() {
        return Err(error("pairing_invitation_invalid"));
    }
    let has_ca = fields.0.iter().any(|(k, _)| k == "caPem");
    let ca_pem = if has_ca {
        Some(
            fields
                .string("caPem")
                .ok_or_else(|| error("pairing_certificate_invalid"))?
                .to_string(),
        )
    } else {
        None
    };
    let ca_sha256 = ca_pem
        .as_deref()
        .map(|pem| certificate(pem, now_ms))
        .transpose()?;
    Ok(InspectedLink {
        origin: normalized,
        invitation,
        expires_ms,
        ca_pem,
        ca_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_792_800_000_000;
    fn link(raw: &str) -> String {
        format!("styx://join#{}", URL_SAFE_NO_PAD.encode(raw))
    }
    fn raw(expires: u64) -> String {
        format!(
            r#"{{"expiresAt":{expires},"invitation":"{}","origin":"https://example.test","schema":1}}"#,
            URL_SAFE_NO_PAD.encode([7u8; 32])
        )
    }
    #[test]
    fn original_order_canonical_approval_and_expiry_boundaries() {
        let input = raw(NOW + 60_000);
        let inspected = inspect(&link(&input), NOW).unwrap();
        let preview = serde_json::to_value(inspected.preview()).unwrap();
        assert_eq!(preview["origin"], "https://example.test");
        assert_eq!(preview["requiresCertificateApproval"], false);
        assert!(preview.get("caSha256").is_none());
        assert!(
            inspect(&link(&input), NOW)
                .unwrap()
                .approve("https://other.test", None, NOW)
                .is_err()
        );
        assert!(
            inspect(&link(&input), NOW)
                .unwrap()
                .approve("https://example.test", Some("unapproved"), NOW)
                .is_err()
        );
        let (origin, invitation, ca, expires) = inspected
            .approve("https://EXAMPLE.test:443/", None, NOW)
            .unwrap()
            .into_parts();
        assert_eq!(origin, "https://example.test");
        assert_eq!(invitation.as_str(), URL_SAFE_NO_PAD.encode([7u8; 32]));
        assert!(ca.is_none());
        assert_eq!(expires, NOW + 60_000);
        for expires in [NOW, NOW - 1, NOW + 600_001, MAX_SAFE_INTEGER + 1] {
            assert!(inspect(&link(&raw(expires)), NOW).is_err());
        }
        assert!(inspect(&link(&input), 0).is_err());
        assert!(
            inspect(&link(&input), NOW)
                .unwrap()
                .approve("https://example.test", None, NOW + 60_000)
                .is_err()
        );
        assert!(inspect(&link(&raw(NOW + 600_000)), NOW).is_ok());
    }
    #[test]
    fn noncanonical_and_schema_confusion_never_become_inspected() {
        let original = raw(NOW + 60_000);
        for changed in [
            format!(" {original}"),
            original.replace(",", ", "),
            original.replace("https://", "https:\\/\\/"),
            original.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
            original.replace("\"schema\":1", "\"schema\":1,\"extra\":true"),
            original.replace("\"schema\":1", "\"schema\":2"),
            original.replace("\"schema\":1", "\"schema\":1.0"),
        ] {
            assert!(inspect(&link(&changed), NOW).is_err());
        }
        let encoded = URL_SAFE_NO_PAD.encode(&original);
        for bad in [
            format!("styx://join/#{encoded}"),
            format!("styx://join?x=1#{encoded}"),
            format!("styx://join#{encoded}="),
            format!("https://join#{encoded}"),
        ] {
            assert!(inspect(&bad, NOW).is_err());
        }
        assert!(inspect(&"x".repeat(MAX_LINK + 1), NOW).is_err());
    }
    #[test]
    fn actual_certificate_der_pin_explicit_approval_and_validity() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before =
            time::OffsetDateTime::from_unix_timestamp((NOW / 1000) as i64 - 60).unwrap();
        params.not_after =
            time::OffsetDateTime::from_unix_timestamp((NOW / 1000) as i64 + 120).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        let expected = hex::encode(Sha256::digest(cert.der()));
        let input = raw(NOW + 60_000).replace(
            "\"schema\":1",
            &format!(
                "\"schema\":1,\"caPem\":{}",
                serde_json::to_string(&pem).unwrap()
            ),
        );
        let inspected = inspect(&link(&input), NOW).unwrap();
        let preview = serde_json::to_value(inspected.preview()).unwrap();
        assert_eq!(preview["caSha256"], expected);
        assert_eq!(preview["requiresCertificateApproval"], true);
        assert!(
            inspect(&link(&input), NOW)
                .unwrap()
                .approve("https://example.test", None, NOW)
                .is_err()
        );
        assert!(
            inspect(&link(&input), NOW)
                .unwrap()
                .approve("https://example.test", Some(&expected.to_uppercase()), NOW)
                .is_err()
        );
        let (_, _, retained, _) = inspected
            .approve("https://example.test", Some(&expected), NOW)
            .unwrap()
            .into_parts();
        assert_eq!(retained.as_deref(), Some(pem.as_str()));
        let expired = raw(NOW + 180_000).replace(
            "\"schema\":1",
            &format!(
                "\"schema\":1,\"caPem\":{}",
                serde_json::to_string(&pem).unwrap()
            ),
        );
        assert!(inspect(&link(&expired), NOW + 120_000).is_err());
        for bad in [
            "not PEM".to_owned(),
            format!("{pem}{pem}"),
            "x".repeat(MAX_CA + 1),
        ] {
            let input = raw(NOW + 60_000).replace(
                "\"schema\":1",
                &format!(
                    "\"schema\":1,\"caPem\":{}",
                    serde_json::to_string(&bad).unwrap()
                ),
            );
            assert!(inspect(&link(&input), NOW).is_err());
        }
    }
}

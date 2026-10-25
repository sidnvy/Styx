//! Historical `deploymentConnectionHash` compatibility for original receipts.
//! Serde owns JSON parsing/escaping/pretty printing; ryu-js owns ECMAScript
//! number formatting. Ordered properties are local to this codec: enabling
//! serde_json's global preserve_order would change unrelated signed contracts.
use crate::identity::Sha256Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeMap};
use serde_json::value::RawValue;
use std::{collections::HashMap, fmt};

#[derive(Debug, thiserror::Error)]
pub enum ConnectionHashError {
    #[error("invalid legacy deployment JSON")]
    Json(#[from] serde_json::Error),
    #[error("legacy deployment exceeds supported bounds or is not an object")]
    Scope,
}

struct Object(Vec<(String, Box<RawValue>)>);
impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Properties;
        impl<'de> de::Visitor<'de> for Properties {
            type Value = Object;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object with original property order")
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Object, A::Error> {
                let mut fields: Vec<(String, Box<RawValue>)> = Vec::new();
                let mut positions = HashMap::<String, usize>::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    // JSON.parse keeps the first insertion position and the
                    // last value, including escaped duplicate property names.
                    if let Some(&index) = positions.get(&key) {
                        fields[index].1 = value;
                    } else {
                        positions.insert(key.clone(), fields.len());
                        fields.push((key, value));
                    }
                }
                Ok(Object(fields))
            }
        }
        d.deserialize_map(Properties)
    }
}

// OrdinaryOwnPropertyKeys orders array-index names before other string keys.
fn property_index(key: &str) -> Option<u32> {
    let n: u32 = key.parse().ok()?;
    (n != u32::MAX && n.to_string() == key).then_some(n)
}

enum Projected {
    Object(Vec<(String, Projected)>),
    Array(Vec<Projected>),
    Scalar(Box<RawValue>),
}
impl Serialize for Projected {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
            Self::Array(values) => values.serialize(serializer),
            Self::Scalar(value) => value.serialize(serializer),
        }
    }
}
fn project(raw: &RawValue, depth: usize) -> Result<Projected, ConnectionHashError> {
    if depth > 64 {
        return Err(ConnectionHashError::Scope);
    }
    Ok(match raw.get().as_bytes()[0] {
        b'{' => {
            let Object(mut fields) = serde_json::from_str(raw.get())?;
            // Stable sort leaves all non-index names in original insertion order.
            fields.sort_by_key(|(key, _)| property_index(key).unwrap_or(u32::MAX));
            Projected::Object(
                fields
                    .into_iter()
                    .map(|(k, v)| Ok((k, project(&v, depth + 1)?)))
                    .collect::<Result<_, ConnectionHashError>>()?,
            )
        }
        b'[' => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(raw.get())?;
            Projected::Array(
                values
                    .iter()
                    .map(|v| project(v, depth + 1))
                    .collect::<Result<_, _>>()?,
            )
        }
        b'"' => {
            let text: String = serde_json::from_str(raw.get())?;
            Projected::Scalar(serde_json::value::to_raw_value(&text)?)
        }
        b't' | b'f' | b'n' => Projected::Scalar(raw.to_owned()),
        _ => {
            // Parse to binary64 like JSON.parse; do not preserve integer digits
            // beyond JS precision or Rust's different exponent notation.
            let n: f64 = raw.get().parse().map_err(|_| ConnectionHashError::Scope)?;
            let mut buffer = ryu_js::Buffer::new();
            let text = if n.is_finite() {
                buffer.format(n)
            } else {
                "null"
            };
            Projected::Scalar(RawValue::from_string(text.to_owned())?)
        }
    })
}

/// Match `src/shared/deployment-scope.mjs` without writing the source config.
/// A receipt hash alone grants no migration/owner authority. The caller must
/// still bind the complete original configuration bytes, file and transaction.
/// Invalid UTF-8, lone UTF-16 surrogates in projected strings, >1 MiB, and
/// >64 projected levels refuse;
/// no alternate hash or normalization is used as a fallback.
pub fn deployment_connection_hash(bytes: &[u8]) -> Result<Sha256Digest, ConnectionHashError> {
    if bytes.len() > 1024 * 1024 {
        return Err(ConnectionHashError::Scope);
    }
    let Object(mut fields) = serde_json::from_slice(bytes)?;
    let gateway = fields.iter_mut().find(|(k, _)| k == "gateway");
    if let Some((_, value)) = gateway.filter(|(_, v)| v.get().starts_with('{')) {
        let Object(mut gateway_fields) = serde_json::from_str(value.get())?;
        if gateway_fields.iter().any(|(k, _)| k == "deviceIngress") {
            gateway_fields.retain(|(k, _)| k != "deviceIngress");
            let gateway = Projected::Object(
                gateway_fields
                    .into_iter()
                    .map(|(k, v)| Ok((k, project(&v, 2)?)))
                    .collect::<Result<_, ConnectionHashError>>()?,
            );
            // Reparse through project to apply JS integer-key ordering to this
            // edited object as well as every untouched nested object.
            *value = serde_json::value::to_raw_value(&gateway)?;
            let object = Projected::Object(
                fields
                    .into_iter()
                    .map(|(k, v)| Ok((k, project(&v, 1)?)))
                    .collect::<Result<_, ConnectionHashError>>()?,
            );
            let raw = serde_json::value::to_raw_value(&object)?;
            let mut projected = serde_json::to_vec_pretty(&project(&raw, 0)?)?;
            projected.push(b'\n');
            return Ok(Sha256Digest::of_bytes(&projected));
        }
    }
    Ok(Sha256Digest::of_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_javascript_projection_vectors_match() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/rust-core-rewrite/LEGACY-DEPLOYMENT-HASH-VECTORS.json"
        ))
        .unwrap();
        for v in corpus["vectors"].as_array().unwrap() {
            assert_eq!(
                deployment_connection_hash(v["input"].as_str().unwrap().as_bytes())
                    .unwrap()
                    .to_hex(),
                v["sha256"].as_str().unwrap(),
                "{}",
                v["id"]
            );
        }
    }
    #[test]
    fn malformed_or_unsupported_inputs_refuse_without_fallback() {
        for raw in [
            "null",
            "[]",
            "{",
            "{}{}",
            r#"{"gateway":{"deviceIngress":true},"bad":"\ud800"}"#,
        ] {
            assert!(deployment_connection_hash(raw.as_bytes()).is_err());
        }
        let deep = format!(
            "{{\"gateway\":{{\"deviceIngress\":true}},\"nested\":{}0{}}}",
            "[".repeat(65),
            "]".repeat(65)
        );
        assert!(deployment_connection_hash(deep.as_bytes()).is_err());
        assert!(deployment_connection_hash(&vec![b' '; 1024 * 1024 + 1]).is_err());
    }
}

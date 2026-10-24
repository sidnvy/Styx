//! Bounded native canonical reader. RawValue preserves unknown numeric lexemes;
//! these bytes do not authorize a writer, legacy handoff or physical apply.
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
};
use styx_contracts::identity::Sha256Digest;
use styx_contracts::native_management::{NATIVE_MARKER_BYTES, NATIVE_STATE_BYTES};
pub use styx_contracts::native_management::{NativeRootMarker, NativeState};
use styx_core::management::state::{validate_marker, validate_state};

const MAX_STATE_BYTES: usize = NATIVE_STATE_BYTES;
const MAX_MARKER_BYTES: usize = NATIVE_MARKER_BYTES;
const MAX_DEPTH: usize = 32;
const MAX_MEMBERS: usize = 4096;
const MAX_KEY_BYTES: usize = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeStateError {
    #[error("native_state_capacity")]
    Capacity,
    #[error("native_state_invalid_json")]
    InvalidJson,
    #[error("native_state_duplicate_key")]
    DuplicateKey,
    #[error("native_root_marker_invalid")]
    InvalidMarker,
    #[error("native_state_invalid")]
    InvalidState,
}
struct Budget {
    members: usize,
    // Preserve typed semantic refusal independently from Serde's syntax error.
    // Returning an inner Err inside Visitor::Value permits serde_json's trailing
    // container check to override it when the visitor stops before a value.
    refusal: Option<NativeStateError>,
}
impl Budget {
    fn refuse<E: de::Error>(&mut self, error: NativeStateError) -> E {
        self.refusal.get_or_insert(error);
        E::custom("native_reader_refused")
    }
    fn member(&mut self) -> Result<(), NativeStateError> {
        self.members = self
            .members
            .checked_add(1)
            .ok_or(NativeStateError::Capacity)?;
        if self.members > MAX_MEMBERS {
            return Err(NativeStateError::Capacity);
        }
        Ok(())
    }
}
struct ObjectGuard<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> Visitor<'de> for ObjectGuard<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_KEY_BYTES {
                return Err(self.budget.refuse(NativeStateError::Capacity));
            }
            if !keys.insert(key) {
                return Err(self.budget.refuse(NativeStateError::DuplicateKey));
            }
            if let Err(error) = self.budget.member() {
                return Err(self.budget.refuse(error));
            }
            let raw = map.next_value::<&'de RawValue>()?;
            if let Err(error) = guard_value(raw, self.budget, self.depth + 1) {
                return Err(self.budget.refuse(error));
            }
        }
        Ok(())
    }
}
struct ArrayGuard<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> Visitor<'de> for ArrayGuard<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON array")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        while let Some(raw) = seq.next_element::<&'de RawValue>()? {
            if let Err(error) = self.budget.member() {
                return Err(self.budget.refuse(error));
            }
            if let Err(error) = guard_value(raw, self.budget, self.depth + 1) {
                return Err(self.budget.refuse(error));
            }
        }
        Ok(())
    }
}
fn guard_value(raw: &RawValue, budget: &mut Budget, depth: usize) -> Result<(), NativeStateError> {
    let bytes = raw.get().as_bytes();
    let first = bytes
        .iter()
        .copied()
        .find(|c| !c.is_ascii_whitespace())
        .ok_or(NativeStateError::InvalidJson)?;
    // RawValue itself is parsed by serde_json's official scanner, including
    // numeric syntax. Primitive values never enter Value/f64/Number conversion.
    if !matches!(first, b'{' | b'[') {
        return Ok(());
    }
    if depth > MAX_DEPTH {
        return Err(NativeStateError::Capacity);
    }
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    let result = if first == b'{' {
        de::Deserializer::deserialize_map(&mut decoder, ObjectGuard { budget, depth })
    } else {
        de::Deserializer::deserialize_seq(&mut decoder, ArrayGuard { budget, depth })
    };
    // This is a typed side channel, never inspection of a parser error string.
    if let Some(refusal) = budget.refusal {
        return Err(refusal);
    }
    result.map_err(|_| NativeStateError::InvalidJson)?;
    decoder.end().map_err(|_| NativeStateError::InvalidJson)
}
fn guard_document(bytes: &[u8], max: usize) -> Result<(), NativeStateError> {
    if bytes.len() > max {
        return Err(NativeStateError::Capacity);
    }
    let raw: &RawValue =
        serde_json::from_slice(bytes).map_err(|_| NativeStateError::InvalidJson)?;
    guard_value(
        raw,
        &mut Budget {
            members: 0,
            refusal: None,
        },
        1,
    )
}

/// Validated schema and exact raw bytes, not a writer/root or execution authority.
/// No Debug/Serde implementation: extensions and original bytes may be private.
pub struct ValidatedNativeState {
    state: NativeState,
    raw: Vec<u8>,
    digest: Sha256Digest,
}
impl ValidatedNativeState {
    pub fn state(&self) -> &NativeState {
        &self.state
    }
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn raw_sha256(&self) -> Sha256Digest {
        self.digest
    }
}
pub fn decode_marker(bytes: &[u8]) -> Result<NativeRootMarker, NativeStateError> {
    guard_document(bytes, MAX_MARKER_BYTES)?;
    let marker: NativeRootMarker =
        serde_json::from_slice(bytes).map_err(|_| NativeStateError::InvalidMarker)?;
    validate_marker(&marker).map_err(|_| NativeStateError::InvalidMarker)?;
    Ok(marker)
}
fn field<T: DeserializeOwned>(
    fields: &mut BTreeMap<String, &RawValue>,
    name: &str,
) -> Result<T, NativeStateError> {
    let raw = fields.remove(name).ok_or(NativeStateError::InvalidState)?;
    serde_json::from_str(raw.get()).map_err(|_| NativeStateError::InvalidState)
}
pub fn decode_state(
    bytes: &[u8],
    marker: &NativeRootMarker,
) -> Result<ValidatedNativeState, NativeStateError> {
    validate_marker(marker).map_err(|_| NativeStateError::InvalidMarker)?;
    guard_document(bytes, MAX_STATE_BYTES)?;
    // Decode each declared field directly from its original JSON fragment.
    // Serde flatten buffering is intentionally not used for unknown numbers.
    let mut fields: BTreeMap<String, &RawValue> =
        serde_json::from_slice(bytes).map_err(|_| NativeStateError::InvalidState)?;
    let state = NativeState {
        schema: field(&mut fields, "schema")?,
        kind: field(&mut fields, "kind")?,
        runtime_format: field(&mut fields, "runtime_format")?,
        reader_contract: field(&mut fields, "reader_contract")?,
        scope_generation: field(&mut fields, "scope_generation")?,
        deployment_raw_sha256: field(&mut fields, "deployment_raw_sha256")?,
        mode: field(&mut fields, "mode")?,
        revision: field(&mut fields, "revision")?,
        last_transaction: field(&mut fields, "last_transaction")?,
        desired: field(&mut fields, "desired")?,
        migration: fields
            .remove("migration")
            .map(|raw| serde_json::from_str(raw.get()).map_err(|_| NativeStateError::InvalidState))
            .transpose()?,
        extensions: fields
            .into_iter()
            .map(|(key, value)| {
                RawValue::from_string(value.get().to_owned())
                    .map(|raw| (key, raw))
                    .map_err(|_| NativeStateError::InvalidState)
            })
            .collect::<Result<_, _>>()?,
    };
    validate_state(&state, marker).map_err(|_| NativeStateError::InvalidState)?;
    Ok(ValidatedNativeState {
        state,
        raw: bytes.to_vec(),
        digest: Sha256Digest::of_bytes(bytes),
    })
}
#[cfg(test)]
#[path = "native_state_tests.rs"]
mod tests;

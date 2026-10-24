//! Snapshot-local reference binding, not owner issuance or operation authority.
//!
//! Runtime must hold the resource's mutex and validate its actual native epoch
//! both before dispatch and after worker events. This registry cannot attest
//! that a browser, document or element is still live. The caller supplies fresh
//! OS entropy for every scope; it must not reconstruct a scope with old entropy.
use std::collections::BTreeMap;
use styx_contracts::{error::ErrorCategory, identity::Sha256Digest, operation::ResourceTarget};

use crate::operations::OwnerLease;

pub const MAX_NATIVE_REFS: usize = 2048;
pub const MAX_REFERENCE_METADATA_BYTES: usize = 256 * 1024;
const MAX_NATIVE_REF_BYTES: usize = 64;
const LOGICAL_ENTRY_OVERHEAD: usize = 64;
const TOKEN_BYTES: usize = 37;

/// Native reference to public opaque token. Returned values are not authority.
pub type NativeToOpaque = BTreeMap<String, String>;

/// Intentionally neither Clone nor serializable: scopes cannot be restored from
/// request DTOs or reused as another resource's reference registry. Logical
/// accounting bounds retained strings plus a per-entry allowance, not allocator
/// RSS or temporary copies retained by a caller of replace_snapshot.
pub struct BrowserReferenceScope {
    owner: OwnerLease,
    target: ResourceTarget,
    entropy: [u8; 32],
    snapshot_revision: u64,
    native_epoch: Option<u64>,
    token_to_native: BTreeMap<String, String>,
}
impl BrowserReferenceScope {
    pub fn new(owner: OwnerLease, target: ResourceTarget, fresh_entropy: [u8; 32]) -> Self {
        Self {
            owner,
            target,
            entropy: fresh_entropy,
            snapshot_revision: 0,
            native_epoch: None,
            token_to_native: BTreeMap::new(),
        }
    }

    /// Replaces rather than merges. Failure invalidates the previous snapshot;
    /// it never evicts one live entry and claims a partially accepted snapshot.
    /// Even invalid/over-budget attempts consume a revision, preventing ABA.
    pub fn replace_snapshot(
        &mut self,
        native_epoch: u64,
        native_refs: &[String],
    ) -> Result<NativeToOpaque, ErrorCategory> {
        self.clear();
        self.snapshot_revision = self
            .snapshot_revision
            .checked_add(1)
            .ok_or(ErrorCategory::Busy)?;
        if native_epoch == 0 {
            return Err(ErrorCategory::InvalidRequest);
        }
        if native_refs.len() > MAX_NATIVE_REFS {
            return Err(ErrorCategory::Busy);
        }
        let mut native_to_opaque = NativeToOpaque::new();
        let mut token_to_native = BTreeMap::new();
        let mut metadata = 0_usize;
        for native in native_refs {
            if !valid_native_ref(native) {
                return Err(ErrorCategory::InvalidRequest);
            }
            if native_to_opaque.contains_key(native) {
                continue;
            }
            let cost = native.len() + TOKEN_BYTES + LOGICAL_ENTRY_OVERHEAD;
            metadata = metadata.checked_add(cost).ok_or(ErrorCategory::Busy)?;
            if metadata > MAX_REFERENCE_METADATA_BYTES {
                return Err(ErrorCategory::Busy);
            }
            let token = self.token(native_epoch, native);
            // A truncated-hash collision is refusal, never aliasing two native
            // references or silently replacing an already assigned reference.
            if token_to_native
                .insert(token.clone(), native.clone())
                .is_some()
            {
                return Err(ErrorCategory::IntegrityFailure);
            }
            native_to_opaque.insert(native.clone(), token);
        }
        self.token_to_native = token_to_native;
        self.native_epoch = Some(native_epoch);
        Ok(native_to_opaque)
    }

    pub fn resolve(
        &self,
        original_owner: &OwnerLease,
        exact_target: &ResourceTarget,
        token: &str,
        current_native_epoch: u64,
    ) -> Result<String, ErrorCategory> {
        if original_owner != &self.owner {
            return Err(ErrorCategory::Unauthorized);
        }
        if current_native_epoch == 0 {
            return Err(ErrorCategory::InvalidRequest);
        }
        if exact_target != &self.target
            || self.native_epoch != Some(current_native_epoch)
            || !valid_opaque_token(token)
        {
            return Err(ErrorCategory::StaleObservation);
        }
        self.token_to_native
            .get(token)
            .cloned()
            .ok_or(ErrorCategory::StaleObservation)
    }

    pub fn current_epoch(&self) -> Option<u64> {
        self.native_epoch
    }

    pub fn clear(&mut self) {
        self.native_epoch = None;
        self.token_to_native.clear();
    }

    pub fn invalidate(&mut self) {
        self.clear();
    }

    fn token(&self, native_epoch: u64, native: &str) -> String {
        let mut material = Vec::with_capacity(512);
        material.extend_from_slice(b"styx-browser-reference-scope-v1\0");
        material.extend_from_slice(&self.entropy);
        // Length prefixes avoid ambiguous concatenations; fixed integers use
        // explicit endian order. No serde/Debug rendering enters this domain.
        for value in [
            self.owner.owner_id().as_str(),
            self.target.operation_id.host_generation.as_str(),
            self.target.operation_id.owner_epoch.as_str(),
        ] {
            material.extend_from_slice(&(value.len() as u64).to_be_bytes());
            material.extend_from_slice(value.as_bytes());
        }
        material.extend_from_slice(&self.target.operation_id.sequence.to_be_bytes());
        material.extend_from_slice(self.target.payload_digest.as_bytes());
        material.extend_from_slice(&self.snapshot_revision.to_be_bytes());
        material.extend_from_slice(&native_epoch.to_be_bytes());
        material.extend_from_slice(&(native.len() as u64).to_be_bytes());
        material.extend_from_slice(native.as_bytes());
        let digest = Sha256Digest::of_bytes(&material).to_hex();
        format!("styx-{}", &digest[..32])
    }
}

fn valid_native_ref(value: &str) -> bool {
    if value.len() > MAX_NATIVE_REF_BYTES {
        return false;
    }
    // Exact legacy syntax /^(?:f\d+)?e\d+$/ with ASCII digits only.
    let bytes = value.as_bytes();
    let mut pos = 0;
    if bytes.first() == Some(&b'f') {
        pos += 1;
        let start = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if pos == start {
            return false;
        }
    }
    if bytes.get(pos) != Some(&b'e') {
        return false;
    }
    pos += 1;
    pos < bytes.len() && bytes[pos..].iter().all(u8::is_ascii_digit)
}
fn valid_opaque_token(value: &str) -> bool {
    value.len() == TOKEN_BYTES
        && value.starts_with("styx-")
        && value.as_bytes()[5..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

#[cfg(test)]
mod tests;

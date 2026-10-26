//! Schema3 effects stay in the SAME ManagementV1 namespace and original writer.
//! These receipts attest durability only, never old-runtime settlement or rename.
use super::native::NativeRetirementFileStamp;
use super::*;
use styx_contracts::native_management::NativeRootIdentity;

pub(in crate::store) type NativeRetirementIntent =
    LegacyCredentialRetirementIntent<NativeRootIdentity, NativeRetirementFileStamp>;
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(in crate::store) type NativePreparedRetirement =
    PreparedCredentialRetirement<NativeRootIdentity, NativeRetirementFileStamp>;
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(in crate::store) type NativeRetiredRecord =
    RetiredCredentialRecord<NativeRootIdentity, NativeRetirementFileStamp>;
pub(in crate::store) type NativeOriginalRetirement =
    OriginalCredentialRetirement<NativeRootIdentity, NativeRetirementFileStamp>;

#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(super) fn actual_root(root: RootIdentity) -> JournalResult<NativeRootIdentity> {
    #[cfg(target_os = "macos")]
    {
        match root {
            RootIdentity::Macos { device, inode, uid } => {
                Ok(NativeRootIdentity::Macos { device, inode, uid })
            }
            _ => Err(JournalError::Conflict),
        }
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let RootIdentity::Linux { device, inode, uid } = root;
        Ok(NativeRootIdentity::Linux { device, inode, uid })
    }
    #[cfg(target_os = "windows")]
    {
        match root {
            RootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => Ok(NativeRootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            }),
            _ => Err(JournalError::Conflict),
        }
    }
}
/// First promotion reserves a formerly opaque extension name. An old reader
/// may preserve that name, but migration must never replace its original bytes.
/// Read raw JSON here: no state re-encoding or conversion of unknown numbers.
pub(in crate::store) fn reject_migration_v2_collision(raw: &[u8]) -> JournalResult<()> {
    struct OriginalKeys;
    impl<'de> serde::Deserialize<'de> for OriginalKeys {
        fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
            struct Keys;
            impl<'de> serde::de::Visitor<'de> for Keys {
                type Value = OriginalKeys;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an original state object without a reserved migration key")
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut map: M,
                ) -> Result<Self::Value, M::Error> {
                    let mut seen = BTreeSet::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if key == styx_contracts::native_management::NATIVE_MIGRATION_V2_KEY
                            || !seen.insert(key)
                        {
                            return Err(serde::de::Error::custom(
                                "original_state_extension_collision",
                            ));
                        }
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                    Ok(OriginalKeys)
                }
            }
            de.deserialize_map(Keys)
        }
    }
    serde_json::from_slice::<OriginalKeys>(raw)
        .map(|_| ())
        .map_err(|_| JournalError::Conflict)
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn canonical(state: &ConfigurationState, intent: &NativeRetirementIntent) -> JournalResult<()> {
    // Native schema3 may not borrow Linux-v1 successor exceptions. The native
    // cutover port must later supply its own exact prepared-target capability.
    if actual_root(state.root.identity())? != intent.config_root {
        return Err(JournalError::Conflict);
    }
    for (name, expected) in [
        ("deployment.json", intent.deployment_raw_sha256),
        ("state.json", intent.before_state_sha256),
    ] {
        let raw = state
            .root
            .read_raw(name, 1024 * 1024)
            .map_err(|_| JournalError::Unknown)?;
        if name == "state.json" {
            reject_migration_v2_collision(raw.bytes())?;
        }
        if Sha256Digest::of_bytes(raw.bytes()) != expected {
            return Err(JournalError::Conflict);
        }
    }
    Ok(())
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn original_native(
    scan: &JournalObservation,
    id: &TransactionId,
) -> JournalResult<NativeObservedRetirement> {
    let inventory = super::super::platform::inventory(scan)?;
    if !inventory.orphans.is_empty() {
        return Err(JournalError::Conflict);
    }
    let mut handoffs = scan_handoffs(scan)?;
    if !handoffs.records.is_empty() || handoffs.native_records.len() != 1 {
        return Err(JournalError::Conflict);
    }
    let original = handoffs.native_records.remove(0);
    if &original.intent.transaction_id != id {
        return Err(JournalError::Conflict);
    }
    Ok(original)
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn recovery_continuation(
    scan: &JournalObservation,
    intent: &NativeRetirementIntent,
    raw: &[u8],
) -> JournalResult<bool> {
    let recovery = scan_owner_recoveries(scan)?;
    let Some(record) = recovery.records.first() else {
        return Ok(false);
    };
    Ok(record.stage() == Some(OwnerRecoveryStage::GuardsHeld)
        && record.intent.transaction_id == intent.transaction_id
        && record.intent.sequence == intent.sequence
        && record.intent.config_root == intent.config_root
        && record.intent.deployment_raw_sha256 == intent.deployment_raw_sha256
        && record.intent.before_state_sha256 == intent.before_state_sha256
        && record.intent.candidate_manifest_sha256 == intent.candidate_manifest_sha256
        && record.intent.publisher_spki_sha256 == intent.publisher_spki_sha256
        && record.intent.successor_retirement_intent_sha256 == Sha256Digest::of_bytes(raw))
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl OwnedManagementJournal {
    pub(in crate::store) fn native_prepared_matches(
        &self,
        prepared: &NativePreparedRetirement,
    ) -> bool {
        self.owner.same_authority(&prepared.owner) && self.namespace == prepared.namespace
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub(in crate::store) fn validate_native_prepared(
        &self,
        maintenance: &ConfigurationMaintenance,
        prepared: &NativePreparedRetirement,
    ) -> JournalResult<()> {
        if !self.native_prepared_matches(prepared)
            || maintenance.transaction_id() != &prepared.intent.transaction_id
        {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            canonical(state, &prepared.intent)?;
            self.with_directory_locked(state, |dir| {
                let old = original_native(
                    &files::scan(dir, self.budget)?,
                    &prepared.intent.transaction_id,
                )?;
                if old.intent != prepared.intent
                    || Sha256Digest::of_bytes(&old.raw) != prepared.raw_intent_sha256
                    || old.prepared != Some(prepared.record_sha256)
                    || old.retired.is_some()
                {
                    return Err(JournalError::Conflict);
                }
                Ok(())
            })
        })
    }
    pub(in crate::store) fn open_for_native_retirement(
        owner: OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        let root_identity = owner.identity()?;
        let namespace = owner.claim_legacy_management_namespace(maintenance, budget)?;
        Ok(Self {
            owner,
            budget,
            namespace,
            root_identity,
        })
    }
    pub(in crate::store) fn prepare_native_credential_retirement(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &NativeRetirementIntent,
    ) -> JournalResult<NativePreparedRetirement> {
        intent.validate()?;
        if maintenance.transaction_id() != &intent.transaction_id {
            return Err(JournalError::Conflict);
        }
        let raw = serde_json::to_vec(intent).map_err(|_| JournalError::InvalidInput)?;
        if raw.len() > MAX_INTENT {
            return Err(JournalError::BudgetExceeded);
        }
        let phase = serde_json::to_vec(&PhaseRecord::<NativeRetirementFileStamp> {
            schema: 3,
            kind: RetirementKind::LegacyCredentialRetirement,
            transaction_id: intent.transaction_id.clone(),
            sequence: intent.sequence,
            raw_intent_sha256: Sha256Digest::of_bytes(&raw),
            stage: CredentialRetirementStage::Prepared,
            previous: None,
            post_stamp: None,
        })
        .map_err(|_| JournalError::InvalidInput)?;
        let [name, phase_name, _] = names(&intent.transaction_id);
        let entries = vec![(name, raw), (phase_name, phase)];
        self.owner.with_maintenance(maintenance, |state| {
            canonical(state, intent)?;
            let result = self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let inventory = super::super::platform::inventory(&scan)?;
                if !inventory.orphans.is_empty() {
                    return Err(JournalError::Conflict);
                }
                let handoffs = scan_handoffs(&scan)?;
                // No continuation by create: an already attempted stage is an
                // original-ID resync operation, never a fresh prepare/adoption.
                if (!scan_owner_recoveries(&scan)?.records.is_empty()
                    && !recovery_continuation(&scan, intent, &entries[0].1)?)
                    || !handoffs.records.is_empty()
                    || !handoffs.native_records.is_empty()
                    || (intent.sequence <= inventory.high_water
                        && !recovery_continuation(&scan, intent, &entries[0].1)?
                        && !super::super::migration_plan::retirement_continuation(
                            &scan,
                            intent,
                            &entries[0].1,
                        )?)
                    || inventory.transactions.iter().any(|tx| {
                        tx.intent.transaction_id == intent.transaction_id
                            || !tx
                                .phase_receipts
                                .last()
                                .is_some_and(|p| p.stage == DurableStage::Committed)
                    })
                    || inventory.transactions.last().is_some_and(|tx| {
                        tx.intent.target_state_sha256 != intent.before_state_sha256
                    })
                {
                    return Err(JournalError::Conflict);
                }
                preflight(state, &scan, &entries, self.budget)?;
                // Reserve the exact bounded retired record before any write or
                // OS effect; ctime may vary but fixed-width fields are bounded.
                let future = vec![0u8; MAX_INTENT]; // budget reservation only, never persisted
                let [_, _, future_name] = names(&intent.transaction_id);
                let mut reserved = entries.clone();
                reserved.push((future_name, future));
                preflight(state, &scan, &reserved, self.budget)?;
                for (name, bytes) in &entries {
                    files::immutable(dir, name, bytes, self.budget, &|_| {})?;
                }
                let observed =
                    original_native(&files::scan(dir, self.budget)?, &intent.transaction_id)?;
                if observed.intent != *intent || observed.retired.is_some() {
                    return Err(JournalError::Unknown);
                }
                prepared(self, &observed)
            })?;
            canonical(state, intent).map_err(|_| JournalError::Unknown)?;
            Ok(result)
        })
    }
    pub(in crate::store) fn record_native_credential_retired(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        source: &NativePreparedRetirement,
        post: &NativeRetirementFileStamp,
    ) -> JournalResult<NativeRetiredRecord> {
        if !self.owner.same_authority(&source.owner)
            || self.namespace != source.namespace
            || maintenance.transaction_id() != &source.intent.transaction_id
            || !source.intent.original_token.same_file_after_rename(post)
        {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            canonical(state, &source.intent)?;
            let result = self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let old = original_native(&scan, &source.intent.transaction_id)?;
                if old.intent != source.intent
                    || Sha256Digest::of_bytes(&old.raw) != source.raw_intent_sha256
                    || old.prepared != Some(source.record_sha256)
                    || old.retired.is_some()
                {
                    return Err(JournalError::Conflict);
                }
                let [raw_name, prepared_name, retired_name] = names(&source.intent.transaction_id);
                let raw = serde_json::to_vec(&PhaseRecord {
                    schema: 3,
                    kind: RetirementKind::LegacyCredentialRetirement,
                    transaction_id: source.intent.transaction_id.clone(),
                    sequence: source.intent.sequence,
                    raw_intent_sha256: source.raw_intent_sha256,
                    stage: CredentialRetirementStage::Retired,
                    previous: Some(source.record_sha256),
                    post_stamp: Some(post.clone()),
                })
                .map_err(|_| JournalError::InvalidInput)?;
                preflight(
                    state,
                    &scan,
                    &[(retired_name.clone(), raw.clone())],
                    self.budget,
                )?;
                for name in [raw_name, prepared_name] {
                    let exact = scan
                        .files
                        .iter()
                        .find(|f| f.name == name)
                        .ok_or(JournalError::Unknown)?
                        .bytes();
                    files::immutable(dir, &name, exact, self.budget, &|_| {})?;
                }
                files::immutable(dir, &retired_name, &raw, self.budget, &|_| {})?;
                let after = original_native(
                    &files::scan(dir, self.budget)?,
                    &source.intent.transaction_id,
                )?;
                if after.intent != source.intent
                    || after.retired != Some(Sha256Digest::of_bytes(&raw))
                    || after.post.as_ref() != Some(post)
                {
                    return Err(JournalError::Unknown);
                }
                Ok(RetiredCredentialRecord {
                    prepared: prepared(self, &after)?,
                    record_sha256: after.retired.ok_or(JournalError::Unknown)?,
                    post_stamp: post.clone(),
                })
            })?;
            canonical(state, &source.intent).map_err(|_| JournalError::Unknown)?;
            Ok(result)
        })
    }
    /// Reify only the recorded Retired predecessor of this original validated
    /// cutover. No rename, new post stamp or source-token restoration occurs.
    #[cfg(target_os = "macos")]
    pub(in crate::store) fn reopen_retired_for_cutover(
        &self,
        maintenance: &ConfigurationMaintenance,
        cutover: &super::super::cutover::PreparedCutover<NativeRootIdentity>,
    ) -> JournalResult<(NativePreparedRetirement, NativeRetiredRecord)> {
        if maintenance.transaction_id() != &cutover.intent().transaction_id {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let source = self.validated_native_cutover_locked(state, &scan, cutover)?;
                let before = original_native(&scan, &source.intent.transaction_id)?;
                if before.retired != Some(source.intent.retired_record_sha256)
                    || before.intent.sequence != source.intent.sequence
                    || before.intent.config_root != source.intent.config_root
                    || before.intent.host_root != source.intent.host_root
                    || before.intent.candidate_manifest_sha256
                        != source.intent.candidate_manifest_sha256
                {
                    return Err(JournalError::Conflict);
                }
                for name in names(&source.intent.transaction_id) {
                    files::sync_file(dir, &name)?;
                }
                super::super::platform::sync_directory(dir)?;
                let after_scan = files::scan(dir, self.budget)?;
                self.validated_native_cutover_locked(state, &after_scan, cutover)?;
                let after = original_native(&after_scan, &source.intent.transaction_id)?;
                if before.raw != after.raw
                    || before.prepared != after.prepared
                    || before.retired != after.retired
                    || before.post != after.post
                {
                    return Err(JournalError::Unknown);
                }
                Ok((
                    prepared(self, &after)?,
                    RetiredCredentialRecord {
                        prepared: prepared(self, &after)?,
                        record_sha256: after.retired.ok_or(JournalError::Conflict)?,
                        post_stamp: after.post.ok_or(JournalError::Conflict)?,
                    },
                ))
            })
        })
    }
    /// Reopen an already Prepared/Retired original before canonical cutover.
    /// Resync attests only original journal durability, never token rename or
    /// old-owner settlement. The caller must retain/revalidate its OS custody.
    #[cfg(any(
        target_os = "macos",
        all(test, target_os = "linux", target_env = "gnu")
    ))]
    pub(in crate::store) fn reopen_native_retirement(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<(NativePreparedRetirement, Option<NativeRetiredRecord>)> {
        if maintenance.transaction_id() != id {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let before = original_native(&files::scan(dir, self.budget)?, id)?;
                // An intent-only write is not a Prepared capability. Recovery
                // must not manufacture the missing phase or replay preparation.
                if before.prepared.is_none() {
                    return Err(JournalError::Conflict);
                }
                canonical(state, &before.intent)?;
                let [raw_name, prepared_name, retired_name] = names(id);
                for name in [raw_name, prepared_name] {
                    files::sync_file(dir, &name)?;
                }
                if before.retired.is_some() {
                    files::sync_file(dir, &retired_name)?;
                }
                super::super::platform::sync_directory(dir)?;
                let after = original_native(&files::scan(dir, self.budget)?, id)?;
                if before.intent != after.intent
                    || before.raw != after.raw
                    || before.prepared != after.prepared
                    || before.retired != after.retired
                    || before.post != after.post
                {
                    return Err(JournalError::Unknown);
                }
                canonical(state, &after.intent).map_err(|_| JournalError::Unknown)?;
                let retired = match (after.retired, after.post.as_ref()) {
                    (Some(record_sha256), Some(post_stamp)) => Some(RetiredCredentialRecord {
                        prepared: prepared(self, &after)?,
                        record_sha256,
                        post_stamp: post_stamp.clone(),
                    }),
                    (None, None) => None,
                    _ => return Err(JournalError::Unknown),
                };
                Ok((prepared(self, &after)?, retired))
            })
        })
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub(in crate::store) fn resync_native_retirement(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<NativeOriginalRetirement> {
        if maintenance.transaction_id() != id {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let before = original_native(&scan, id)?;
                canonical(state, &before.intent)?;
                let [raw, prepared, retired] = names(id);
                let mut exact = vec![raw];
                if before.prepared.is_some() {
                    exact.push(prepared)
                }
                if before.retired.is_some() {
                    exact.push(retired)
                }
                for name in exact {
                    files::sync_file(dir, &name)?;
                }
                super::super::platform::sync_directory(dir)?;
                let after = original_native(&files::scan(dir, self.budget)?, id)?;
                if before.intent != after.intent
                    || before.raw != after.raw
                    || before.prepared != after.prepared
                    || before.retired != after.retired
                    || before.post != after.post
                {
                    return Err(JournalError::Unknown);
                }
                canonical(state, &after.intent).map_err(|_| JournalError::Unknown)?;
                Ok(after.original())
            })
        })
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "management_handoff_native_writer_tests.rs"]
mod tests;

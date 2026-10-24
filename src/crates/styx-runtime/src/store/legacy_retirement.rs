//! Original-locator retirement under the SAME writer/maintenance and journal.
//! Only the migration adapter calls this after joined physical settlement.
//! No activation, owner release, token copy, automatic retry or rollback exists.
use super::*;
use crate::store::secure_journal::JournalBudget;
use crate::{
    release::VerifiedNativeRelease,
    store::management::{
        OwnedManagementJournal,
        handoff::{
            LegacyCredentialRetirementIntent, PreparedCredentialRetirement,
            RetiredCredentialRecord, RetirementFileStamp, RetirementKind, RetirementLinuxRoot,
        },
    },
};
use nix::fcntl::{AtFlags, RenameFlags, renameat2};
use styx_contracts::identity::Sha256Digest;

#[derive(Default)]
pub(super) struct RetirementSlot {
    attempted: bool,
    indeterminate: bool,
    handles: Option<TokenHandles>,
    prepared: Option<Arc<PreparedCredentialRetirement>>,
    retired: Option<RetiredCredentialRecord>,
    journal: Option<Arc<Mutex<OwnedManagementJournal>>>,
}
struct TokenHandles {
    device: File,
    file: File,
    original: RetirementFileStamp,
    destination: PathBuf,
    post: Option<RetirementFileStamp>,
}
/// Non-secret facts only. Authority remains with the original opaque fence.
pub(crate) struct CredentialRetirementObservation {
    pub transaction_id: styx_contracts::identity::TransactionId,
    pub retired_relative_path: PathBuf,
    pub original_inode_preserved: bool,
    pub original_bytes_preserved: bool,
    pub original_locator_absent: bool,
    pub retired_receipt_sha256: Sha256Digest,
}
fn root_stamp(root: RootIdentity) -> RetirementLinuxRoot {
    let RootIdentity::Linux { device, inode, uid } = root;
    RetirementLinuxRoot { device, inode, uid }
}
fn token_material(file: &FrozenFile) -> bool {
    file.binding.root == LegacyMaterialRoot::Host
        && file.binding.relative_path == std::path::Path::new("device/host.token")
        && matches!(file.binding.role, PreservationRole::PairingCredential)
}
fn stamp(file: &File, expected: &[u8]) -> JournalResult<RetirementFileStamp> {
    let before = private_stamp(file)?;
    if expected.is_empty() || expected.len() > 4096 || before.byte_len != expected.len() as u64 {
        return Err(JournalError::Conflict);
    }
    let bytes = Zeroizing::new(exact_read(file, expected.len())?);
    if bytes.as_slice() != expected || private_stamp(file)? != before {
        return Err(JournalError::Conflict);
    }
    let metadata = file.metadata().map_err(|_| JournalError::Unknown)?;
    let result = RetirementFileStamp {
        device: before.device,
        inode: before.inode,
        uid: metadata.uid(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        byte_len: before.byte_len,
        modified_seconds: before.modified_seconds,
        modified_nanoseconds: before.modified_nanoseconds,
        changed_seconds: before.changed_seconds,
        changed_nanoseconds: before.changed_nanoseconds,
        sha256: Sha256Digest::of_bytes(&bytes),
    };
    if private_stamp(file)? != before {
        return Err(JournalError::Unknown);
    }
    Ok(result)
}
fn observation(stamp: &RetirementFileStamp) -> FileObservation {
    FileObservation {
        device: stamp.device,
        inode: stamp.inode,
        byte_len: stamp.byte_len,
        modified_seconds: stamp.modified_seconds,
        modified_nanoseconds: stamp.modified_nanoseconds,
        changed_seconds: stamp.changed_seconds,
        changed_nanoseconds: stamp.changed_nanoseconds,
    }
}
fn same_renamed_file(before: &RetirementFileStamp, after: &RetirementFileStamp) -> bool {
    before.device == after.device
        && before.inode == after.inode
        && before.uid == after.uid
        && before.mode == after.mode
        && before.nlink == after.nlink
        && before.byte_len == after.byte_len
        && before.modified_seconds == after.modified_seconds
        && before.modified_nanoseconds == after.modified_nanoseconds
        && before.sha256 == after.sha256
}
fn absent(directory: &File, name: &std::ffi::OsStr) -> JournalResult<()> {
    match nix::sys::stat::fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(Errno::ENOENT) => Ok(()),
        Ok(_) => Err(JournalError::Conflict),
        Err(_) => Err(JournalError::Unknown),
    }
}
impl RetirementSlot {
    pub(super) fn require_complete_or_original(&self) -> JournalResult<()> {
        if self.indeterminate || (self.attempted && self.retired.is_none()) {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
    /// This is the ONLY exception to original-name preservation. The original
    /// token inode/bytes stay bound, and the original name must now be absent.
    pub(super) fn validate_relocated(
        &self,
        host: &PrivateRoot,
        old: &FrozenFile,
    ) -> JournalResult<bool> {
        if !token_material(old) || !self.attempted {
            return Ok(false);
        }
        self.require_complete_or_original()?;
        let handles = self.handles.as_ref().ok_or(JournalError::Unknown)?;
        let record = self.retired.as_ref().ok_or(JournalError::Unknown)?;
        let post = handles.post.as_ref().ok_or(JournalError::Unknown)?;
        if record.post_stamp() != post
            || record.intent().original_token != handles.original
            || record.intent().token_destination() != handles.destination
        {
            return Err(JournalError::Unknown);
        }
        host.ensure_absent(&old.binding.relative_path)
            .map_err(|_| JournalError::Unknown)?;
        let now = host
            .read_raw(&handles.destination, old.limit)
            .map_err(|_| JournalError::Unknown)?;
        if now.observation() != &observation(post)
            || now.bytes() != old.bytes.as_slice()
            || stamp(&handles.file, &old.bytes)? != *post
        {
            return Err(JournalError::Unknown);
        }
        host.inner
            .with_legacy_device_directory(|named| {
                let a = named.metadata()?;
                let b = handles.device.metadata()?;
                if (a.dev(), a.ino(), a.uid()) != (b.dev(), b.ino(), b.uid()) {
                    return Err(super::super::StoreError::Changed);
                }
                Ok(())
            })
            .map_err(|_| JournalError::Unknown)?;
        // Check again after the held-directory comparison, without trusting a
        // pathname alone or accepting a same-byte replacement inode.
        let after = host
            .read_raw(&handles.destination, old.limit)
            .map_err(|_| JournalError::Unknown)?;
        if after.observation() != now.observation() || after.bytes() != old.bytes.as_slice() {
            return Err(JournalError::Unknown);
        }
        Ok(true)
    }
}
impl LegacyWriterFence {
    /// Store-private effect port. The trusted migration caller MUST hold the
    /// original joined service proof and revalidate it before AND after this.
    /// No public DTO/boolean can call this through the external control plane.
    pub(crate) fn retire_credential_locator(
        &self,
        candidate: &VerifiedNativeRelease,
    ) -> Result<CredentialRetirementObservation, LegacyFenceError> {
        self.validate()?;
        let result = self.retire_credential_inner(candidate, &|_| {});
        if result.is_err()
            && let Ok(mut slot) = self.retirement.lock()
            && slot.attempted
        {
            slot.indeterminate = true;
        }
        result.map_err(classify)
    }
    fn retire_credential_inner(
        &self,
        candidate: &VerifiedNativeRelease,
        observer: &dyn Fn(&str),
    ) -> JournalResult<CredentialRetirementObservation> {
        candidate.revalidate().map_err(|_| JournalError::Unknown)?;
        let report = candidate.report();
        if report.scope != "runtime_candidate" || report.target != "x86_64-unknown-linux-gnu" {
            return Err(JournalError::InvalidInput);
        }
        let service = self.service.as_ref().ok_or(JournalError::InvalidInput)?;
        let journal_handle = Arc::new(Mutex::new(
            OwnedManagementJournal::open_for_legacy_retirement(
                self.owner.clone(),
                &self.maintenance,
                JournalBudget::default(),
            )?,
        ));
        // The namespace has exactly one logical handle for this owner lifetime.
        // Retain it even on failure; observation never claims it a second time.
        self.retirement
            .lock()
            .map_err(|_| JournalError::Unknown)?
            .journal = Some(journal_handle.clone());
        let mut journal = journal_handle.lock().map_err(|_| JournalError::Unknown)?;
        let inventory = journal.observe()?;
        if !inventory.orphans.is_empty()
            || !inventory.handoffs.is_empty()
            || inventory.transactions.iter().any(|t| {
                t.phase_receipts
                    .last()
                    .is_none_or(|p| p.stage != styx_contracts::management::DurableStage::Committed)
            })
        {
            return Err(JournalError::Conflict);
        }
        let sequence = inventory
            .high_water
            .checked_add(1)
            .ok_or(JournalError::InvalidInput)?;
        let token = self
            .frozen
            .iter()
            .find(|f| token_material(f))
            .ok_or(JournalError::InvalidInput)?;
        let material = |root, path: &str| {
            self.frozen
                .iter()
                .find(|f| {
                    f.binding.root == root && f.binding.relative_path == std::path::Path::new(path)
                })
                .ok_or(JournalError::InvalidInput)
        };
        let before = material(LegacyMaterialRoot::Configuration, "state.json")?;
        let deployment = material(LegacyMaterialRoot::Configuration, "deployment.json")?;
        // Bind all selected private originals without ever logging their bytes
        // or claiming this selection is the complete C07 preservation inventory.
        let selected:Vec<_>=self.frozen.iter().map(|f|serde_json::json!({"root":if f.binding.root==LegacyMaterialRoot::Host{"host"}else{"configuration"},"path":f.binding.relative_path,"role":f.binding.role,"observation":f.binding.observation,"sha256":f.sha256})).collect();
        let preservation_sha256 = Sha256Digest::of_bytes(
            &serde_json::to_vec(&selected).map_err(|_| JournalError::InvalidInput)?,
        );
        let intent = self.owner.with_maintenance(&self.maintenance, |state| {
            let mut slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            if slot.attempted {
                return Err(JournalError::Conflict);
            }
            let handles = self
                .host
                .inner
                .with_legacy_device_directory(|device| {
                    Ok((|| {
                        let file = File::from(
                            openat(
                                device,
                                "host.token",
                                OFlag::O_RDONLY
                                    | OFlag::O_NONBLOCK
                                    | OFlag::O_NOFOLLOW
                                    | OFlag::O_CLOEXEC,
                                Mode::empty(),
                            )
                            .map_err(|_| JournalError::Unknown)?,
                        );
                        let original = stamp(&file, &token.bytes)?;
                        if observation(&original) != token.binding.observation {
                            return Err(JournalError::Conflict);
                        }
                        let destination = PathBuf::from(format!(
                            "device/.styx-retired-host-token-{}",
                            self.maintenance.transaction_id().as_str()
                        ));
                        absent(
                            device,
                            destination.file_name().ok_or(JournalError::InvalidInput)?,
                        )?;
                        Ok(TokenHandles {
                            device: device.try_clone().map_err(|_| JournalError::Unknown)?,
                            file,
                            original,
                            destination,
                            post: None,
                        })
                    })())
                })
                .map_err(|_| JournalError::Unknown)??;
            let intent = LegacyCredentialRetirementIntent {
                schema: 1,
                kind: RetirementKind::LegacyCredentialRetirement,
                transaction_id: self.maintenance.transaction_id().clone(),
                sequence,
                config_root: root_stamp(state.root.identity()),
                host_root: root_stamp(self.host_identity.clone()),
                deployment_raw_sha256: Sha256Digest::of_bytes(&deployment.bytes),
                before_state_sha256: Sha256Digest::of_bytes(&before.bytes),
                preservation_sha256,
                service_descriptor_sha256: service.raw_sha256(),
                candidate_manifest_sha256: report.manifest_sha256,
                publisher_spki_sha256: Sha256Digest::try_from(report.publisher_spki_sha256.clone())
                    .map_err(|_| JournalError::InvalidInput)?,
                original_token: handles.original.clone(),
            };
            if intent.token_source() != token.binding.relative_path
                || intent.token_destination() != handles.destination
            {
                return Err(JournalError::InvalidInput);
            }
            slot.attempted = true;
            slot.handles = Some(handles);
            Ok(intent)
        })?;
        let prepared = Arc::new(journal.prepare_credential_retirement(&self.maintenance, &intent)?);
        observer("prepared_synced");
        self.owner.with_maintenance(&self.maintenance, |_| {
            let mut slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            slot.prepared = Some(prepared.clone());
            let handles = slot.handles.as_mut().ok_or(JournalError::Unknown)?;
            self.host
                .inner
                .with_legacy_device_directory(|named| {
                    Ok((|| {
                        let a = named.metadata().map_err(|_| JournalError::Unknown)?;
                        let b = handles
                            .device
                            .metadata()
                            .map_err(|_| JournalError::Unknown)?;
                        if (a.dev(), a.ino(), a.uid()) != (b.dev(), b.ino(), b.uid())
                            || stamp(&handles.file, &token.bytes)? != handles.original
                        {
                            return Err(JournalError::Conflict);
                        }
                        let current = self
                            .host
                            .read_raw("device/host.token", token.limit)
                            .map_err(|_| JournalError::Unknown)?;
                        if current.observation() != &token.binding.observation
                            || current.bytes() != token.bytes.as_slice()
                        {
                            return Err(JournalError::Conflict);
                        }
                        let destination = handles
                            .destination
                            .file_name()
                            .ok_or(JournalError::InvalidInput)?;
                        absent(named, destination)?;
                        handles.file.sync_all().map_err(|_| JournalError::Unknown)?;
                        named.sync_all().map_err(|_| JournalError::Unknown)?;
                        renameat2(
                            named,
                            "host.token",
                            named,
                            destination,
                            RenameFlags::RENAME_NOREPLACE,
                        )
                        .map_err(|_| JournalError::Unknown)?;
                        observer("renamed");
                        let post = stamp(&handles.file, &token.bytes)?;
                        if !same_renamed_file(&handles.original, &post) {
                            return Err(JournalError::Unknown);
                        }
                        handles.post = Some(post);
                        absent(named, std::ffi::OsStr::new("host.token"))?;
                        handles.file.sync_all().map_err(|_| JournalError::Unknown)?;
                        named.sync_all().map_err(|_| JournalError::Unknown)?;
                        observer("device_synced");
                        Ok(())
                    })())
                })
                .map_err(|_| JournalError::Unknown)?
        })?;
        let post = {
            self.retirement
                .lock()
                .map_err(|_| JournalError::Unknown)?
                .handles
                .as_ref()
                .and_then(|h| h.post.clone())
                .ok_or(JournalError::Unknown)?
        };
        let record = journal.record_credential_retired(&self.maintenance, &prepared, &post)?;
        observer("retired_record_synced");
        self.owner.with_maintenance(&self.maintenance, |_| {
            let mut slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            if slot.indeterminate || slot.retired.is_some() {
                return Err(JournalError::Unknown);
            }
            slot.retired = Some(record);
            Ok(())
        })?;
        drop(journal);
        self.validate().map_err(|_| JournalError::Unknown)?;
        self.credential_retirement_observation()
            .map_err(|_| JournalError::Unknown)
    }
    pub(crate) fn invalidate_credential_retirement(&self) {
        if let Ok(mut slot) = self.retirement.lock() {
            slot.indeterminate = true;
        }
    }
    pub(crate) fn credential_retirement_observation(
        &self,
    ) -> Result<CredentialRetirementObservation, LegacyFenceError> {
        self.validate()?;
        let (intent, prepared_sha256, retired_sha256, post_stamp, journal_handle) = {
            let slot = self
                .retirement
                .lock()
                .map_err(|_| LegacyFenceError::Unknown)?;
            let prepared = slot.prepared.as_ref().ok_or(LegacyFenceError::Unknown)?;
            let record = slot
                .retired
                .as_ref()
                .ok_or(LegacyFenceError::BusyOrUnresolved)?;
            if prepared.intent() != record.intent() {
                return Err(LegacyFenceError::Unknown);
            }
            (
                record.intent().clone(),
                prepared.record_sha256(),
                record.record_sha256(),
                record.post_stamp().clone(),
                slot.journal
                    .as_ref()
                    .ok_or(LegacyFenceError::Unknown)?
                    .clone(),
            )
        };
        // Re-sync and compare the exact original journal chain. Presence or an
        // in-memory receipt cannot replace fresh durability under this writer.
        let original = journal_handle
            .lock()
            .map_err(|_| LegacyFenceError::Unknown)?
            .resync_original_retirement(&self.maintenance, &intent.transaction_id)
            .map_err(classify)?;
        if original.intent != intent
            || original.raw_intent
                != serde_json::to_vec(&intent).map_err(|_| LegacyFenceError::Unknown)?
            || original.prepared_sha256 != Some(prepared_sha256)
            || original.retired_sha256 != Some(retired_sha256)
            || original.post_stamp.as_ref() != Some(&post_stamp)
        {
            self.invalidate_credential_retirement();
            return Err(LegacyFenceError::Unknown);
        }
        self.validate()?;
        let slot = self
            .retirement
            .lock()
            .map_err(|_| LegacyFenceError::Unknown)?;
        let record = slot.retired.as_ref().ok_or(LegacyFenceError::Unknown)?;
        Ok(CredentialRetirementObservation {
            transaction_id: record.intent().transaction_id.clone(),
            retired_relative_path: record.intent().token_destination(),
            original_inode_preserved: true,
            original_bytes_preserved: true,
            original_locator_absent: true,
            retired_receipt_sha256: record.record_sha256(),
        })
    }
}

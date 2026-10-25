//! Windows private OS effects for the original C07 schema-3 retirement.
//! This is not a writer, phase ledger, owner settlement, or activation grant.
//! The migration coordinator must retain the original settled owner scope.
use super::*;
use crate::{
    release::VerifiedNativeRelease,
    store::{
        configuration::{ConfigurationMaintenance, OwnedConfigurationRoot},
        management::{
            OwnedManagementJournal,
            handoff::{NativePreparedRetirement, NativeRetiredRecord, NativeRetirementFileStamp},
        },
        secure_journal::{JournalError, JournalResult},
    },
};
use std::os::windows::fs::FileExt;
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    native_management::NativeRootIdentity,
};
use zeroize::Zeroizing;
fn unknown<T>(_: T) -> JournalError {
    JournalError::Unknown
}
fn native(root: RootIdentity) -> JournalResult<NativeRootIdentity> {
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
        _ => Err(JournalError::InvalidInput),
    }
}
fn bytes(file: &File, expected: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !(1..=4096).contains(&expected) {
        return Err(StoreError::TooLarge);
    }
    let mut data = Zeroizing::new(vec![0u8; expected + 1]);
    let mut count = 0;
    while count < data.len() {
        let n = file.seek_read(&mut data[count..], count as u64)?;
        if n == 0 {
            break;
        }
        count += n;
    }
    if count != expected {
        return Err(StoreError::Changed);
    }
    data.truncate(count);
    Ok(data)
}
fn stamp(file: &File, expected: &[u8]) -> Result<NativeRetirementFileStamp> {
    let before = private_facts(file, false)?;
    let owner = ffi::private(file)?;
    if bytes(file, expected.len())?.as_slice() != expected || private_facts(file, false)? != before
    {
        return Err(StoreError::Changed);
    }
    let value = before.observation;
    Ok(NativeRetirementFileStamp::Windows {
        volume_serial: value.device,
        file_id: value.inode,
        owner_sid: owner,
        nlink: u64::from(before.links),
        byte_len: value.byte_len,
        modified_seconds: value.modified_seconds,
        modified_nanoseconds: value.modified_nanoseconds,
        changed_seconds: value.changed_seconds,
        changed_nanoseconds: value.changed_nanoseconds,
        sha256: Sha256Digest::of_bytes(expected),
    })
}
fn same_file(a: &NativeRetirementFileStamp, b: &NativeRetirementFileStamp) -> bool {
    use crate::store::management::handoff::ProofStamp;
    a.same_file_after_rename(b)
}
/// Never Deserialize/Clone. Every attempted mutation and failure retains this
/// original object; a failed effect cannot be repaired/replayed by a new path.
pub(in crate::store) struct WindowsTokenRetirement {
    host: Root,
    device: Root,
    transaction: TransactionId,
    original: NativeRetirementFileStamp,
    bytes: Zeroizing<Vec<u8>>,
    destination: String,
    file: Option<File>,
    attempted: bool,
    post: Option<NativeRetirementFileStamp>,
    indeterminate: bool,
}
impl Root {
    /// Caller already holds the SAME configuration writer+maintenance. Opening
    /// this fixed existing material neither creates a token nor releases owner.
    pub(in crate::store) fn prepare_token_retirement(
        &self,
        transaction: &TransactionId,
        expected: &RawFile,
    ) -> JournalResult<WindowsTokenRetirement> {
        if expected.relative_path() != Path::new("device/host.token")
            || !(1..=4096).contains(&expected.bytes().len())
        {
            return Err(JournalError::InvalidInput);
        }
        self.validate_root().map_err(unknown)?;
        let before = self
            .read_raw(Path::new("device/host.token"), 4096)
            .map_err(unknown)?;
        if before.observation() != expected.observation() || before.bytes() != expected.bytes() {
            return Err(JournalError::Conflict);
        }
        let directory = self.journal_directory("device").map_err(unknown)?;
        let device = Root::from_directory_handle(&directory).map_err(unknown)?;
        let destination = format!(".styx-retired-host-token-{}", transaction.as_str());
        Root::validate_journal_name(&destination).map_err(unknown)?;
        device
            .ensure_absent(Path::new(&destination))
            .map_err(unknown)?;
        let path = device.path.join("host.token");
        let file = ffi::open_retirement_token(&path).map_err(unknown)?;
        ffi::require_no_streams(&path).map_err(unknown)?;
        let original = stamp(&file, expected.bytes()).map_err(unknown)?;
        if private_facts(&file, false).map_err(unknown)?.observation != *expected.observation()
            || ffi::final_path(&file).map_err(unknown)? != path
        {
            return Err(JournalError::Conflict);
        }
        self.validate_root().map_err(unknown)?;
        device.validate_root().map_err(unknown)?;
        Ok(WindowsTokenRetirement {
            host: self.clone(),
            device,
            transaction: transaction.clone(),
            original,
            bytes: Zeroizing::new(expected.bytes().to_vec()),
            destination,
            file: Some(file),
            attempted: false,
            post: None,
            indeterminate: false,
        })
    }
}
impl WindowsTokenRetirement {
    pub(in crate::store) fn original_stamp(&self) -> &NativeRetirementFileStamp {
        &self.original
    }
    pub(in crate::store) fn host_identity(&self) -> JournalResult<NativeRootIdentity> {
        native(self.host.identity())
    }
    /// Shared coordinator entry after actual owner admission: execute the one
    /// original file effect, verify the retained readonly pin, then append the
    /// real Retired phase through the SAME journal. The caller retains self,
    /// journal, owner, maintenance and original admission even on error.
    /// No owner mutex is held while acquiring the journal writer. An error after
    /// effect never grants activation or permits a second rename; use only the
    /// original journal's read/resync path to resolve the durable phase.
    pub(in crate::store) fn retire_and_record(
        &mut self,
        journal: &mut OwnedManagementJournal,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        prepared: &NativePreparedRetirement,
        candidate: &VerifiedNativeRelease,
    ) -> JournalResult<NativeRetiredRecord> {
        if !journal.native_prepared_matches(prepared) {
            return Err(JournalError::Conflict);
        }
        journal.validate_native_prepared(maintenance, prepared)?;
        let post = self.retire(owner, maintenance, prepared, candidate)?;
        let result = (|| {
            if self.observed_retired()? != post {
                return Err(JournalError::Unknown);
            }
            let recorded =
                journal.record_native_credential_retired(maintenance, prepared, &post)?;
            if self.observed_retired()? != post {
                return Err(JournalError::Unknown);
            }
            Ok(recorded)
        })();
        if result.is_err() {
            self.indeterminate = true;
        }
        result
    }
    fn original_matches(&self) -> JournalResult<()> {
        self.host.validate_root().map_err(unknown)?;
        self.device.validate_root().map_err(unknown)?;
        let file = self.file.as_ref().ok_or(JournalError::Unknown)?;
        if stamp(file, &self.bytes).map_err(unknown)? != self.original
            || ffi::final_path(file).map_err(unknown)? != self.device.path.join("host.token")
        {
            return Err(JournalError::Conflict);
        }
        ffi::require_no_streams(&self.device.path.join("host.token")).map_err(unknown)?;
        self.device
            .ensure_absent(Path::new(&self.destination))
            .map_err(unknown)
    }
    /// Actual one-shot original-file effect. The opaque Prepared is from the
    /// SAME native journal/writer; raw JSON or a caller bool cannot replace it.
    /// The shared coordinator calls record_native_credential_retired only AFTER
    /// this returns, without holding an owner lock across journal acquisition.
    pub(in crate::store) fn retire(
        &mut self,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        prepared: &NativePreparedRetirement,
        candidate: &VerifiedNativeRelease,
    ) -> JournalResult<NativeRetirementFileStamp> {
        if self.attempted || self.indeterminate || self.post.is_some() {
            return Err(JournalError::Conflict);
        }
        if !prepared.matches_owner(owner)
            || prepared.intent().transaction_id != self.transaction
            || maintenance.transaction_id() != &self.transaction
        {
            return Err(JournalError::Conflict);
        }
        candidate.revalidate().map_err(unknown)?;
        let report = candidate.report();
        let intent = prepared.intent();
        if intent.schema != 3
            || report.scope != "runtime_candidate"
            || report.target != "x86_64-pc-windows-msvc"
            || report.manifest_sha256 != intent.candidate_manifest_sha256
            || Sha256Digest::try_from(report.publisher_spki_sha256.clone()).map_err(unknown)?
                != intent.publisher_spki_sha256
            || intent.original_token != self.original
            || intent.host_root != self.host_identity()?
            || intent.token_destination() != Path::new("device").join(&self.destination)
        {
            return Err(JournalError::Conflict);
        }
        let result = owner.with_maintenance(maintenance, |state| {
            if native(state.root.identity())? != intent.config_root {
                return Err(JournalError::Conflict);
            }
            for (name, digest) in [
                ("state.json", intent.before_state_sha256),
                ("deployment.json", intent.deployment_raw_sha256),
            ] {
                let raw = state.root.read_raw(name, 1024 * 1024).map_err(unknown)?;
                if Sha256Digest::of_bytes(raw.bytes()) != digest {
                    return Err(JournalError::Conflict);
                }
            }
            self.effect()
        });
        if result.is_err() && self.attempted {
            self.indeterminate = true;
        }
        result
    }
    fn effect(&mut self) -> JournalResult<NativeRetirementFileStamp> {
        self.original_matches()?;
        // From this point any failure stays indeterminate. Never issue the
        // rename again, even if the destination appears absent afterward.
        self.attempted = true;
        let file = self.file.as_ref().ok_or(JournalError::Unknown)?;
        ffi::rename_journal_file(file, &self.device.directory, &self.destination, false)
            .map_err(unknown)?;
        ffi::flush_file(file).map_err(unknown)?;
        let post = stamp(file, &self.bytes).map_err(unknown)?;
        if !same_file(&self.original, &post)
            || ffi::final_path(file).map_err(unknown)? != self.device.path.join(&self.destination)
        {
            return Err(JournalError::Unknown);
        }
        self.device
            .ensure_absent(Path::new("host.token"))
            .map_err(unknown)?;
        self.device.sync_directory().map_err(unknown)?;
        self.host.sync_directory().map_err(unknown)?;
        // Windows sharing forbids an ordinary protected reader while this
        // original WRITE|DELETE handle is open. Match existing canonical
        // publication: close it, reopen the exact named object, compare its
        // file ID/content/ACL/post-stamp, and retain a no-write/delete pin.
        drop(self.file.take());
        let pinned = ffi::open(
            &self.device.path.join(&self.destination),
            false,
            false,
            false,
        )
        .map_err(unknown)?;
        self.file = Some(pinned);
        let file = self.file.as_ref().ok_or(JournalError::Unknown)?;
        // Metadata change time may be finalized on writable handle close.
        // Only the same original identity/bytes/mtime/owner may survive;
        // the durable post-stamp is sampled from the new stable read pin.
        let final_post = stamp(file, &self.bytes).map_err(unknown)?;
        if !same_file(&post, &final_post) {
            return Err(JournalError::Unknown);
        }
        ffi::require_no_streams(&self.device.path.join(&self.destination)).map_err(unknown)?;
        self.device
            .ensure_absent(Path::new("host.token"))
            .map_err(unknown)?;
        self.device.validate_root().map_err(unknown)?;
        self.host.validate_root().map_err(unknown)?;
        self.post = Some(final_post.clone());
        Ok(final_post)
    }
    /// Read-only revalidation of this effect; no write retry or new scope grant.
    pub(in crate::store) fn observed_retired(&self) -> JournalResult<NativeRetirementFileStamp> {
        if self.indeterminate {
            return Err(JournalError::Unknown);
        }
        let post = self.post.as_ref().ok_or(JournalError::Conflict)?;
        self.host.validate_root().map_err(unknown)?;
        self.device.validate_root().map_err(unknown)?;
        let file = self.file.as_ref().ok_or(JournalError::Unknown)?;
        if stamp(file, &self.bytes).map_err(unknown)? != *post
            || ffi::final_path(file).map_err(unknown)? != self.device.path.join(&self.destination)
        {
            return Err(JournalError::Unknown);
        }
        self.device
            .ensure_absent(Path::new("host.token"))
            .map_err(unknown)?;
        let named = self
            .device
            .read_raw(Path::new(&self.destination), 4096)
            .map_err(unknown)?;
        let facts = private_facts(file, false).map_err(unknown)?;
        if named.observation() != &facts.observation || named.bytes() != self.bytes.as_slice() {
            return Err(JournalError::Unknown);
        }
        Ok(post.clone())
    }
}

/// Raw original material observations selected by the trusted migration reader.
/// This object does not discover roles, validate a signed profile, or authorize
/// retirement; it retains exact original bytes and root identity for rechecks.
pub(in crate::store) struct WindowsOriginalMaterials {
    root: Root,
    files: Vec<(PreservationInput, FileObservation, Zeroizing<Vec<u8>>)>,
}
impl Root {
    pub(in crate::store) fn freeze_migration_materials(
        &self,
        inputs: &[PreservationInput],
    ) -> JournalResult<WindowsOriginalMaterials> {
        if inputs.is_empty() || inputs.len() > 32 {
            return Err(JournalError::InvalidInput);
        }
        self.validate_root().map_err(unknown)?;
        let mut files = Vec::new();
        let mut total = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for input in inputs {
            if !seen.insert(input.relative_path.clone()) {
                return Err(JournalError::InvalidInput);
            }
            let raw = self
                .read_raw(&input.relative_path, 1024 * 1024)
                .map_err(unknown)?;
            if let Some(policy) = &input.json_version {
                crate::store::json_version(raw.bytes(), policy).map_err(unknown)?;
            }
            total = total
                .checked_add(raw.bytes().len())
                .ok_or(JournalError::BudgetExceeded)?;
            if total > 2 * 1024 * 1024 {
                return Err(JournalError::BudgetExceeded);
            }
            files.push((
                input.clone(),
                raw.observation().clone(),
                Zeroizing::new(raw.bytes().to_vec()),
            ));
        }
        let result = WindowsOriginalMaterials {
            root: self.clone(),
            files,
        };
        result.revalidate()?;
        Ok(result)
    }
}
impl WindowsOriginalMaterials {
    pub(in crate::store) fn revalidate(&self) -> JournalResult<()> {
        self.revalidate_inner(None)
    }
    pub(in crate::store) fn revalidate_after_retirement(
        &self,
        retired: &WindowsTokenRetirement,
    ) -> JournalResult<()> {
        self.revalidate_inner(Some(retired))
    }
    fn revalidate_inner(&self, retired: Option<&WindowsTokenRetirement>) -> JournalResult<()> {
        self.root.validate_root().map_err(unknown)?;
        for (input, observation, bytes) in &self.files {
            if input.relative_path == Path::new("device/host.token")
                && let Some(retired) = retired
            {
                if self.root.identity() != retired.host.identity()
                    || bytes.as_slice() != retired.bytes.as_slice()
                {
                    return Err(JournalError::Conflict);
                }
                retired.observed_retired()?;
                continue;
            }
            let raw = self
                .root
                .read_raw(&input.relative_path, bytes.len())
                .map_err(unknown)?;
            if raw.observation() != observation || raw.bytes() != bytes.as_slice() {
                return Err(JournalError::Conflict);
            }
        }
        self.root.validate_root().map_err(unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Cleanup(Option<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }

    /// Actual private NTFS rename/file-ID/read-sharing evidence, not old owner
    /// settlement or production activation. Uses the existing owned test root.
    #[test]
    #[ignore = "STYX_TEST_WINDOWS_STORE_ROOT; isolated original-token effects only; no installed profile/service"]
    fn windows_original_token_rename_and_collision_preserve_identity() {
        let path = PathBuf::from(
            std::env::var_os("STYX_TEST_WINDOWS_STORE_ROOT").expect("explicit private parent"),
        );
        let parent = Root::open(&path).expect("private fixture parent");
        let name = format!("migration-{}", uuid::Uuid::new_v4());
        let mut cleanup = Cleanup(None);
        let host = match parent.create_fresh_child(OsStr::new(&name)) {
            Ok(v) => v,
            Err(_) => panic!("fresh host fixture"),
        };
        cleanup.0 = Some(path.join(&name));
        let device_file = host.create_journal_directory("device", true).unwrap();
        let device = Root::from_directory_handle(&device_file).unwrap();
        let protected = PrivateRoot {
            inner: device.clone(),
        };
        let writer = protected.try_configuration_writer().unwrap();
        device
            .create_fixed(&writer, "host.token", b"synthetic-owned-token", &|_| {})
            .unwrap();
        drop(writer);
        let original = host.read_raw(Path::new("device/host.token"), 4096).unwrap();
        let tx: TransactionId = "windows-native-file-effect".try_into().unwrap();
        let mut effect = host.prepare_token_retirement(&tx, &original).unwrap();
        // The original retained rename handle rejects another writer/delete.
        assert!(ffi::open(&device.path.join("host.token"), false, true, false).is_err());
        let post = effect.effect().unwrap();
        assert!(same_file(effect.original_stamp(), &post));
        assert!(effect.observed_retired().is_ok());
        assert!(host.ensure_absent(Path::new("device/host.token")).is_ok());
        let destination = Path::new("device").join(&effect.destination);
        let after = host.read_raw(&destination, 4096).unwrap();
        assert_eq!(after.bytes(), original.bytes());
        assert_eq!(after.observation().device, original.observation().device);
        assert_eq!(after.observation().inode, original.observation().inode);
        assert!(ffi::open(&device.path.join(&effect.destination), false, true, false).is_err());
        drop(effect);
        // Separate source plus preexisting destination is refused BEFORE rename.
        let writer = protected.try_configuration_writer().unwrap();
        device
            .create_fixed(&writer, "host.token", b"second-synthetic-token", &|_| {})
            .unwrap();
        drop(writer);
        let second = host.read_raw(Path::new("device/host.token"), 4096).unwrap();
        assert!(host.prepare_token_retirement(&tx, &second).is_err());
        assert_eq!(
            host.read_raw(Path::new("device/host.token"), 4096)
                .unwrap()
                .bytes(),
            second.bytes()
        );
        assert_eq!(
            host.read_raw(&destination, 4096).unwrap().bytes(),
            original.bytes()
        );
        // Drop every own directory/file pin before deleting only our fixture.
        drop(protected);
        drop(device);
        drop(device_file);
        drop(host);
        std::fs::remove_dir_all(path.join(name)).unwrap();
        cleanup.0 = None;
    }
}

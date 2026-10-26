//! Read-only original Windows custody plus durable validated-tail recovery.
//! Never replays Startup exclusion, token retirement, Exec or pair probes.
use super::*;
use crate::store::{
    committed_runtime_native::NativeValidatedMigrationSnapshot,
    management::cutover::PreparedCutover,
    native_migration_job::{
        NativeMigrationCommittedScope, NativeMigrationObservation, NativeMigrationOwnerTask,
        retain_scope,
    },
    platform::restart::{StartupLinkCustody, StartupLocation, StartupOriginal},
};
use std::{collections::BTreeSet, sync::Arc};
use styx_core::management::transaction::{DurableStage, JournalReceipt};
use tokio::{
    runtime::Handle,
    sync::{SemaphorePermit, oneshot},
};

struct ReadPin {
    path: PathBuf,
    file: File,
    raw: Vec<u8>,
    stamp: NativeRetirementFileStamp,
}
impl ReadPin {
    fn open(
        root: &Root,
        name: &Path,
        raw: &[u8],
        stamp: Option<&NativeRetirementFileStamp>,
    ) -> JournalResult<Self> {
        root.validate_root().map_err(failed)?;
        let path = root.path.join(name);
        // Existing private names only. No writable or delete authority is acquired.
        let file = ffi::open(&path, false, false, false).map_err(failed)?;
        ffi::require_no_streams(&path).map_err(failed)?;
        let actual = native_stamp(&file, raw)?;
        if stamp.is_some_and(|stamp| stamp != &actual) {
            return Err(JournalError::Unknown);
        }
        let value = Self {
            path,
            file,
            raw: raw.to_vec(),
            stamp: actual,
        };
        value.validate()?;
        root.validate_root().map_err(failed)?;
        Ok(value)
    }
    fn validate(&self) -> JournalResult<()> {
        if ffi::final_path(&self.file).map_err(failed)? != self.path
            || native_stamp(&self.file, &self.raw)? != self.stamp
        {
            return Err(JournalError::Unknown);
        }
        ffi::require_no_streams(&self.path).map_err(failed)?;
        let named = ffi::open(&self.path, false, false, false).map_err(failed)?;
        if native_stamp(&named, &self.raw)? != self.stamp {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
}
/// Token bytes live only in a bounded zeroizing temporary; original post stamp
/// and the actual no-write/no-delete HANDLE are retained, never a copied token.
struct RetiredTokenPin {
    host: Root,
    device: Root,
    path: PathBuf,
    file: File,
    post: NativeRetirementFileStamp,
}
impl RetiredTokenPin {
    fn open(
        host: &PrivateRoot,
        retirement: &NativeRetirementIntent,
        post: &NativeRetirementFileStamp,
    ) -> JournalResult<Self> {
        use crate::store::management::handoff::ProofStamp;
        if root_native(host.identity())? != retirement.host_root
            || !retirement.original_token.same_file_after_rename(post)
        {
            return Err(JournalError::Conflict);
        }
        host.ensure_absent("device/host.token").map_err(failed)?;
        let device = Root::open(&host.inner.path.join("device")).map_err(failed)?;
        let destination = retirement.token_destination();
        let name = destination.file_name().ok_or(JournalError::Conflict)?;
        let path = device.path.join(name);
        let file = ffi::open(&path, false, false, false).map_err(failed)?;
        let value = Self {
            host: host.inner.clone(),
            device,
            path,
            file,
            post: post.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    fn stamp(&self, file: &File) -> JournalResult<NativeRetirementFileStamp> {
        let NativeRetirementFileStamp::Windows { byte_len, .. } = &self.post else {
            return Err(JournalError::Conflict);
        };
        let len = usize::try_from(*byte_len).map_err(failed)?;
        if !(1..=4096).contains(&len) {
            return Err(JournalError::Conflict);
        }
        let facts = private_facts(file, false).map_err(failed)?;
        if facts.links != 1 || facts.observation.byte_len != *byte_len {
            return Err(JournalError::Unknown);
        }
        let mut raw = zeroize::Zeroizing::new(vec![0u8; len + 1]);
        let mut count = 0;
        while count < raw.len() {
            let n = file
                .seek_read(&mut raw[count..], count as u64)
                .map_err(failed)?;
            if n == 0 {
                break;
            }
            count += n;
        }
        if count != len || private_facts(file, false).map_err(failed)? != facts {
            return Err(JournalError::Unknown);
        }
        let o = &facts.observation;
        Ok(NativeRetirementFileStamp::Windows {
            volume_serial: o.device,
            file_id: o.inode,
            owner_sid: ffi::private(file).map_err(failed)?,
            nlink: u64::from(facts.links),
            byte_len: o.byte_len,
            modified_seconds: o.modified_seconds,
            modified_nanoseconds: o.modified_nanoseconds,
            changed_seconds: o.changed_seconds,
            changed_nanoseconds: o.changed_nanoseconds,
            sha256: Sha256Digest::of_bytes(&raw[..len]),
        })
    }
    fn validate(&self) -> JournalResult<()> {
        self.host.validate_root().map_err(failed)?;
        self.device.validate_root().map_err(failed)?;
        self.host
            .ensure_absent(Path::new("device/host.token"))
            .map_err(failed)?;
        ffi::require_no_streams(&self.path).map_err(failed)?;
        if ffi::final_path(&self.file).map_err(failed)? != self.path
            || self.stamp(&self.file)? != self.post
        {
            return Err(JournalError::Unknown);
        }
        let named = ffi::open(&self.path, false, false, false).map_err(failed)?;
        if self.stamp(&named)? != self.post {
            return Err(JournalError::Unknown);
        }
        self.device.validate_root().map_err(failed)?;
        self.host.validate_root().map_err(failed)
    }
}
struct WindowsResumedCustody {
    root: Root,
    archive: Root,
    pins: Vec<ReadPin>,
    archive_members: BTreeSet<String>,
    held: LegacyGuardsHeld,
    startup: StartupLinkCustody,
    token: RetiredTokenPin,
}
impl WindowsResumedCustody {
    #[expect(
        clippy::too_many_arguments,
        reason = "closed same-journal original recovery custody"
    )]
    fn open(
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        journal: &OwnedManagementJournal,
        prepared: &PreparedCutover<NativeRootIdentity>,
        root: &PrivateRoot,
        host: &PrivateRoot,
        os: &WindowsLegacyObservation,
        retirement: &NativeRetirementIntent,
        post: &NativeRetirementFileStamp,
    ) -> JournalResult<Self> {
        use crate::store::management::handoff::ProofStamp;
        let source = journal.resync_legacy_owner_recovery_for_cutover(maintenance, prepared)?;
        if source.intent().schema != 3
            || !journal.owner_recovery_prepared_matches(&source)
            || source.intent().candidate_manifest_sha256
                != prepared.intent().candidate_manifest_sha256
            || source.intent().publisher_spki_sha256 != prepared.intent().publisher_spki_sha256
            || source.intent().successor_retirement_intent_sha256
                != Sha256Digest::of_bytes(&serde_json::to_vec(retirement).map_err(failed)?)
            || root_native(root.identity())? != source.intent().config_root
        {
            return Err(JournalError::Conflict);
        }
        let held = source.into_guards_held()?;
        let source = held.prepared();
        let now = os.checkpoint().map_err(failed)?;
        let boot = admitted_boot(&source.intent().current_boot, now)?;
        if !now.definitely_after_old_ms(boot.unix_micros / 1000) {
            return Err(JournalError::Conflict);
        }
        admitted_boot(
            source.boot_observation().ok_or(JournalError::Conflict)?,
            now,
        )?;
        // Existing archive only: this path cannot initialize missing C effects.
        let parent = root
            .inner
            .journal_directory("foreground-recovery")
            .map_err(failed)?;
        let parent = Root::from_directory_handle(&parent).map_err(failed)?;
        let archive = parent
            .journal_directory(maintenance.transaction_id().as_str())
            .map_err(failed)?;
        let archive = Root::from_directory_handle(&archive).map_err(failed)?;
        let checkpoint = source.startup_checkpoint().ok_or(JournalError::Conflict)?;
        let startup = StartupLinkCustody::reopen(
            owner.clone(),
            maintenance,
            StartupOriginal {
                transaction: maintenance.transaction_id().clone(),
                config_root: source.intent().config_root.clone(),
                startup_directory: PathBuf::from(&checkpoint.startup_directory),
                original: checkpoint.original_link.clone(),
                bytes: source.startup_raw().ok_or(JournalError::Conflict)?.to_vec(),
                target: checkpoint.target.clone(),
                arguments: checkpoint.arguments.clone(),
                working_directory: checkpoint.working_directory.clone(),
                checkpoint_boot: boot,
            },
            archive.clone(),
            os,
        )?;
        if startup.location() != StartupLocation::Archived
            || !startup.matches_prepared(source)
            || source.startup_post() != Some(&startup.validate_excluded(maintenance, os)?)
        {
            return Err(JournalError::Conflict);
        }
        startup.observe_later_boot_while_excluded(maintenance, os)?;
        let mut expected = BTreeSet::from([
            "foreground-recovery.lock.retired".to_owned(),
            "windows-startup-original.lnk".to_owned(),
        ]);
        let mut pins = Vec::new();
        let posts = source
            .archived_original_posts()
            .ok_or(JournalError::Conflict)?;
        if posts.len() != source.originals().len() {
            return Err(JournalError::Conflict);
        }
        for (original, post) in source.originals().iter().zip(posts) {
            if original.name != post.name || !original.stamp.same_file_after_rename(&post.stamp) {
                return Err(JournalError::Conflict);
            }
            for suffix in ["before", "retired"] {
                let name = format!("{}.{}", original.name.source_name(), suffix);
                expected.insert(name.clone());
                pins.push(ReadPin::open(
                    &archive,
                    Path::new(&name),
                    &original.raw,
                    if suffix == "retired" {
                        Some(&post.stamp)
                    } else {
                        None
                    },
                )?);
            }
        }
        let posts = source.guards_held_posts().ok_or(JournalError::Conflict)?;
        if posts.len() != 4 || source.guard_bytes().len() != 4 {
            return Err(JournalError::Conflict);
        }
        for (guard, post) in source.guard_bytes().iter().zip(posts) {
            if guard.name != post.name {
                return Err(JournalError::Conflict);
            }
            pins.push(ReadPin::open(
                &root.inner,
                Path::new(guard.name.source_name()),
                &guard.raw,
                Some(&post.stamp),
            )?);
        }
        pins.push(ReadPin::open(
            &archive,
            Path::new("foreground-recovery.lock.retired"),
            &source
                .guard_bytes()
                .first()
                .ok_or(JournalError::Conflict)?
                .raw,
            None,
        )?);
        let mut count = 0;
        for entry in std::fs::read_dir(&archive.path).map_err(failed)? {
            count += 1;
            let name = entry
                .map_err(failed)?
                .file_name()
                .into_string()
                .map_err(failed)?;
            if count > expected.len() || !expected.contains(&name) {
                return Err(JournalError::Conflict);
            }
        }
        if count != expected.len() {
            return Err(JournalError::Unknown);
        }
        let service = service_binding(host, retirement, os)?;
        pins.push(ReadPin::open(
            &host.inner,
            Path::new("service.json"),
            service.bytes(),
            None,
        )?);
        let token = RetiredTokenPin::open(host, retirement, post)?;
        let value = Self {
            root: root.inner.clone(),
            archive,
            pins,
            archive_members: expected,
            held,
            startup,
            token,
        };
        value.validate(maintenance, os)?;
        let rechecked = journal.resync_legacy_owner_recovery_for_cutover(maintenance, prepared)?;
        if rechecked.intent() != value.held.prepared().intent()
            || rechecked.guards_held_posts() != value.held.prepared().guards_held_posts()
            || rechecked.archived_original_posts()
                != value.held.prepared().archived_original_posts()
        {
            return Err(JournalError::Unknown);
        }
        Ok(value)
    }
    fn physical(&self) -> JournalResult<()> {
        self.root.validate_root().map_err(failed)?;
        self.archive.validate_root().map_err(failed)?;
        for name in [
            "foreground-owner.json",
            "foreground-observer.json",
            "foreground-recovery.lock",
        ] {
            self.root.ensure_absent(Path::new(name)).map_err(failed)?;
        }
        let mut count = 0;
        for entry in std::fs::read_dir(&self.archive.path).map_err(failed)? {
            count += 1;
            let name = entry
                .map_err(failed)?
                .file_name()
                .into_string()
                .map_err(failed)?;
            if count > self.archive_members.len() || !self.archive_members.contains(&name) {
                return Err(JournalError::Conflict);
            }
        }
        if count != self.archive_members.len() {
            return Err(JournalError::Unknown);
        }
        for pin in &self.pins {
            pin.validate()?;
        }
        self.token.validate()
    }
    fn validate(
        &self,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.physical()?;
        if self.held.prepared().startup_post()
            != Some(&self.startup.validate_excluded(maintenance, os)?)
        {
            return Err(JournalError::Unknown);
        }
        self.startup
            .observe_later_boot_while_excluded(maintenance, os)?;
        Ok(())
    }
    fn validate_locked(
        &self,
        state: &crate::store::configuration::ConfigurationState,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.physical()?;
        if self.held.prepared().startup_post()
            != Some(
                &self
                    .startup
                    .validate_excluded_locked(state, owner, maintenance, os)?,
            )
        {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
}

pub(in crate::store) struct WindowsResumedCutover<'a> {
    owner: &'a OwnedConfigurationRoot,
    maintenance: &'a ConfigurationMaintenance,
    prepared: &'a PreparedCutover<NativeRootIdentity>,
    committed: JournalReceipt,
}
impl WindowsResumedCutover<'_> {
    pub(in crate::store) fn matches_fenced_owner(
        &self,
        owner: &OwnedConfigurationRoot,
        root: &RootIdentity,
        transaction: Option<&TransactionId>,
    ) -> bool {
        self.owner.same_authority(owner)
            && self.maintenance.matches(owner)
            && self.prepared.matches_owner(owner)
            && root_native(root.clone())
                .is_ok_and(|root| root == self.prepared.intent().config_root)
            && transaction == Some(self.maintenance.transaction_id())
            && self.committed.stage == DurableStage::Committed
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "retains the original closed recovery scope"
)]
pub(in crate::store) fn start_resume_validated_windows_host_migration(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<SemaphorePermit<'static>>,
) -> NativeMigrationOwnerTask {
    let (sender, observation) = oneshot::channel();
    let executor = runtime.clone();
    let job = runtime.spawn_blocking(move || {
        executor.block_on(run(
            state_dir,
            owner,
            maintenance,
            journal,
            candidate,
            app_scope,
            permit,
            sender,
        ))
    });
    NativeMigrationOwnerTask::from_job(observation, job)
}
#[expect(
    clippy::too_many_arguments,
    reason = "original blocking worker owns its complete recovery scope"
)]
async fn run(
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    mut journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<SemaphorePermit<'static>>,
    sender: oneshot::Sender<NativeMigrationObservation>,
) {
    let transaction = maintenance.transaction_id().clone();
    let mut sender = Some(sender);
    macro_rules! keep {($result:expr,$stage:literal $(,$held:expr)* $(,)?)=>{
        match $result {Ok(value)=>value,Err(_)=>retain_scope((&owner,&maintenance,&journal,&candidate,&app_scope,&permit,$($held,)*),&mut sender,
            NativeMigrationObservation {transaction_id:transaction.clone(),stage:$stage,local_exec_report:None,pair_admission_report:None,rejected_scope:None,committed_scope:None}).await}
    };}
    let starting = keep!(
        journal.resync_native_cutover(&maintenance, &transaction),
        "unknown_windows_resume_starting_chain"
    );
    let snapshot = keep!(
        NativeValidatedMigrationSnapshot::open(&state_dir, starting.last_stage),
        "unknown_windows_validated_materials",
        &starting
    );
    let prepared = keep!(
        journal.reopen_validated_native_cutover(&maintenance, candidate.clone()),
        "unknown_windows_validated_chain",
        &snapshot
    );
    let saved = keep!(
        journal.resync_native_migration_plan(&maintenance),
        "unknown_windows_saved_plan",
        &snapshot,
        &prepared
    );
    keep!(
        (|| -> JournalResult<()> {
            if !maintenance.matches(&owner)
                || !journal.configuration_root().same_authority(&owner)
                || snapshot.root_identity() != owner.identity()?
                || snapshot.original().intent != *prepared.intent()
                || saved.selection != candidate.runtime_selection().map_err(failed)?
            {
                return Err(JournalError::Conflict);
            }
            saved.validate_cutover(snapshot.original())?;
            let host = saved.desired.host.as_ref().ok_or(JournalError::Conflict)?;
            if saved.desired.gateway.is_some()
                || host.autostart
                    != styx_contracts::native_management::NativeAutostartDesired::Disabled
            {
                return Err(JournalError::Conflict);
            }
            match (host.manager, &app_scope) {
                (styx_contracts::native_management::NativeManager::ForegroundCli, None) => (),
                (styx_contracts::native_management::NativeManager::AppManaged, Some(scope))
                    if scope.state_dir() == state_dir =>
                {
                    scope.validate().map_err(failed)?;
                }
                _ => return Err(JournalError::Conflict),
            }
            snapshot.revalidate()
        })(),
        "unknown_windows_resume_binding",
        &snapshot,
        &prepared,
        &saved
    );
    let root = keep!(
        PrivateRoot::open(&state_dir),
        "unknown_windows_resume_root",
        &snapshot,
        &prepared,
        &saved
    );
    let host = keep!(
        PrivateRoot::open(snapshot.host_base_dir()),
        "unknown_windows_resume_host",
        &snapshot,
        &prepared,
        &saved,
        &root
    );
    let descriptor = keep!(
        host.read_raw("service.json", 32768),
        "unknown_windows_resume_service",
        &snapshot,
        &prepared,
        &saved,
        &root,
        &host
    );
    let descriptor: WindowsServiceDescriptor = keep!(
        serde_json::from_slice(descriptor.bytes()),
        "unknown_windows_resume_service_format",
        &snapshot,
        &prepared,
        &saved,
        &root,
        &host
    );
    let os = keep!(
        WindowsLegacyObservation::capture_foreground_only(&descriptor.task_name),
        "unknown_windows_resume_os",
        &snapshot,
        &prepared,
        &saved,
        &root,
        &host
    );
    let lease = keep!(
        host.try_execution_lease(),
        "unknown_windows_resume_execution_lease",
        &snapshot,
        &prepared,
        &saved,
        &root,
        &host,
        &os
    );
    let (retirement, record) = keep!(
        journal.reopen_retired_for_cutover(&maintenance, &prepared),
        "unknown_windows_resume_retirement",
        &snapshot,
        &prepared,
        &saved,
        &root,
        &host,
        &os,
        &lease
    );
    let custody = keep!(
        WindowsResumedCustody::open(
            &owner,
            &maintenance,
            &journal,
            &prepared,
            &root,
            &host,
            &os,
            retirement.intent(),
            record.post_stamp()
        ),
        "unknown_windows_resume_original_custody",
        &snapshot,
        &prepared,
        &saved,
        &root,
        &host,
        &os,
        &lease,
        &retirement,
        &record
    );
    let canonical = keep!(
        root.read_raw(
            "state.json",
            styx_contracts::native_management::NATIVE_STATE_BYTES
        ),
        "unknown_windows_resume_canonical",
        &snapshot,
        &prepared,
        &custody,
        &lease
    );
    let local = keep!(
        snapshot
            .original()
            .validation_report()
            .ok_or(JournalError::Conflict),
        "unknown_windows_resume_local_report",
        &snapshot,
        &prepared,
        &custody,
        &lease
    )
    .to_vec();
    let pair = keep!(
        snapshot
            .original()
            .paired_validation_report()
            .ok_or(JournalError::Conflict),
        "unknown_windows_resume_pair_report",
        &snapshot,
        &prepared,
        &custody,
        &lease
    )
    .to_vec();
    let validate = || -> JournalResult<()> {
        snapshot.revalidate_materials()?;
        lease.validate().map_err(failed)?;
        custody.validate(&maintenance, &os)?;
        if let Some(app) = &app_scope {
            app.validate().map_err(failed)?;
        }
        let raw = root
            .read_raw(
                "state.json",
                styx_contracts::native_management::NATIVE_STATE_BYTES,
            )
            .map_err(failed)?;
        if raw.observation() != canonical.observation() || raw.bytes() != prepared.target() {
            return Err(JournalError::Unknown);
        }
        Ok(())
    };
    for next in [DurableStage::Verified, DurableStage::Committed] {
        keep!(
            validate(),
            "unknown_windows_resume_materials_before_phase",
            &snapshot,
            &prepared,
            &custody,
            &lease
        );
        let current = keep!(
            journal.resync_native_cutover(&maintenance, &transaction),
            "unknown_windows_resume_phase",
            &snapshot,
            &prepared,
            &custody,
            &lease
        );
        keep!(
            if current.raw_intent == snapshot.original().raw_intent
                && current.validation_report() == Some(local.as_slice())
                && current.paired_validation_report() == Some(pair.as_slice())
            {
                Ok(())
            } else {
                Err(JournalError::Unknown)
            },
            "unknown_windows_resume_report_changed",
            &snapshot,
            &prepared,
            &custody,
            &lease
        );
        if matches!(
            (current.last_stage, next),
            (DurableStage::Applied, DurableStage::Verified)
                | (DurableStage::Verified, DurableStage::Committed)
        ) {
            keep!(
                journal.append_cutover_phase(&maintenance, &prepared, next),
                "unknown_windows_resume_phase_append",
                &snapshot,
                &prepared,
                &custody,
                &lease
            );
        }
    }
    keep!(
        validate(),
        "unknown_windows_resume_final_materials",
        &snapshot,
        &prepared,
        &custody,
        &lease
    );
    let current = keep!(
        journal.resync_native_cutover(&maintenance, &transaction),
        "unknown_windows_resume_final_chain",
        &snapshot,
        &prepared,
        &custody,
        &lease
    );
    let committed = keep!(
        current
            .phases
            .last()
            .filter(|phase| phase.stage == DurableStage::Committed)
            .cloned()
            .ok_or(JournalError::Unknown),
        "unknown_windows_resume_not_committed",
        &snapshot,
        &prepared,
        &custody,
        &lease
    );
    let proof = WindowsResumedCutover {
        owner: &owner,
        maintenance: &maintenance,
        prepared: &prepared,
        committed,
    };
    keep!(
        owner.with_maintenance(&maintenance, |state| {
            lease.validate().map_err(failed)?;
            snapshot.revalidate_materials()?;
            custody.validate_locked(state, &owner, &maintenance, &os)?;
            if let Some(app) = &app_scope {
                app.validate().map_err(failed)?;
            }
            let raw = state
                .root
                .read_raw(
                    "state.json",
                    styx_contracts::native_management::NATIVE_STATE_BYTES,
                )
                .map_err(failed)?;
            if raw.observation() != canonical.observation() || raw.bytes() != prepared.target() {
                return Err(JournalError::Unknown);
            }
            journal.validate_committed_cutover_locked(state, &prepared, &proof.committed)?;
            let inventory = journal.observe_locked(state)?;
            if inventory.has_unresolved_legacy_handoffs()
                || inventory.high_water != prepared.intent().sequence
                || inventory.committed_cutover_anchor
                    != Some((
                        prepared.intent().sequence,
                        prepared.intent().target_state_sha256,
                    ))
            {
                return Err(JournalError::Conflict);
            }
            state.finish_windows_resumed_cutover(&proof, &owner)
        }),
        "unknown_windows_resume_admission",
        &snapshot,
        &prepared,
        &custody,
        &lease
    );
    drop(lease);
    if let Some(sender) = sender.take() {
        let _ = sender.send(NativeMigrationObservation {
            transaction_id: transaction,
            stage: "resumed_committed_admission_released",
            local_exec_report: Some(local),
            pair_admission_report: Some(pair),
            rejected_scope: None,
            committed_scope: Some(Box::new(NativeMigrationCommittedScope {
                recovery_permit: Some(permit),
                app_scope,
                owner: owner.clone(),
                journal,
                candidate: candidate.clone(),
            })),
        });
    }
}

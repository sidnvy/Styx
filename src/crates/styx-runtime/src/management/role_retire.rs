//! Retire stopped role roots by same-parent, no-replace rename. No deletion,
//! credential migration, remote revocation or automatic operation replay.
use crate::enrollment::EnrollmentBootstrap;
use crate::store::enrollment::{EnrollmentJournal, JournalBudget};
use crate::store::{ConfigurationWriterGuard, ExecutionLeaseGuard, PrivateRoot};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use styx_contracts::native_host::NativeHostJoinSeed;
use styx_core::enrollment::Limits;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RetireOptions {
    #[serde(default)]
    pub allow_other_devices: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtherDevice {
    pub device_id: styx_contracts::identity::DeviceId,
    pub label: String,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetiredPath {
    pub old_path: PathBuf,
    pub new_path: PathBuf,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetireReport {
    pub schema: u16,
    pub operation: &'static str,
    pub outcome: &'static str,
    pub operations_replayed: bool,
    pub other_devices: Vec<OtherDevice>,
    pub retired: Vec<RetiredPath>,
    pub restart_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_outcome: Option<&'static str>,
}
impl Default for RetireReport {
    fn default() -> Self {
        Self {
            schema: 1,
            operation: "role_retire",
            outcome: "not_dispatched",
            operations_replayed: false,
            other_devices: vec![],
            retired: vec![],
            restart_required: false,
            pairing_outcome: None,
        }
    }
}
#[derive(Debug, thiserror::Error)]
#[error("{code}")]
pub struct RetireError {
    pub code: &'static str,
    pub report: RetireReport,
}
impl RetireError {
    fn refused(code: &'static str) -> Self {
        Self {
            code,
            report: RetireReport::default(),
        }
    }
    fn unknown(code: &'static str) -> Self {
        let report = RetireReport {
            outcome: "unknown",
            restart_required: true,
            ..RetireReport::default()
        };
        Self { code, report }
    }
    pub fn exit_code(&self) -> u8 {
        if self.report.outcome == "unknown" {
            4
        } else {
            2
        }
    }
}
struct Root {
    path: PathBuf,
    parent: PrivateRoot,
    root: PrivateRoot,
    lease: ExecutionLeaseGuard,
    writer: ConfigurationWriterGuard,
}
impl Root {
    fn open(path: &Path) -> Result<Self, RetireError> {
        if !path.is_absolute()
            || path.components().any(|part| {
                !matches!(
                    part,
                    Component::Normal(_) | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(RetireError::refused("role_retire_invalid_roots"));
        }
        let parent = PrivateRoot::open(
            path.parent()
                .ok_or_else(|| RetireError::refused("role_retire_invalid_roots"))?,
        )
        .map_err(|_| RetireError::refused("role_retire_root_refused"))?;
        let root = PrivateRoot::open(path)
            .map_err(|_| RetireError::refused("role_retire_root_refused"))?;
        let lease = root
            .try_execution_lease()
            .map_err(|_| RetireError::refused("role_retire_role_busy"))?;
        let writer = root
            .try_configuration_writer()
            .map_err(|_| RetireError::refused("role_retire_configuration_busy"))?;
        Ok(Self {
            path: path.to_owned(),
            parent,
            root,
            lease,
            writer,
        })
    }
    fn validate(&self) -> Result<(), RetireError> {
        let fail = || RetireError::refused("role_retire_root_changed");
        self.lease.validate().map_err(|_| fail())?;
        self.writer.validate().map_err(|_| fail())?;
        if PrivateRoot::open(&self.path)
            .map_err(|_| fail())?
            .identity()
            != self.root.identity()
            || PrivateRoot::open(self.path.parent().ok_or_else(fail)?)
                .map_err(|_| fail())?
                .identity()
                != self.parent.identity()
        {
            return Err(fail());
        }
        Ok(())
    }
}
/// Prepared under all original root leases. App drops its stopped child scopes
/// only after this preflight, so consent/busy refusals leave its setup intact.
pub(crate) struct PreparedRetire {
    roots: Vec<Root>,
    paths: Vec<RetiredPath>,
    report: RetireReport,
    suffix: String,
}
pub(crate) fn prepare(
    host: Option<&Path>,
    gateway: Option<&Path>,
    options: RetireOptions,
) -> Result<PreparedRetire, RetireError> {
    if let (Some(host), Some(gateway)) = (host, gateway)
        && (host.starts_with(gateway) || gateway.starts_with(host))
    {
        return Err(RetireError::refused("role_retire_invalid_roots"));
    }
    let host = host.map(Root::open).transpose()?;
    let mut gateway = gateway.map(Root::open).transpose()?;
    if let (Some(host), Some(gateway)) = (&host, &gateway)
        && host.root.identity() == gateway.root.identity()
    {
        return Err(RetireError::refused("role_retire_invalid_roots"));
    }
    let mut report = RetireReport::default();
    if let Some(gateway) = &mut gateway {
        // A missing/unreadable seed excludes nobody. A copied label alone can
        // never hide another approved Host from the confirmation.
        let own = host
            .as_ref()
            .and_then(|host| {
                host.root
                    .read_raw("host-join-seed-v1.json", 1024 * 1024)
                    .ok()
            })
            .and_then(|raw| serde_json::from_slice::<NativeHostJoinSeed>(raw.bytes()).ok());
        let diagnostics = EnrollmentBootstrap::recover_existing(
            &gateway.root,
            &mut gateway.writer,
            Limits::default(),
        )
        .map_err(|_| RetireError::refused("role_retire_enrollment_unproven"))?
        .diagnostics()
        .map_err(|_| RetireError::refused("role_retire_enrollment_unproven"))?;
        if diagnostics.unresolved {
            return Err(RetireError::refused("role_retire_enrollment_unproven"));
        }
        let journal = EnrollmentJournal::open_existing(
            &gateway.root,
            &mut gateway.writer,
            JournalBudget::default(),
        )
        .map_err(|_| RetireError::refused("role_retire_enrollment_unproven"))?;
        let devices = journal
            .approved_devices()
            .map_err(|_| RetireError::refused("role_retire_enrollment_unproven"))?;
        if devices.len() != diagnostics.devices - diagnostics.revoked_devices {
            return Err(RetireError::refused("role_retire_enrollment_unproven"));
        }
        report.other_devices = devices
            .into_iter()
            .filter(|device| {
                own.as_ref().is_none_or(|own| {
                    own.device_id != device.device_id || own.fingerprint != device.fingerprint
                })
            })
            .map(|device| OtherDevice {
                device_id: device.device_id,
                label: device.label,
            })
            .collect();
        if !report.other_devices.is_empty() && !options.allow_other_devices {
            return Err(RetireError {
                code: "role_retire_gateway_has_devices",
                report,
            });
        }
    }
    let now = time::OffsetDateTime::now_utc();
    let suffix = format!(
        ".retired-{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let roots: Vec<_> = host.into_iter().chain(gateway).collect();
    let mut paths = Vec::new();
    for root in &roots {
        root.validate()?;
        paths.push(destination(&root.path, &suffix)?);
    }
    Ok(PreparedRetire {
        roots,
        paths,
        report,
        suffix,
    })
}
fn destination(path: &Path, suffix: &str) -> Result<RetiredPath, RetireError> {
    let mut name = path
        .file_name()
        .ok_or_else(|| RetireError::refused("role_retire_invalid_roots"))?
        .to_os_string();
    name.push(suffix);
    let new_path = path.with_file_name(name);
    match std::fs::symlink_metadata(&new_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err(RetireError::refused("role_retire_backup_exists")),
    }
    Ok(RetiredPath {
        old_path: path.to_owned(),
        new_path,
    })
}
impl PreparedRetire {
    /// Fixed App-owned input files are backed up alongside the roots. Never
    /// include the container, its instance lease, publisher pins or selection.
    pub(crate) fn add_input(&mut self, path: &Path) -> Result<(), RetireError> {
        self.paths.push(destination(path, &self.suffix)?);
        Ok(())
    }
    pub(crate) fn retire(mut self) -> Result<RetireReport, RetireError> {
        for root in &self.roots {
            root.validate()?;
        }
        // Windows directory/lease handles deliberately deny DELETE sharing.
        // Release OUR reader handles: any competing opener still pins the old
        // name and makes the atomic rename fail; after rename it cannot open it.
        #[cfg(target_os = "windows")]
        self.roots.clear();
        for path in &self.paths {
            if rename_exclusive(&path.old_path, &path.new_path).is_err() {
                self.report.outcome = "unknown";
                self.report.restart_required = true;
                return Err(RetireError {
                    code: "role_retire_rename_unknown",
                    report: self.report,
                });
            }
            self.report.retired.push(path.clone());
        }
        self.report.outcome = "retired";
        Ok(self.report)
    }
}
pub fn retire_role(
    host: &Path,
    gateway: Option<&Path>,
    options: RetireOptions,
) -> Result<RetireReport, RetireError> {
    prepare(Some(host), gateway, options)?.retire()
}

const SETUP_RETIRE_JOURNAL: &str = ".styx-setup-retire-v1";
fn journal_exists(path: &Path) -> Result<bool, RetireError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        _ => Err(RetireError::unknown("setup_retirement_unknown")),
    }
}

/// Serialize CLI setup against explicit retirement of that same container.
pub struct SetupContainerGuard {
    path: PathBuf,
    root: PrivateRoot,
    lease: ExecutionLeaseGuard,
}
impl SetupContainerGuard {
    pub fn acquire(path: &Path) -> Result<Self, RetireError> {
        let root =
            PrivateRoot::open(path).map_err(|_| RetireError::refused("setup_container_refused"))?;
        let lease = root
            .try_execution_lease()
            .map_err(|_| RetireError::refused("setup_container_busy"))?;
        let guard = Self {
            path: path.to_owned(),
            root,
            lease,
        };
        guard.validate()?;
        let journal = path.join(SETUP_RETIRE_JOURNAL);
        if journal_exists(&journal)? {
            let journal = PrivateRoot::open(&journal)
                .map_err(|_| RetireError::unknown("setup_retirement_unknown"))?;
            let begin = journal.read_raw("begin", 64);
            let done = journal.read_raw("done", 64);
            match (begin, done) {
                (Ok(begin), Ok(done))
                    if begin.bytes() == b"started\n" && done.bytes() == b"completed\n" => {}
                (Err(_), Err(_))
                    if journal.ensure_absent("begin").is_ok()
                        && journal.ensure_absent("done").is_ok() => {}
                _ => return Err(RetireError::unknown("setup_retirement_unknown")),
            }
        }
        Ok(guard)
    }
    pub fn validate(&self) -> Result<(), RetireError> {
        self.lease
            .validate()
            .map_err(|_| RetireError::refused("setup_container_changed"))?;
        if PrivateRoot::open(&self.path)
            .map_err(|_| RetireError::refused("setup_container_changed"))?
            .identity()
            != self.root.identity()
        {
            return Err(RetireError::refused("setup_container_changed"));
        }
        Ok(())
    }
}

fn setup_join_input(name: &str) -> bool {
    matches!(
        name,
        "setup-intent.json"
            | "host-deployment.json"
            | "host-public-identity.json"
            | "join-ca.pem"
            | "invitation"
            | "join-input.started"
            | "join-input.done"
            | "request.started"
            | "request.done"
            | "claim.done"
            | "host-running.started"
            | "host-running.done"
    ) || name
        .strip_prefix("pasted-join-link-")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        || name
            .strip_prefix("claim-")
            .and_then(|s| s.split_once('.'))
            .is_some_and(|(n, suffix)| {
                !n.is_empty()
                    && n.bytes().all(|b| b.is_ascii_digit())
                    && matches!(suffix, "started" | "pending" | "done")
            })
        || name
            .strip_prefix("host-service-")
            .and_then(|s| s.split_once("-r"))
            .and_then(|(action, rest)| {
                rest.split_once('.')
                    .map(|(revision, suffix)| (action, revision, suffix))
            })
            .is_some_and(|(action, revision, suffix)| {
                matches!(action, "install" | "enable" | "start")
                    && !revision.is_empty()
                    && revision.bytes().all(|b| b.is_ascii_digit())
                    && matches!(suffix, "started" | "done")
            })
}

// Only the local Join attempt is retired from a Hub. In particular its
// original setup intent, runtime selection, Gateway and Tunnel inputs remain.
#[allow(dead_code)] // Wired only after both retained-owner admission APIs exist.
fn setup_hub_join_input(name: &str) -> bool {
    (setup_join_input(name) && name != "setup-intent.json")
        || matches!(
            name,
            "local-invite.started"
                | "local-invite.done"
                | "invitation-source"
                | "join-link"
                | "approve.started"
                | "approve.done"
        )
}

/// This is a preliminary fence only; it does not authenticate a Host prefix
/// or Gateway ledger and does not authorize retirement or another request.
#[allow(dead_code)]
fn validate_hub_join_steps(inputs: &PrivateRoot, names: &[String]) -> Result<(), RetireError> {
    let fail = || RetireError::refused("role_retire_hub_join_unproven");
    for step in ["local-invite", "join-input", "request"] {
        for (suffix, expected) in [
            ("started", b"dispatched\n".as_slice()),
            ("done", b"completed\n".as_slice()),
        ] {
            let raw = inputs
                .read_raw(format!("{step}.{suffix}"), 64)
                .map_err(|_| fail())?;
            if raw.bytes() != expected {
                return Err(fail());
            }
        }
    }
    for name in [
        "host-deployment.json",
        "host-public-identity.json",
        "join-ca.pem",
        "invitation",
        "invitation-source",
        "join-link",
    ] {
        let raw = inputs.read_raw(name, 1024 * 1024).map_err(|_| fail())?;
        if raw.bytes().is_empty() {
            return Err(fail());
        }
    }
    // Any approval, claim, running or service dispatch invalidates this narrow
    // preflight, including unmatched/partial started files and odd suffixes.
    if names.iter().any(|name| {
        name.starts_with("approve.")
            || name.starts_with("claim-")
            || name.starts_with("claim.")
            || name.starts_with("host-running.")
            || name.starts_with("host-service-")
    }) {
        return Err(fail());
    }
    Ok(())
}

/// Explicitly abandon this CLI Join attempt, retaining every moved byte.
pub fn retire_setup_host(setup: &Path, host: &Path) -> Result<RetireReport, RetireError> {
    if !setup.is_absolute() || host != setup.join("host") {
        return Err(RetireError::refused("role_retire_invalid_roots"));
    }
    let guard = SetupContainerGuard::acquire(setup)?;
    let inputs_path = setup.join("inputs");
    let inputs = PrivateRoot::open(&inputs_path)
        .map_err(|_| RetireError::refused("role_retire_setup_inputs_refused"))?;
    let intent = inputs
        .read_raw("setup-intent.json", 1024 * 1024)
        .map_err(|_| RetireError::refused("role_retire_setup_intent_refused"))?;
    let intent: serde_json::Value = serde_json::from_slice(intent.bytes())
        .map_err(|_| RetireError::refused("role_retire_setup_intent_refused"))?;
    if intent.get("role").and_then(serde_json::Value::as_str) == Some("hub") {
        return retire_setup_hub_join(guard, &inputs_path, inputs, host);
    }
    if intent.get("role").and_then(serde_json::Value::as_str) != Some("join") {
        return Err(RetireError::refused("role_retire_setup_not_join"));
    }
    let own_link = intent
        .get("join_link_file")
        .and_then(serde_json::Value::as_str)
        .map(Path::new)
        .filter(|path| path.parent() == Some(inputs_path.as_path()))
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .map(str::to_owned);
    if own_link
        .as_deref()
        .is_some_and(|name| !setup_join_input(name) || !name.starts_with("pasted-join-link-"))
    {
        return Err(RetireError::refused("role_retire_setup_inputs_refused"));
    }
    let mut prepared = prepare(Some(host), None, RetireOptions::default())?;
    for entry in std::fs::read_dir(&inputs_path)
        .map_err(|_| RetireError::refused("role_retire_setup_inputs_refused"))?
    {
        let entry = entry.map_err(|_| RetireError::refused("role_retire_setup_inputs_refused"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| RetireError::refused("role_retire_setup_inputs_refused"))?;
        if setup_join_input(name) || own_link.as_deref() == Some(name) {
            inputs
                .read_raw(name, 1024 * 1024)
                .map_err(|_| RetireError::refused("role_retire_setup_inputs_refused"))?;
            prepared.add_input(&inputs_path.join(name))?;
        }
    }
    guard.validate()?;
    let journal_path = setup.join(SETUP_RETIRE_JOURNAL);
    if journal_exists(&journal_path)? {
        let backup = destination(&journal_path, &prepared.suffix)?;
        rename_exclusive(&backup.old_path, &backup.new_path)
            .map_err(|_| RetireError::refused("role_retire_journal_archive_refused"))?;
    }
    let journal = guard
        .root
        .create_setup_journal_child(SETUP_RETIRE_JOURNAL)
        .map_err(|_| RetireError::refused("role_retire_journal_refused"))?;
    journal
        .create_setup_export("begin".as_ref(), b"started\n")
        .map_err(|_| RetireError::refused("role_retire_journal_refused"))?;
    let mut report = prepared.retire()?;
    if guard.root.sync_setup_directory().is_err() || inputs.sync_setup_directory().is_err() {
        report.outcome = "unknown";
        report.restart_required = true;
        return Err(RetireError {
            code: "role_retire_completion_unknown",
            report,
        });
    }
    if journal
        .create_setup_export("done".as_ref(), b"completed\n")
        .is_err()
    {
        report.outcome = "unknown";
        report.restart_required = true;
        return Err(RetireError {
            code: "role_retire_completion_unknown",
            report,
        });
    }
    Ok(report)
}

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
))]
fn retire_setup_hub_join(
    guard: SetupContainerGuard,
    inputs_path: &Path,
    inputs: PrivateRoot,
    host: &Path,
) -> Result<RetireReport, RetireError> {
    use crate::management::native_join::retirement_host_preflight;
    use styx_core::enrollment::RejectionRequest;
    // The Windows store denies DELETE sharing. Dropping its original writer
    // before rename would let an independent native writer enter the gap.
    // This new Hub recovery remains refused there until an equivalent atomic
    // ownership handoff exists; the pre-existing Join retirement is unchanged.
    if cfg!(target_os = "windows") {
        return Err(RetireError::refused(
            "role_retire_hub_join_platform_unsupported",
        ));
    }
    let refuse = || RetireError::refused("role_retire_hub_join_unproven");
    let unknown = || RetireError::unknown("setup_retirement_unknown");
    let setup = &guard.path;
    if host != setup.join("host") {
        return Err(refuse());
    }
    let gateway_path = setup.join("gateway");
    let mut prepared = prepare(Some(host), None, RetireOptions::default())?;
    let host_root = prepared.roots.pop().ok_or_else(refuse)?;
    let mut gateway = Root::open(&gateway_path)?;
    if host_root.root.identity() == gateway.root.identity() {
        return Err(refuse());
    }
    let host_identity = host_root.root.identity();
    let gateway_identity = gateway.root.identity();
    let Root {
        path: _,
        parent: _,
        root,
        lease: host_lease,
        writer,
    } = host_root;
    let proof = retirement_host_preflight(host, root, writer).map_err(|_| refuse())?;
    let gateway_ca = gateway
        .root
        .read_raw("gateway-ca.pem", 128 * 1024)
        .map_err(|_| refuse())?;
    proof
        .validate_gateway_ca(gateway_ca.bytes())
        .map_err(|_| refuse())?;
    EnrollmentBootstrap::validate_retirement_reader(&gateway.root, &mut gateway.writer)
        .map_err(|_| refuse())?;

    let mut names: Vec<String> = std::fs::read_dir(inputs_path)
        .map_err(|_| refuse())?
        .map(|entry| {
            entry
                .map_err(|_| refuse())
                .and_then(|e| e.file_name().into_string().map_err(|_| refuse()))
        })
        .collect::<Result<_, _>>()?;
    names.sort();
    validate_hub_join_steps(&inputs, &names)?;
    let public = inputs
        .read_raw("host-public-identity.json", 16384)
        .map_err(|_| refuse())?;
    let report: serde_json::Value = serde_json::from_slice(public.bytes()).map_err(|_| refuse())?;
    if report.get("schema").and_then(|v| v.as_u64()) != Some(1)
        || report.get("operation").and_then(|v| v.as_str()) != Some("native_host_request")
        || report.get("status").and_then(|v| v.as_str()) != Some("awaiting_approval")
        || report.get("state_dir").and_then(|v| v.as_str()) != host.to_str()
        || report.get("device_id").and_then(|v| v.as_str()) != Some(proof.selection.device.as_str())
        || report.get("fingerprint").and_then(|v| v.as_str())
            != Some(proof.selection.fingerprint.to_hex().as_str())
        || report.get("request_id").and_then(|v| v.as_str())
            != Some(proof.selection.request.as_str())
        || report.get("comparison_code").and_then(|v| v.as_str())
            != Some(proof.selection.comparison.as_str())
        || report.get("expires_at").and_then(|v| v.as_u64()) != Some(proof.expires_at)
    {
        return Err(refuse());
    }
    let mut pinned = Vec::new();
    let intent = inputs
        .read_raw("setup-intent.json", 1024 * 1024)
        .map_err(|_| refuse())?;
    let intent_value: serde_json::Value =
        serde_json::from_slice(intent.bytes()).map_err(|_| refuse())?;
    if intent_value.get("role").and_then(|v| v.as_str()) != Some("hub") {
        return Err(refuse());
    }
    pinned.push(intent);
    for name in &names {
        if setup_hub_join_input(name) {
            let raw = inputs.read_raw(name, 1024 * 1024).map_err(|_| refuse())?;
            prepared.add_input(&inputs_path.join(name))?;
            pinned.push(raw);
        }
    }
    let revalidate = |gateway: &Root,
                      pinned: &[crate::store::RawFile]|
     -> Result<(), RetireError> {
        guard.validate()?;
        if PrivateRoot::open(inputs_path)
            .map_err(|_| refuse())?
            .identity()
            != inputs.identity()
        {
            return Err(refuse());
        }
        host_lease.validate().map_err(|_| refuse())?;
        gateway.validate()?;
        proof.validate().map_err(|_| refuse())?;
        let mut current: Vec<String> = std::fs::read_dir(inputs_path)
            .map_err(|_| refuse())?
            .map(|entry| {
                entry
                    .map_err(|_| refuse())
                    .and_then(|e| e.file_name().into_string().map_err(|_| refuse()))
            })
            .collect::<Result<_, _>>()?;
        current.sort();
        if current != names {
            return Err(refuse());
        }
        let after = gateway
            .root
            .read_raw("gateway-ca.pem", 128 * 1024)
            .map_err(|_| refuse())?;
        if after.observation() != gateway_ca.observation() || after.bytes() != gateway_ca.bytes() {
            return Err(refuse());
        }
        for before in pinned {
            let after = inputs
                .read_raw(before.relative_path(), 1024 * 1024)
                .map_err(|_| refuse())?;
            if after.observation() != before.observation() || after.bytes() != before.bytes() {
                return Err(refuse());
            }
        }
        Ok(())
    };
    revalidate(&gateway, &pinned)?;
    let journal_path = setup.join(SETUP_RETIRE_JOURNAL);
    if journal_exists(&journal_path)? {
        let backup = destination(&journal_path, &prepared.suffix)?;
        rename_exclusive(&backup.old_path, &backup.new_path).map_err(|_| unknown())?;
    }
    let journal = guard
        .root
        .create_setup_journal_child(SETUP_RETIRE_JOURNAL)
        .map_err(|_| unknown())?;
    journal
        .create_setup_export("begin".as_ref(), b"started\n")
        .map_err(|_| unknown())?;
    let input_pins: Vec<_> = pinned.iter().map(|p| serde_json::json!({"path":p.relative_path(), "sha256":p.sha256(), "observation":p.observation()})).collect();
    let target = serde_json::json!({"schema":1,"setup":guard.root.identity(),"inputs_root":inputs.identity(),"host":host_identity,
        "gateway":gateway_identity,"request_id":proof.selection.request,"device_id":proof.selection.device,
        "fingerprint":proof.selection.fingerprint,"comparison_code":proof.selection.comparison,
        "pairing":proof.pairing,"expires_at":proof.expires_at,"seed_sha256":proof.seed_sha256,"dispatch_sha256":proof.dispatch_sha256,
        "reply_sha256":proof.reply_sha256,"gateway_ca_sha256":gateway_ca.sha256(),"inputs":input_pins,"paths":prepared.paths});
    let target = serde_json::to_vec(&target).map_err(|_| unknown())?;
    journal
        .create_setup_export("target.json".as_ref(), &target)
        .map_err(|_| unknown())?;
    guard.root.sync_setup_directory().map_err(|_| unknown())?;
    revalidate(&gateway, &pinned).map_err(|_| unknown())?;
    let selection = RejectionRequest {
        request: proof.selection.request.clone(),
        device: proof.selection.device.clone(),
        fingerprint: proof.selection.fingerprint,
        comparison: proof.selection.comparison.clone(),
    };
    let bootstrap = EnrollmentBootstrap::recover_existing_for_retirement(
        &gateway.root,
        &mut gateway.writer,
        Limits::default(),
    )
    .map_err(|_| unknown())?;
    bootstrap
        .retirement_preflight(&selection, &proof.pairing, proof.expires_at)
        .map_err(|_| unknown())?;
    let receipt = bootstrap
        .abandon_pending_for_retirement(selection, &proof.pairing, proof.expires_at)
        .map_err(|_| unknown())?;
    let pairing_outcome = match receipt.outcome {
        crate::enrollment::retirement::RetirementOutcome::Rejected => "rejected",
        crate::enrollment::retirement::RetirementOutcome::Expired => "expired",
    };
    let receipt = serde_json::to_vec(&serde_json::json!({
        "schema":1,
        "target_sha256":styx_contracts::identity::Sha256Digest::of_bytes(&target),
        "outcome":pairing_outcome,
        "intent_digest":receipt.intent_digest,
        "durable_receipt":receipt.durable_receipt,
        "durable_clock_floor":receipt.durable_clock_floor,
        "revision":receipt.revision
    }))
    .map_err(|_| unknown())?;
    journal
        .create_setup_export("settled".as_ref(), &receipt)
        .map_err(|_| unknown())?;
    revalidate(&gateway, &pinned).map_err(|_| unknown())?;
    // POSIX rename works with the original files open: retain the Host writer
    // and its exact prefix pins through every rename and completion receipt.
    // Releasing only an execution lease is insufficient for native Join writers.
    #[cfg(target_os = "windows")]
    drop(proof);
    #[cfg(target_os = "windows")]
    drop(host_lease);
    let mut report = prepared.retire().map_err(|_| unknown())?;
    report.pairing_outcome = Some(pairing_outcome);
    if guard.root.sync_setup_directory().is_err()
        || inputs.sync_setup_directory().is_err()
        || journal
            .create_setup_export("done".as_ref(), b"completed\n")
            .is_err()
    {
        report.outcome = "unknown";
        report.restart_required = true;
        return Err(RetireError {
            code: "role_retire_completion_unknown",
            report,
        });
    }
    Ok(report)
}

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
)))]
fn retire_setup_hub_join(
    _: SetupContainerGuard,
    _: &Path,
    _: PrivateRoot,
    _: &Path,
) -> Result<RetireReport, RetireError> {
    Err(RetireError::refused("role_retire_hub_unsupported"))
}
/// Use official platform no-replace rename primitives, including for a name
/// collision appearing after preflight. There is no overwrite fallback.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)] // Official no-replace rename ABI only.
pub(crate) fn rename_exclusive(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: both CStrings remain alive for the official libc syscall.
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
#[cfg(target_os = "windows")]
#[allow(unsafe_code)] // Official MoveFileExW ABI, with no replacement flag.
pub(crate) fn rename_exclusive(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both NUL-terminated UTF16 buffers remain alive for this call.
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), 0)
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests;

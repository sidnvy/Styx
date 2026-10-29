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

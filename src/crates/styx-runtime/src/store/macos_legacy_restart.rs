//! Read-only fixed original launchd restart exclusion. No stop/unload/disable,
//! process census, shell, secret argv or service-by-name mutation is performed.
use super::*;
use crate::store::secure_journal::{JournalError, JournalResult};
use serde::Deserialize;
use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
struct FolderPin {
    path: PathBuf,
    parent: File,
    identity: (u64, u64),
    missing_child: Option<OsString>,
}
pub(super) struct MacLegacyRestartSources {
    root: Root,
    host: Root,
    service: Option<RawFile>,
    labels: Vec<String>,
    folders: Vec<FolderPin>,
}
#[derive(Deserialize)]
struct Service {
    label: String,
    #[serde(rename = "installRoot")]
    install_root: PathBuf,
    #[serde(rename = "hostConfigFile")]
    host_config: PathBuf,
    #[serde(rename = "trustPublicKeyFile")]
    publisher: PathBuf,
}
fn error<T>(r: Result<T>) -> JournalResult<T> {
    r.map_err(|_| JournalError::Unknown)
}
fn trusted_folder(path: &Path) -> JournalResult<(File, (u64, u64))> {
    if !path.is_absolute()
        || std::fs::canonicalize(path).map_err(|_| JournalError::Unknown)? != path
    {
        return Err(JournalError::Conflict);
    }
    let directory = nix::fcntl::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| JournalError::Unknown)?;
    let held = directory.metadata().map_err(|_| JournalError::Unknown)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| JournalError::Unknown)?;
    if !held.is_dir()
        || !named.is_dir()
        || held.dev() != named.dev()
        || held.ino() != named.ino()
        || held.mode() & 0o022 != 0
        || ![0, current_uid()].contains(&held.uid())
    {
        return Err(JournalError::Conflict);
    }
    Ok((directory, (held.dev(), held.ino())))
}
fn folder(path: PathBuf) -> JournalResult<FolderPin> {
    match trusted_folder(&path) {
        Ok((parent, identity)) => Ok(FolderPin {
            path,
            parent,
            identity,
            missing_child: None,
        }),
        Err(_)
            if std::fs::symlink_metadata(&path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            let parent_path = path.parent().ok_or(JournalError::Conflict)?;
            let (parent, identity) = trusted_folder(parent_path)?;
            let child = path
                .file_name()
                .ok_or(JournalError::Conflict)?
                .to_os_string();
            if !matches!(
                nix::sys::stat::fstatat(
                    &parent,
                    child.as_os_str(),
                    nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW
                ),
                Err(nix::errno::Errno::ENOENT)
            ) {
                return Err(JournalError::Conflict);
            }
            Ok(FolderPin {
                path,
                parent,
                identity,
                missing_child: Some(child),
            })
        }
        Err(e) => Err(e),
    }
}
fn absent(pin: &FolderPin, labels: &[String]) -> JournalResult<()> {
    let parent_path = if pin.missing_child.is_some() {
        pin.path.parent().ok_or(JournalError::Conflict)?
    } else {
        pin.path.as_path()
    };
    let (named, _) = trusted_folder(parent_path)?;
    let h = pin.parent.metadata().map_err(|_| JournalError::Unknown)?;
    let n = named.metadata().map_err(|_| JournalError::Unknown)?;
    if (h.dev(), h.ino()) != pin.identity || (n.dev(), n.ino()) != pin.identity {
        return Err(JournalError::Unknown);
    }
    let names: Vec<_> = if let Some(child) = &pin.missing_child {
        vec![child.clone()]
    } else {
        labels
            .iter()
            .map(|label| OsString::from(format!("{label}.plist")))
            .collect()
    };
    for name in names {
        match nix::sys::stat::fstatat(
            &pin.parent,
            name.as_os_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => {}
            _ => return Err(JournalError::Conflict),
        }
    }
    Ok(())
}
fn bounded_read(mut stream: impl Read) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    stream.by_ref().take(65537).read_to_end(&mut data)?;
    if data.len() > 65536 {
        return Err(std::io::Error::other("launchctl_output_capacity"));
    }
    Ok(data)
}
fn launchd_absent(target: &str, until: Instant) -> JournalResult<()> {
    let mut child = Command::new("/bin/launchctl")
        .args(["print", target])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| JournalError::Unknown)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(JournalError::Unknown);
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(JournalError::Unknown);
    };
    // Scoped readers cannot detach. On timeout/error the original unreaped Child
    // is killed and actually waited before both pipe-reader joins complete.
    thread::scope(|scope| {
        let out = scope.spawn(move || bounded_read(stdout));
        let err = scope.spawn(move || bounded_read(stderr));
        let waited = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let actual = child.wait();
                    break actual
                        .map_err(|_| JournalError::Unknown)
                        .and(Err(JournalError::Unknown));
                }
            }
        };
        let stdout = out
            .join()
            .map_err(|_| JournalError::Unknown)?
            .map_err(|_| JournalError::Unknown)?;
        let stderr = err
            .join()
            .map_err(|_| JournalError::Unknown)?
            .map_err(|_| JournalError::Unknown)?;
        let status = waited?;
        if status.code() != Some(113) || !stdout.is_empty() {
            return Err(JournalError::Conflict);
        }
        let text = std::str::from_utf8(&stderr)
            .map_err(|_| JournalError::Unknown)?
            .to_ascii_lowercase();
        if !text.contains("could not find service")
            && !text.contains("could not find specified service")
        {
            return Err(JournalError::Unknown);
        }
        Ok(())
    })
}
impl MacLegacyRestartSources {
    pub(super) fn capture(root: &Root, host: &Root) -> JournalResult<Self> {
        let service = match host.read_raw(Path::new("service.json"), 32768) {
            Ok(raw) => Some(raw),
            Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                error(host.ensure_absent(Path::new("service.json")))?;
                None
            }
            Err(_) => return Err(JournalError::Unknown),
        };
        let mut labels = vec![
            format!(
                "app.styx.gateway.{}",
                &styx_contracts::identity::Sha256Digest::of_bytes(
                    root.path.as_os_str().as_encoded_bytes()
                )
                .to_hex()[..12]
            ),
            "app.styx.desktop-login".into(),
        ];
        if let Some(raw) = &service {
            let d: Service =
                serde_json::from_slice(raw.bytes()).map_err(|_| JournalError::Unsupported)?;
            if !d.label.starts_with("app.styx.")
                || d.label.len() > 128
                || !d
                    .label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || d.install_root != host.path.join("install")
                || d.host_config != host.path.join("device/host.json")
                || d.publisher != host.path.join("publisher.pem")
            {
                return Err(JournalError::Conflict);
            }
            labels.push(d.label);
        }
        let user = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .map_err(|_| JournalError::Unknown)?
            .ok_or(JournalError::Unknown)?;
        let home = user.dir;
        let (home_fd, _) = trusted_folder(&home)?;
        if home_fd.metadata().map_err(|_| JournalError::Unknown)?.uid() != current_uid() {
            return Err(JournalError::Conflict);
        }
        let folders = vec![
            home.join("Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchDaemons"),
            PathBuf::from("/System/Library/LaunchAgents"),
            PathBuf::from("/System/Library/LaunchDaemons"),
        ]
        .into_iter()
        .map(folder)
        .collect::<JournalResult<Vec<_>>>()?;
        let value = Self {
            root: root.clone(),
            host: host.clone(),
            service,
            labels,
            folders,
        };
        value.revalidate()?;
        Ok(value)
    }
    pub(super) fn service_sha256(&self) -> Option<styx_contracts::identity::Sha256Digest> {
        self.service
            .as_ref()
            .map(|raw| styx_contracts::identity::Sha256Digest::of_bytes(raw.bytes()))
    }
    pub(super) fn revalidate(&self) -> JournalResult<()> {
        error(self.root.validate_root())?;
        error(self.host.validate_root())?;
        match &self.service {
            Some(original) => {
                let now = error(self.host.read_raw(Path::new("service.json"), 32768))?;
                if now.observation() != original.observation() || now.bytes() != original.bytes() {
                    return Err(JournalError::Unknown);
                }
            }
            None => error(self.host.ensure_absent(Path::new("service.json")))?,
        }
        for pin in &self.folders {
            absent(pin, &self.labels)?;
        }
        let until = Instant::now() + Duration::from_secs(15);
        for domain in [
            format!("gui/{}", current_uid()),
            format!("user/{}", current_uid()),
            "system".into(),
        ] {
            for label in &self.labels {
                if Instant::now() >= until {
                    return Err(JournalError::Unknown);
                }
                launchd_absent(&format!("{domain}/{label}"), until)?;
            }
        }
        for pin in &self.folders {
            absent(pin, &self.labels)?;
        }
        error(self.root.validate_root())?;
        error(self.host.validate_root())?;
        Ok(())
    }
}

//! Linux installation uses the existing signed release stager and setup owner.
//! Download directories are never retained as installed execution paths.
use super::setup::Failure;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(super) enum Mode {
    Gateway,
    Desktop,
}

#[cfg(target_os = "linux")]
fn release_failure(error: styx_runtime::release::ReleaseError) -> Failure {
    if error.exit_code() == 4 {
        Failure::unknown(error.code())
    } else {
        Failure::new(error.code())
    }
}

pub(super) struct Options {
    pub payload: PathBuf,
    pub publisher: PathBuf,
    pub pin: String,
    pub bin: Option<PathBuf>,
    pub authorize: bool,
    pub setup: bool,
    pub mode: Mode,
}

#[cfg(target_os = "linux")]
fn prepare_bin(bin: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !bin.is_absolute()
        || bin.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(Failure::new("install_absolute_bin_required"));
    }
    if !bin.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(bin)
            .map_err(|_| Failure::new("install_bin_unavailable"))?;
    }
    let meta =
        std::fs::symlink_metadata(bin).map_err(|_| Failure::new("install_bin_unavailable"))?;
    if !meta.is_dir()
        || meta.uid() != nix::unistd::getuid().as_raw()
        || meta.mode() & 0o022 != 0
        || bin
            .canonicalize()
            .map_err(|_| Failure::new("install_bin_unavailable"))?
            != bin
    {
        return Err(Failure::new("install_owner_bin_required"));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub(super) fn link(payload: &Path, bin: &Path, previous: Option<&Path>) -> Result<(), Failure> {
    use std::os::unix::fs::symlink;
    prepare_bin(bin)?;
    let target = payload.join("bin/styx");
    let destination = bin.join("styx");
    if let Ok(existing) = std::fs::read_link(&destination) {
        if existing == target {
            return Ok(());
        }
        if previous.is_some_and(|p| existing == p.join("bin/styx")) {
            let temporary = bin.join(format!(".styx-install-{}", std::process::id()));
            symlink(&target, &temporary)
                .map_err(|_| Failure::new("install_command_update_unavailable"))?;
            let result = std::fs::rename(&temporary, &destination);
            if result.is_err() {
                let _ = std::fs::remove_file(&temporary);
            }
            return result.map_err(|_| Failure::new("install_command_update_unavailable"));
        }
        return Err(Failure::new("install_existing_command_preserved"));
    }
    symlink(&target, &destination)
        .map_err(|_| Failure::new("install_existing_command_preserved"))?;
    Ok(())
}
#[cfg(target_os = "linux")]
pub(super) fn default_bin() -> Result<PathBuf, Failure> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/bin"))
        .ok_or_else(|| Failure::new("install_home_unavailable"))
}

#[cfg(target_os = "linux")]
fn releases() -> Result<PathBuf, Failure> {
    let home = PathBuf::from(
        std::env::var_os("HOME").ok_or_else(|| Failure::new("install_home_unavailable"))?,
    );
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    let parent = data.join("styx/releases");
    if !parent.is_absolute() {
        return Err(Failure::new("install_absolute_data_directory_required"));
    }
    Ok(parent)
}

#[cfg(target_os = "linux")]
pub(super) async fn previous_command(
    bin: &Path,
    original: Option<&super::setup::Payload>,
    pin: &str,
) -> Result<Option<PathBuf>, Failure> {
    prepare_bin(bin)?;
    let command = match std::fs::read_link(bin.join("styx")) {
        Ok(command) => command,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Failure::new("install_existing_command_preserved")),
    };
    let previous = command
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Failure::new("install_existing_command_preserved"))?;
    let bootstrap = original.filter(|v| previous == v.payload_dir);
    if command != previous.join("bin/styx")
        || !(previous.starts_with(releases()?) || bootstrap.is_some())
    {
        return Err(Failure::new("install_existing_command_preserved"));
    }
    let key = match bootstrap {
        Some(original) => original.publisher_file.clone(),
        None => previous
            .parent()
            .ok_or_else(|| Failure::new("install_existing_command_preserved"))?
            .join("publisher.pem"),
    };
    styx_runtime::release::inspect_selection(previous, &key, pin)
        .await
        .map_err(release_failure)?;
    Ok(Some(previous.to_owned()))
}

pub(super) async fn run(options: Options) -> Result<(), Failure> {
    let Options {
        payload,
        publisher,
        pin,
        bin,
        authorize,
        setup,
        mode,
    } = options;
    if !authorize {
        return Err(Failure::new("install_authorization_required"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (payload, publisher, pin, bin, setup, mode);
        Err(Failure::new("install_use_native_platform_package"))
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::DirBuilderExt;
        let root = super::setup::root_default()?;
        let intent = root.join("inputs/setup-intent.json");
        if setup && !intent.exists() && !super::setup_prompt::terminal() {
            return Err(Failure::new("install_setup_requires_terminal"));
        }
        let admitted = styx_runtime::release::inspect_selection(&payload, &publisher, &pin)
            .await
            .map_err(release_failure)?;
        let parent = releases()?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)
            .map_err(|_| Failure::new("install_directory_unavailable"))?;
        let name = admitted.manifest_sha256.to_hex();
        let destination = parent.join(&name);
        let installed = if destination.exists() {
            let existing = styx_runtime::release::inspect_selection(
                &destination.join("payload"),
                &destination.join("publisher.pem"),
                &pin,
            )
            .await
            .map_err(release_failure)?;
            if existing.manifest_sha256 != admitted.manifest_sha256 {
                return Err(Failure::new("install_existing_release_mismatch"));
            }
            existing
        } else {
            styx_runtime::release::stage(&payload, &publisher, &pin, &parent, name.as_ref())
                .await
                .map_err(release_failure)?
        };
        let payload = PathBuf::from(&installed.payload_path);
        let publisher = PathBuf::from(&installed.publisher_file);
        let bin = bin.map(Ok).unwrap_or_else(default_bin)?;
        if intent.exists() {
            let existing = super::setup::Answers::load(&intent)?;
            if !matches!(
                (mode, existing.role),
                (Mode::Gateway, super::setup::Role::Gateway)
                    | (
                        Mode::Desktop,
                        super::setup::Role::Join | super::setup::Role::Hub
                    )
            ) {
                return Err(Failure::new("install_existing_role_preserved"));
            }
            // Install and update have one entry. --setup only requests first-run
            // questions; an existing installation always updates its services
            // and CLI together in the same independent OS job.
            match super::upgrade::run(
                payload.clone(),
                Some(publisher.clone()),
                Some(pin.clone()),
                Some(root.clone()),
                true,
                Some(bin.clone()),
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(error)
                    if setup
                        && matches!(
                            error.code,
                            "upgrade_nothing_set_up" | "upgrade_existing_linux_services_required"
                        ) =>
                {
                    let bootstrap = styx_runtime::release::inspect_selection(
                        &existing.payload.payload_dir,
                        &existing.payload.publisher_file,
                        &pin,
                    )
                    .await
                    .map_err(release_failure)?;
                    if bootstrap.manifest_sha256 != installed.manifest_sha256 {
                        return Err(error);
                    }
                    for role in ["gateway", "host"] {
                        let path = root.join(role);
                        if path.exists() {
                            let selected = styx_runtime::management::native_gateway_admin::committed_runtime_selection(&path)
                                .await.map_err(Failure::admin)?;
                            if selected.manifest_sha256 != installed.manifest_sha256 {
                                return Err(error);
                            }
                        }
                    }
                    // Finish an interrupted first setup only on its existing
                    // selected package; never turn an update into a fresh profile.
                    let previous = previous_command(&bin, Some(&existing.payload), &pin).await?;
                    link(&payload, &bin, previous.as_deref())?;
                    if matches!(mode, Mode::Gateway) {
                        super::install_boot::ensure_gateway_boot()?;
                    }
                    return super::setup::run_installed(existing.payload, mode).await;
                }
                Err(error) => return Err(error),
            }
        }
        let previous = previous_command(&bin, None, &pin).await?;
        link(&payload, &bin, previous.as_deref())?;
        println!("Installed Styx: {}", bin.join("styx").display());
        if setup {
            if matches!(mode, Mode::Gateway) {
                super::install_boot::ensure_gateway_boot()?;
            }
            super::setup::run_installed(
                super::setup::Payload {
                    payload_dir: payload,
                    publisher_file: publisher,
                    expected_publisher: pin,
                },
                mode,
            )
            .await
        } else {
            println!("Next: {} setup", bin.join("styx").display());
            Ok(())
        }
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn existing_command_is_never_replaced() {
        let root = std::env::temp_dir().join(format!("styx-cli-install-{}", std::process::id()));
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let payload = root.join("release");
        link(&payload, &bin, None).unwrap();
        assert_eq!(
            std::fs::read_link(bin.join("styx")).unwrap(),
            payload.join("bin/styx")
        );
        link(&payload, &bin, None).unwrap();
        assert!(link(&root.join("other"), &bin, None).is_err());
        let upgraded = root.join("upgraded");
        link(&upgraded, &bin, Some(&payload)).unwrap();
        assert_eq!(
            std::fs::read_link(bin.join("styx")).unwrap(),
            upgraded.join("bin/styx")
        );
        assert!(link(&payload, &bin, Some(&payload)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

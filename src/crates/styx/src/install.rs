//! Install a Linux owner CLI link only after the existing signed-release reader
//! has admitted the payload with an external publisher pin. No profile mutation.
use super::setup::Failure;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
fn link(payload: &Path, bin: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
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
    let target = payload.join("bin/styx");
    let destination = bin.join("styx");
    if let Ok(existing) = std::fs::read_link(&destination) {
        if existing == target {
            return Ok(());
        }
        return Err(Failure::new("install_existing_command_preserved"));
    }
    symlink(&target, &destination)
        .map_err(|_| Failure::new("install_existing_command_preserved"))?;
    Ok(())
}
pub(super) async fn run(
    payload: PathBuf,
    publisher: PathBuf,
    pin: String,
    bin: Option<PathBuf>,
    authorize: bool,
) -> Result<(), Failure> {
    if !authorize {
        return Err(Failure::new("install_authorization_required"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (payload, publisher, pin, bin);
        Err(Failure::new("install_use_native_platform_package"))
    }
    #[cfg(target_os = "linux")]
    {
        let admitted = styx_runtime::release::inspect_selection(&payload, &publisher, &pin)
            .await
            .map_err(|e| Failure::new(e.code()))?;
        let payload = PathBuf::from(admitted.payload_path);
        let bin = bin.unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/bin")
        });
        link(&payload, &bin)?;
        println!(
            "Installed: {}\nReopen your login shell, then run: command -v styx; styx setup\nIf your login PATH does not include this directory, add it explicitly: {}",
            bin.join("styx").display(),
            bin.display()
        );
        Ok(())
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
        link(&payload, &bin).unwrap();
        assert_eq!(
            std::fs::read_link(bin.join("styx")).unwrap(),
            payload.join("bin/styx")
        );
        link(&payload, &bin).unwrap();
        assert!(link(&root.join("other"), &bin).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

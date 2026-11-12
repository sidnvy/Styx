//! Verified immutable version-container staging. Never installs or activates.
use super::*;
use std::ffi::OsStr;
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
static STAGERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Copy only an already verified C08 closure into a wholly new private version
/// container. Its fixed children are payload/ and publisher.pem. A lost waiter
/// does not cancel the original blocking worker, release its slot or retry it.
/// Every failure after creation is Unknown; partial files are retained in place.
pub async fn stage(
    payload: &Path,
    publisher_file: &Path,
    expected_pin: &str,
    destination_parent: &Path,
    name: &OsStr,
) -> Result<NativeRuntimeSelection> {
    stage_with_policy(
        payload,
        publisher_file,
        expected_pin,
        destination_parent,
        name,
        true,
    )
    .await
}

/// First App setup installs an already admitted bundle into its private Runtime.
/// Check each signed member while copying, without two additional tree scans.
pub(crate) async fn stage_installed(
    payload: &Path,
    publisher_file: &Path,
    expected_pin: &str,
    destination_parent: &Path,
    name: &OsStr,
) -> Result<NativeRuntimeSelection> {
    stage_with_policy(
        payload,
        publisher_file,
        expected_pin,
        destination_parent,
        name,
        false,
    )
    .await
}

async fn stage_with_policy(
    payload: &Path,
    publisher_file: &Path,
    expected_pin: &str,
    destination_parent: &Path,
    name: &OsStr,
    full_admission: bool,
) -> Result<NativeRuntimeSelection> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let expected =
            PublisherFingerprint::parse(expected_pin).map_err(|_| ReleaseError::Invalid)?;
        let permit = STAGERS.try_acquire().map_err(|_| ReleaseError::Busy)?;
        let payload = payload.to_owned();
        let publisher_file = publisher_file.to_owned();
        let destination_parent = destination_parent.to_owned();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            stage_blocking(
                &payload,
                &publisher_file,
                &expected,
                &destination_parent,
                &name,
                full_admission,
            )
        })
        .await
        .map_err(|_| ReleaseError::Unknown)?
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (
            payload,
            publisher_file,
            expected_pin,
            destination_parent,
            name,
        );
        Err(ReleaseError::Unsupported)
    }
}
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn stage_blocking(
    payload: &Path,
    publisher_file: &Path,
    expected: &PublisherFingerprint,
    destination_parent: &Path,
    name: &OsStr,
    full_admission: bool,
) -> Result<NativeRuntimeSelection> {
    use crate::store::{ReleaseCopyMember, ReleaseStage};
    let source = open_release(payload, publisher_file, expected, full_admission)?;
    // Reject preview scope/unsupported readers before any destination creation.
    source.runtime_selection()?;
    let parent = PrivateRoot::open(destination_parent)?;
    if destination_parent.starts_with(payload) {
        return Err(ReleaseError::Invalid);
    }
    // From the first mkdir attempt onward, absence of an output is never
    // reported as a rollback. No failed name may be adopted on a later call.
    let mut destination = ReleaseStage::create(&parent, destination_parent, name)
        .map_err(|_| ReleaseError::Unknown)?;
    let result = (|| {
        let mut members: Vec<_> = source
            .manifest
            .files
            .iter()
            .map(|member| {
                (
                    PathBuf::from(&member.path),
                    member.size,
                    member.sha256,
                    member.executable,
                )
            })
            .collect();
        for (name, raw) in [
            ("manifest.json", &source.manifest_file),
            ("manifest.sig", &source.signature_file),
        ] {
            members.push((
                PathBuf::from(name),
                raw.bytes().len() as u64,
                Sha256Digest::of_bytes(raw.bytes()),
                false,
            ));
        }
        for (path, bytes, digest, executable) in members {
            destination.copy_member(
                &source.root,
                ReleaseCopyMember {
                    source_relative: &path,
                    destination_relative: &Path::new("payload").join(&path),
                    bytes,
                    sha256: digest,
                    executable,
                },
            )?;
        }
        destination.copy_member(
            &source.publisher_root,
            ReleaseCopyMember {
                source_relative: source.publisher_file.relative_path(),
                destination_relative: Path::new("publisher.pem"),
                bytes: source.publisher_file.bytes().len() as u64,
                sha256: Sha256Digest::of_bytes(source.publisher_file.bytes()),
                executable: false,
            },
        )?;
        source.revalidate()?;
        let staged = open_release(
            &destination.path().join("payload"),
            &destination.path().join("publisher.pem"),
            expected,
            full_admission,
        )?;
        if staged.manifest_file.bytes() != source.manifest_file.bytes()
            || staged.signature_file.bytes() != source.signature_file.bytes()
            || staged.publisher_file.bytes() != source.publisher_file.bytes()
        {
            return Err(ReleaseError::Changed);
        }
        let selection = staged.runtime_selection()?;
        source.revalidate()?;
        Ok(selection)
    })();
    result.map_err(|_| ReleaseError::Unknown)
}

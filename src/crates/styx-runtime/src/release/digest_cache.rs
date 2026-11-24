//! Per-user cache of payload file digests from the last full check of a signed
//! manifest. A verification reuses a digest only while that file's device,
//! inode, size, mtime and ctime are unchanged; any other file is read and hashed
//! again. The cache is an optimisation, not an authority: a missing, unreadable
//! or stale cache only means a full check, and the signed manifest still decides
//! every member. Same-user write access to the cache grants nothing that same-user
//! write access to the payload did not already grant.
use crate::store::{FileObservation, KnownDigests, PayloadMember};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use styx_contracts::identity::Sha256Digest;

const MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct CacheFile {
    schema: u16,
    manifest_sha256: Sha256Digest,
    members: Vec<Entry>,
}
#[derive(Serialize, Deserialize, PartialEq)]
struct Entry {
    path: PathBuf,
    device: u64,
    inode: u64,
    byte_len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    sha256: Sha256Digest,
}
impl Entry {
    fn of(member: &PayloadMember) -> Self {
        let o = &member.observation;
        Self {
            path: member.path.clone(),
            device: o.device,
            inode: o.inode,
            byte_len: o.byte_len,
            modified: (o.modified_seconds, o.modified_nanoseconds),
            changed: (o.changed_seconds, o.changed_nanoseconds),
            sha256: member.sha256,
        }
    }
    fn observation(&self) -> FileObservation {
        FileObservation {
            device: self.device,
            inode: self.inode,
            byte_len: self.byte_len,
            modified_seconds: self.modified.0,
            modified_nanoseconds: self.modified.1,
            changed_seconds: self.changed.0,
            changed_nanoseconds: self.changed.1,
        }
    }
}

/// Private per-user directory, or none when the platform location is unknown.
fn directory() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?
        .join("styx");
    #[cfg(target_os = "macos")]
    let base = PathBuf::from(std::env::var_os("HOME")?).join("Library/Caches/Styx");
    #[cfg(target_os = "windows")]
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("Styx");
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let base: PathBuf = return None;
    let dir = base.join("payload-digests-v1");
    if !dir.is_absolute() {
        return None;
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir).ok()?;
    let metadata = std::fs::symlink_metadata(&dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::Uid::current().as_raw() || metadata.mode() & 0o077 != 0 {
            return None;
        }
    }
    metadata.is_dir().then_some(dir)
}
fn file_name(manifest_sha256: &Sha256Digest) -> String {
    format!("{}.json", manifest_sha256.to_hex())
}

/// Digests recorded for exactly this signed manifest, or none.
pub(crate) fn load(manifest_sha256: &Sha256Digest) -> KnownDigests {
    directory()
        .and_then(|dir| read(&dir.join(file_name(manifest_sha256))))
        .filter(|cache| cache.schema == 1 && cache.manifest_sha256 == *manifest_sha256)
        .map(|cache| {
            cache
                .members
                .into_iter()
                .map(|entry| (entry.path.clone(), (entry.observation(), entry.sha256)))
                .collect()
        })
        .unwrap_or_default()
}
fn read(path: &Path) -> Option<CacheFile> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Record the members of a completed full check. Best effort: a failed write
/// only costs the next start a full check.
pub(crate) fn store(
    manifest_sha256: &Sha256Digest,
    known: &KnownDigests,
    members: &[PayloadMember],
) {
    let unchanged = known.len() == members.len()
        && members.iter().all(|member| {
            known.get(&member.path) == Some(&(member.observation.clone(), member.sha256))
        });
    if unchanged {
        return;
    }
    let cache = CacheFile {
        schema: 1,
        manifest_sha256: *manifest_sha256,
        members: members.iter().map(Entry::of).collect(),
    };
    let (Some(dir), Ok(bytes)) = (directory(), serde_json::to_vec(&cache)) else {
        return;
    };
    let name = file_name(manifest_sha256);
    let temporary = dir.join(format!("{name}.{}", uuid::Uuid::new_v4().simple()));
    if write_private(&temporary, &bytes).is_err()
        || std::fs::rename(&temporary, dir.join(&name)).is_err()
    {
        let _ = std::fs::remove_file(&temporary);
    }
}
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // Windows: %LOCALAPPDATA% is already private to this user.
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

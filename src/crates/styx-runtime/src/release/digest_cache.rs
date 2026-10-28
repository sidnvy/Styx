//! Per-role cache of payload file digests from the last full check. A start
//! reuses a digest only while that file's device, inode, size, mtime and ctime
//! are unchanged; any other file is read and hashed again. The cache is an
//! optimisation, not an authority: a missing, unreadable or stale cache only
//! means a full check, and the signed manifest still decides every member.
use crate::store::{FileObservation, KnownDigests, PayloadMember};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use styx_contracts::identity::Sha256Digest;

pub(crate) const FILE_NAME: &str = "payload-digests-v1.json";
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

/// Digests recorded for exactly this signed manifest, or none.
pub(crate) fn load(dir: &Path, manifest_sha256: &Sha256Digest) -> KnownDigests {
    read(dir)
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
fn read(dir: &Path) -> Option<CacheFile> {
    let path = dir.join(FILE_NAME);
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return None;
    }
    serde_json::from_slice(&std::fs::read(&path).ok()?).ok()
}

/// Record the members of a completed full check. Best effort: a failed write
/// only costs the next start a full check.
pub(crate) fn store(
    dir: &Path,
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
    let Ok(bytes) = serde_json::to_vec(&cache) else {
        return;
    };
    let temporary = dir.join(format!("{FILE_NAME}.{}", uuid::Uuid::new_v4().simple()));
    if write_private(&temporary, &bytes).is_err()
        || std::fs::rename(&temporary, dir.join(FILE_NAME)).is_err()
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
    // Windows: the private role root's protected ACL is inherited.
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

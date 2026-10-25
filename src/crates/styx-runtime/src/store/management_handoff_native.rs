//! Private v3 journal evidence. Serialized facts never confer a writer or
//! attest original process settlement/credential rename.
use super::*;
use serde::de::DeserializeOwned;
use styx_contracts::native_management::NativeRootIdentity;

pub(in crate::store) trait ProofRoot:
    Clone + PartialEq + Eq + Serialize + DeserializeOwned
{
    const RETIREMENT_SCHEMA: u16;
    fn permits_cutover(schema: u16) -> bool;
    fn native_identity(&self) -> NativeRootIdentity;
    fn valid_pair(&self, other: &Self) -> bool;
}
impl ProofRoot for RetirementLinuxRoot {
    const RETIREMENT_SCHEMA: u16 = 1;
    fn permits_cutover(schema: u16) -> bool {
        matches!(schema, 1 | 2)
    }
    fn native_identity(&self) -> NativeRootIdentity {
        NativeRootIdentity::Linux {
            device: self.device,
            inode: self.inode,
            uid: self.uid,
        }
    }
    fn valid_pair(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.inode != 0
                && other.inode != 0
                && self.uid == other.uid
                && self.uid == nix::unistd::geteuid().as_raw()
        }
        #[cfg(not(unix))]
        {
            let _ = other;
            false
        }
    }
}
impl ProofRoot for NativeRootIdentity {
    const RETIREMENT_SCHEMA: u16 = 3;
    fn permits_cutover(schema: u16) -> bool {
        matches!(schema, 3 | 4)
    }
    fn native_identity(&self) -> NativeRootIdentity {
        self.clone()
    }
    fn valid_pair(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Linux { inode, uid, .. },
                Self::Linux {
                    inode: other_inode,
                    uid: other_uid,
                    ..
                },
            )
            | (
                Self::Macos { inode, uid, .. },
                Self::Macos {
                    inode: other_inode,
                    uid: other_uid,
                    ..
                },
            ) => *inode != 0 && *other_inode != 0 && uid == other_uid,
            (
                Self::Windows {
                    file_id, owner_sid, ..
                },
                Self::Windows {
                    file_id: other_file,
                    owner_sid: other_sid,
                    ..
                },
            ) => {
                *file_id != 0
                    && *other_file != 0
                    && owner_sid == other_sid
                    && owner_sid.len() <= 184
                    && owner_sid.starts_with("S-1-")
                    && owner_sid[4..]
                        .split('-')
                        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            }
            _ => false,
        }
    }
}
pub(in crate::store) trait ProofStamp<R>:
    Clone + PartialEq + Eq + Serialize + DeserializeOwned
{
    fn valid_for(&self, root: &R) -> bool;
    fn content_sha256(&self) -> Sha256Digest;
    fn same_file_after_rename(&self, post: &Self) -> bool;
}
impl ProofStamp<RetirementLinuxRoot> for RetirementFileStamp {
    fn content_sha256(&self) -> Sha256Digest {
        self.sha256
    }
    fn valid_for(&self, root: &RetirementLinuxRoot) -> bool {
        self.valid(root.uid)
    }
    fn same_file_after_rename(&self, post: &Self) -> bool {
        self.same_renamed_file(post)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::store) enum NativeRetirementFileStamp {
    Linux {
        stamp: RetirementFileStamp,
    },
    Macos {
        stamp: RetirementFileStamp,
    },
    Windows {
        volume_serial: u64,
        file_id: u64,
        owner_sid: String,
        nlink: u64,
        byte_len: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
        sha256: Sha256Digest,
    },
}
impl ProofStamp<NativeRootIdentity> for NativeRetirementFileStamp {
    fn content_sha256(&self) -> Sha256Digest {
        match self {
            Self::Linux { stamp } | Self::Macos { stamp } => stamp.sha256,
            Self::Windows { sha256, .. } => *sha256,
        }
    }
    fn valid_for(&self, root: &NativeRootIdentity) -> bool {
        if !root.valid_pair(root) {
            return false;
        }
        match (self, root) {
            (Self::Linux { stamp }, NativeRootIdentity::Linux { uid, .. })
            | (Self::Macos { stamp }, NativeRootIdentity::Macos { uid, .. }) => stamp.valid(*uid),
            (
                Self::Windows {
                    file_id,
                    owner_sid,
                    nlink,
                    byte_len,
                    modified_seconds,
                    modified_nanoseconds,
                    changed_seconds,
                    changed_nanoseconds,
                    ..
                },
                NativeRootIdentity::Windows {
                    owner_sid: expected,
                    ..
                },
            ) => {
                *file_id != 0
                    && owner_sid == expected
                    && *nlink == 1
                    && (1..=4096).contains(byte_len)
                    && *modified_seconds >= 0
                    && *changed_seconds >= 0
                    && (0..1_000_000_000).contains(modified_nanoseconds)
                    && (0..1_000_000_000).contains(changed_nanoseconds)
                    && modified_nanoseconds % 100 == 0
                    && changed_nanoseconds % 100 == 0
            }
            _ => false,
        }
    }
    fn same_file_after_rename(&self, post: &Self) -> bool {
        match (self, post) {
            (Self::Linux { stamp }, Self::Linux { stamp: other })
            | (Self::Macos { stamp }, Self::Macos { stamp: other }) => {
                stamp.same_renamed_file(other)
            }
            (
                Self::Windows {
                    volume_serial,
                    file_id,
                    owner_sid,
                    nlink,
                    byte_len,
                    modified_seconds,
                    modified_nanoseconds,
                    sha256,
                    ..
                },
                Self::Windows {
                    volume_serial: volume,
                    file_id: file,
                    owner_sid: owner,
                    nlink: links,
                    byte_len: bytes,
                    modified_seconds: seconds,
                    modified_nanoseconds: nanos,
                    sha256: digest,
                    ..
                },
            ) => {
                let root = NativeRootIdentity::Windows {
                    volume_serial: *volume_serial,
                    file_id: *file_id,
                    owner_sid: owner_sid.clone(),
                };
                self.valid_for(&root)
                    && post.valid_for(&root)
                    && volume_serial == volume
                    && file_id == file
                    && owner_sid == owner
                    && nlink == links
                    && byte_len == bytes
                    && modified_seconds == seconds
                    && modified_nanoseconds == nanos
                    && sha256 == digest
            }
            _ => false,
        }
    }
}
pub(in crate::store) type NativeObservedRetirement =
    ObservedRetirement<NativeRootIdentity, NativeRetirementFileStamp>;

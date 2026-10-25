//! Read-only pins for exactly the installed Styx App and embedded Cua images.
//! This is not a PrivateRoot, PayloadInventory, arbitrary bundle loader or spawn
//! permit. Existing private-store and PinnedExecutable rules are unchanged.

use super::super::{ffi, observation, open_at};
use super::{signing_information, stream_hash};
use crate::store::{FileObservation, ProcessIdentity, Result, StoreError};
use core_foundation::url::CFURL;
use nix::{
    fcntl::OFlag,
    sys::stat::Mode,
    unistd::{geteuid, getuid},
};
use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};
use std::{
    ffi::OsStr,
    fs::{File, Metadata},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::identity::Sha256Digest;

const APP: &str = "/Applications/Styx.app";
const CERT: &str = "cb50cee601419f28b43756f4fc8aefdbf60abae2";
const DIRECTORIES: [&str; 4] = ["Applications", "Styx.app", "Contents", "MacOS"];
// The existing payload per-file cap; this factory is not a new tuning knob.
const MAX_IMAGE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryFacts {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
fn directory_facts(file: &File, system_ancestor: bool, uid: u32) -> Result<DirectoryFacts> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.mode() & 0o7002 != 0 {
        return Err(StoreError::NotPrivate);
    }
    if system_ancestor {
        // / and /Applications are OS-owned anchors. /Applications commonly
        // permits admin-group replacement and has a deny-delete ACL. This is
        // not credential privacy: signature + before/after locator identity
        // must still validate the installed bundle. No ancestor chmod/ACL edit.
        if metadata.uid() != 0 {
            return Err(StoreError::NotPrivate);
        }
    } else {
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(StoreError::NotPrivate);
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(StoreError::NotPrivate);
        }
        // Reuse the native opaque ACL validation. Nonempty ACL on App-owned
        // directories is conservatively unsupported, even a harmless one.
        ffi::require_empty_acl(file)?;
    }
    Ok(DirectoryFacts {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
    })
}
struct DirectoryPin {
    file: File,
    facts: DirectoryFacts,
}
struct BundleSource {
    directories: Vec<DirectoryPin>,
    creator: ProcessIdentity,
    uid: u32,
}
fn open_directory(parent: &File, name: &str) -> Result<File> {
    open_at(
        parent,
        OsStr::new(name),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY,
        Mode::empty(),
    )
}
impl BundleSource {
    fn open_fixed() -> Result<Self> {
        let uid = getuid().as_raw();
        if uid != geteuid().as_raw() {
            return Err(StoreError::NotPrivate);
        }
        let root = File::open("/")?;
        let facts = directory_facts(&root, true, uid)?;
        let mut directories = vec![DirectoryPin { file: root, facts }];
        for (index, name) in DIRECTORIES.iter().enumerate() {
            let file = open_directory(&directories.last().expect("root").file, name)?;
            let facts = directory_facts(&file, index == 0, uid)?;
            directories.push(DirectoryPin { file, facts });
        }
        let source = Self {
            directories,
            creator: ProcessIdentity::current()?,
            uid,
        };
        source.revalidate()?;
        Ok(source)
    }
    fn revalidate(&self) -> Result<()> {
        if getuid().as_raw() != self.uid
            || geteuid().as_raw() != self.uid
            || !self.creator.still_current()?
        {
            return Err(StoreError::ProcessIdentityUnavailable);
        }
        let mut current = File::open("/")?;
        for (index, original) in self.directories.iter().enumerate() {
            if index > 0 {
                current = open_directory(&current, DIRECTORIES[index - 1])?;
            }
            let system_ancestor = index <= 1;
            if directory_facts(&original.file, system_ancestor, self.uid)? != original.facts
                || directory_facts(&current, system_ancestor, self.uid)? != original.facts
            {
                return Err(StoreError::Changed);
            }
        }
        Ok(())
    }
    fn macos_directory(&self) -> &File {
        &self.directories.last().expect("fixed chain").file
    }
}

#[derive(Clone, Copy)]
enum Member {
    App,
    Daemon,
}
impl Member {
    fn name(self) -> &'static str {
        match self {
            Self::App => "Styx",
            Self::Daemon => "cua-driver",
        }
    }
    fn path(self) -> PathBuf {
        Path::new(APP).join("Contents/MacOS").join(self.name())
    }
    fn requirement(self) -> Result<SecRequirement> {
        let suffix = if matches!(self, Self::App) {
            " and identifier \"app.styx.host\""
        } else {
            ""
        };
        format!("certificate leaf = H\"{CERT}\"{suffix}")
            .parse()
            .map_err(|_| StoreError::Unsupported)
    }
}
#[derive(Clone, Eq, PartialEq)]
struct MemberFacts {
    file: FileObservation,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
}
fn member_facts(file: &File, uid: u32) -> Result<MemberFacts> {
    let metadata: Metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o111 == 0
        || (metadata.uid() != 0 && metadata.uid() != uid)
    {
        return Err(StoreError::NotRegularFile);
    }
    ffi::require_empty_acl(file)?;
    if metadata.len() > MAX_IMAGE_BYTES {
        return Err(StoreError::TooLarge);
    }
    Ok(MemberFacts {
        file: observation(&metadata),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    })
}
fn open_member(source: &BundleSource, member: Member) -> Result<File> {
    open_at(
        source.macos_directory(),
        OsStr::new(member.name()),
        OFlag::O_RDONLY | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
}

/// Original readonly image descriptor and content/signing identity. No public
/// constructor, arbitrary locator, mutable File, or executable-launch method.
pub(crate) struct SignedAppMember {
    source: Arc<BundleSource>,
    member: Member,
    file: File,
    facts: MemberFacts,
    sha256: Sha256Digest,
    cdhash: Vec<u8>,
}
impl SignedAppMember {
    fn pin(source: Arc<BundleSource>, member: Member) -> Result<Self> {
        source.revalidate()?;
        let file = open_member(&source, member)?;
        let facts = member_facts(&file, source.uid)?;
        let sha256 = stream_hash(&file, facts.file.byte_len)?;
        if member_facts(&file, source.uid)? != facts
            || member_facts(&open_member(&source, member)?, source.uid)? != facts
        {
            return Err(StoreError::Changed);
        }
        let url = CFURL::from_path(member.path(), false).ok_or(StoreError::Unsupported)?;
        let code =
            SecStaticCode::from_path(&url, Flags::NONE).map_err(|_| StoreError::Unsupported)?;
        // SecStaticCode.h documents native-architecture validation by default.
        // Let Security.framework handle thin/universal Mach-O and choose its
        // native slice; do not apply the spawn-only PinnedExecutable thin guard.
        // The CDHash below belongs to this same selected static code object.
        // Source binding must still match the original live SecCode to it;
        // a different loaded/Rosetta slice is refused, never implicitly adopted.
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
            &member.requirement()?,
        )
        .map_err(|_| StoreError::Changed)?;
        let cdhash = signing_information::cdhash(&code)?;
        let pin = Self {
            source,
            member,
            file,
            facts,
            sha256,
            cdhash,
        };
        pin.revalidate()?;
        // Rehash the original FD after the path-based Security call so the
        // signing observation cannot silently replace our retained image bytes.
        if stream_hash(&pin.file, pin.facts.file.byte_len)? != pin.sha256 {
            return Err(StoreError::Changed);
        }
        pin.revalidate()?;
        Ok(pin)
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.source.revalidate()?;
        if member_facts(&self.file, self.source.uid)? != self.facts
            || member_facts(&open_member(&self.source, self.member)?, self.source.uid)?
                != self.facts
        {
            return Err(StoreError::Changed);
        }
        self.source.revalidate()
    }
    pub(crate) fn source_path_for_image_attestation(&self) -> Result<PathBuf> {
        self.revalidate()?;
        Ok(self.member.path())
    }
    pub(crate) fn expected_cdhash(&self) -> Result<Vec<u8>> {
        self.revalidate()?;
        Ok(self.cdhash.clone())
    }
    pub(crate) fn expected_sha256(&self) -> Result<Sha256Digest> {
        self.revalidate()?;
        Ok(self.sha256)
    }
    pub(crate) fn retained_file(&self) -> Result<&File> {
        self.revalidate()?;
        Ok(&self.file)
    }
}

/// Exactly two members of the fixed, original-cert App. This does not prove any
/// running process is App-owned; the source adapter still binds actual peers.
pub(crate) struct SignedAppMembers {
    pub(crate) app: Arc<SignedAppMember>,
    pub(crate) daemon: Arc<SignedAppMember>,
}
impl SignedAppMembers {
    pub(crate) fn open_fixed() -> Result<Self> {
        let source = Arc::new(BundleSource::open_fixed()?);
        let app = Arc::new(SignedAppMember::pin(source.clone(), Member::App)?);
        let daemon = Arc::new(SignedAppMember::pin(source.clone(), Member::Daemon)?);
        source.revalidate()?;
        let url = CFURL::from_path(APP, true).ok_or(StoreError::Unsupported)?;
        let code =
            SecStaticCode::from_path(&url, Flags::NONE).map_err(|_| StoreError::Unsupported)?;
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::CHECK_NESTED_CODE | Flags::NO_NETWORK_ACCESS,
            &Member::App.requirement()?,
        )
        .map_err(|_| StoreError::Changed)?;
        let members = Self { app, daemon };
        members.revalidate()?;
        Ok(members)
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.app.revalidate()?;
        self.daemon.revalidate()
    }
}

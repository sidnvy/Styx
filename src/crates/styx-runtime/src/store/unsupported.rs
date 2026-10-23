//! Deliberate fail-closed platform boundary; no std::fs/lockfile fallback.
use super::*;
pub(super) enum Root {}
impl Root {
    pub(super) fn open(_: &Path) -> Result<Self> {
        Err(StoreError::Unsupported)
    }
    pub(super) fn identity(&self) -> RootIdentity {
        match *self {}
    }
    pub(super) fn read_raw(&self, _: &Path, _: usize) -> Result<RawFile> {
        match *self {}
    }
    pub(super) fn try_lock(&self, _: LockResource) -> Result<Lock> {
        match *self {}
    }
}
pub(super) enum Lock {}
impl Lock {
    pub(super) fn identity(&self) -> &LeaseIdentity {
        match *self {}
    }
    pub(super) fn validate(&self) -> Result<()> {
        match *self {}
    }
}
pub(super) fn process_identity(_: u32) -> Result<ProcessIdentity> {
    Err(StoreError::Unsupported)
}
pub(super) fn process_matches(_: &ProcessIdentity) -> Result<bool> {
    Err(StoreError::Unsupported)
}

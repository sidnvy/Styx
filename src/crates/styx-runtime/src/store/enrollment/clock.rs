//! Durable monotonic observation floor under the same exclusive writer. This is
//! not a wall-clock source and never repairs a rolled-back wall clock by itself.
use super::*;
const NAME: &str = "clock.floor";

impl EnrollmentJournal<'_> {
    /// None is allowed only for a provably fresh namespace, never as zero for an
    /// existing journal. The recovery adapter decides that from the full scan.
    pub fn read_time_floor(&self) -> JournalResult<Option<u64>> {
        self.read(NAME)?
            .map(|raw| {
                let bytes: [u8; 8] = raw.try_into().map_err(|_| JournalError::Unknown)?;
                Ok(u64::from_be_bytes(bytes))
            })
            .transpose()
    }
    /// Persist before observing any TTL-bearing operation, including rejected
    /// requests and read-only claims. Failed durability leaves admission closed.
    pub fn record_time_floor(&mut self, now: u64) -> JournalResult<()> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            use nix::{
                errno::Errno,
                fcntl::{OFlag, RenameFlags, openat, renameat2},
                sys::stat::Mode,
            };
            use std::{fs::File, io::Write};
            let before = self.read_time_floor()?;
            if before.is_some_and(|floor| now < floor) {
                return Err(JournalError::Conflict);
            }
            files::with_namespace(self, |dir| {
                if before == Some(now) {
                    files::sync_file(dir, NAME)?;
                    dir.sync_all().map_err(|_| JournalError::Unknown)?;
                    if files::read(dir, NAME, 8)?.as_deref() != Some(now.to_be_bytes().as_slice()) {
                        return Err(JournalError::Unknown);
                    }
                    return Ok(());
                }
                // Replacement needs one bounded temporary entry even though the
                // final floor is fixed-size. Unknown crash remnants are retained.
                let inventory = files::scan(dir, self.budget)?;
                if inventory.files.len() >= self.budget.max_files
                    || inventory
                        .total_bytes
                        .checked_add(8)
                        .is_none_or(|n| n > self.budget.max_bytes)
                    || self.budget.max_file_bytes < 8
                {
                    return Err(JournalError::BudgetExceeded);
                }
                let mut entropy = [0u8; 16];
                getrandom::fill(&mut entropy).map_err(|_| JournalError::Unknown)?;
                let temporary = format!("orphan-{}.temporary", super::super::sha256(&entropy));
                let mut file = File::from(
                    openat(
                        dir,
                        temporary.as_str(),
                        OFlag::O_WRONLY
                            | OFlag::O_CREAT
                            | OFlag::O_EXCL
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC,
                        Mode::S_IRUSR | Mode::S_IWUSR,
                    )
                    .map_err(|_| JournalError::Unknown)?,
                );
                file.write_all(&now.to_be_bytes())
                    .map_err(|_| JournalError::Unknown)?;
                file.sync_all().map_err(|_| JournalError::Unknown)?;
                let current = files::read(dir, NAME, 8)?;
                if current.as_deref() != before.map(u64::to_be_bytes).as_ref().map(|v| v.as_slice())
                {
                    return Err(JournalError::Unknown);
                }
                let flags = if before.is_some() {
                    RenameFlags::empty()
                } else {
                    RenameFlags::RENAME_NOREPLACE
                };
                match renameat2(dir, temporary.as_str(), dir, NAME, flags) {
                    Ok(()) => (),
                    Err(Errno::EEXIST) => return Err(JournalError::Conflict),
                    Err(_) => return Err(JournalError::Unknown),
                }
                dir.sync_all().map_err(|_| JournalError::Unknown)?;
                if files::read(dir, NAME, 8)?.as_deref() != Some(now.to_be_bytes().as_slice()) {
                    return Err(JournalError::Unknown);
                }
                Ok(())
            })
        }
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            let before = self.read_time_floor()?;
            if before.is_some_and(|floor| now < floor) {
                return Err(JournalError::Conflict);
            }
            let expected = before.map(u64::to_be_bytes);
            let bytes = now.to_be_bytes();
            files::with_namespace(self, |dir| {
                // The OS primitive owns native replacement/durability and
                // revalidates the exact expected bytes under this same writer.
                // Equal floors also require real sync/readback, not a cached ACK.
                super::super::secure_journal::files::replace_observed(
                    dir,
                    NAME,
                    expected.as_ref().map(|value| value.as_slice()),
                    &bytes,
                    self.budget,
                    &|_| {},
                )?;
                if files::read(dir, NAME, 8)?.as_deref() != Some(bytes.as_slice()) {
                    return Err(JournalError::Unknown);
                }
                Ok(())
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = now;
            Err(JournalError::Unsupported)
        }
    }
}

#[cfg(test)]
#[path = "clock_tests.rs"]
mod tests;

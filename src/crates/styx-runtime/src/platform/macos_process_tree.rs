//! Bounded Darwin descendant custody, identified by PID, birth time and uid.
use std::{collections::BTreeSet, io};

const MAX_PROCESSES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    pid: libc::pid_t,
    seconds: u64,
    micros: u64,
    uid: libc::uid_t,
}

impl Identity {
    fn from_info(info: &libc::proc_bsdinfo) -> Self {
        Self {
            pid: info.pbi_pid as libc::pid_t,
            seconds: info.pbi_start_tvsec,
            micros: info.pbi_start_tvusec,
            uid: info.pbi_uid,
        }
    }

    fn is_alive(self) -> io::Result<bool> {
        let Some(info) = native::info(self.pid)? else {
            return Ok(false);
        };
        if (info.pbi_start_tvsec, info.pbi_start_tvusec) != (self.seconds, self.micros) {
            return Ok(false);
        }
        if info.pbi_uid != self.uid {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(true)
    }

    /// False means the recorded process is gone; no signal was sent.
    fn kill(self) -> io::Result<bool> {
        // Darwin has no pidfd. Recheck birth and uid immediately before kill;
        // never use a name, process group or a stale PID alone as authority.
        if !self.is_alive()? {
            return Ok(false);
        }
        native::kill(self.pid)
    }
}

pub(crate) struct ProcessTree {
    root: Option<Identity>,
    descendants: BTreeSet<Identity>,
    enumeration_failed: bool,
}

impl ProcessTree {
    pub(crate) fn new(pid: u32) -> Self {
        let root = libc::pid_t::try_from(pid)
            .ok()
            .filter(|pid| *pid > 0)
            .and_then(|pid| native::info(pid).ok().flatten())
            .filter(|info| info.pbi_uid == native::uid())
            .map(|info| Identity::from_info(&info));
        Self {
            root,
            descendants: BTreeSet::new(),
            enumeration_failed: root.is_none(),
        }
    }

    /// Union snapshots into retained custody, including across cleanup retries.
    pub(crate) fn snapshot(&mut self) {
        if self.walk().is_err() {
            // A later empty tree cannot repair a missed enumeration.
            self.enumeration_failed = true;
        }
    }

    fn walk(&mut self) -> io::Result<()> {
        let root = self
            .root
            .ok_or_else(|| io::Error::other("process_tree_root_unknown"))?;
        let mut pending = vec![root];
        let mut visited = BTreeSet::new();
        while let Some(parent) = pending.pop() {
            if !visited.insert(parent) || !parent.is_alive()? {
                continue;
            }
            let children = native::children(parent.pid)?;
            // Do not attach the children of a replacement parent to this tree.
            if !parent.is_alive()? {
                continue;
            }
            for pid in children {
                let Some(info) = native::info(pid)? else {
                    continue;
                };
                if info.pbi_ppid != parent.pid as u32 {
                    continue; // Exited/reparented between list and info.
                }
                if info.pbi_uid != root.uid {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                let identity = Identity::from_info(&info);
                if !self.descendants.contains(&identity) {
                    if self.descendants.len() == MAX_PROCESSES {
                        return Err(io::Error::other("process_tree_limit"));
                    }
                    self.descendants.insert(identity);
                }
                if !visited.contains(&identity) {
                    pending.push(identity);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn confirmed_gone(&self) -> bool {
        !self.enumeration_failed
            && self
                .descendants
                .iter()
                .all(|identity| matches!(identity.is_alive(), Ok(false)))
    }

    pub(crate) fn kill_remaining(&self) {
        for identity in &self.descendants {
            // Signal failure cannot become proof: confirmed_gone re-observes
            // every identity, and errors retain custody.
            let _ = identity.kill();
        }
    }
}

// Only these small OS wrappers need raw pointers. All buffer sizes and PID
// validation are fixed here; callers receive owned Rust values.
#[allow(unsafe_code)]
mod native {
    use super::*;
    use std::mem::{MaybeUninit, size_of, size_of_val};

    pub(super) fn uid() -> libc::uid_t {
        // SAFETY: geteuid has no preconditions or pointer arguments.
        unsafe { libc::geteuid() }
    }

    pub(super) fn info(pid: libc::pid_t) -> io::Result<Option<libc::proc_bsdinfo>> {
        if pid <= 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
        // SAFETY: info points to writable, aligned storage of the exact size
        // requested by PROC_PIDTBSDINFO; it is read only on a full-size result.
        let count = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size_of::<libc::proc_bsdinfo>() as libc::c_int,
            )
        };
        if count == 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if count as usize != size_of::<libc::proc_bsdinfo>() {
            return Err(io::Error::other("process_info_incomplete"));
        }
        // SAFETY: the OS returned the full initialized proc_bsdinfo above.
        let info = unsafe { info.assume_init() };
        if info.pbi_pid != pid as u32 {
            return Err(io::Error::other("process_info_pid_mismatch"));
        }
        Ok(Some(info))
    }

    pub(super) fn children(pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
        // One extra entry detects saturation instead of accepting a truncated
        // snapshot. proc_listchildpids returns a PID count, not a byte count.
        let mut pids = [0 as libc::pid_t; MAX_PROCESSES + 1];
        // SAFETY: __error returns this thread's writable errno. Clearing it
        // distinguishes zero children from libproc's zero-on-error return.
        let count = unsafe {
            *libc::__error() = 0;
            libc::proc_listchildpids(
                pid,
                pids.as_mut_ptr().cast(),
                size_of_val(&pids) as libc::c_int,
            )
        };
        let error = io::Error::last_os_error();
        if count < 0 || (count == 0 && error.raw_os_error() != Some(0)) {
            return Err(error);
        }
        if count as usize >= pids.len() {
            return Err(io::Error::other("process_tree_limit"));
        }
        let pids = &pids[..count as usize];
        if pids.iter().any(|pid| *pid <= 0) {
            return Err(io::Error::other("process_tree_invalid_pid"));
        }
        Ok(pids.to_vec())
    }

    pub(super) fn kill(pid: libc::pid_t) -> io::Result<bool> {
        // SAFETY: callers supply a positive PID, freshly checked against its
        // recorded identity; this never addresses a process group.
        if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
            Ok(true)
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::{Child, Command},
        thread,
        time::{Duration, Instant},
    };

    struct Shell(Child);
    impl Drop for Shell {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn walk_finds_both_sleeps_and_confirms_their_exit() {
        let mut shell = Shell(
            Command::new("/bin/sh")
                .args(["-c", "sleep 30 & sleep 30"])
                .spawn()
                .unwrap(),
        );
        let mut tree = ProcessTree::new(shell.0.id());
        let until = Instant::now() + Duration::from_secs(5);
        while tree.descendants.len() < 2 && Instant::now() < until {
            tree.snapshot();
            thread::sleep(Duration::from_millis(20));
        }
        // Kill the sleeps first so the shell can reap them before it exits.
        tree.kill_remaining();
        assert_eq!(tree.descendants.len(), 2);
        assert!(!tree.enumeration_failed);
        for identity in &tree.descendants {
            assert!(identity.seconds > 0);
            assert!(identity.micros < 1_000_000);
            assert_eq!(identity.uid, native::uid());
        }
        shell.0.wait().unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while !tree.confirmed_gone() && Instant::now() < until {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(tree.confirmed_gone());
    }

    #[test]
    fn wrong_birth_is_gone_and_never_signalled() {
        let mut child = Shell(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        let info = native::info(child.0.id() as libc::pid_t).unwrap().unwrap();
        let actual = Identity::from_info(&info);
        let wrong = Identity {
            seconds: actual.seconds + 1,
            ..actual
        };
        assert!(!wrong.is_alive().unwrap());
        assert!(!wrong.kill().unwrap());
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(actual.is_alive().unwrap());
    }
}

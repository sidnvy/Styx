//! Signed App publication: source identity is distinct from current desktop availability.
use serde::Deserialize;

#[derive(Deserialize, Eq, PartialEq)]
pub(super) struct Hint {
    pub(super) schema: u32,
    pub(super) generation: String,
    pub(super) owner_pid: u32,
    pub(super) daemon_pid: u32,
    pub(super) bundle_id: String,
    // Console availability is published by this same signed App owner. TCC
    // still comes from the original daemon's standard check_permissions.
    pub(super) host_on_console: bool,
    pub(super) host_session_locked: bool,
}
impl Hint {
    pub(super) fn same_source(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.generation == other.generation
            && self.owner_pid == other.owner_pid
            && self.daemon_pid == other.daemon_pid
            && self.bundle_id == other.bundle_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication() -> Hint {
        Hint {
            schema: 1,
            generation: "same-app-generation".into(),
            owner_pid: 100,
            daemon_pid: 101,
            bundle_id: "app.styx.host".into(),
            host_on_console: true,
            host_session_locked: false,
        }
    }

    #[test]
    fn lock_and_console_changes_do_not_replace_the_running_source() {
        let original = publication();
        let mut current = publication();
        current.host_session_locked = true;
        assert!(
            original.same_source(&current),
            "locking is availability, not source replacement"
        );
        current.host_session_locked = false;
        current.host_on_console = false;
        assert!(
            original.same_source(&current),
            "leaving console is availability, not source replacement"
        );
        current.host_on_console = true;
        assert!(original.same_source(&current));
    }

    #[test]
    fn actual_source_replacements_remain_fenced() {
        let original = publication();
        let mut other = publication();
        other.owner_pid += 1;
        assert!(!original.same_source(&other));
        let mut other = publication();
        other.daemon_pid += 1;
        assert!(!original.same_source(&other));
        let mut other = publication();
        other.generation = "replacement".into();
        assert!(!original.same_source(&other));
        let mut other = publication();
        other.bundle_id = "another.app".into();
        assert!(!original.same_source(&other));
        let mut other = publication();
        other.schema += 1;
        assert!(!original.same_source(&other));
    }
}

//! Private read-only facts over the exact FD retained by BoundMacSource.
//! Runs on the existing blocking boundary. The owner must retain/join its work
//! handle if the outer waiter is cancelled; dropping a waiter is not cleanup.

use super::*;
use std::{
    io::{Read, Write},
    time::Instant,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    result: Option<NativeObservation>,
    error: Option<String>,
    exit_code: Option<i32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeObservation {
    schema: u32,
    platform: String,
    daemon_instance: String,
    uid: u32,
    daemon: ProcessBirth,
    parent: ProcessBirth,
    pub(crate) session: SessionObservation,
    pub(crate) permissions: Permissions,
    pub(crate) registry_before: RegistryObservation,
    pub(crate) registry_after: RegistryObservation,
    lifetime: Lifetime,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessBirth {
    pid: u32,
    start_seconds: u64,
    start_microseconds: u64,
}
impl ProcessBirth {
    fn matches(&self, original: &ProcessIdentity, uid: u32) -> bool {
        matches!(original, ProcessIdentity::Macos {
            pid, start_seconds, start_microseconds, uid: actual, ..
        } if *pid == self.pid && *start_seconds == self.start_seconds
            && *start_microseconds == self.start_microseconds && *actual == uid
            && self.start_seconds > 0 && self.start_microseconds < 1_000_000)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
pub(crate) enum SessionStatus {
    #[serde(rename = "unlocked")]
    Unlocked,
    #[serde(rename = "desktop_session_unknown")]
    Unknown,
    #[serde(rename = "desktop_session_locked")]
    Locked,
    #[serde(rename = "no_graphical_session")]
    NoGraphicalSession,
    #[serde(rename = "desktop_session_disconnected")]
    Disconnected,
    #[serde(rename = "desktop_session_ambiguous")]
    Ambiguous,
    #[serde(rename = "desktop_session_changed")]
    Changed,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionObservation {
    pub(crate) uid: Option<u32>,
    pub(crate) audit_id: Option<u32>,
    pub(crate) status: SessionStatus,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Permissions {
    pub(crate) accessibility: bool,
    pub(crate) screen_recording: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lifetime {
    embedded_configured: bool,
    stdin_monitor_enabled: bool,
    stdin_monitor_started: bool,
    original_stdin_pipe: bool,
    ended: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum BoolObservation {
    Known(bool),
    Missing,
    Invalid,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum ConsoleUuidObservation {
    Known(String),
    Missing,
    Invalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum LockTimeObservation {
    Known(u32),
    Missing,
    Invalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsoleLockEvidence {
    PerRowUnlocked,
    KernelConsoleSecurityOpen,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectedRow {
    pub(crate) uid: u32,
    pub(crate) audit_id: u32,
    pub(crate) console_uuid: ConsoleUuidObservation,
    pub(crate) session_id: Option<u32>,
    pub(crate) on_console: BoolObservation,
    pub(crate) login_done: BoolObservation,
    pub(crate) screen_locked: BoolObservation,
    pub(crate) screen_locked_time: LockTimeObservation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsoleEpoch {
    root_entry_id: u64,
    resources_entry_id: u64,
    seed: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ConsoleEpochObservation {
    Cfdata4NativeEndian {
        root_before: u64,
        root_after: u64,
        resources_before: u64,
        resources_after: u64,
        before: u32,
        after: u32,
    },
    Unavailable,
}
impl ConsoleEpochObservation {
    fn stable_stamp(&self) -> Option<ConsoleEpoch> {
        match *self {
            Self::Cfdata4NativeEndian {
                root_before,
                root_after,
                resources_before,
                resources_after,
                before,
                after,
            } if root_before != 0
                && resources_before != 0
                && root_before == root_after
                && resources_before == resources_after
                && before == after =>
            {
                Some(ConsoleEpoch {
                    root_entry_id: root_before,
                    resources_entry_id: resources_before,
                    seed: before,
                })
            }
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryObservation {
    read_status: String,
    pub(crate) global_io_console_locked: BoolObservation,
    pub(crate) selected_unique_row: Option<SelectedRow>,
    selection_status: String,
    user_count: Option<u32>,
    lock_evidence: Option<ConsoleLockEvidence>,
    epoch: ConsoleEpochObservation,
}

impl RegistryObservation {
    fn validated_lock_evidence(&self) -> Option<ConsoleLockEvidence> {
        self.epoch.stable_stamp()?;
        if self.read_status != "copied"
            || self.selection_status != "unique"
            || self.global_io_console_locked != BoolObservation::Known(false)
        {
            return None;
        }
        let row = self.selected_unique_row.as_ref()?;
        if row.on_console != BoolObservation::Known(true)
            || row.login_done != BoolObservation::Known(true)
            || !matches!(
                row.screen_locked_time,
                LockTimeObservation::Missing | LockTimeObservation::Known(0)
            )
        {
            return None;
        }
        let ConsoleUuidObservation::Known(uuid) = &row.console_uuid else {
            return None;
        };
        if Uuid::parse_str(uuid)
            .ok()
            .is_none_or(|value| value.is_nil() || value.to_string() != *uuid)
        {
            return None;
        }
        let expected = match row.screen_locked {
            BoolObservation::Known(false) => ConsoleLockEvidence::PerRowUnlocked,
            BoolObservation::Missing if self.user_count == Some(1) => {
                ConsoleLockEvidence::KernelConsoleSecurityOpen
            }
            _ => return None,
        };
        (self.lock_evidence == Some(expected)).then_some(expected)
    }
}

/// An authenticated native identity candidate, not a Core registration/grant.
/// The console instance comes ONLY from the matching IOConsoleUsers row UUID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedConsoleIdentity {
    pub(crate) uid: u32,
    pub(crate) audit_id: u32,
    pub(crate) console_uuid: String,
    pub(crate) epoch: ConsoleEpoch,
}
impl NativeObservation {
    pub(crate) fn console_identity(&self) -> Option<ObservedConsoleIdentity> {
        let before = self.registry_before.selected_unique_row.as_ref()?;
        let after = self.registry_after.selected_unique_row.as_ref()?;
        if self.registry_before.read_status != "copied"
            || self.registry_after.read_status != "copied"
            || self.registry_before.selection_status != "unique"
            || self.registry_after.selection_status != "unique"
            || before != after
            || Some(before.uid) != self.session.uid
            || Some(before.audit_id) != self.session.audit_id
            || before.uid != self.uid
            || matches!(before.audit_id, 0 | u32::MAX)
            || before.audit_id == u32::MAX - 1
            || before.on_console != BoolObservation::Known(true)
            || before.login_done != BoolObservation::Known(true)
        {
            return None;
        }
        let ConsoleUuidObservation::Known(value) = &before.console_uuid else {
            return None;
        };
        let uuid = Uuid::parse_str(value).ok()?;
        if uuid.is_nil() || value.len() != 36 || uuid.to_string() != *value {
            return None;
        }
        Some(ObservedConsoleIdentity {
            uid: before.uid,
            audit_id: before.audit_id,
            console_uuid: value.clone(),
            epoch: self
                .registry_before
                .epoch
                .stable_stamp()
                .filter(|value| Some(*value) == self.registry_after.epoch.stable_stamp())?,
        })
    }
    /// Separate labelled kernel-console-security evidence is not a fabricated
    /// row lock bit, TCC grant, or atomic native input fence.
    pub(crate) fn observed_unlocked(&self) -> bool {
        self.schema == 2
            && self.session.status == SessionStatus::Unlocked
            && self.console_identity().is_some()
            && self.registry_before == self.registry_after
            && self.registry_before.validated_lock_evidence().is_some()
    }
}

impl BoundMacSource {
    /// Entire exchange stays serialized by &mut self on the original FD. No
    /// reconnect, side channel, action, hidden retry, or descriptor boolean.
    pub(crate) fn observe_native(&mut self, deadline: Instant) -> Result<NativeObservation> {
        self.fresh_binding()?;
        // Any partial protocol exchange or panic permanently fences this source.
        // A later waiter cannot consume a delayed reply as a different request.
        self.fenced = true;
        let value = self.exchange_native_observation(deadline)?;
        self.check_binding()?;
        if Instant::now() >= deadline {
            return Err(BindingError::NativeProtocol);
        }
        if value.schema != 2
            || value.platform != "macos"
            || value.uid != self.candidate.uid
            || !value
                .daemon
                .matches(&self.candidate.daemon, self.candidate.uid)
            || !value
                .parent
                .matches(&self.candidate.owner, self.candidate.uid)
            || value
                .session
                .uid
                .is_some_and(|uid| uid != self.candidate.uid)
            || !value.lifetime.embedded_configured
            || !value.lifetime.stdin_monitor_enabled
            || !value.lifetime.stdin_monitor_started
            || !value.lifetime.original_stdin_pipe
            || value.lifetime.ended
        {
            return Err(BindingError::NativeProtocol);
        }
        let instance =
            Uuid::parse_str(&value.daemon_instance).map_err(|_| BindingError::NativeProtocol)?;
        if instance.is_nil()
            || value.daemon_instance.len() != 36
            || instance.to_string() != value.daemon_instance
            || self
                .native_instance
                .as_ref()
                .is_some_and(|original| original != &value.daemon_instance)
        {
            return Err(BindingError::NativeProtocol);
        }
        let identity = value.console_identity();
        if self
            .native_console
            .as_ref()
            .is_some_and(|original| identity.as_ref() != Some(original))
        {
            return Err(BindingError::Fenced);
        }
        if value.session.status == SessionStatus::Unlocked && !value.observed_unlocked() {
            return Err(BindingError::NativeProtocol);
        }
        self.native_instance = Some(value.daemon_instance.clone());
        self.native_console = identity;
        self.fenced = false;
        // Locked/Unknown are actual typed results, never Ready. Core owns grant,
        // generation and operation admission separately from these observations.
        Ok(value)
    }
    fn exchange_native_observation(&mut self, deadline: Instant) -> Result<NativeObservation> {
        self.protocol_clean = false;
        let bytes = self.exchange_frame(
            b"{\"method\":\"styx_private_desktop_observation_v1\"}\n",
            deadline,
            16 * 1024,
        )?;
        self.protocol_clean = true;
        let reply: Response =
            serde_json::from_slice(&bytes).map_err(|_| BindingError::NativeProtocol)?;
        if !reply.ok || reply.error.is_some() || reply.exit_code.is_some() {
            return Err(BindingError::NativeProtocol);
        }
        reply.result.ok_or(BindingError::NativeProtocol)
    }
    fn exchange_frame(&self, request: &[u8], deadline: Instant, maximum: usize) -> Result<Vec<u8>> {
        let mut probe = [0u8; 1];
        match recv(
            self.stream.as_raw_fd(),
            &mut probe,
            MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
        ) {
            Err(nix::errno::Errno::EAGAIN) => {}
            _ => return Err(BindingError::NativeProtocol),
        }
        let mut stream = &self.stream;
        let mut sent = 0;
        while sent < request.len() {
            wait_fd(&self.stream, libc::POLLOUT, deadline)?;
            match stream.write(&request[sent..]) {
                Ok(0) => return Err(BindingError::NativeProtocol),
                Ok(count) => sent += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => return Err(BindingError::NativeProtocol),
            }
        }
        let mut received = Vec::new();
        loop {
            wait_fd(&self.stream, libc::POLLIN, deadline)?;
            let mut buffer = [0u8; 4096];
            let count = match stream.read(&mut buffer) {
                Ok(0) => return Err(BindingError::NativeProtocol),
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(_) => return Err(BindingError::NativeProtocol),
            };
            if received.len() + count > maximum {
                return Err(BindingError::NativeProtocol);
            }
            received.extend_from_slice(&buffer[..count]);
            if let Some(index) = received.iter().position(|byte| *byte == b'\n') {
                if index + 1 != received.len() {
                    return Err(BindingError::NativeProtocol);
                }
                return Ok(received[..index].to_vec());
            }
        }
    }
}

fn wait_fd(stream: &UnixStream, events: libc::c_short, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(BindingError::NativeProtocol)?;
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::AsFd;
        let flags = PollFlags::from_bits(events).ok_or(BindingError::NativeProtocol)?;
        let mut descriptors = [PollFd::new(stream.as_fd(), flags)];
        let timeout = PollTimeout::try_from(millis).map_err(|_| BindingError::NativeProtocol)?;
        let result = match poll(&mut descriptors, timeout) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return Err(BindingError::NativeProtocol),
            Ok(value) => value,
        };
        let revents = descriptors[0]
            .revents()
            .ok_or(BindingError::NativeProtocol)?;
        if result <= 0
            || revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
            || !revents.intersects(flags)
            || Instant::now() >= deadline
        {
            return Err(BindingError::NativeProtocol);
        }
        return Ok(());
    }
}

#[derive(Clone)]
pub(crate) struct WindowReadEvidence {
    pub(crate) count: usize,
    pub(crate) digest: styx_contracts::identity::Sha256Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponse {
    ok: bool,
    result: Option<serde_json::Value>,
    error: Option<String>,
    exit_code: Option<i32>,
}
impl BoundMacSource {
    fn exchange_value(&mut self, request: &[u8], deadline: Instant) -> Result<serde_json::Value> {
        self.protocol_clean = false;
        let bytes = self.exchange_frame(request, deadline, 64 * 1024)?;
        self.protocol_clean = true;
        let reply: RawResponse =
            serde_json::from_slice(&bytes).map_err(|_| BindingError::NativeProtocol)?;
        if !reply.ok || reply.error.is_some() || reply.exit_code.is_some() {
            return Err(BindingError::NativeProtocol);
        }
        reply.result.ok_or(BindingError::NativeProtocol)
    }
    /// Fixed no-user-arguments acquisition on the SAME authenticated facts FD.
    /// This creates one private native read transport, retained until source stop.
    pub(crate) fn probe_windows(&mut self, deadline: Instant) -> Result<WindowReadEvidence> {
        self.fresh_binding()?;
        if self.probe_drained {
            return Err(BindingError::Fenced);
        }
        self.fenced = true;
        if self.probe_session.is_none() {
            let sid = format!("styx-source-{}", Uuid::new_v4().simple());
            let mut request =
                serde_json::to_vec(&serde_json::json!({"method":"session_begin","session_id":sid}))
                    .map_err(|_| BindingError::NativeProtocol)?;
            request.push(b'\n');
            // Store original identity BEFORE sending: lost ACK is never a new begin.
            self.probe_session = Some(sid);
            let reply = self.exchange_value(&request, deadline)?;
            if reply != serde_json::json!({"session_begin":true}) {
                return Err(BindingError::NativeProtocol);
            }
        }
        let mut request=serde_json::to_vec(&serde_json::json!({"method":"call","name":"list_windows","args":{},"session_id":self.probe_session})).map_err(|_|BindingError::NativeProtocol)?;
        request.push(b'\n');
        let value = self.exchange_value(&request, deadline)?;
        if value
            .get("isError")
            .is_some_and(|v| v != &serde_json::Value::Bool(false))
        {
            return Err(BindingError::NativeProtocol);
        }
        let windows = value
            .get("structuredContent")
            .and_then(|v| v.get("windows"))
            .and_then(serde_json::Value::as_array)
            .ok_or(BindingError::NativeProtocol)?;
        if windows.len() > 512 {
            return Err(BindingError::NativeProtocol);
        }
        for row in windows {
            if row
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .is_none_or(|v| v == 0 || v > u32::MAX as u64)
                || row
                    .get("window_id")
                    .and_then(serde_json::Value::as_u64)
                    .is_none_or(|v| v == 0)
            {
                return Err(BindingError::NativeProtocol);
            }
        }
        let raw = serde_json::to_vec(&value).map_err(|_| BindingError::NativeProtocol)?;
        let evidence = WindowReadEvidence {
            count: windows.len(),
            digest: styx_contracts::identity::Sha256Digest::of_bytes(&raw),
        };
        self.check_binding()?;
        if Instant::now() >= deadline {
            return Err(BindingError::NativeProtocol);
        }
        self.fenced = false;
        Ok(evidence)
    }
    pub(crate) fn drain_probe(&mut self, deadline: Instant) -> Result<bool> {
        if self.probe_drained {
            return Ok(true);
        }
        if self.probe_session.is_none() {
            return Ok(true);
        }
        // Authorization can be fenced while the original transport remains
        // frame-aligned. Only cleanup may use that FD; never revive admission.
        // An interrupted frame cannot consume a delayed reply as a drain ACK.
        if !self.protocol_clean {
            return Err(BindingError::NativeProtocol);
        }
        self.check_binding()?;
        self.fenced = true;
        let value = self.exchange_value(
            b"{\"method\":\"styx_private_transport_drain_v1\"}\n",
            deadline,
        )?;
        if value != serde_json::json!({"schema":1,"drained":true}) {
            return Err(BindingError::NativeProtocol);
        }
        self.check_binding()?;
        self.probe_drained = true;
        Ok(true)
    }
}

#[cfg(test)]
mod console_contract_tests {
    use super::*;
    fn candidate() -> RegistryObservation {
        RegistryObservation {
            epoch: ConsoleEpochObservation::Cfdata4NativeEndian {
                root_before: 1,
                root_after: 1,
                resources_before: 2,
                resources_after: 2,
                before: 3,
                after: 3,
            },
            read_status: "copied".into(),
            selection_status: "unique".into(),
            user_count: Some(1),
            global_io_console_locked: BoolObservation::Known(false),
            lock_evidence: Some(ConsoleLockEvidence::KernelConsoleSecurityOpen),
            selected_unique_row: Some(SelectedRow {
                uid: 501,
                audit_id: 1001,
                console_uuid: ConsoleUuidObservation::Known(
                    "7463ea88-7056-4b41-94d4-9b4311d2a970".into(),
                ),
                session_id: Some(100),
                on_console: BoolObservation::Known(true),
                login_done: BoolObservation::Known(true),
                screen_locked: BoolObservation::Missing,
                screen_locked_time: LockTimeObservation::Missing,
            }),
        }
    }
    #[test]
    fn original_unconsumed_epoch_is_not_reused_after_lock_unlock_or_source_change() {
        let original = candidate();
        let unconsumed = original.epoch.stable_stamp().unwrap();
        let mut after_unlock = candidate();
        after_unlock.epoch = ConsoleEpochObservation::Cfdata4NativeEndian {
            root_before: 1,
            root_after: 1,
            resources_before: 2,
            resources_after: 2,
            before: 5,
            after: 5,
        };
        assert!(after_unlock.validated_lock_evidence().is_some());
        assert_ne!(after_unlock.epoch.stable_stamp(), Some(unconsumed));
        let mut replaced = candidate();
        replaced.epoch = ConsoleEpochObservation::Cfdata4NativeEndian {
            root_before: 1,
            root_after: 1,
            resources_before: 7,
            resources_after: 7,
            before: 3,
            after: 3,
        };
        assert_ne!(replaced.epoch.stable_stamp(), Some(unconsumed));
        let mut transitioning = candidate();
        transitioning.epoch = ConsoleEpochObservation::Cfdata4NativeEndian {
            root_before: 1,
            root_after: 1,
            resources_before: 2,
            resources_after: 2,
            before: 3,
            after: 4,
        };
        assert!(transitioning.validated_lock_evidence().is_none());
        transitioning.epoch = ConsoleEpochObservation::Unavailable;
        assert!(transitioning.validated_lock_evidence().is_none());
        assert!(
            serde_json::from_str::<ConsoleEpochObservation>(
                r#"{"source":"unconditional","before":3,"after":3}"#
            )
            .is_err()
        );
    }
    #[test]
    fn labelled_kernel_evidence_never_turns_missing_or_transition_into_row_false() {
        let candidate = candidate();
        assert_eq!(
            candidate.validated_lock_evidence(),
            Some(ConsoleLockEvidence::KernelConsoleSecurityOpen)
        );
        assert_eq!(
            candidate
                .selected_unique_row
                .as_ref()
                .unwrap()
                .screen_locked,
            BoolObservation::Missing
        );
        for change in 0..10 {
            let mut bad = candidate.clone();
            let row = bad.selected_unique_row.as_mut().unwrap();
            match change {
                0 => bad.global_io_console_locked = BoolObservation::Known(true),
                1 => row.screen_locked = BoolObservation::Known(true),
                2 => row.screen_locked_time = LockTimeObservation::Known(u32::MAX),
                3 => row.screen_locked_time = LockTimeObservation::Known(1),
                4 => row.screen_locked_time = LockTimeObservation::Invalid,
                5 => bad.user_count = Some(2),
                6 => row.on_console = BoolObservation::Known(false),
                7 => row.console_uuid = ConsoleUuidObservation::Missing,
                8 => bad.lock_evidence = Some(ConsoleLockEvidence::PerRowUnlocked),
                _ => bad.global_io_console_locked = BoolObservation::Invalid,
            }
            assert_eq!(bad.validated_lock_evidence(), None, "case {change}");
            assert_ne!(bad, candidate); // before/after transition cannot be stable
        }
        let mut explicit = candidate;
        explicit.selected_unique_row.as_mut().unwrap().screen_locked =
            BoolObservation::Known(false);
        explicit.lock_evidence = Some(ConsoleLockEvidence::PerRowUnlocked);
        explicit.user_count = Some(2); // exact matching row remains strict per-row evidence
        assert_eq!(
            explicit.validated_lock_evidence(),
            Some(ConsoleLockEvidence::PerRowUnlocked)
        );
        let unknown_source =
            serde_json::from_str::<ConsoleLockEvidence>("\"unconditional_unlocked\"");
        assert!(unknown_source.is_err());
    }
}

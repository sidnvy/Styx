//! Standard Cua service observations on the authenticated App-owned socket.
//! The App's existing native bridge owns console availability; Cua's native
//! check_permissions owns live TCC facts. No private daemon method or IOKit seed.
use super::*;
use std::{
    io::{Read, Write},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionStatus {
    Unlocked,
    Locked,
}
pub(crate) struct SessionObservation {
    pub(crate) uid: Option<u32>,
    pub(crate) audit_id: Option<u32>,
    pub(crate) status: SessionStatus,
}
pub(crate) struct Permissions {
    pub(crate) accessibility: bool,
    pub(crate) screen_recording: bool,
}
pub(crate) struct NativeObservation {
    pub(crate) session: SessionObservation,
    pub(crate) permissions: Permissions,
    console_uuid: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedConsoleIdentity {
    pub(crate) uid: u32,
    pub(crate) audit_id: u32,
    pub(crate) console_uuid: String,
}
impl NativeObservation {
    pub(crate) fn console_identity(&self) -> Option<ObservedConsoleIdentity> {
        Some(ObservedConsoleIdentity {
            uid: self.session.uid?,
            audit_id: self.session.audit_id?,
            console_uuid: self.console_uuid.clone(),
        })
    }
    pub(crate) fn observed_unlocked(&self) -> bool {
        self.session.status == SessionStatus::Unlocked && self.console_identity().is_some()
    }
}
fn tool_result(value: &serde_json::Value) -> Result<&serde_json::Value> {
    if value
        .get("isError")
        .is_some_and(|v| v != &serde_json::Value::Bool(false))
    {
        return Err(BindingError::NativeProtocol);
    }
    value
        .get("structuredContent")
        .ok_or(BindingError::NativeProtocol)
}
fn permissions_from_result(value: &serde_json::Value) -> Result<Permissions> {
    let value = tool_result(value)?;
    Ok(Permissions {
        accessibility: value
            .get("accessibility")
            .and_then(serde_json::Value::as_bool)
            .ok_or(BindingError::NativeProtocol)?,
        screen_recording: value
            .get("screen_recording")
            .and_then(serde_json::Value::as_bool)
            .ok_or(BindingError::NativeProtocol)?,
    })
}
impl BoundMacSource {
    fn service_tool(
        &mut self,
        name: &str,
        mut args: serde_json::Value,
        until: Instant,
    ) -> Result<serde_json::Value> {
        if let Some(session) = &self.probe_session {
            args["session"] = serde_json::json!(session);
        }
        let mut request = serde_json::to_vec(&serde_json::json!({
            "method":"call", "name":name, "args":args, "session_id":self.probe_session,
        }))
        .map_err(|_| BindingError::NativeProtocol)?;
        request.push(b'\n');
        self.exchange_value(&request, until)
    }
    fn ensure_probe_session(&mut self, until: Instant) -> Result<()> {
        if self.probe_drained {
            return Err(BindingError::Fenced);
        }
        if self.probe_session.is_some() {
            return Ok(());
        }
        let session = format!("styx-source-{}", Uuid::new_v4().simple());
        // Retain the identity before dispatch; a lost acknowledgement is not a
        // license to mint a different session or replay an action.
        self.probe_session = Some(session.clone());
        let mut request =
            serde_json::to_vec(&serde_json::json!({"method":"session_begin","session_id":session}))
                .map_err(|_| BindingError::NativeProtocol)?;
        request.push(b'\n');
        if self.exchange_value(&request, until)? != serde_json::json!({"session_begin":true}) {
            return Err(BindingError::NativeProtocol);
        }
        let begun = self.service_tool("start_session", serde_json::json!({}), until)?;
        if tool_result(&begun)?.get("active") != Some(&serde_json::Value::Bool(true)) {
            return Err(BindingError::NativeProtocol);
        }
        Ok(())
    }
    pub(crate) fn observe_native(&mut self, until: Instant) -> Result<NativeObservation> {
        self.observe_native_mode(until)
    }
    pub(in crate::providers::cua) fn observe_initial_native(
        &mut self,
        until: Instant,
    ) -> Result<NativeObservation> {
        self.observe_native_mode(until)
    }
    fn observe_native_mode(&mut self, until: Instant) -> Result<NativeObservation> {
        self.fresh_binding()?;
        self.fenced = true;
        self.ensure_probe_session(until)?;
        let response = self.service_tool(
            "check_permissions",
            serde_json::json!({"prompt":false}),
            until,
        )?;
        let permissions = permissions_from_result(&response)?;
        self.check_binding()?;
        if Instant::now() >= until {
            return Err(BindingError::NativeProtocol);
        }
        // Current hint bytes come from the same signed App generation checked
        // by check_binding; the daemon's kernel audit token supplies its ASID.
        let value = NativeObservation {
            session: SessionObservation {
                uid: Some(self.candidate.uid),
                audit_id: Some(self.peer_token.val[6]),
                status: if self.candidate.hint.host_on_console
                    && !self.candidate.hint.host_session_locked
                {
                    SessionStatus::Unlocked
                } else {
                    SessionStatus::Locked
                },
            },
            permissions,
            console_uuid: self.candidate.hint.generation.clone(),
        };
        let identity = value.console_identity();
        if self
            .native_console
            .as_ref()
            .is_some_and(|old| Some(old) != identity.as_ref())
        {
            return Err(BindingError::Fenced);
        }
        self.native_console = identity;
        self.initial_provisional = true;
        self.fenced = false;
        Ok(value)
    }
    pub(in crate::providers::cua) fn commit_initial_native_pair(
        &mut self,
        control: &mut Self,
        before: &NativeObservation,
        after: &NativeObservation,
        control_after: &NativeObservation,
        until: Instant,
    ) -> Result<bool> {
        if Instant::now() >= until
            || !before.observed_unlocked()
            || !after.observed_unlocked()
            || !control_after.observed_unlocked()
            || before.console_identity() != after.console_identity()
            || after.console_identity() != control_after.console_identity()
        {
            return Err(BindingError::Fenced);
        }
        self.check_binding()?;
        control.check_binding()?;
        self.initial_provisional = false;
        control.initial_provisional = false;
        Ok(false) // No independent IOKit epoch/seed qualification remains.
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
        self.exchange_value_diagnostic(request, deadline, None)
    }
    fn probe_protocol_failure(
        &mut self,
        probe: Option<(ProbeStage, Instant)>,
        cause: ProbeCause,
        deadline: Instant,
    ) -> BindingError {
        if let Some((stage, started)) = probe {
            self.remember_probe_failure(ProbeDiagnostic::observed(stage, cause, started, deadline));
        }
        BindingError::NativeProtocol
    }
    fn exchange_value_diagnostic(
        &mut self,
        request: &[u8],
        deadline: Instant,
        probe: Option<(ProbeStage, Instant)>,
    ) -> Result<serde_json::Value> {
        self.protocol_clean = false;
        let bytes = self.exchange_frame(request, deadline, 64 * 1024)?;
        self.protocol_clean = true;
        let reply: RawResponse = serde_json::from_slice(&bytes)
            .map_err(|_| self.probe_protocol_failure(probe, ProbeCause::ReplyJson, deadline))?;
        if !reply.ok || reply.error.is_some() {
            return Err(self.probe_protocol_failure(probe, ProbeCause::ReplyRefused, deadline));
        }
        if reply.exit_code.is_some() {
            return Err(self.probe_protocol_failure(probe, ProbeCause::ReplyExitCode, deadline));
        }
        reply.result.ok_or_else(|| {
            self.probe_protocol_failure(probe, ProbeCause::ReplyMissingResult, deadline)
        })
    }
    /// Fixed no-user-arguments acquisition on the SAME authenticated facts FD.
    /// This creates one private native read transport, retained until source stop.
    pub(crate) fn probe_windows(&mut self, deadline: Instant) -> Result<WindowReadEvidence> {
        let started = Instant::now();
        let mut stage = ProbeStage::SessionBinding;
        let result: Result<WindowReadEvidence> = (|| {
            self.fresh_binding()?;
            if self.probe_drained {
                return Err(BindingError::Fenced);
            }
            self.fenced = true;
            self.ensure_probe_session(deadline)?;
            stage = ProbeStage::ListWindowsExchange;
            let mut request=serde_json::to_vec(&serde_json::json!({"method":"call","name":"list_windows","args":{"session":self.probe_session},"session_id":self.probe_session})).map_err(|_|BindingError::NativeProtocol)?;
            request.push(b'\n');
            let value =
                self.exchange_value_diagnostic(&request, deadline, Some((stage, started)))?;
            stage = ProbeStage::ListWindowsResult;
            if value
                .get("isError")
                .is_some_and(|v| v != &serde_json::Value::Bool(false))
            {
                return Err(self.probe_protocol_failure(
                    Some((stage, started)),
                    ProbeCause::WindowsReplyIsError,
                    deadline,
                ));
            }
            let windows = value
                .get("structuredContent")
                .and_then(|v| v.get("windows"))
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    self.probe_protocol_failure(
                        Some((stage, started)),
                        ProbeCause::WindowsArrayMissing,
                        deadline,
                    )
                })?;
            stage = ProbeStage::ListWindowsRows;
            if windows.len() > 512 {
                return Err(self.probe_protocol_failure(
                    Some((stage, started)),
                    ProbeCause::WindowsLimit,
                    deadline,
                ));
            }
            for row in windows {
                if row
                    .get("pid")
                    .and_then(serde_json::Value::as_u64)
                    .is_none_or(|v| v == 0 || v > u32::MAX as u64)
                {
                    return Err(self.probe_protocol_failure(
                        Some((stage, started)),
                        ProbeCause::WindowPidInvalid,
                        deadline,
                    ));
                }
                if row
                    .get("window_id")
                    .and_then(serde_json::Value::as_u64)
                    .is_none_or(|v| v == 0)
                {
                    return Err(self.probe_protocol_failure(
                        Some((stage, started)),
                        ProbeCause::WindowIdInvalid,
                        deadline,
                    ));
                }
            }
            let raw = serde_json::to_vec(&value).map_err(|_| BindingError::NativeProtocol)?;
            let evidence = WindowReadEvidence {
                count: windows.len(),
                digest: styx_contracts::identity::Sha256Digest::of_bytes(&raw),
            };
            stage = ProbeStage::ReadBindingAfter;
            self.check_binding()?;
            stage = ProbeStage::ReadDeadline;
            if Instant::now() >= deadline {
                return Err(BindingError::NativeProtocol);
            }
            self.fenced = false;
            Ok(evidence)
        })();
        if let Err(error) = result {
            let cause = if stage == ProbeStage::ReadDeadline {
                ProbeCause::Deadline
            } else {
                error.probe_cause()
            };
            self.remember_probe_failure(ProbeDiagnostic::observed(stage, cause, started, deadline));
        }
        result
    }
    pub(crate) fn drain_probe(&mut self, deadline: Instant) -> Result<bool> {
        if self.probe_drained || self.probe_daemon_exited {
            return Ok(true);
        }
        if self.probe_session.is_none() {
            self.probe_drained = true;
            self.fence_initial_native();
            return Ok(true);
        }
        if self.original_daemon_ended()? {
            // The original observation task is joined by DesktopSource::stop.
            // A departed daemon cannot run its session, but did not ACK its end.
            self.probe_daemon_exited = true;
            self.fence_initial_native();
            return Ok(true);
        }
        if !self.protocol_clean {
            return Err(BindingError::NativeProtocol);
        }
        self.check_cleanup_binding()?;
        self.fenced = true;
        // Standard end_session is an actual tool result. The legacy service
        // method session_end always ACKs and cannot prove successful cleanup.
        let ended = self.service_tool("end_session", serde_json::json!({}), deadline)?;
        if tool_result(&ended)?.get("active") != Some(&serde_json::Value::Bool(false)) {
            return Err(BindingError::NativeProtocol);
        }
        self.check_cleanup_binding()?;
        self.probe_drained = true;
        Ok(true)
    }
}
#[cfg(test)]
mod standard_observation_tests {
    use super::*;
    #[test]
    fn tcc_facts_require_native_booleans_and_successful_tool_result() {
        let good = serde_json::json!({"isError":false,"structuredContent":{"accessibility":true,"screen_recording":false}});
        let result = permissions_from_result(&good).unwrap();
        assert!(result.accessibility && !result.screen_recording);
        for bad in [
            serde_json::json!({"isError":true,"structuredContent":{"accessibility":true,"screen_recording":true}}),
            serde_json::json!({"structuredContent":{"accessibility":"true","screen_recording":true}}),
            serde_json::json!({"structuredContent":{"accessibility":true}}),
        ] {
            assert!(permissions_from_result(&bad).is_err());
        }
    }
}

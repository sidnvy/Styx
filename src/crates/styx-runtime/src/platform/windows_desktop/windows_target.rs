//! Read-target custody only. Does not mint UIA object or input authorization.
#![allow(unsafe_code)]
use super::windows_native_observation::{NativeSession, ObservationError, Result};
use crate::store::ProcessIdentity;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use styx_contracts::session::SessionIdentity;
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::{
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

pub(crate) struct Target {
    identity: ProcessIdentity,
    process: OwnedHandle,
    session: NativeSession,
    pid: u32,
    window: u64,
}
impl Target {
    pub(crate) fn acquire(pid: u32, window: u64) -> Result<Self> {
        if pid == 0 || window == 0 || usize::try_from(window).is_err() {
            return Err(ObservationError::Malformed);
        }
        let identity = ProcessIdentity::observe(pid).map_err(|_| ObservationError::Changed)?;
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return Err(ObservationError::PermissionDenied);
        }
        let value = Self {
            identity,
            process: unsafe { OwnedHandle::from_raw_handle(raw) },
            session: NativeSession::acquire_current()?,
            pid,
            window,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let observed = self.session.observe()?;
        let SessionIdentity::Windows {
            sid, session_id, ..
        } = &observed.identity
        else {
            return Err(ObservationError::Malformed);
        };
        let ProcessIdentity::Windows {
            owner_sid,
            creation_time_100ns,
            ..
        } = &self.identity
        else {
            return Err(ObservationError::Malformed);
        };
        if sid != owner_sid {
            return Err(ObservationError::PermissionDenied);
        }
        let mut current_session = 0;
        if unsafe { ProcessIdToSessionId(self.pid, &mut current_session) } == 0
            || current_session != *session_id
        {
            return Err(ObservationError::Changed);
        }
        let mut birth = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe {
            GetProcessTimes(
                self.process.as_raw_handle(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(ObservationError::Changed);
        }
        let stamp = (u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime);
        if stamp != *creation_time_100ns
            || !self
                .identity
                .still_current()
                .map_err(|_| ObservationError::Changed)?
        {
            return Err(ObservationError::Changed);
        }
        self.session.contains_window(self.pid, self.window)?;
        if self.session.observe()? != observed {
            return Err(ObservationError::Changed);
        }
        Ok(())
    }
}

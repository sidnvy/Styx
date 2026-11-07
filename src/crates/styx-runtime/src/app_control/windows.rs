#![allow(unsafe_code)] // Kernel peer identity and retained process waits only; no signalling.
use super::*;
use crate::store::{PrivateRoot, ProcessIdentity, RootIdentity, WindowsLocalFile};
use std::{
    ffi::OsString,
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::ClientOptions,
    time::{Duration, Instant, timeout},
};
use windows_sys::Win32::{
    Foundation::{FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{
            GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW, WaitForSingleObject,
        },
    },
};
const FRAME: usize = 8192;
fn error() -> ControlError {
    ControlError("app_control_peer_or_protocol_refused")
}
struct Peer {
    handle: OwnedHandle,
    pid: u32,
    birth: u64,
}
impl Peer {
    fn open(pid: u32, birth: &str, sid: &str, image: &Path) -> Result<Self, ControlError> {
        let expected_birth = birth.parse::<u64>().map_err(|_| error())?;
        if pid == 0 || expected_birth == 0 {
            return Err(error());
        }
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000, 0, pid) };
        if handle.is_null() {
            return Err(error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(error());
        }
        let actual_birth =
            (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        if actual_birth != expected_birth {
            return Err(error());
        }
        match ProcessIdentity::observe(pid).map_err(|_| error())? {
            ProcessIdentity::Windows {
                creation_time_100ns,
                owner_sid,
                ..
            } if creation_time_100ns == actual_birth && owner_sid == sid => {}
            _ => return Err(error()),
        }
        let mut text = vec![0u16; 32768];
        let mut len = text.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(handle.as_raw_handle(), 0, text.as_mut_ptr(), &mut len)
        } == 0
            || len == 0
        {
            return Err(error());
        }
        let actual = PathBuf::from(OsString::from_wide(&text[..len as usize]));
        if std::fs::canonicalize(actual).map_err(|_| error())?
            != std::fs::canonicalize(image).map_err(|_| error())?
        {
            return Err(error());
        }
        Ok(Self {
            handle,
            pid,
            birth: actual_birth,
        })
    }
    fn exit(&self) -> Result<Option<u32>, ControlError> {
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.handle.as_raw_handle(), &mut code) } == 0 {
                    return Err(error());
                }
                Ok(Some(code))
            }
            _ => Err(error()),
        }
    }
}
async fn frame<R: tokio::io::AsyncRead + Unpin>(read: &mut R) -> Result<Vec<u8>, ControlError> {
    let mut bytes = Vec::new();
    loop {
        let byte = read.read_u8().await.map_err(|_| error())?;
        if byte == b'\n' {
            return Ok(bytes);
        }
        if bytes.len() == FRAME {
            return Err(error());
        }
        bytes.push(byte);
    }
}
pub(super) async fn request(state: &Path, operation: Operation) -> Result<Report, ControlError> {
    if !state.is_absolute() {
        return Err(ControlError("app_control_absolute_state_required"));
    }
    let root =
        PrivateRoot::open(state).map_err(|_| ControlError("app_control_profile_unavailable"))?;
    let RootIdentity::Windows {
        volume_serial,
        file_id,
        owner_sid,
    } = root.identity()
    else {
        return Err(error());
    };
    let sid = owner_sid.clone();
    let name = format!(
        r"\\.\pipe\Styx.AppControl.v1.{}.{:016x}.{:016x}",
        sid, volume_serial, file_id
    );
    let mut report = Report::initial(operation);
    let mut pipe = match ClientOptions::new()
        .security_qos_flags(windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION)
        .open(&name)
    {
        Ok(pipe) => pipe,
        Err(e) if e.raw_os_error() == Some(2) => {
            report.status = "unavailable".into();
            report.code = Some("app_owner_endpoint_unavailable".into());
            return Ok(report);
        }
        Err(e) if e.raw_os_error() == Some(231) => {
            report.status = "busy".into();
            report.code = Some("app_control_busy".into());
            return Ok(report);
        }
        Err(_) => return Err(ControlError("app_owner_endpoint_unavailable")),
    };
    let hello: Hello = serde_json::from_slice(
        &timeout(Duration::from_secs(5), frame(&mut pipe))
            .await
            .map_err(|_| ControlError("app_owner_not_responding"))??,
    )
    .map_err(|_| error())?;
    let mut actual = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut actual) } == 0
        || hello.pid != actual
        || hello.schema != 1
        || hello.kind != "styx-local-app-owner"
        || hello.owner_sid != sid
    {
        return Err(error());
    }
    let same = PrivateRoot::open(Path::new(&hello.state_directory)).map_err(|_| error())?;
    if same.identity() != root.identity() {
        return Err(error());
    }
    let cli = std::env::current_exe().map_err(|_| error())?;
    let bin = cli.parent().ok_or_else(error)?;
    let native = bin.parent().ok_or_else(error)?;
    if bin
        .file_name()
        .is_none_or(|x| x.to_str().is_none_or(|s| !s.eq_ignore_ascii_case("bin")))
        || native
            .file_name()
            .is_none_or(|x| x.to_str().is_none_or(|s| !s.eq_ignore_ascii_case("native")))
    {
        return Err(ControlError("app_control_use_bundled_cli"));
    }
    let package = native.parent().ok_or_else(error)?;
    // Installed package metadata and managed App bytes are public, read-only
    // inputs. Protect modification and retain their original namespace/handles;
    // do not require the confidentiality policy of the private state above.
    // These consistency pins are not an Authenticode or publisher grant.
    let package_path = package.to_owned();
    let metadata_pin = WindowsLocalFile::open(&package_path.join("windows-runtime.json"), 16384)
        .map_err(|_| error())?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata_pin.read_bytes(16384).map_err(|_| error())?)
            .map_err(|_| error())?;
    let app_image_pin =
        WindowsLocalFile::open(&package_path.join("StyxPreview.exe"), 16 * 1024 * 1024)
            .map_err(|_| error())?;
    let app_hash = app_image_pin.digest().to_hex();
    if metadata["desktopApp"]["path"] != "StyxPreview.exe"
        || metadata["desktopApp"]["sha256"].as_str() != Some(app_hash.as_str())
    {
        return Err(error());
    }
    let app = Peer::open(
        hello.pid,
        &hello.creation_file_time,
        &sid,
        &package_path.join("StyxPreview.exe"),
    )?;
    let core = hello
        .core
        .as_ref()
        .map(|p| Peer::open(p.pid, &p.creation_file_time, &sid, &cli))
        .transpose()?;
    report.app_pid = Some(app.pid);
    report.core_pid = core.as_ref().map(|p| p.pid);
    let id = uuid::Uuid::new_v4().simple().to_string();
    let mut request=serde_json::to_vec(&serde_json::json!({"schema":1,"id":id,"operation":operation.name(),"stateDirectory":hello.state_directory})).map_err(|_|error())?;
    request.push(b'\n');
    // Once sending starts there is one request only. A timeout/lost response is
    // Unknown; dropping this pipe cannot cancel or replay the original owner job.
    let until = Instant::now() + Duration::from_secs(30);
    let reply = timeout(Duration::from_secs(30), async {
        pipe.write_all(&request).await.map_err(|_| error())?;
        serde_json::from_slice::<Reply>(&frame(&mut pipe).await?).map_err(|_| error())
    })
    .await;
    let Ok(Ok(reply)) = reply else {
        return Ok(report);
    };
    if reply.schema != 1 || reply.id != id {
        return Ok(report);
    }
    let outcome = reply.result;
    report.code = outcome.code;
    if matches!(operation, Operation::Status) {
        if !matches!(
            outcome.status.as_str(),
            "running" | "stopping" | "ready_to_exit" | "unknown"
        ) || outcome.starting.is_none()
            || outcome.busy.is_none()
        {
            return Err(error());
        }
        report.status = outcome.status;
        report.starting = outcome.starting;
        report.busy = outcome.busy;
        return Ok(report);
    }
    if outcome.status == "busy" {
        report.status = "busy".into();
        return Ok(report);
    }
    if outcome.status != "ready_to_exit" {
        return Ok(report);
    }
    if let Some(exit) = &outcome.core_exit {
        if let Some(core) = &core {
            if exit.pid != core.pid
                || exit.creation_file_time.parse::<u64>().ok() != Some(core.birth)
            {
                return Ok(report);
            }
        } else {
            if exit.pid == 0
                || exit
                    .creation_file_time
                    .parse::<u64>()
                    .ok()
                    .is_none_or(|v| v == 0)
            {
                return Ok(report);
            }
            report.core_pid = Some(exit.pid);
            report.core_exit_observed_by = Some("original_app_owner");
        }
        report.core_exit_code = Some(exit.exit_code);
        if !exit.stdin_eof || !exit.io_joined {
            report
                .code
                .get_or_insert("app_core_cleanup_unconfirmed".into());
        }
    } else if core.is_some() {
        return Ok(report);
    }
    loop {
        let app_exit = app.exit()?;
        let core_exit = core.as_ref().map(|p| p.exit()).transpose()?.flatten();
        if let Some(code) = app_exit {
            report.app_exited = Some(true);
            report.app_exit_code = Some(code);
            report.core_exited = core
                .as_ref()
                .map(|_| core_exit.is_some())
                .or_else(|| outcome.core_exit.as_ref().map(|_| true));
            if core.is_some() {
                report.core_exit_observed_by = Some("retained_process_wait");
            }
            if let (Some(actual), Some(declared)) = (core_exit, report.core_exit_code) {
                if actual as i32 != declared {
                    report.code = Some("app_control_exit_mismatch".into());
                    return Ok(report);
                }
            }
            if core.is_some() && core_exit.is_none() {
                return Ok(report);
            }
            report.status = if code == 0
                && core_exit.is_none_or(|c| c == 0)
                && report.core_exit_code.is_none_or(|c| c == 0)
                && report.code.is_none()
            {
                "exited"
            } else {
                "unclean_exit"
            }
            .into();
            if let Some(c) = core_exit {
                report.core_exit_code = Some(c as i32);
            }
            return Ok(report);
        }
        if Instant::now() >= until {
            return Ok(report);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

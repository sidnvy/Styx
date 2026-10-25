//! Read-only Shell bindings. Call on the SAME retained MTA worker as
//! WindowsLegacyObservation. No Resolve, Save, ShellExecute or environment expansion.
use super::windows_legacy_observation::ObservationError;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree, IPersistStream},
        UI::Shell::{
            FOLDERID_Startup, IShellLinkW, KF_FLAG_DEFAULT, SHCreateMemStream,
            SHGetKnownFolderPath, SLGP_RAWPATH, ShellLink,
        },
    },
    core::Interface,
};
// Matches private management_owner_recovery::MAX_RECOVERY_RAW = 4096.
// That constant is not exported; do not widen the existing journal contract.
pub(crate) const MAX_STARTUP_RECOVERY_RAW: usize = 4096;
type Result<T> = std::result::Result<T, ObservationError>;
fn native<T>(_: T) -> ObservationError {
    ObservationError::Native
}
fn text(raw: &[u16]) -> Result<String> {
    let end = raw
        .iter()
        .position(|x| *x == 0)
        .ok_or(ObservationError::Invalid)?;
    String::from_utf16(&raw[..end]).map_err(native)
}
#[allow(unsafe_code)] // Narrow official Shell allocator/COM ABI boundary.
pub(crate) fn current_startup_directory() -> Result<PathBuf> {
    // Official known-folder query verifies existence; it does not create it.
    let value =
        unsafe { SHGetKnownFolderPath(&FOLDERID_Startup, KF_FLAG_DEFAULT, HANDLE::default()) }
            .map_err(native)?;
    let result = (|| {
        let mut count = 0usize;
        // OS-owned null-terminated allocation. Bound the local copy; always free.
        while count < 32768 && unsafe { *value.0.add(count) } != 0 {
            count += 1;
        }
        if count == 0 || count == 32768 {
            return Err(ObservationError::Invalid);
        }
        let raw = unsafe { std::slice::from_raw_parts(value.0, count) };
        Ok(PathBuf::from(OsString::from_wide(raw)))
    })();
    unsafe { CoTaskMemFree(Some(value.0.cast())) };
    result
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LinkFields {
    pub(crate) target: String,
    pub(crate) arguments: String,
    pub(crate) working_directory: String,
}
/// Parses retained original bytes through the OS, never reopening a wire path.
/// GetPath RAWPATH intentionally rejects environment-variable aliases downstream.
#[allow(unsafe_code)] // Narrow official Shell/COM ABI boundary.
pub(crate) fn link_fields(bytes: &[u8]) -> Result<LinkFields> {
    if bytes.is_empty() || bytes.len() > MAX_STARTUP_RECOVERY_RAW {
        return Err(ObservationError::Invalid);
    }
    unsafe {
        let stream = SHCreateMemStream(Some(bytes)).ok_or(ObservationError::Native)?;
        let link: IShellLinkW =
            CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(native)?;
        let persist: IPersistStream = link.cast().map_err(native)?;
        persist.Load(&stream).map_err(native)?;
        let mut target = [0u16; 260];
        let mut arguments = vec![0u16; 32768];
        let mut working_directory = [0u16; 260];
        link.GetPath(&mut target, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)
            .map_err(native)?;
        link.GetArguments(&mut arguments).map_err(native)?;
        link.GetWorkingDirectory(&mut working_directory)
            .map_err(native)?;
        let value = LinkFields {
            target: text(&target)?,
            arguments: text(&arguments)?,
            working_directory: text(&working_directory)?,
        };
        // The fixed legacy installer uses fully expanded short paths. At the
        // documented GetPath MAX_PATH boundary, ambiguity/truncation is refused.
        if value.target.is_empty()
            || value.target.encode_utf16().count() >= 259
            || value.working_directory.is_empty()
            || value.working_directory.encode_utf16().count() >= 259
            || value.arguments.encode_utf16().count() >= 32767
        {
            return Err(ObservationError::Invalid);
        }
        Ok(value)
    }
}

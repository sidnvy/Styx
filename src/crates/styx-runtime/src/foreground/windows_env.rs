//! Local Windows paths and a minimal OS-derived executor environment. Neither
//! inherited SSH variables nor arbitrary host.json keys become worker authority.
use super::profile::ProfileError;
use std::{
    collections::BTreeMap,
    path::{Component, Path, Prefix},
};

pub(super) fn local_absolute(path: &Path) -> Result<(), ProfileError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        return Err(ProfileError::Invalid);
    }
    for part in components {
        let Component::Normal(name) = part else {
            return Err(ProfileError::Invalid);
        };
        let Some(name) = name.to_str() else {
            return Err(ProfileError::Invalid);
        };
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if name.is_empty()
            || name.contains([':', '\0'])
            || name.ends_with(['.', ' '])
            || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(ProfileError::Invalid);
        }
    }
    // Path::components normalizes interior '.'. Reject their raw spelling too,
    // so a validated locator never silently acquires different semantics.
    let raw = path.to_str().ok_or(ProfileError::Invalid)?;
    if raw
        .split(['/', '\\'])
        .any(|part| part == "." || part == "..")
        || raw.contains('\0')
    {
        return Err(ProfileError::Invalid);
    }
    Ok(())
}

pub(super) fn executor_environment(
    profile: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ProfileError> {
    if profile.keys().any(|key| key != "CODEX_HOME") {
        return Err(ProfileError::UnsupportedExecutorEnvironment);
    }
    let (windows, user) = os::directories().map_err(|_| ProfileError::ProtectedRead)?;
    local_absolute(&windows)?;
    local_absolute(&user)?;
    let system = windows.join("System32");
    let to_text = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or(ProfileError::Invalid)
    };
    let windows_text = to_text(&windows)?;
    let user_text = to_text(&user)?;
    let drive = user_text.get(..2).ok_or(ProfileError::Invalid)?;
    let temp = user.join("AppData/Local/Temp");
    // A shared temp directory must never become an implicit private worker
    // namespace. Refuse unsuitable ACLs without changing installed permissions.
    let _temp_root =
        crate::store::PrivateRoot::open(&temp).map_err(|_| ProfileError::ProtectedRead)?;
    let mut result = BTreeMap::from([
        ("SystemRoot".into(), windows_text.clone()),
        ("WinDir".into(), windows_text),
        ("ComSpec".into(), to_text(&system.join("cmd.exe"))?),
        (
            "Path".into(),
            format!(
                "{};{};{}",
                to_text(&system)?,
                to_text(&windows)?,
                to_text(&system.join("WindowsPowerShell/v1.0"))?
            ),
        ),
        ("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into()),
        ("USERPROFILE".into(), user_text.clone()),
        ("HOMEDRIVE".into(), drive.to_owned()),
        ("HOMEPATH".into(), user_text[2..].to_owned()),
        ("APPDATA".into(), to_text(&user.join("AppData/Roaming"))?),
        ("LOCALAPPDATA".into(), to_text(&user.join("AppData/Local"))?),
        ("TEMP".into(), to_text(&temp)?),
        ("TMP".into(), to_text(&temp)?),
    ]);
    result.extend(profile.clone());
    Ok(result)
}

#[allow(unsafe_code)]
mod os {
    use std::{
        ffi::OsString,
        io,
        os::windows::{
            ffi::OsStringExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::PathBuf,
    };
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::{
            SystemInformation::GetWindowsDirectoryW,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::GetUserProfileDirectoryW,
    };
    pub(super) fn directories() -> io::Result<(PathBuf, PathBuf)> {
        let mut windows = vec![0u16; 32768];
        // SAFETY: writable bounded buffer, Win32 reports UTF-16 count excluding
        // the terminator. Oversized or empty results are refused, never truncated.
        let count = unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) };
        if count == 0 || count as usize >= windows.len() {
            return Err(io::Error::last_os_error());
        }
        windows.truncate(count as usize);
        let mut token = std::ptr::null_mut();
        // SAFETY: current-process pseudo handle and one valid out handle. Query
        // token only; no impersonation, elevation or privilege modification.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcessToken succeeded and transfers this unique handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
        let mut profile = vec![0u16; 32768];
        let mut size = profile.len() as u32;
        // SAFETY: owned live token, bounded writable UTF-16 output and count.
        if unsafe {
            GetUserProfileDirectoryW(
                token.as_raw_handle().cast(),
                profile.as_mut_ptr(),
                &mut size,
            )
        } == 0
            || size == 0
            || size as usize > profile.len()
        {
            return Err(io::Error::last_os_error());
        }
        if profile[size as usize - 1] != 0 {
            return Err(io::Error::other("invalid profile directory"));
        }
        profile.truncate(size as usize - 1);
        Ok((
            PathBuf::from(OsString::from_wide(&windows)),
            PathBuf::from(OsString::from_wide(&profile)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_windows_paths_refuse_remote_device_ads_and_ambiguous_names() {
        for good in [r"C:\Users\Sid", "D:/Styx/Host", r"C:\"] {
            assert!(local_absolute(Path::new(good)).is_ok(), "{good}");
        }
        for bad in [
            r"\\server\share\x",
            r"\\?\C:\x",
            r"\\.\C:\x",
            "C:relative",
            "/root",
            r"C:\a\..\b",
            r"C:\a\.\b",
            "C:/a:stream",
            "C:/dir. ",
            "C:/NUL.txt",
            "C:/COM1",
        ] {
            assert!(local_absolute(Path::new(bad)).is_err(), "{bad}");
        }
    }
}

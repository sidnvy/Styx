//! Existing native UI channel selection maps to OS-owned standard locations.
//! No PATH search, registry command line, shell or implicit existing-profile attach.
use super::*;

pub(super) fn selected_channel(channel: &str) -> Result<PathBuf> {
    let relative: &[&str] = match channel {
        "chrome" => &["Google/Chrome/Application/chrome.exe"],
        "msedge" => &["Microsoft/Edge/Application/msedge.exe"],
        "auto" => &[
            "Google/Chrome/Application/chrome.exe",
            "Microsoft/Edge/Application/msedge.exe",
        ],
        _ => return Err(ErrorCategory::CapabilityUnsupported),
    };
    let mut candidates = std::collections::BTreeSet::new();
    for root in known::program_files()? {
        for suffix in relative {
            let candidate = root.join(suffix);
            match std::fs::symlink_metadata(&candidate) {
                Ok(_) => {
                    candidates.insert(candidate);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(ErrorCategory::PermissionDenied),
            }
        }
    }
    // Multiple installations or auto with both browsers is ambiguous: the UI
    // must select a channel or a protected local config must select a path.
    if candidates.len() != 1 {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    let path = candidates
        .into_iter()
        .next()
        .ok_or(ErrorCategory::CapabilityUnsupported)?;
    canonical(&path)?;
    Ok(path)
}
#[allow(unsafe_code)]
mod known {
    use super::*;
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows_sys::Win32::UI::Shell::{
        CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86, SHGFP_TYPE_CURRENT, SHGetFolderPathW,
    };
    pub(super) fn program_files() -> Result<Vec<PathBuf>> {
        let mut roots = std::collections::BTreeSet::new();
        for id in [CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86] {
            let mut buffer = [0u16; 260];
            // Documented fixed MAX_PATH output; no allocation or global env read.
            if unsafe {
                SHGetFolderPathW(
                    std::ptr::null_mut(),
                    id as i32,
                    std::ptr::null_mut(),
                    SHGFP_TYPE_CURRENT as u32,
                    buffer.as_mut_ptr(),
                )
            } != 0
            {
                return Err(ErrorCategory::CapabilityUnsupported);
            }
            let len = buffer
                .iter()
                .position(|c| *c == 0)
                .filter(|n| *n > 0)
                .ok_or(ErrorCategory::CapabilityUnsupported)?;
            let path = PathBuf::from(OsString::from_wide(&buffer[..len]));
            canonical(&path)?;
            roots.insert(path);
        }
        Ok(roots.into_iter().collect())
    }
}

//! Small official Darwin ABI boundary. No ACL layout/parser, mutation, process
//! command-line inspection, shell/sysctl utility or caller-selected sysctl name.
#![allow(unsafe_code)]
use super::*;
use std::{ffi::c_void, mem::MaybeUninit, os::fd::AsRawFd, ptr::NonNull};

const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
// Apple SDK <sys/acl.h>: acl_t/acl_entry_t are opaque pointers. Their layout is
// intentionally never reproduced. These functions are in the standard C library.
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, index: libc::c_int, entry: *mut *mut c_void) -> libc::c_int;
    fn acl_valid(acl: *mut c_void) -> libc::c_int;
    fn acl_free(value: *mut c_void) -> libc::c_int;
}
struct OwnedAcl(NonNull<c_void>);
impl Drop for OwnedAcl {
    fn drop(&mut self) {
        // SAFETY: exactly the allocation returned by acl_get_fd_np, freed once;
        // no entry pointer escapes or is dereferenced by Rust.
        unsafe {
            acl_free(self.0.as_ptr());
        }
    }
}
pub(super) fn require_empty_acl(file: &File) -> Result<()> {
    // SAFETY: file retains a valid borrowed descriptor through this call. Darwin
    // returns an independent OS-allocated ACL object, never a borrowed file ptr.
    // SAFETY: Darwin errno is thread-local; clear it before the fd query so an
    // absent return cannot accidentally inherit a previous ENOENT.
    unsafe {
        *libc::__error() = 0;
    }
    let pointer = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(pointer) = NonNull::new(pointer) else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            // Apple acl_get_fd_np -> fstatx_np -> filesec_get_property reports
            // an absent ACL property as NULL/ENOENT on a valid held descriptor.
            // This is not path ENOENT or an unsupported-filesystem shortcut.
            file.metadata()?;
            return Ok(());
        }
        return Err(StoreError::Io(error));
    };
    let acl = OwnedAcl(pointer);
    // SAFETY: acl is a live OS-owned ACL object; validation changes only its
    // independent working copy, not the actual file's access control list.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(StoreError::Io(std::io::Error::last_os_error()));
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: the ACL stays alive; entry points to writable pointer-sized memory.
    // Darwin's convention differs from Linux: 0 means an entry WAS returned.
    let result = unsafe { acl_get_entry(acl.0.as_ptr(), ACL_FIRST_ENTRY, &mut entry) };
    if result == 0 {
        return Err(StoreError::NotPrivate);
    }
    if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // The independently validated, freshly retrieved ACL has no first entry.
        Ok(())
    } else {
        Err(StoreError::Io(std::io::Error::last_os_error()))
    }
}
fn boot_session() -> Result<String> {
    let mut buffer = [0u8; 64];
    let mut length = buffer.len();
    // SAFETY: fixed NUL-terminated key; buffer has exactly length writable bytes;
    // null new-value arguments make this read-only. No kernel-sized allocation.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(StoreError::Io(std::io::Error::last_os_error()));
    }
    if length != 37
        || buffer[36] != 0
        || !buffer[..36].iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(StoreError::ProcessIdentityUnavailable);
    }
    String::from_utf8(buffer[..36].to_ascii_lowercase())
        .map_err(|_| StoreError::ProcessIdentityUnavailable)
}
fn bsd_info(pid: u32) -> Result<Option<libc::proc_bsdinfo>> {
    let pid = i32::try_from(pid)
        .ok()
        .filter(|p| *p > 0)
        .ok_or(StoreError::ProcessIdentityUnavailable)?;
    let mut value = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    // SAFETY: libc supplies the actual Darwin repr(C) structure. Its pointer is
    // valid for size bytes; only an exact returned size permits assume_init.
    // SAFETY: __error returns this thread's writable errno slot. Clearing it
    // prevents a short/zero result from reusing an unrelated stale ESRCH.
    unsafe {
        *libc::__error() = 0;
    }
    let returned = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            value.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if returned != size as i32 {
        let error = std::io::Error::last_os_error();
        if returned <= 0 && error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return if returned <= 0 && error.raw_os_error().is_some_and(|e| e != 0) {
            Err(StoreError::Io(error))
        } else {
            Err(StoreError::ProcessIdentityUnavailable)
        };
    }
    // SAFETY: the kernel reported the complete initialized libc structure size.
    let value = unsafe { value.assume_init() };
    if value.pbi_pid != pid as u32
        || value.pbi_start_tvsec == 0
        || value.pbi_start_tvusec >= 1_000_000
    {
        return Err(StoreError::ProcessIdentityUnavailable);
    }
    Ok(Some(value))
}
pub(super) fn process_identity_optional(pid: u32) -> Result<Option<ProcessIdentity>> {
    let boot = boot_session()?;
    let Some(first) = bsd_info(pid)? else {
        return Ok(None);
    };
    let Some(second) = bsd_info(pid)? else {
        return Ok(None);
    };
    if boot != boot_session()?
        || first.pbi_pid != second.pbi_pid
        || first.pbi_uid != second.pbi_uid
        || first.pbi_start_tvsec != second.pbi_start_tvsec
        || first.pbi_start_tvusec != second.pbi_start_tvusec
    {
        return Err(StoreError::Changed);
    }
    Ok(Some(ProcessIdentity::Macos {
        boot_session_id: boot,
        pid,
        start_seconds: first.pbi_start_tvsec,
        start_microseconds: first.pbi_start_tvusec,
        uid: first.pbi_uid,
    }))
}
pub(super) fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    process_identity_optional(pid)?
        .ok_or_else(|| StoreError::Io(std::io::Error::from_raw_os_error(libc::ESRCH)))
}

/// Thin official Darwin renameatx_np/RENAME_EXCL ABI. Both names are checked
/// single components relative to the caller's original retained directory FDs.
/// Unsupported operations remain errors; there is no ordinary-rename fallback.
pub(super) fn rename_exclusive(
    source: &File,
    source_name: &str,
    destination: &File,
    destination_name: &str,
) -> Result<()> {
    journal_component(source_name)?;
    journal_component(destination_name)?;
    let source_name =
        std::ffi::CString::new(source_name).map_err(|_| StoreError::InvalidRelativePath)?;
    let destination_name =
        std::ffi::CString::new(destination_name).map_err(|_| StoreError::InvalidRelativePath)?;
    // SAFETY: both live directory descriptors remain borrowed through the
    // official libc call; CString owns both bounded NUL-terminated components.
    if unsafe {
        libc::renameatx_np(
            source.as_raw_fd(),
            source_name.as_ptr(),
            destination.as_raw_fd(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    } != 0
    {
        return Err(StoreError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

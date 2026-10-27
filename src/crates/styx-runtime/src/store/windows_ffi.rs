//! Official windows-sys ABI boundary. No private OS structures or protocols.
#![allow(unsafe_code)]
use super::*;
use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_HANDLE_EOF, ERROR_INVALID_PARAMETER, FILETIME, GENERIC_READ,
        GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        self, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE, ACE_HEADER,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::*,
    System::{
        SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
        },
        Threading::*,
    },
};
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn io_error() -> StoreError {
    std::io::Error::last_os_error().into()
}
fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut raw: Vec<_> = value.encode_wide().collect();
    if raw.len() > 32760 || raw.contains(&0) {
        return Err(StoreError::InvalidRelativePath);
    }
    raw.push(0);
    Ok(raw)
}
fn sid_string(sid: Security::PSID) -> Result<String> {
    if sid.is_null() || unsafe { Security::IsValidSid(sid) } == 0 {
        return Err(StoreError::NotPrivate);
    }
    let mut raw = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(io_error());
    }
    let _owned = Local(raw.cast());
    let mut len = 0;
    while len < 256 && unsafe { *raw.add(len) } != 0 {
        len += 1;
    }
    if len == 256 {
        return Err(StoreError::NotPrivate);
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
        .map_err(|_| StoreError::NotPrivate)
}
fn user_sid(process: windows_sys::Win32::Foundation::HANDLE) -> Result<String> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut required = 0;
    unsafe {
        Security::GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required < size_of::<TOKEN_USER>() as u32 || required > 65536 {
        return Err(StoreError::ProcessIdentityUnavailable);
    }
    // Vec<usize> provides alignment for official TOKEN_USER, unlike a byte Vec.
    let mut buffer = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        Security::GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io_error());
    }
    // SAFETY: TOKEN_USER fits in the aligned allocation, and API success
    // initialized it. Its SID is then bounded against that same allocation.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    bounded_sid(
        user.User.Sid,
        buffer.as_ptr() as usize,
        (buffer.as_ptr() as usize) + required as usize,
    )
}
pub(super) fn current_sid() -> Result<String> {
    user_sid(unsafe { GetCurrentProcess() })
}
/// Bounds every SID dereference against its original API-owned container.
fn bounded_sid(sid: Security::PSID, start: usize, end: usize) -> Result<String> {
    let address = sid as usize;
    if address < start
        || address
            .checked_add(size_of::<Security::SID>())
            .is_none_or(|n| n > end)
    {
        return Err(StoreError::NotPrivate);
    }
    // SAFETY: the official SID fixed prefix fits inside the owned API buffer;
    // read_unaligned avoids assuming any alignment for the variable-size SID.
    let prefix = unsafe { ptr::read_unaligned(sid.cast::<Security::SID>()) };
    let length = 8usize
        .checked_add(usize::from(prefix.SubAuthorityCount) * 4)
        .ok_or(StoreError::NotPrivate)?;
    if address.checked_add(length).is_none_or(|n| n > end) {
        return Err(StoreError::NotPrivate);
    }
    sid_string(sid)
}
/// Owner must be the current user. Only that user, SYSTEM and Administrators may
/// receive effective allow ACEs. Null/unrecognized DACLs and ACE forms fail shut.
pub(super) fn private(file: &File) -> Result<String> {
    checked_acl(file, false)
}
/// Local administrator-selected executable: ordinary read ACEs are permitted,
/// but only the current user and OS administrators may alter the image.
pub(super) fn local_executable_acl(file: &File) -> Result<String> {
    checked_acl(file, true)
}
fn checked_acl(file: &File, executable: bool) -> Result<String> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: valid retained File handle and pointers to initialized output slots.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    let _owned = Local(descriptor);
    if descriptor.is_null() || acl.is_null() {
        return Err(StoreError::NotPrivate);
    }
    // SAFETY: success returned an owned self-relative security descriptor.
    let bytes = unsafe { Security::GetSecurityDescriptorLength(descriptor) } as usize;
    if bytes == 0 || bytes > 65536 {
        return Err(StoreError::NotPrivate);
    }
    let base = descriptor as usize;
    let end = base.checked_add(bytes).ok_or(StoreError::NotPrivate)?;
    let current = current_sid()?;
    let actual = bounded_sid(owner, base, end)?;
    let acl_start = acl as usize;
    let trusted = |sid: &str| {
        sid == current
            || sid == "S-1-5-18"
            || sid == "S-1-5-32-544"
            || executable && sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    };
    if (!executable && actual != current || executable && !trusted(&actual))
        || acl_start < base
        || acl_start
            .checked_add(size_of::<Security::ACL>())
            .is_none_or(|n| n > end)
    {
        return Err(StoreError::NotPrivate);
    }
    // SAFETY: the official ACL fixed header is entirely in the owned descriptor.
    let header = unsafe { ptr::read_unaligned(acl) };
    let acl_end = acl_start
        .checked_add(usize::from(header.AclSize))
        .ok_or(StoreError::NotPrivate)?;
    if usize::from(header.AclSize) < size_of::<Security::ACL>()
        || acl_end > end
        || header.AceCount > 4096
    {
        return Err(StoreError::NotPrivate);
    }
    // SAFETY: the complete ACL extent was bounded above, not just its header.
    if unsafe { Security::IsValidAcl(acl) } == 0 {
        return Err(StoreError::NotPrivate);
    }
    const READ_ONLY: u32 = 0x8000_0000 | 0x2000_0000 | 0x0012_0000 | 0x0000_00A9;
    for index in 0..header.AceCount {
        let mut raw = ptr::null_mut();
        // SAFETY: validated owned ACL and output pointer; the returned ACE is
        // checked against the same original ACL before any Rust dereference.
        if unsafe { Security::GetAce(acl, u32::from(index), &mut raw) } == 0 || raw.is_null() {
            return Err(StoreError::NotPrivate);
        }
        let address = raw as usize;
        if address < acl_start + size_of::<Security::ACL>()
            || address
                .checked_add(size_of::<ACE_HEADER>())
                .is_none_or(|n| n > acl_end)
        {
            return Err(StoreError::NotPrivate);
        }
        // SAFETY: official ACE header fits in the already bounded ACL buffer.
        let ace_header = unsafe { ptr::read_unaligned(raw.cast::<ACE_HEADER>()) };
        let ace_end = address
            .checked_add(usize::from(ace_header.AceSize))
            .ok_or(StoreError::NotPrivate)?;
        if usize::from(ace_header.AceSize) < size_of::<ACE_HEADER>() || ace_end > acl_end {
            return Err(StoreError::NotPrivate);
        }
        if u32::from(ace_header.AceFlags) & Security::INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match u32::from(ace_header.AceType) {
            ACCESS_DENIED_ACE_TYPE => {}
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE if executable => {
                if usize::from(ace_header.AceSize) < size_of::<ACCESS_ALLOWED_CALLBACK_ACE>() {
                    return Err(StoreError::NotPrivate);
                }
                // SAFETY: the official fixed callback ACE fits inside the
                // original bounded ACE. Its variable SID is bounded separately.
                let ace = unsafe { ptr::read_unaligned(raw.cast::<ACCESS_ALLOWED_CALLBACK_ACE>()) };
                let sid_address = address
                    .checked_add(std::mem::offset_of!(ACCESS_ALLOWED_CALLBACK_ACE, SidStart))
                    .ok_or(StoreError::NotPrivate)?;
                bounded_sid(raw.with_addr(sid_address), address, ace_end)?;
                // A callback/condition can restrict this allow, never grant
                // rights outside Mask. Accept only an entirely read-only upper
                // bound, without interpreting the opaque callback payload.
                // Even trusted SIDs may not carry modifying callback rights;
                // private-store ACLs and every other ACE type remain unchanged.
                if ace.Mask & !READ_ONLY != 0 {
                    return Err(StoreError::NotPrivate);
                }
            }
            ACCESS_ALLOWED_ACE_TYPE => {
                if usize::from(ace_header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                    return Err(StoreError::NotPrivate);
                }
                // SAFETY: the complete fixed official ACE fits inside its
                // bounded original AceSize; variable SID extent checked next.
                let ace = unsafe { ptr::read_unaligned(raw.cast::<ACCESS_ALLOWED_ACE>()) };
                let sid_address = address
                    .checked_add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                    .ok_or(StoreError::NotPrivate)?;
                let allowed = bounded_sid(raw.with_addr(sid_address), address, ace_end)?;
                // Generic rights are not pre-mapped by GetSecurityInfo. Include
                // both generic and concrete modification/delete/security rights.
                let relevant = if executable {
                    ace.Mask & !READ_ONLY
                } else {
                    ace.Mask
                };
                if relevant != 0 && !trusted(&allowed) {
                    return Err(StoreError::NotPrivate);
                }
            }
            _ => return Err(StoreError::NotPrivate),
        }
    }
    Ok(actual)
}
// Convert the official SDDL form once; Local owns the API allocation through
// the consuming CreateFile/CreateDirectory call. No descriptor layout is copied.
fn private_descriptor(directory: bool) -> Result<Local> {
    let sid = current_sid()?;
    let inherit = if directory { "OICI" } else { "" };
    let sddl = wide(OsStr::new(&format!(
        "O:{sid}D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)(A;{inherit};FA;;;{sid})"
    )))?;
    let mut descriptor = ptr::null_mut();
    // SAFETY: NUL-terminated UTF16 SDDL and valid output pointer. Local follows
    // the documented LocalFree ownership rule for the returned allocation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io_error());
    }
    Ok(Local(descriptor))
}
/// Creates at most this one child. AlreadyExists conveys no privacy/type proof:
/// the caller must still reopen without following reparse points and validate.
pub(super) fn create_private_directory(path: &Path) -> Result<()> {
    let path = wide(path.as_os_str())?;
    let descriptor = private_descriptor(true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: live absolute UTF16 path and descriptor retained across the call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0
        && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
    {
        return Err(io_error());
    }
    Ok(())
}
/// Strict fresh creation: unlike the scratch helper above, an existing name is
/// an error, never an object to adopt. No directory-flush guarantee is implied.
pub(super) fn create_new_private_directory(path: &Path) -> Result<()> {
    let path = wide(path.as_os_str())?;
    let descriptor = private_descriptor(true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: bounded NUL-terminated path and owned descriptor live through call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(io_error());
    }
    Ok(())
}
/// Exclusively creates a private regular fixed file. This deliberately does
/// not change OPEN_ALWAYS used by the existing independent lock-resource port.
pub(super) fn create_new_private_file(path: &Path) -> Result<File> {
    create_new_file(path, false)
}
pub(super) fn create_new_journal_file(path: &Path) -> Result<File> {
    create_new_file(path, true)
}
fn create_new_file(path: &Path, rename: bool) -> Result<File> {
    let path = wide(path.as_os_str())?;
    let descriptor = private_descriptor(false)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: official CreateFileW ABI, live private descriptor, and valid UTF16.
    // Fixed files deny write/delete sharing. Rename-capable journal files add
    // DELETE access and delete sharing, retaining their exact source object even
    // if its name changes. All writers close before ordinary protected readers.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | if rename { DELETE } else { 0 },
            FILE_SHARE_READ | if rename { FILE_SHARE_DELETE } else { 0 },
            &attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io_error());
    }
    // SAFETY: successful CreateFileW returned one uniquely owned noninherit handle.
    let file = unsafe { File::from_raw_handle(handle) };
    if facts(&file)?.directory {
        return Err(StoreError::NotRegularFile);
    }
    private(&file)?;
    Ok(file)
}
/// Reopen an already observed journal source without truncation or creation.
/// Caller must compare its original file identity and exact bytes before use.
/// No write sharing keeps that actual source immutable until its handle closes.
pub(super) fn open_journal_for_rename(path: &Path) -> Result<File> {
    let path = wide(path.as_os_str())?;
    // SAFETY: bounded absolute path, official ABI, noninheritable OPEN_EXISTING.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io_error());
    }
    // SAFETY: successful CreateFileW transfers unique ownership of one handle.
    let file = unsafe { File::from_raw_handle(handle) };
    if facts(&file)?.directory {
        return Err(StoreError::NotRegularFile);
    }
    private(&file)?;
    Ok(file)
}
/// Flush only this actual writable file/directory HANDLE. The caller validates
/// its original identity, private ACL and local NTFS support. No volume flush,
/// administrator elevation or physical power-loss claim is implied.
pub(super) fn flush_file(file: &File) -> Result<()> {
    // SAFETY: live owned file/directory handle was opened with GENERIC_WRITE.
    if unsafe { FlushFileBuffers(file.as_raw_handle()) } == 0 {
        return Err(io_error());
    }
    Ok(())
}
/// Obtain a bounded OS-normalized DOS path, not a caller-supplied locator.
/// The caller must reopen all ancestors without reparse/delete sharing and
/// compare the original HANDLE identity before using that path.
pub(super) fn final_path(file: &File) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: original retained HANDLE and one bounded output buffer.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    } as usize;
    if length == 0 {
        return Err(io_error());
    }
    if length >= buffer.len() {
        return Err(StoreError::InvalidRoot);
    }
    let name = String::from_utf16(&buffer[..length]).map_err(|_| StoreError::InvalidRoot)?;
    // Only the local drive form is accepted by normalized_root, never UNC,
    // device, volume GUID or an arbitrary path obtained from network data.
    let local = name
        .strip_prefix("\\\\?\\")
        .ok_or(StoreError::InvalidRoot)?;
    normalized_root(Path::new(local))
}
/// Source is the actual original writable/delete-capable HANDLE. Destination
/// is derived from the original retained namespace HANDLE. Root retains all
/// ancestor/name pins without delete sharing while using this absolute path.
/// Win32 requires a NULL RootDirectory on the supported actual target; source
/// selection still uses its original HANDLE, with no copy/delete fallback.
/// Caller owns the original configuration writer and validates expected target
/// bytes for the replace case; this is not hostile-same-UID atomic CAS.
pub(super) fn rename_journal_file(
    file: &File,
    directory: &File,
    name: &str,
    replace: bool,
) -> Result<()> {
    component(OsStr::new(name))?;
    if OsStr::new(name).encode_wide().count() > 255 {
        return Err(StoreError::InvalidRelativePath);
    }
    // The destination cannot be supplied as an arbitrary path. Resolve the
    // validated component under the OS-observed original namespace. Its Root
    // owner retains/rechecks the complete ancestor chain and directory identity.
    let destination = final_path(directory)?.join(name);
    let encoded = wide(destination.as_os_str())?;
    let name_bytes = (encoded.len() - 1) * 2;
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let total = offset
        .checked_add(encoded.len() * 2)
        .ok_or(StoreError::TooLarge)?;
    // Word allocation supplies the alignment of official FILE_RENAME_INFO;
    // zeroed storage includes its padding and the bounded trailing WCHAR array.
    let mut storage = vec![0usize; total.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: aligned allocation fits all fields and the encoded filename plus
    // terminator. FileNameLength excludes the terminator per official ABI.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            encoded.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            encoded.len(),
        );
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            total as u32,
        ) == 0
        {
            return Err(io_error());
        }
    }
    Ok(())
}
/// Restrict the new writable port to the local fixed NTFS semantics used by
/// its write-through contract. Existing read/lease ports retain their behavior.
pub(super) fn require_local_ntfs(path: &Path, directory: &File) -> Result<()> {
    let drive: PathBuf = path.components().take(2).collect();
    let drive = wide(drive.as_os_str())?;
    // DRIVE_FIXED from the documented GetDriveTypeW enum. A mapped remote drive
    // is not accepted merely because its drive-letter path looks local.
    const DRIVE_FIXED: u32 = 3;
    // SAFETY: normalized absolute drive root, bounded and NUL terminated.
    if unsafe { GetDriveTypeW(drive.as_ptr()) } != DRIVE_FIXED {
        return Err(StoreError::InvalidRoot);
    }
    let mut filesystem = [0u16; 32];
    // SAFETY: original directory HANDLE and one fixed-size output buffer. Null
    // optional metadata outputs are permitted by the official Win32 contract.
    if unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io_error());
    }
    let end = filesystem
        .iter()
        .position(|v| *v == 0)
        .ok_or(StoreError::InvalidRoot)?;
    if filesystem[..end] != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16] {
        return Err(StoreError::InvalidRoot);
    }
    Ok(())
}
/// Ancestors and every opened directory omit FILE_SHARE_DELETE; regular input
/// files additionally omit FILE_SHARE_WRITE. Kernel sharing locks pin the names
/// while retained handles exist. Handles are non-inheritable by default.
pub(super) fn open(path: &Path, directory: bool, write: bool, create: bool) -> Result<File> {
    let path = wide(path.as_os_str())?;
    let descriptor = if create {
        Some(private_descriptor(false)?)
    } else {
        None
    };
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ref().map_or(ptr::null_mut(), |value| value.0),
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | if write { GENERIC_WRITE } else { 0 },
            FILE_SHARE_READ
                | if directory || write {
                    FILE_SHARE_WRITE
                } else {
                    0
                },
            if create { &attributes } else { ptr::null() },
            if create { OPEN_ALWAYS } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            ptr::null_mut(),
        )
    };
    drop(descriptor);
    if handle == INVALID_HANDLE_VALUE {
        return Err(io_error());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    let facts = facts(&file)?;
    if facts.directory != directory {
        return Err(StoreError::NotRegularFile);
    }
    Ok(file)
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Facts {
    pub observation: FileObservation,
    pub directory: bool,
    pub links: u32,
}
pub(super) fn facts(file: &File) -> Result<Facts> {
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(StoreError::NotRegularFile);
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let mut basic = FILE_BASIC_INFO::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileBasicInfo,
                ptr::addr_of_mut!(basic).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
    {
        return Err(io_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || basic.LastWriteTime < 0
        || basic.ChangeTime < 0
    {
        return Err(StoreError::NotRegularFile);
    }
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if !directory && info.nNumberOfLinks != 1 {
        return Err(StoreError::NotRegularFile);
    }
    Ok(Facts {
        directory,
        links: info.nNumberOfLinks,
        observation: FileObservation {
            device: u64::from(info.dwVolumeSerialNumber),
            inode: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            byte_len: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            modified_seconds: basic.LastWriteTime / 10_000_000,
            modified_nanoseconds: (basic.LastWriteTime % 10_000_000) * 100,
            changed_seconds: basic.ChangeTime / 10_000_000,
            changed_nanoseconds: (basic.ChangeTime % 10_000_000) * 100,
        },
    })
}
pub(super) fn require_no_streams(path: &Path) -> Result<()> {
    let path = wide(path.as_os_str())?;
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let handle = unsafe {
        FindFirstStreamW(
            path.as_ptr(),
            FindStreamInfoStandard,
            ptr::addr_of_mut!(data).cast(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let e = std::io::Error::last_os_error();
        return if e.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
            Ok(())
        } else {
            Err(e.into())
        };
    }
    struct Find(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Find {
        fn drop(&mut self) {
            unsafe {
                FindClose(self.0);
            }
        }
    }
    let _owned = Find(handle);
    let len = data
        .cStreamName
        .iter()
        .position(|n| *n == 0)
        .ok_or(StoreError::NotRegularFile)?;
    if String::from_utf16(&data.cStreamName[..len]).map_err(|_| StoreError::NotRegularFile)?
        != "::$DATA"
    {
        return Err(StoreError::NotRegularFile);
    }
    if unsafe { FindNextStreamW(handle, ptr::addr_of_mut!(data).cast()) } != 0 {
        return Err(StoreError::NotRegularFile);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() != Some(ERROR_HANDLE_EOF as i32) {
        return Err(e.into());
    }
    Ok(())
}
pub(super) fn process_optional(pid: u32) -> Result<Option<ProcessIdentity>> {
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        let e = std::io::Error::last_os_error();
        return if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) && pid != 0 {
            Ok(None)
        } else {
            Err(StoreError::ProcessIdentityUnavailable)
        };
    }
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(StoreError::ProcessIdentityUnavailable);
    }
    let sid = user_sid(process.as_raw_handle())?;
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(None),
        WAIT_TIMEOUT => Ok(Some(ProcessIdentity::Windows {
            pid,
            creation_time_100ns: (u64::from(created.dwHighDateTime) << 32)
                | u64::from(created.dwLowDateTime),
            owner_sid: sid,
        })),
        _ => Err(StoreError::ProcessIdentityUnavailable),
    }
}

#[cfg(test)]
mod callback_acl_tests {
    use super::*;
    use windows_sys::Win32::{
        Security::ACCESS_ALLOWED_CALLBACK_ACE,
        System::SystemServices::ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    };

    // Microsoft conditional-ACE grammar: XA;flags;rights;;;SID;(expression).
    // Member_of accepts SID(BA); the condition's truth is deliberately irrelevant
    // to our conservative maximum-rights check. Explicit current-user FA permits
    // fixture creation/read/cleanup even when this callback condition is false.
    // https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-
    fn fixture(sid: &str, mask: u32) -> (PathBuf, File) {
        let current = current_sid().expect("current test user SID");
        let sddl = wide(OsStr::new(&format!(
            "O:{current}D:P(A;;FA;;;{current})(XA;;0x{mask:08x};;;{sid};(Member_of {{SID(BA)}}))"
        )))
        .expect("bounded test SDDL");
        let mut descriptor = ptr::null_mut();
        // SAFETY: NUL-terminated SDDL and initialized output pointer. Local owns
        // the successful official allocation until CreateFileW has consumed it.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0,
            "conditional SDDL must parse: {}",
            std::io::Error::last_os_error()
        );
        let descriptor = Local(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let path = std::env::temp_dir().join(format!(
            "styx-callback-acl-{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        let name = wide(path.as_os_str()).expect("bounded fresh fixture name");
        // SAFETY: fresh CREATE_NEW only. DELETE_ON_CLOSE cleans this exact
        // kernel-owned fixture on normal return or assertion unwind; no SetACL,
        // recursive cleanup, installed image or existing file is touched.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | DELETE,
                FILE_SHARE_READ,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "fresh fixture creation: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful CreateFileW transfers its one owned HANDLE to File.
        let file = unsafe { File::from_raw_handle(handle) };
        assert_stored_callback(&file, mask);
        (path, file)
    }

    fn assert_stored_callback(file: &File, expected_mask: u32) {
        let mut acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: retained file handle and valid output slots. Query the actual
        // stored DACL, so a stripped/ordinary ACE cannot make a negative pass.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        let _descriptor = Local(descriptor);
        assert_eq!(status, 0, "read fixture DACL");
        assert!(!acl.is_null());
        assert_ne!(unsafe { Security::IsValidAcl(acl) }, 0);
        // SAFETY: successful GetSecurityInfo and IsValidAcl supply the official
        // ACL layout. GetAce supplies each valid ACE; check size before casting.
        let count = unsafe { (*acl).AceCount };
        let mut callbacks = 0;
        for index in 0..count {
            let mut raw = ptr::null_mut();
            assert_ne!(
                unsafe { Security::GetAce(acl, u32::from(index), &mut raw) },
                0
            );
            assert!(!raw.is_null());
            let header = unsafe { ptr::read_unaligned(raw.cast::<ACE_HEADER>()) };
            if u32::from(header.AceType) == ACCESS_ALLOWED_CALLBACK_ACE_TYPE {
                assert!(usize::from(header.AceSize) > size_of::<ACCESS_ALLOWED_CALLBACK_ACE>());
                let ace = unsafe { ptr::read_unaligned(raw.cast::<ACCESS_ALLOWED_CALLBACK_ACE>()) };
                assert_eq!(ace.Mask, expected_mask);
                assert_eq!(u32::from(header.AceFlags) & Security::INHERIT_ONLY_ACE, 0);
                callbacks += 1;
            }
        }
        assert_eq!(callbacks, 1, "actual effective conditional callback ACE");
    }

    #[test]
    fn callback_read_only_users_is_local_image_only() {
        let (path, file) = fixture("BU", 0x0012_00a9);
        assert!(
            local_executable_acl(&file).is_ok(),
            "ordinary read/execute callback"
        );
        assert!(
            matches!(private(&file), Err(StoreError::NotPrivate)),
            "private store must still reject callback ACEs"
        );
        drop(file);
        assert!(!path.try_exists().expect("fixture deletion observation"));
    }

    #[test]
    fn callback_modification_is_rejected_even_for_trusted_sid() {
        let current = current_sid().expect("current test user SID");
        for (sid, extra) in [
            ("BU", FILE_WRITE_DATA),
            ("BU", FILE_DELETE_CHILD),
            ("BU", WRITE_DAC),
            (current.as_str(), WRITE_DAC),
        ] {
            let (path, file) = fixture(sid, 0x0012_00a9 | extra);
            assert!(
                matches!(local_executable_acl(&file), Err(StoreError::NotPrivate)),
                "modifying callback must be rejected: mask={extra:08x}"
            );
            assert!(matches!(private(&file), Err(StoreError::NotPrivate)));
            drop(file);
            assert!(!path.try_exists().expect("fixture deletion observation"));
        }
    }
}

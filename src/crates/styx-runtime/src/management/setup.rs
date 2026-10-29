//! Small OS/input adapters for the CLI. Enrollment and service actors retain
//! all validation and authority; these helpers never write canonical state.
use crate::store::PrivateRoot;
use std::{io, path::Path};

pub fn private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::other("absolute_private_path_required"));
    }
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::other("private_directory_alias_refused"));
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    if !path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
        }
        #[cfg(windows)]
        {
            let parent = path
                .parent()
                .ok_or_else(|| io::Error::other("private_parent_required"))?;
            private_directory(parent)?;
            PrivateRoot::open(parent)
                .map_err(io::Error::other)?
                .open_or_create_private_child(
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| io::Error::other("private_name_required"))?,
                )
                .map_err(io::Error::other)?;
        }
    }
    PrivateRoot::open(path).map_err(io::Error::other)?;
    Ok(())
}
pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("private_parent_required"))?;
    let root = PrivateRoot::open(parent).map_err(io::Error::other)?;
    root.create_setup_export(
        path.file_name()
            .ok_or_else(|| io::Error::other("private_name_required"))?,
        bytes,
    )
    .map(|_| ())
    .map_err(io::Error::other)
}
pub fn read_private(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let root = PrivateRoot::open(
        path.parent()
            .ok_or_else(|| io::Error::other("private_parent_required"))?,
    )
    .map_err(io::Error::other)?;
    Ok(root
        .read_raw(
            Path::new(
                path.file_name()
                    .ok_or_else(|| io::Error::other("private_name_required"))?,
            ),
            limit,
        )
        .map_err(io::Error::other)?
        .bytes()
        .to_vec())
}

/// Reuse the App's exact link parser, certificate checks and confirmation.
pub struct JoinLink(crate::app::pairing_link::InspectedLink);
impl JoinLink {
    pub fn inspect(link: &str, now_ms: u64) -> Result<Self, &'static str> {
        crate::app::pairing_link::inspect(link, now_ms)
            .map(Self)
            .map_err(|e| e.code())
    }
    pub fn preview(&self) -> serde_json::Value {
        serde_json::to_value(self.0.preview()).expect("public link preview")
    }
    pub fn accept(
        self,
        origin: &str,
        ca: Option<&str>,
        now_ms: u64,
        ca_file: &Path,
        invitation_file: &Path,
    ) -> Result<String, &'static str> {
        let accepted = self.0.approve(origin, ca, now_ms).map_err(|e| e.code())?;
        let (origin, invitation, pem, _) = accepted.into_parts();
        let pem = pem.ok_or("join_link_certificate_required")?;
        write_new(ca_file, pem.as_bytes()).map_err(|_| "join_input_publication_unknown")?;
        write_new(invitation_file, invitation.as_bytes())
            .map_err(|_| "join_input_publication_unknown")?;
        Ok(origin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PrivateAddress {
    pub interface: String,
    pub address: std::net::Ipv4Addr,
}
/// Presentation filter only. Explicit answers still use the existing IP rules.
pub fn suggested_interface(name: &str) -> bool {
    ![
        "docker", "br-", "veth", "virbr", "cni", "flannel", "podman", "lxcbr", "lxdbr",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
pub fn interface_kind(name: &str) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        // Only OS interface names, never arbitrary input paths.
        if name.contains('/') || name == "." || name == ".." {
            return None;
        }
        let path = Path::new("/sys/class/net").join(name);
        if path.join("wireless").is_dir() {
            return Some("Wi-Fi");
        }
        if std::fs::read_to_string(path.join("uevent"))
            .is_ok_and(|value| value.lines().any(|line| line == "DEVTYPE=wireguard"))
        {
            return Some("WireGuard");
        }
        // ARPHRD_NONE covers WireGuard and other layer-3 tunnels. Without an
        // explicit DEVTYPE, do not misidentify a different VPN as WireGuard.
        if std::fs::read_to_string(path.join("type")).is_ok_and(|value| value.trim() == "65534") {
            return Some("VPN / tunnel");
        }
    }
    let _ = name;
    None
}

/// Local wall-clock display only; timestamps used by actors remain untouched.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn local_datetime(unix_ms: u64) -> Option<String> {
    let seconds: libc::time_t = (unix_ms / 1000).try_into().ok()?;
    let mut output = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: both pointers are valid; localtime_r initializes output on success.
    if unsafe { libc::localtime_r(&seconds, output.as_mut_ptr()) }.is_null() {
        return None;
    }
    let output = unsafe { output.assume_init() };
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        i64::from(output.tm_year) + 1900,
        output.tm_mon + 1,
        output.tm_mday,
        output.tm_hour,
        output.tm_min,
        output.tm_sec
    ))
}
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn local_datetime(unix_ms: u64) -> Option<String> {
    use windows::Win32::{
        Foundation::{FILETIME, SYSTEMTIME},
        System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime},
    };
    let ticks = unix_ms
        .checked_mul(10_000)?
        .checked_add(116_444_736_000_000_000)?;
    let file = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: initialized inputs and valid output pointers; None selects OS zone.
    unsafe {
        FileTimeToSystemTime(&file, &mut utc).ok()?;
        SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).ok()?;
    }
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond
    ))
}
pub fn private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    // Share the Gateway's allowlist; no independent network validation rule.
    super::super::gateway::auth::lan_address(true, Some(&ip.to_string())).is_ok()
}
pub fn plugin_display_name(value: &str) -> Option<&str> {
    static CONTROLS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        // Surrogates (Cs) cannot occur in a Rust str.
        regex::Regex::new(r"[\p{Cc}\p{Cf}\u2028\u2029]").expect("fixed Unicode pattern")
    });
    let value =
        value.trim_matches(|c: char| c != '\u{0085}' && c.is_whitespace() || c == '\u{feff}');
    if !value.is_empty() && value.chars().count() <= 64 && !CONTROLS.is_match(value) {
        Some(value)
    } else {
        None
    }
}
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn os_hostname() -> Option<String> {
    let mut bytes = [0u8; 256];
    // SAFETY: gethostname writes at most the length of the supplied buffer.
    if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return None;
    }
    let end = bytes.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&bytes[..end])
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}
#[cfg(not(unix))]
pub fn os_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}
#[cfg(unix)]
#[allow(unsafe_code)] // libc owns getifaddrs allocation; only OS IPv4 records are read.
pub fn private_addresses() -> io::Result<Vec<PrivateAddress>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: valid out-pointer; success returns a linked list owned until freeifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _owned = Addresses(head);
    let mut current = head;
    let mut output = Vec::new();
    while !current.is_null() {
        // SAFETY: OS list remains allocated; sockaddr family is checked before casting.
        let item = unsafe { &*current };
        if item.ifa_flags & libc::IFF_LOOPBACK as u32 == 0
            && !item.ifa_addr.is_null()
            && !item.ifa_name.is_null()
            && unsafe { (*item.ifa_addr).sa_family as i32 } == libc::AF_INET
        {
            let raw = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in>() };
            let ip = std::net::Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes());
            if private_ipv4(ip) {
                let name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                output.push(PrivateAddress {
                    interface: name,
                    address: ip,
                });
            }
        }
        current = item.ifa_next;
    }
    output.sort_by(|a, b| (&a.interface, a.address).cmp(&(&b.interface, b.address)));
    output.dedup();
    Ok(output)
}
#[cfg(not(unix))]
pub fn private_addresses() -> io::Result<Vec<PrivateAddress>> {
    Ok(Vec::new())
}

/// A secret is never returned to the presentation layer. Only the existing
/// configure actor consumes its private temporary input, which is then removed.
pub fn configure_hidden_tunnel(
    state: &Path,
    tunnel: &str,
    input: &Path,
    fence: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let secret = hidden_line().map_err(|_| "hidden_tunnel_prompt_failed")?;
    write_new(input, secret.as_bytes()).map_err(|_| "private_tunnel_input_failed")?;
    let result = fence().and_then(|_| {
        crate::foreground::tunnel::configure(state, tunnel, input, true, true)
            .map(|_| ())
            .map_err(|e| e.code())
    });
    std::fs::remove_file(input).map_err(|_| "private_tunnel_input_cleanup_failed")?;
    result
}

#[cfg(unix)]
#[allow(unsafe_code)] // Thin termios adapter using the platform libc bindings.
fn hidden_line() -> io::Result<zeroize::Zeroizing<String>> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let fd = terminal.as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr initializes the provided termios on success.
    if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let original = unsafe { original.assume_init() };
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    hidden.c_cc[libc::VMIN] = 1;
    hidden.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { libc::tcsetattr(self.0, libc::TCSAFLUSH, &self.1) };
        }
    }
    let restore = Restore(fd, original);
    writeln!(&terminal, "Tunnel API key (input hidden):")?;
    let mut secret = zeroize::Zeroizing::new(String::new());
    let result = (|| {
        let mut reader = &terminal;
        loop {
            let mut byte = [0];
            reader.read_exact(&mut byte)?;
            match byte[0] {
                b'\r' | b'\n' => return Ok(()),
                3 | 4 => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "secure_input_cancelled",
                    ));
                }
                8 | 127 => {
                    secret.pop();
                }
                b if b.is_ascii() => {
                    if secret.len() == 65536 {
                        return Err(io::Error::other("bounded_secret_required"));
                    }
                    secret.push(char::from(b));
                }
                _ => return Err(io::Error::other("secure_input_invalid")),
            }
        }
    })();
    drop(restore);
    let _ = writeln!(&terminal);
    result?;
    if secret.len() > 65536 {
        return Err(io::Error::other("bounded_secret_required"));
    }
    while secret.ends_with(['\r', '\n']) {
        secret.pop();
    }
    Ok(secret)
}
#[cfg(windows)]
fn hidden_line() -> io::Result<zeroize::Zeroizing<String>> {
    // Read-Host uses the Windows console's secure input. The fixed script has no
    // interpolated input; its private pipe is consumed here and never logged.
    let output = std::process::Command::new("powershell.exe").args(["-NoProfile", "-Command", "$s=Read-Host -AsSecureString; $p=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try {[Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($p))} finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p)}"])
        .stdin(std::process::Stdio::inherit()).stderr(std::process::Stdio::null()).output()?;
    if !output.status.success() {
        return Err(io::Error::other("secure_input_unavailable"));
    }
    String::from_utf8(output.stdout)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| io::Error::other("secure_input_invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setup_private_addresses_exclude_loopback_link_local_and_public() {
        for ip in [
            "127.0.0.1",
            "169.254.1.2",
            "8.8.8.8",
            "0.0.0.0",
            "224.0.0.1",
            "100.128.0.1",
        ] {
            assert!(!private_ipv4(ip.parse().unwrap()));
        }
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1"] {
            assert!(private_ipv4(ip.parse().unwrap()));
        }
    }
    #[test]
    fn setup_suggestions_hide_container_bridges_without_hiding_wifi_or_vpn() {
        for name in [
            "docker0",
            "br-a12",
            "vethab",
            "virbr0",
            "cni0",
            "flannel.1",
            "podman0",
            "lxcbr0",
            "lxdbr0",
        ] {
            assert!(!suggested_interface(name), "{name}");
        }
        for name in ["eth1", "wlp4s0", "czy", "wg0", "tun0"] {
            assert!(suggested_interface(name), "{name}");
        }
        assert!(interface_kind("../etc").is_none());
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "setup_tests.rs"]
mod scenario_tests;

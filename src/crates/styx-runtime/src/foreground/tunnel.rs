//! Secure MCP Tunnel configuration and Gateway-owned transport supervision.
//! Only the selected signed release supplies an executable. No MCP request is replayed.
use super::ForegroundError;
use crate::store::{PinnedExecutable, PrivateRoot};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::Arc,
    time::Duration,
};
use styx_contracts::native_release::NativeExternalWorker;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const RETRY: Duration = Duration::from_secs(15);
const OBSERVATION_HEADER: &str = "X-Styx-Tunnel-Observation: file:";

/// Diagnostics only. A per-process random marker is supplied in the signed
/// tunnel client's forwarding headers, never its discovery headers. It does
/// not authorize requests or introduce conversation/owner authority.
pub(crate) struct RequestObservation {
    marker: Zeroizing<Vec<u8>>,
    path: PathBuf,
    root: PrivateRoot,
    counters: std::sync::Mutex<(u64, Option<u64>)>,
}
impl RequestObservation {
    pub(crate) fn record(&self, marker: &[u8]) {
        if aws_lc_rs::constant_time::verify_slices_are_equal(marker, &self.marker).is_err() {
            return;
        }
        let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            return;
        };
        let Ok(now) = u64::try_from(now.as_millis()) else {
            return;
        };
        let mut count = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        count.0 = count.0.saturating_add(1);
        count.1 = Some(now);
        if let Ok(bytes) = serde_json::to_vec(
            &serde_json::json!({"schema":1,"requests":count.0,"last_seen_unix_ms":count.1}),
        ) {
            let _ = atomic_write(&self.path, &self.root, "request-observation.json", &bytes);
        }
    }
}
pub(crate) fn observe_requests(state: &Path) -> Result<Option<Arc<RequestObservation>>> {
    let Some((path, root)) = directory(state, false)? else {
        return Ok(None);
    };
    if connection(&root)?.is_none() {
        return Ok(None);
    }
    let old = request_observation(state)?;
    let marker = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string().into_bytes());
    atomic_write(&path, &root, "request-marker", &marker)?;
    Ok(Some(Arc::new(RequestObservation {
        marker,
        path,
        root,
        counters: std::sync::Mutex::new((
            old["requests"].as_u64().unwrap_or(0),
            old["last_seen_unix_ms"].as_u64(),
        )),
    })))
}
/// Private metadata only: no request body, headers, account or conversation ID.
pub fn request_observation(state: &Path) -> Result<serde_json::Value> {
    let empty = || serde_json::json!({"schema":1,"requests":0,"last_seen_unix_ms":null});
    let Some((_, root)) = directory(state, false)? else {
        return Ok(empty());
    };
    if root.ensure_absent("request-observation.json").is_ok() {
        return Ok(empty());
    }
    let raw = root
        .read_raw("request-observation.json", 1024)
        .map_err(|_| error("tunnel_observation_unavailable"))?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Observation {
        schema: u16,
        requests: u64,
        last_seen_unix_ms: Option<u64>,
    }
    let value: Observation =
        serde_json::from_slice(raw.bytes()).map_err(|_| error("tunnel_observation_invalid"))?;
    if value.schema != 1 {
        return Err(error("tunnel_observation_invalid"));
    }
    Ok(
        serde_json::json!({"schema":1,"requests":value.requests,"last_seen_unix_ms":value.last_seen_unix_ms}),
    )
}
#[cfg(unix)]
const STOP_TIMEOUT: Duration = Duration::from_secs(4);
type Result<T> = std::result::Result<T, ForegroundError>;
pub fn worker_error() -> ForegroundError {
    error("tunnel_configuration_worker_failed")
}
fn error(code: &'static str) -> ForegroundError {
    ForegroundError(code)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Connection {
    schema: u32,
    tunnel_id: String,
    key_file: String,
    auto_start: bool,
}
impl Connection {
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || !identifier(&self.tunnel_id, "tunnel_", 8, 128)
            || self.key_file.len() != 36
            || !self.key_file.starts_with("key-")
            || !self.key_file[4..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(error("invalid_tunnel_configuration"));
        }
        Ok(())
    }
}
fn identifier(value: &str, prefix: &str, min: usize, max: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|tail| {
        (min..=max).contains(&tail.len())
            && tail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    })
}
fn read_secret(path: &Path) -> Result<Zeroizing<String>> {
    let root = PrivateRoot::open(path.parent().ok_or(error("private_tunnel_file_required"))?)
        .map_err(|_| error("private_tunnel_file_required"))?;
    let raw = root
        .read_raw(
            Path::new(
                path.file_name()
                    .ok_or(error("private_tunnel_file_required"))?,
            ),
            65536,
        )
        .map_err(|_| error("private_tunnel_file_required"))?;
    String::from_utf8(raw.bytes().to_vec())
        .map(Zeroizing::new)
        .map_err(|_| error("invalid_tunnel_secret"))
}
fn directory(state: &Path, create: bool) -> Result<Option<(PathBuf, PrivateRoot)>> {
    if !state.is_absolute() {
        return Err(error("absolute_state_directory_required"));
    }
    let parent = PrivateRoot::open(state).map_err(|_| error("tunnel_protected_read"))?;
    let path = state.join("tunnel");
    if !path
        .try_exists()
        .map_err(|_| error("tunnel_protected_read"))?
    {
        if !create {
            return Ok(None);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(error("tunnel_protected_write")),
            }
        }
        #[cfg(target_os = "windows")]
        parent
            .open_or_create_private_child("tunnel")
            .map_err(|_| error("tunnel_protected_write"))?;
        #[cfg(not(any(unix, target_os = "windows")))]
        return Err(error("tunnel_platform_unsupported"));
    }
    drop(parent);
    let root = PrivateRoot::open(&path).map_err(|_| error("tunnel_protected_read"))?;
    Ok(Some((path, root)))
}
fn connection(root: &PrivateRoot) -> Result<Option<Connection>> {
    if root.ensure_absent("connection.json").is_ok() {
        return Ok(None);
    }
    let raw = root
        .read_raw("connection.json", 4096)
        .map_err(|_| error("invalid_tunnel_configuration"))?;
    let c: Connection =
        serde_json::from_slice(raw.bytes()).map_err(|_| error("invalid_tunnel_configuration"))?;
    c.validate()?;
    let key = root
        .read_raw(&c.key_file, 1024)
        .map_err(|_| error("invalid_tunnel_runtime_key"))?;
    if !std::str::from_utf8(key.bytes()).is_ok_and(|v| identifier(v, "sk-", 16, 512)) {
        return Err(error("invalid_tunnel_runtime_key"));
    }
    Ok(Some(c))
}
fn atomic_write(path: &Path, root: &PrivateRoot, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = format!("tmp-{}", uuid::Uuid::new_v4().simple());
    root.create_pairing_invitation(std::ffi::OsStr::new(&temporary), bytes)
        .map_err(|_| error("tunnel_protected_write"))?;
    let result = fs::rename(path.join(&temporary), path.join(name))
        .map_err(|_| error("tunnel_protected_write"));
    if result.is_err() {
        let _ = fs::remove_file(path.join(&temporary));
    }
    result?;
    #[cfg(unix)]
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| error("tunnel_protected_write"))?;
    Ok(())
}
fn open_file(path: &Path, write: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}
fn owner(path: &Path, root: &PrivateRoot) -> Result<File> {
    if root.ensure_absent("owner.lock").is_ok() {
        // Exclusive publication; a concurrent creator may win, then we open its lock.
        let _ = root.create_pairing_invitation(std::ffi::OsStr::new("owner.lock"), b"tunnel\n");
    }
    root.read_raw("owner.lock", 64)
        .map_err(|_| error("tunnel_protected_read"))?;
    let file =
        open_file(&path.join("owner.lock"), true).map_err(|_| error("tunnel_protected_read"))?;
    file.try_lock()
        .map_err(|_| error("tunnel_running_or_busy"))?;
    Ok(file)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    schema: u32,
    status: &'static str,
    tunnel_id: Option<String>,
    auto_start: bool,
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<&'static str>,
}
fn projection(c: Option<Connection>, available: bool) -> TunnelStatus {
    TunnelStatus {
        schema: 1,
        status: if c.is_some() {
            "configured"
        } else {
            "not_configured"
        },
        auto_start: c.as_ref().is_some_and(|c| c.auto_start),
        tunnel_id: c.map(|c| c.tunnel_id),
        available,
        transport: None,
    }
}

pub fn configure(
    state: &Path,
    tunnel_id: &str,
    api_key_file: &Path,
    auto_start: bool,
    authorize: bool,
) -> Result<TunnelStatus> {
    if !authorize {
        return Err(error("explicit_tunnel_authorization_required"));
    }
    if !identifier(tunnel_id, "tunnel_", 8, 128) {
        return Err(error("invalid_tunnel_id"));
    }
    if !api_key_file.is_absolute() {
        return Err(error("private_tunnel_file_required"));
    }
    let secret = read_secret(api_key_file)?;
    let secret = secret.trim_end_matches(['\r', '\n']);
    if !identifier(secret, "sk-", 16, 512) {
        return Err(error("invalid_tunnel_runtime_key"));
    }
    let (path, root) = directory(state, true)?.ok_or(error("tunnel_protected_write"))?;
    let _owner = owner(&path, &root)?;
    let old = connection(&root)?;
    let c = Connection {
        schema: 1,
        tunnel_id: tunnel_id.into(),
        key_file: format!("key-{}", uuid::Uuid::new_v4().simple()),
        auto_start,
    };
    atomic_write(&path, &root, &c.key_file, secret.as_bytes())?;
    let raw = serde_json::to_vec(&c).map_err(|_| error("invalid_tunnel_configuration"))?;
    // Preserve the key if rename succeeded but durability confirmation failed.
    atomic_write(&path, &root, "connection.json", &raw)?;
    if let Some(old) = old {
        fs::remove_file(path.join(old.key_file))
            .map_err(|_| error("tunnel_old_key_removal_failed"))?;
    }
    Ok(projection(Some(c), available(state)))
}
pub fn remove(state: &Path, authorize: bool) -> Result<TunnelStatus> {
    if !authorize {
        return Err(error("explicit_tunnel_authorization_required"));
    }
    if let Some((path, root)) = directory(state, false)? {
        let _owner = owner(&path, &root)?;
        if let Some(c) = connection(&root)? {
            fs::remove_file(path.join("connection.json"))
                .map_err(|_| error("tunnel_protected_write"))?;
            fs::remove_file(path.join(c.key_file)).map_err(|_| error("tunnel_protected_write"))?;
        }
        for name in ["gateway-header", "health.url"] {
            if path
                .join(name)
                .try_exists()
                .map_err(|_| error("tunnel_protected_read"))?
            {
                fs::remove_file(path.join(name)).map_err(|_| error("tunnel_protected_write"))?;
            }
        }
    }
    Ok(projection(None, available(state)))
}
// Read-only C07 selection validation, including its committed journal tip. A
// user-supplied path or an unsigned status file can never select an executable.
fn selected_release(state: &Path) -> Result<crate::release::VerifiedNativeRelease> {
    use crate::store::{native_host_snapshot::validated_runtime_selection, native_state};
    let root = PrivateRoot::open(state).map_err(|_| error("tunnel_protected_read"))?;
    let marker_raw = root
        .read_raw(".styx-native-root-v1.json", 4096)
        .map_err(|_| error("tunnel_protected_read"))?;
    let marker = native_state::decode_marker(marker_raw.bytes())
        .map_err(|_| error("tunnel_protected_read"))?;
    let raw = root
        .read_raw("state.json", 1024 * 1024)
        .map_err(|_| error("tunnel_protected_read"))?;
    let canonical = native_state::decode_state(raw.bytes(), &marker)
        .map_err(|_| error("tunnel_protected_read"))?;
    let selection = validated_runtime_selection(&root, &canonical, &marker)
        .map_err(|_| error("tunnel_protected_read"))?;
    crate::release::verify_selected(&selection).map_err(|_| error("tunnel_client_unavailable"))
}
fn available(state: &Path) -> bool {
    selected_release(state).is_ok_and(|release| {
        release
            .worker_image(NativeExternalWorker::TunnelClient)
            .is_ok()
    })
}
fn read_status(state: &Path) -> Result<(TunnelStatus, Option<PathBuf>)> {
    let Some((path, root)) = directory(state, false)? else {
        return Ok((projection(None, available(state)), None));
    };
    let mut status = projection(connection(&root)?, available(state));
    // Only the live lock held by this Gateway's supervisor admits a health probe.
    if root.ensure_absent("owner.lock").is_err() {
        let file = open_file(&path.join("owner.lock"), true)
            .map_err(|_| error("tunnel_protected_read"))?;
        if !file
            .metadata()
            .map_err(|_| error("tunnel_protected_read"))?
            .is_file()
        {
            return Err(error("tunnel_protected_read"));
        }
        match file.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) => {
                // Windows byte-range locks also prevent reading the lock's
                // contents through a second handle. No persisted PID is used.
                status.transport = Some("starting");
                return Ok((status, Some(path)));
            }
            Err(_) => return Err(error("tunnel_protected_read")),
            Ok(()) => (),
        }
    }
    Ok((status, None))
}
pub async fn status(state: &Path) -> Result<TunnelStatus> {
    let state = state.to_path_buf();
    let (mut status, path) = tokio::task::spawn_blocking(move || read_status(&state))
        .await
        .map_err(|_| worker_error())??;
    if let Some(path) = path
        && path.join("health.url").exists()
    {
        status.transport = Some(health(&path).await);
    }
    Ok(status)
}
/// Only this module constructs the fixed tunnel argv. Native spawn adapters
/// accept this type rather than a caller-selected command or arbitrary flags.
#[derive(Clone)]
pub(crate) struct Arguments(Vec<OsString>);
impl Arguments {
    #[cfg(any(test, target_os = "windows"))]
    pub(crate) fn as_slice(&self) -> &[OsString] {
        &self.0
    }
}

fn arguments(c: &Connection, state: &Path, port: u16) -> Arguments {
    let tunnel = state.join("tunnel");
    Arguments(vec![
        "run".into(),
        "--control-plane.tunnel-id".into(),
        c.tunnel_id.clone().into(),
        "--control-plane.api-key".into(),
        file_reference("file:", &tunnel.join(&c.key_file)),
        "--mcp.server-url".into(),
        format!("https://127.0.0.1:{port}/mcp").into(),
        "--ca-bundle".into(),
        state.join("gateway-ca.pem").into_os_string(),
        "--mcp.extra-headers".into(),
        file_reference("Authorization: file:", &tunnel.join("gateway-header")),
        "--mcp.discovery-extra-headers".into(),
        file_reference("Authorization: file:", &tunnel.join("gateway-header")),
        "--health.listen-addr".into(),
        "127.0.0.1:0".into(),
        "--health.url-file".into(),
        tunnel.join("health.url").into_os_string(),
        "--log.format".into(),
        "json".into(),
        "--log.level".into(),
        "warn".into(),
    ])
}
fn file_reference(prefix: &str, path: &Path) -> OsString {
    let mut value = OsString::from(prefix);
    value.push(path);
    value
}
fn environment(path: &Path) -> Result<BTreeMap<OsString, OsString>> {
    let mut env = BTreeMap::new();
    #[cfg(target_os = "windows")]
    {
        let inherited = super::windows_env::executor_environment(&BTreeMap::new(), path)?;
        env.extend(inherited.into_iter().map(|(k, v)| (k.into(), v.into())));
        // All profile/config/temp inputs belong to this tunnel, not the OS user profile.
        for key in ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"] {
            env.insert(key.into(), path.as_os_str().into());
        }
    }
    #[cfg(not(target_os = "windows"))]
    env.insert("PATH".into(), "/usr/bin:/bin".into());
    env.insert("HOME".into(), path.as_os_str().into());
    env.insert("XDG_CONFIG_HOME".into(), path.as_os_str().into());
    Ok(env)
}
async fn health(path: &Path) -> &'static str {
    let url = (|| -> Option<url::Url> {
        let mut file = open_file(&path.join("health.url"), false).ok()?;
        if !file.metadata().ok()?.is_file() || file.metadata().ok()?.len() > 2048 {
            return None;
        }
        let mut raw = String::new();
        file.read_to_string(&mut raw).ok()?;
        let url = url::Url::parse(raw.trim()).ok()?;
        (url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && matches!(url.path(), "/" | "/healthz" | "/readyz"))
        .then_some(url)
    })();
    let Some(url) = url else {
        return "unavailable";
    };
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(1500))
        .build()
    else {
        return "unavailable";
    };
    let (live, ready) = tokio::join!(
        client.get(url.join("/healthz").expect("fixed URL")).send(),
        client.get(url.join("/readyz").expect("fixed URL")).send()
    );
    match (live, ready) {
        (Ok(live), Ok(ready)) if live.status() == 200 && ready.status() == 200 => "ready",
        (Ok(live), _) if live.status() == 200 => "starting",
        _ => "unavailable",
    }
}
#[derive(Serialize)]
struct TunnelEvent {
    schema: u32,
    event: &'static str,
    exit_code: Option<i32>,
}
fn emit(stop: &CancellationToken, event: &'static str, exit_code: Option<i32>) {
    // Same stdout JSON-lines contract as foreground events. Never forward raw client logs.
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer(
        &mut out,
        &TunnelEvent {
            schema: 1,
            event,
            exit_code,
        },
    )
    .is_err()
        || out.write_all(b"\n").is_err()
        || out.flush().is_err()
    {
        stop.cancel();
    }
}

#[derive(Clone)]
enum Image {
    Native(Arc<PinnedExecutable>),
    #[cfg(all(test, target_os = "linux"))]
    Fake(PathBuf),
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
type Process = tokio::process::Child;
#[cfg(target_os = "macos")]
type Process = crate::platform::macos_spawn::RunningChild;
#[cfg(target_os = "windows")]
type Process = crate::platform::windows_spawn::RunningChild;

struct Child {
    process: Process,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    readers: Vec<tokio::task::JoinHandle<std::io::Result<u64>>>,
}
impl Child {
    async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let exit = self.process.wait().await?;
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        while let Some(reader) = self.readers.last_mut() {
            let _ = reader.await;
            self.readers.pop();
        }
        Ok(exit)
    }
}

async fn spawn(image: &Image, args: Arguments, path: &Path) -> Result<Child> {
    let env = environment(path)?;
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let binary = match image {
            Image::Native(image) => image
                .launch_path()
                .map_err(|_| error("tunnel_client_integrity_failed"))?,
            #[cfg(all(test, target_os = "linux"))]
            Image::Fake(path) => path.clone(),
        };
        let mut command = tokio::process::Command::new(binary);
        command
            .args(args.0)
            .current_dir(path)
            .env_clear()
            .envs(env)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        command
            .spawn()
            .map(|process| Child { process })
            .map_err(|_| error("tunnel_client_start_failed"))
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let Image::Native(image) = image;
        let image = image.clone();
        let cwd = path.to_path_buf();
        let started = tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "macos")]
            let suspended = crate::platform::macos_spawn::spawn_suspended(image, args.0, cwd, env);
            #[cfg(target_os = "windows")]
            let suspended = {
                let budget = Arc::new(tokio::sync::Semaphore::new(1))
                    .try_acquire_owned()
                    .expect("one Gateway-owned startup slot");
                crate::platform::windows_spawn::spawn_tunnel_suspended(
                    image,
                    Arc::new(budget),
                    cwd,
                    env,
                    args,
                )
            };
            suspended.and_then(|child| child.verify_and_resume())
        })
        .await
        .map_err(|_| error("tunnel_client_start_failed"))?;
        let mut process = match started {
            Ok(child) => child,
            Err(failure) => {
                if let Some(mut child) = failure.into_owned_child() {
                    child
                        .terminate_and_wait()
                        .await
                        .map_err(|_| error("tunnel_stop_unknown"))?;
                }
                return Err(error("tunnel_client_start_failed"));
            }
        };
        // Drain and discard native pipes; never log upstream output or leave
        // detached readers behind when the Gateway finishes its joined stop.
        let mut readers = Vec::new();
        if let Some(mut stream) = process.take_stdout() {
            readers.push(tokio::spawn(async move {
                tokio::io::copy(&mut stream, &mut tokio::io::sink()).await
            }));
        }
        if let Some(mut stream) = process.take_stderr() {
            readers.push(tokio::spawn(async move {
                tokio::io::copy(&mut stream, &mut tokio::io::sink()).await
            }));
        }
        drop(process.take_stdin());
        Ok(Child { process, readers })
    }
}
async fn terminate(child: &mut Child) -> Result<ExitStatus> {
    #[cfg(unix)]
    {
        #[cfg(not(target_os = "macos"))]
        if let Some(pid) = child.process.id() {
            // The owned Tokio child is not reaped while this call holds &mut.
            // No persisted PID or external process name participates in stopping it.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        #[cfg(target_os = "macos")]
        child
            .process
            .request_terminate()
            .map_err(|_| error("tunnel_stop_unknown"))?;
        if let Ok(result) = tokio::time::timeout(STOP_TIMEOUT, child.wait()).await {
            return result.map_err(|_| error("tunnel_stop_unknown"));
        }
    }
    child
        .process
        .start_kill()
        .map_err(|_| error("tunnel_stop_unknown"))?;
    child.wait().await.map_err(|_| error("tunnel_stop_unknown"))
}

pub(super) fn unavailable(stop: &CancellationToken) {
    emit(stop, "tunnel_unavailable", None);
}
pub(super) fn start(
    state: PathBuf,
    port: u16,
    release: Arc<crate::release::VerifiedNativeRelease>,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let result = run(state, port, release, stop.clone()).await;
        if result.is_err() {
            unavailable(&stop);
        }
        result
    })
}
struct Prepared {
    path: PathBuf,
    _root: PrivateRoot,
    _owner: File,
    image: Arc<PinnedExecutable>,
    arguments: Arguments,
}
fn prepare(
    state: &Path,
    port: u16,
    release: &crate::release::VerifiedNativeRelease,
) -> Result<Option<Prepared>> {
    let Some((path, root)) = directory(state, false)? else {
        return Ok(None);
    };
    let owner = owner(&path, &root)?;
    let Some(c) = connection(&root)? else {
        return Ok(None);
    };
    if !c.auto_start {
        return Ok(None);
    }
    let image = Arc::new(
        release
            .pin_worker(NativeExternalWorker::TunnelClient)
            .map_err(|_| error("tunnel_client_unavailable"))?,
    );
    let token = read_secret(&state.join("gateway-model.token"))?;
    let token = token.trim_end_matches(['\r', '\n']);
    if !(32..=4096).contains(&token.len())
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(error("invalid_gateway_model_credential"));
    }
    let header = Zeroizing::new(format!("Bearer {token}"));
    atomic_write(&path, &root, "gateway-header", header.as_bytes())?;
    let mut args = arguments(&c, state, port);
    // Only real forwarded MCP traffic has the observation marker. The client's
    // automatic startup discovery still uses its separate original headers.
    if root.ensure_absent("request-marker").is_err() {
        root.read_raw("request-marker", 128)
            .map_err(|_| error("tunnel_observation_unavailable"))?;
        args.0.extend([
            "--mcp.extra-headers".into(),
            file_reference(OBSERVATION_HEADER, &path.join("request-marker")),
        ]);
    }
    Ok(Some(Prepared {
        path,
        _root: root,
        _owner: owner,
        image,
        arguments: args,
    }))
}
/// Pins and the original release remain retained until this task reaps its last
/// child. Gateway joins it on every stop, including listener/control failures.
pub(super) async fn run(
    state: PathBuf,
    port: u16,
    release: Arc<crate::release::VerifiedNativeRelease>,
    stop: CancellationToken,
) -> Result<()> {
    if !release
        .manifest()
        .worker_closures
        .iter()
        .any(|worker| worker.kind == NativeExternalWorker::TunnelClient)
    {
        unavailable(&stop);
        return Ok(());
    }
    let original = release.clone();
    let prepared = tokio::task::spawn_blocking(move || prepare(&state, port, &original))
        .await
        .map_err(|_| error("tunnel_configuration_worker_failed"))??;
    let Some(prepared) = prepared else {
        return Ok(());
    };
    let result = supervise(
        Image::Native(prepared.image),
        prepared.arguments,
        &prepared.path,
        stop,
    )
    .await;
    // Do not release the lock or original verified release before actual child wait.
    for name in ["health.url", "gateway-header"] {
        let _ = fs::remove_file(prepared.path.join(name));
    }
    result
}

async fn supervise(
    image: Image,
    args: Arguments,
    path: &Path,
    stop: CancellationToken,
) -> Result<()> {
    while !stop.is_cancelled() {
        if path.join("health.url").symlink_metadata().is_ok() {
            fs::remove_file(path.join("health.url"))
                .map_err(|_| error("tunnel_protected_write"))?;
        }
        match spawn(&image, args.clone(), path).await {
            Ok(mut child) => {
                emit(&stop, "tunnel_started", None);
                let mut ready = false;
                let mut interval = tokio::time::interval(Duration::from_millis(250));
                let result = loop {
                    tokio::select! {
                        biased;
                        _ = stop.cancelled() => break terminate(&mut child).await,
                        result = child.wait() => break result.map_err(|_| error("tunnel_wait_unknown")),
                        _ = interval.tick(), if !ready => {
                            // Health checks are bounded and cancellable; a probe cannot delay stop.
                            let transport = tokio::select! {
                                biased;
                                _ = stop.cancelled() => continue,
                                result = health(path) => result,
                            };
                            if transport == "ready" { ready = true; emit(&stop, "tunnel_ready", None); }
                        }
                    }
                };
                let exit = result?;
                let _ = fs::remove_file(path.join("health.url"));
                emit(&stop, "tunnel_exited", exit.code());
            }
            Err(failure) if failure.code() == "tunnel_stop_unknown" => return Err(failure),
            Err(_) => emit(&stop, "tunnel_start_failed", None),
        }
        // Retry only the transport process. Never replay a queued MCP operation.
        tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(RETRY) => () }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("styx-tunnel-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn config() -> Connection {
        Connection {
            schema: 1,
            tunnel_id: "tunnel_abcdefgh".into(),
            key_file: format!("key-{}", "a".repeat(32)),
            auto_start: true,
        }
    }
    #[test]
    fn tunnel_arguments_match_v0_0_17_exactly() {
        let actual = arguments(&config(), Path::new("/private/gateway"), 8795);
        let expected = vec![
            "run",
            "--control-plane.tunnel-id",
            "tunnel_abcdefgh",
            "--control-plane.api-key",
            "file:/private/gateway/tunnel/key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--mcp.server-url",
            "https://127.0.0.1:8795/mcp",
            "--ca-bundle",
            "/private/gateway/gateway-ca.pem",
            "--mcp.extra-headers",
            "Authorization: file:/private/gateway/tunnel/gateway-header",
            "--mcp.discovery-extra-headers",
            "Authorization: file:/private/gateway/tunnel/gateway-header",
            "--health.listen-addr",
            "127.0.0.1:0",
            "--health.url-file",
            "/private/gateway/tunnel/health.url",
            "--log.format",
            "json",
            "--log.level",
            "warn",
        ];
        assert_eq!(
            actual.0,
            expected.into_iter().map(OsString::from).collect::<Vec<_>>()
        );
        let env = environment(Path::new("/private/gateway/tunnel")).unwrap();
        assert_eq!(
            env.keys().map(|v| v.to_str().unwrap()).collect::<Vec<_>>(),
            ["HOME", "PATH", "XDG_CONFIG_HOME"]
        );
    }
    #[tokio::test]
    async fn tunnel_configuration_authorization_validation_rotation_and_redaction() {
        let dir = Temporary::new();
        let key = dir.0.join("input-key");
        let secret = "sk-abcdefghijklmnop";
        private(&key, secret.as_bytes());
        assert_eq!(
            configure(&dir.0, "tunnel_abcdefgh", &key, true, false)
                .err()
                .unwrap()
                .code(),
            "explicit_tunnel_authorization_required"
        );
        assert!(!dir.0.join("tunnel").exists());
        for id in [
            "tunnel_short",
            "tunnel_abcdefgh/",
            "tunnel_abcdefgh\n",
            "other_abcdefgh",
        ] {
            assert!(configure(&dir.0, id, &key, false, true).is_err());
        }
        for invalid in [
            "sk-short",
            "sk-abcdefghijklmnop!",
            "sk-abcdefghijklmnop\nINJECT",
        ] {
            private(&key, invalid.as_bytes());
            assert!(configure(&dir.0, "tunnel_abcdefgh", &key, true, true).is_err());
        }
        private(&key, secret.as_bytes());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(configure(&dir.0, "tunnel_abcdefgh", &key, true, true).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let report = configure(&dir.0, "tunnel_abcdefgh", &key, true, true).unwrap();
        assert!(!serde_json::to_string(&report).unwrap().contains(secret));
        let path = dir.0.join("tunnel");
        let root = PrivateRoot::open(&path).unwrap();
        let old = connection(&root).unwrap().unwrap();
        assert_eq!(
            fs::read_to_string(path.join(&old.key_file)).unwrap(),
            secret
        );
        for name in ["connection.json", &old.key_file] {
            assert_eq!(
                fs::metadata(path.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        configure(&dir.0, "tunnel_ijklmnop", &key, false, true).unwrap();
        assert!(!path.join(old.key_file).exists());
        let report = status(&dir.0).await.unwrap();
        assert_eq!(report.tunnel_id.as_deref(), Some("tunnel_ijklmnop"));
        assert!(!report.auto_start);
        assert!(!report.available);
        let held = owner(&path, &root).unwrap();
        assert_eq!(status(&dir.0).await.unwrap().transport, Some("starting"));
        private(&path.join("health.url"), b"http://untrusted.invalid:8080/");
        assert_eq!(status(&dir.0).await.unwrap().transport, Some("unavailable"));
        assert!(remove(&dir.0, true).is_err());
        assert!(configure(&dir.0, "tunnel_abcdefgh", &key, true, true).is_err());
        drop(held);
        assert!(remove(&dir.0, false).is_err());
        assert_eq!(remove(&dir.0, true).unwrap().status, "not_configured");
        assert!(!path.join("connection.json").exists());
        assert!(
            !fs::read_dir(&path).unwrap().any(|f| f
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("key-"))
        );
        assert!(key.exists()); // Only the old managed copy is removed, never the input.
        for c in [
            Connection {
                schema: 2,
                ..config()
            },
            Connection {
                key_file: "../input-key".into(),
                ..config()
            },
            Connection {
                tunnel_id: "bad".into(),
                ..config()
            },
        ] {
            assert!(c.validate().is_err());
        }
    }
    #[tokio::test]
    async fn tunnel_fake_client_exact_argv_restarts_after_15_seconds_and_is_reaped_on_stop() {
        let dir = Temporary::new();
        let script = dir.0.join("fake-client");
        // This test deliberately needs no socket permission. Independent process
        // effects prove arguments, cleared environment, restart, TERM and wait.
        private(
            &script,
            br#"#!/usr/bin/python3
import json, os, signal, sys, time
with open('calls.jsonl', 'a') as out:
    out.write(json.dumps({'argv':sys.argv[1:], 'env':dict(os.environ), 'pid':os.getpid()})+'\n')
if not os.path.exists('once'):
    open('once', 'w').close()
    sys.exit(23)
def stop(*_):
    open('terminated', 'w').write(str(os.getpid()))
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
open('running', 'w').write(str(os.getpid()))
while True: time.sleep(0.05)
"#,
        );
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let args = arguments(&config(), &dir.0, 8795);
        let expected = args
            .as_slice()
            .iter()
            .map(|s| s.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let stop = CancellationToken::new();
        let original_stop = stop.clone();
        let path = dir.0.clone();
        let start = std::time::Instant::now();
        let task = tokio::spawn(async move {
            supervise(Image::Fake(script), args, &path, original_stop).await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        while !dir.0.join("running").exists() {
            if tokio::time::Instant::now() > deadline {
                stop.cancel();
                task.await.unwrap().unwrap();
                panic!("fake tunnel did not restart");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        stop.cancel();
        task.await.unwrap().unwrap();
        assert!(start.elapsed() >= RETRY);
        let calls = fs::read_to_string(dir.0.join("calls.jsonl")).unwrap();
        let calls = calls
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2);
        for call in &calls {
            assert_eq!(call["argv"], serde_json::json!(expected));
            assert_eq!(call["env"]["HOME"], dir.0.to_str().unwrap());
            for name in call["env"].as_object().unwrap().keys() {
                assert!(["HOME", "XDG_CONFIG_HOME", "PATH", "LC_CTYPE"].contains(&name.as_str()));
            }
            let pid = call["pid"].as_i64().unwrap() as i32;
            assert_eq!(
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
                Err(nix::errno::Errno::ESRCH)
            );
        }
        assert!(dir.0.join("terminated").exists());
    }
    #[tokio::test]
    async fn tunnel_health_requires_both_endpoints_and_observes_recovery_requires_loopback_sockets()
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = Temporary::new();
        // Requires loopback socket permission; run this unchanged on the review machine.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("requires loopback sockets (sandbox may deny bind)");
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        private(
            &dir.0.join("health.url"),
            format!("http://{}/", listener.local_addr().unwrap()).as_bytes(),
        );
        let state = ready.clone();
        let requests = observed.clone();
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut raw = [0u8; 2048];
                let n = socket.read(&mut raw).await.unwrap();
                let request = std::str::from_utf8(&raw[..n]).unwrap();
                let path = request.split_whitespace().nth(1).unwrap().to_owned();
                let code = if path == "/healthz" || state.load(std::sync::atomic::Ordering::SeqCst)
                {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                };
                requests.lock().unwrap().push(path);
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {code}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        assert_eq!(health(&dir.0).await, "starting");
        ready.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(health(&dir.0).await, "ready");
        server.await.unwrap();
        let routes = observed.lock().unwrap();
        assert_eq!(
            routes
                .iter()
                .filter(|route| route.as_str() == "/healthz")
                .count(),
            2
        );
        assert_eq!(
            routes
                .iter()
                .filter(|route| route.as_str() == "/readyz")
                .count(),
            2
        );
    }
    #[tokio::test]
    async fn tunnel_stop_kills_and_waits_after_grace_period_and_cancels_retry() {
        let dir = Temporary::new();
        let script = dir.0.join("fake-client");
        private(&script, b"#!/usr/bin/python3\nimport os, signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nopen('running','w').write(str(os.getpid()))\nwhile True: time.sleep(0.05)\n");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let stop = CancellationToken::new();
        let child_stop = stop.clone();
        let path = dir.0.clone();
        let task = tokio::spawn(async move {
            supervise(Image::Fake(script), Arguments(vec![]), &path, child_stop).await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !dir.0.join("running").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid = fs::read_to_string(dir.0.join("running"))
            .unwrap()
            .parse()
            .unwrap();
        let started = std::time::Instant::now();
        stop.cancel();
        task.await.unwrap().unwrap();
        assert!(started.elapsed() >= STOP_TIMEOUT);
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
        // A cancelled Gateway never waits out or re-enters the restart delay.
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        supervise(
            Image::Fake(dir.0.join("missing")),
            Arguments(vec![]),
            &dir.0,
            cancelled,
        )
        .await
        .unwrap();
    }
    async fn gateway_fixture(parent: &Path, port: u16, worker: bool, auto_start: bool) -> PathBuf {
        // Gateway bootstrap admits one job per process; parallel tests take turns.
        static FIXTURES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _turn = FIXTURES.lock().await;
        use crate::management::{native, native_gateway};
        use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePublicKey};
        use styx_contracts::identity::Sha256Digest;
        use styx_contracts::native_management::NativeRunDesired;
        let payload = parent.join("payload");
        fs::create_dir(&payload).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(payload.join("bin")).unwrap();
        fs::set_permissions(payload.join("bin"), fs::Permissions::from_mode(0o700)).unwrap();
        private(
            &payload.join("bin/styx"),
            &fs::read("/usr/bin/true").unwrap(),
        );
        fs::set_permissions(payload.join("bin/styx"), fs::Permissions::from_mode(0o700)).unwrap();
        private(&payload.join("LICENSE"), b"fixture license");
        private(&payload.join("source-inputs.json"), b"{}");
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let pin = crate::crypto::PublisherVerifyingKey::from_spki_pem(public.as_bytes())
            .unwrap()
            .fingerprint()
            .unwrap();
        let publisher = parent.join("publisher.pem");
        private(&publisher, public.as_bytes());
        let mut paths = vec![
            ("bin/styx", true),
            ("LICENSE", false),
            ("source-inputs.json", false),
        ];
        if worker {
            let path = payload.join("workers/tunnel-client");
            fs::create_dir(payload.join("workers")).unwrap();
            fs::set_permissions(payload.join("workers"), fs::Permissions::from_mode(0o700))
                .unwrap();
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let source = parent.join("fake.c");
            private(&source, br#"#include <stdio.h>
#include <unistd.h>
#include <signal.h>
static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }
int main(int argc, char **argv) {
    char name[80]; snprintf(name, sizeof(name), "argv-%d", getpid());
    FILE *out = fopen(name, "w"); if (!out) return 80;
    for (int i = 1; i < argc; i++) fprintf(out, "%s\n", argv[i]); fclose(out);
    FILE *once = fopen("once", "r");
    if (!once) { once = fopen("once", "w"); if (!once) return 81; fclose(once); return 23; }
    fclose(once); signal(SIGTERM, stop);
    out = fopen("running", "w"); if (!out) return 82; fprintf(out, "%d", getpid()); fclose(out);
    while (!stopped) usleep(10000);
    out = fopen("terminated", "w"); if (!out) return 83; fprintf(out, "%d", getpid()); fclose(out); return 0;
}
"#);
            let binary = path.join("tunnel-client-runtime");
            assert!(
                std::process::Command::new("/usr/bin/cc")
                    .arg(&source)
                    .arg("-o")
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
            private(&path.join("LICENSE"), b"fixture tunnel license");
            private(&path.join("NOTICE"), b"fixture tunnel notice");
            paths.extend([
                ("workers/tunnel-client/tunnel-client-runtime", true),
                ("workers/tunnel-client/LICENSE", false),
                ("workers/tunnel-client/NOTICE", false),
            ]);
        }
        let files = paths.iter().map(|(path, executable)| {
            let bytes = fs::read(payload.join(path)).unwrap();
            serde_json::json!({"path":path,"size":bytes.len(),"sha256":Sha256Digest::of_bytes(&bytes),"executable":executable})
        }).collect::<Vec<_>>();
        let mut manifest = serde_json::json!({"schema":2,"runtime_format":"native_rust_v1","component":"styx","scope":"runtime_candidate",
            "minimum_reader":"native_runtime_selected_v1","target":"x86_64-unknown-linux-gnu","version":"0.4.0-test",
            "entrypoint":"bin/styx","source":{"revision":"a".repeat(40),"inputs_sha256":Sha256Digest::of_bytes(b"{}")},
            "contracts":{"control":1,"management_state":3},"files":files,"external_workers":[]});
        if worker {
            manifest["external_workers"] = serde_json::json!(["tunnel_client"]);
            manifest["worker_closures"] = serde_json::json!([{"kind":"tunnel_client","version":"0.0.17",
                "source_manifest_sha256":Sha256Digest::of_bytes(b"fixture source"),"source_publisher_spki_sha256":pin.as_hex(),
                "entrypoint":"workers/tunnel-client/tunnel-client-runtime", "members":paths.iter().skip(3).map(|(p,_)|p).collect::<Vec<_>>()}]);
        }
        let raw = serde_json::to_vec(&manifest).unwrap();
        private(&payload.join("manifest.json"), &raw);
        private(&payload.join("manifest.sig"), &key.sign(&raw).to_bytes());
        let release = crate::release::verify(&payload, &publisher, &pin).unwrap();
        let selection = parent.join("selection.json");
        private(
            &selection,
            &serde_json::to_vec(&release.runtime_selection().unwrap()).unwrap(),
        );
        let deployment = parent.join("deployment.json");
        private(&deployment, &serde_json::to_vec(&serde_json::json!({"schema":1,"mode":"create-local","gateway":{"url":format!("https://127.0.0.1:{port}/"),"listenHost":"127.0.0.1"}})).unwrap());
        native_gateway::bootstrap(
            parent,
            std::ffi::OsStr::new("gateway"),
            &deployment,
            &selection,
        )
        .await
        .unwrap();
        let gateway = parent.join("gateway");
        let input = parent.join("key");
        private(&input, b"sk-abcdefghijklmnop");
        configure(&gateway, "tunnel_abcdefgh", &input, auto_start, true).unwrap();
        let plan = native::plan(
            &gateway,
            native::NativeDesiredChange {
                component: native::NativeComponent::Gateway,
                run: NativeRunDesired::Running,
                transaction_id: "tunnel-test-running".try_into().unwrap(),
                sequence: 1,
            },
        )
        .await
        .unwrap();
        native::apply(&gateway, &plan.plan_file).await.unwrap();
        gateway
    }
    #[tokio::test]
    async fn tunnel_signed_payload_availability_preserves_optional_worker_without_sockets() {
        // Real signed inventories and committed native selection; no transport or account acceptance claim.
        for worker in [true, false] {
            let dir = Temporary::new();
            let state = gateway_fixture(&dir.0, 59443, worker, true).await;
            let report = status(&state).await.unwrap();
            assert_eq!(report.status, "configured");
            assert_eq!(report.available, worker);
            assert!(report.transport.is_none());
        }
    }
    #[tokio::test]
    async fn tunnel_gateway_restart_autostart_and_stop_reaps_native_fake_requires_loopback_sockets()
    {
        use crate::foreground::gateway_run;
        // Requires loopback socket permission and /usr/bin/cc. This exercises the
        // real Gateway owner, selected signed payload and native executable pin.
        for (worker, auto_start) in [(true, true), (true, false), (false, true)] {
            let reserved = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("requires loopback sockets (sandbox may deny bind)");
            let port = reserved.local_addr().unwrap().port();
            drop(reserved);
            let dir = Temporary::new();
            let state = gateway_fixture(&dir.0, port, worker, auto_start).await;
            let stop = CancellationToken::new();
            let _stop_guard = stop.clone().drop_guard();
            let (events, mut received) = tokio::sync::mpsc::channel(16);
            let original_stop = stop.clone();
            let original_state = state.clone();
            let gateway =
                tokio::spawn(
                    async move { gateway_run(&original_state, original_stop, events).await },
                );
            let listening = tokio::time::timeout(Duration::from_secs(10), async {
                while let Some(event) = received.recv().await {
                    if event.event == "gateway_listening" {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false);
            let started = std::time::Instant::now();
            let running = if worker && auto_start && listening {
                tokio::time::timeout(Duration::from_secs(25), async {
                    while !state.join("tunnel/running").exists() {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    true
                })
                .await
                .unwrap_or(false)
            } else {
                false
            };
            let report = status(&state).await;
            let header = fs::read_to_string(state.join("tunnel/gateway-header"));
            let ca =
                reqwest::Certificate::from_pem(&fs::read(state.join("gateway-ca.pem")).unwrap())
                    .unwrap();
            let http = reqwest::Client::builder()
                .no_proxy()
                .add_root_certificate(ca)
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap()
                .get(format!("https://127.0.0.1:{port}/mcp"))
                .send()
                .await;
            stop.cancel();
            let outcome = gateway.await.unwrap();
            // Assertions follow joined stop so every negative-control failure still reaps its child.
            assert!(listening);
            assert!(
                http.is_ok(),
                "Gateway must keep serving with or without the optional worker"
            );
            assert!(outcome.unwrap().local_stop_complete());
            let report = report.unwrap();
            assert_eq!(report.available, worker);
            if worker && auto_start {
                assert!(running);
                assert!(started.elapsed() >= RETRY);
                assert_eq!(report.transport, Some("starting"));
                assert_eq!(
                    header.unwrap(),
                    format!(
                        "Bearer {}",
                        fs::read_to_string(state.join("gateway-model.token"))
                            .unwrap()
                            .trim()
                    )
                );
                let tunnel = state.join("tunnel");
                let config = connection(&PrivateRoot::open(&tunnel).unwrap())
                    .unwrap()
                    .unwrap();
                let expected = arguments(&config, &state, port)
                    .0
                    .into_iter()
                    .map(|v| v.into_string().unwrap())
                    .collect::<Vec<_>>();
                let calls = fs::read_dir(&tunnel)
                    .unwrap()
                    .filter_map(|v| {
                        let v = v.unwrap();
                        v.file_name()
                            .to_str()
                            .unwrap()
                            .starts_with("argv-")
                            .then_some(v.path())
                    })
                    .collect::<Vec<_>>();
                assert_eq!(calls.len(), 2);
                for call in calls {
                    assert_eq!(
                        fs::read_to_string(&call)
                            .unwrap()
                            .lines()
                            .collect::<Vec<_>>(),
                        expected.iter().map(String::as_str).collect::<Vec<_>>()
                    );
                    let pid = call
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .strip_prefix("argv-")
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert_eq!(
                        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
                        Err(nix::errno::Errno::ESRCH)
                    );
                }
                assert!(tunnel.join("terminated").exists());
                assert!(!tunnel.join("gateway-header").exists());
            } else {
                assert!(!state.join("tunnel/once").exists());
                assert!(header.is_err());
            }
            assert!(status(&state).await.unwrap().transport.is_none());
        }
    }
    #[tokio::test]
    async fn tunnel_stale_or_nonloopback_health_cannot_report_ready() {
        let dir = Temporary::new();
        for url in [
            "http://example.com:80/",
            "http://127.0.0.1:1/",
            "http://127.0.0.1:1/evil",
            "http://user@127.0.0.1:1/",
        ] {
            private(&dir.0.join("health.url"), url.as_bytes());
            assert_eq!(health(&dir.0).await, "unavailable");
        }
    }
}

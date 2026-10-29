//! First-run orchestration over the existing native actors. Input receipts are
//! resumability fences, never an alternative enrollment or management ledger.
use super::{plugin_package, setup_prompt as prompt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use styx_contracts::native_management::{NativeManager, NativeRunDesired};
use styx_runtime::management::{
    native, native_gateway, native_gateway_admin as admin, native_join, setup as inputs,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Role {
    Hub,
    Join,
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Payload {
    pub payload_dir: PathBuf,
    pub publisher_file: PathBuf,
    #[serde(deserialize_with = "deserialize_publisher_pin")]
    pub expected_publisher: String,
}
fn normalize_publisher_pin(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}
fn deserialize_publisher_pin<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<String, D::Error> {
    String::deserialize(decoder).map(|value| normalize_publisher_pin(&value))
}
fn publisher_default(payload: &Path) -> Option<PathBuf> {
    let mut candidates = BTreeSet::new();
    for directory in std::iter::once(payload).chain(payload.parent()) {
        for entry in std::fs::read_dir(directory).ok()? {
            let entry = entry.ok()?;
            let name = entry.file_name();
            if name
                .to_str()
                .is_some_and(|name| name.starts_with("publisher") && name.ends_with(".pem"))
                && entry.file_type().ok()?.is_file()
            {
                candidates.insert(entry.path());
            }
        }
    }
    if candidates.len() == 1 {
        candidates.pop_first()
    } else {
        None
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tunnel {
    pub id: String,
    pub api_key_file: Option<PathBuf>,
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plugin {
    pub display_name: String,
    pub output: PathBuf,
    #[serde(default)]
    pub wait: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Answers {
    pub schema: u16,
    pub role: Role,
    pub payload: Payload,
    pub label: String,
    pub workspace: PathBuf,
    pub shell: PathBuf,
    #[serde(default)]
    pub browser: bool,
    pub browser_executable: Option<PathBuf>,
    #[serde(default)]
    pub computer: bool,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub networks: Vec<std::net::Ipv4Addr>,
    pub join_link_file: Option<PathBuf>,
    pub tunnel: Option<Tunnel>,
    pub plugin: Option<Plugin>,
    #[serde(default, skip_serializing)]
    pub approve: BTreeSet<String>,
}
fn default_port() -> u16 {
    22022
}
pub(super) struct Failure {
    pub code: &'static str,
    pub exit: u8,
    // Unknown errors may own the original coordinator/OS job. Retain them until
    // the CLI's explicit whole-process teardown, just like native_recovery_result.
    _owner: Option<Box<dyn std::any::Any + Send>>,
}
impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl Failure {
    pub fn hint(&self) -> Option<&'static str> {
        if let Some(error) = self
            ._owner
            .as_ref()
            .and_then(|owner| owner.downcast_ref::<native_join::JoinError>())
            && let Some(hint) = error.hint()
        {
            return Some(hint);
        }
        match self.code {
            "gateway_listen_failed" | "gateway_lan_listen_failed" => Some(
                "The hub could not open its network port. Check whether another program is using it, then choose a free port.",
            ),
            "setup_gateway_unavailable" => Some(
                "The hub is not responding. Check styx status and the hub service logs; another program may be using the selected port.",
            ),
            "native_release_publisher_untrusted" | "native_release_payload_integrity" => Some(
                "The installed Styx files did not match the trusted publisher or signature. Check the fingerprint against the download page / release notes and obtain the matching signed download.",
            ),
            "setup_tunnel_not_ready_check_status" => Some(
                "The ChatGPT tunnel is not ready. Check your internet connection, tunnel ID and API key with styx status, then run styx setup again.",
            ),
            _ => None,
        }
    }
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            exit: 2,
            _owner: None,
        }
    }
    fn unknown(code: &'static str) -> Self {
        Self {
            code,
            exit: 4,
            _owner: None,
        }
    }
    fn native(value: native::NativeManagementError) -> Self {
        let exit = value.exit_code();
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        let exit = if value.requires_process_teardown() {
            4
        } else {
            exit
        };
        Self {
            code: value.code(),
            exit,
            _owner: Some(Box::new(value)),
        }
    }
    fn join(value: native_join::JoinError) -> Self {
        Self {
            code: value.code(),
            exit: value.exit_code(),
            _owner: Some(Box::new(value)),
        }
    }
    fn bootstrap(value: native_gateway::BootstrapError) -> Self {
        Self {
            code: value.code(),
            exit: value.exit_code(),
            _owner: Some(Box::new(value)),
        }
    }
    pub(super) fn admin(value: admin::AdminError) -> Self {
        Self {
            code: value.code(),
            exit: value.exit_code(),
            _owner: Some(Box::new(value)),
        }
    }
}
impl From<&'static str> for Failure {
    fn from(value: &'static str) -> Self {
        Self::new(value)
    }
}
type Result<T> = std::result::Result<T, Failure>;
pub(super) fn root_default() -> Result<PathBuf> {
    if let Some(root) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(root).join("styx"));
    }
    Ok(home()?.join(".local/state/styx"))
}
fn home() -> Result<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .ok_or_else(|| Failure::new("setup_home_unavailable"))
}
fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(inputs::os_hostname)
        .unwrap_or_else(|| "This computer".into())
}
pub(super) fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::new("setup_clock_unavailable"))?
            .as_millis(),
    )
    .map_err(|_| Failure::new("setup_clock_unavailable"))
}
fn shell_default() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    } else {
        PathBuf::from("/bin/bash")
    }
}
fn browser_default() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".into(),
        ]
    } else if cfg!(windows) {
        ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"]
            .iter()
            .filter_map(std::env::var_os)
            .flat_map(|p| {
                [
                    PathBuf::from(&p).join("Google/Chrome/Application/chrome.exe"),
                    PathBuf::from(p).join("Microsoft/Edge/Application/msedge.exe"),
                ]
            })
            .collect()
    } else {
        vec![
            "/usr/bin/google-chrome-stable".into(),
            "/usr/bin/google-chrome".into(),
            "/usr/bin/microsoft-edge".into(),
            "/usr/bin/chromium".into(),
            "/usr/bin/chromium-browser".into(),
        ]
    };
    candidates.into_iter().find(|p| p.is_file())
}
impl Answers {
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.label.trim().is_empty()
            || self.label.chars().any(char::is_control)
            || self.label.chars().count() > 128
            || self.port == 0
        {
            return Err("setup_answers_invalid".into());
        }
        for path in [
            &self.workspace,
            &self.shell,
            &self.payload.payload_dir,
            &self.payload.publisher_file,
        ] {
            if !path.is_absolute() {
                return Err("setup_absolute_paths_required".into());
            }
        }
        if self.networks.len() > 4
            || self.networks.iter().collect::<BTreeSet<_>>().len() != self.networks.len()
            || self.networks.iter().any(|ip| !inputs::private_ipv4(*ip))
        {
            return Err("setup_network_choices_invalid".into());
        }
        if self.payload.expected_publisher.len() != 64
            || !self
                .payload
                .expected_publisher
                .bytes()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err("setup_external_publisher_pin_required".into());
        }
        if self.role == Role::Join
            && (!self.networks.is_empty() || self.tunnel.is_some() || self.plugin.is_some())
        {
            return Err("setup_join_cannot_configure_hub".into());
        }
        if let Some(tunnel) = &self.tunnel
            && (!plugin_package::tunnel_id(&tunnel.id)
                || tunnel
                    .api_key_file
                    .as_ref()
                    .is_some_and(|p| !p.is_absolute()))
        {
            return Err("setup_tunnel_choices_invalid".into());
        }
        if self.browser
            && self
                .browser_executable
                .as_ref()
                .is_none_or(|p| !p.is_absolute())
        {
            return Err("setup_browser_executable_required".into());
        }
        if self
            .join_link_file
            .as_ref()
            .is_some_and(|p| !p.is_absolute())
        {
            return Err("setup_absolute_join_link_file_required".into());
        }
        if let Some(plugin) = &self.plugin
            && (self.tunnel.is_none()
                || !plugin.output.is_absolute()
                || plugin.output.file_name().and_then(|p| p.to_str()) != Some("styx-native")
                || inputs::plugin_display_name(&plugin.display_name).is_none())
        {
            return Err("setup_plugin_choices_invalid".into());
        }
        const ACTIONS: &[&str] = &[
            "inputs",
            "payload",
            "workspace",
            "gateway",
            "tunnel",
            "gateway-service",
            "invite",
            "trust",
            "request",
            "approve",
            "claim",
            "host-service",
            "gateway-run",
            "host-run",
            "plugin",
        ];
        if self.approve.iter().any(|s| !ACTIONS.contains(&s.as_str())) {
            return Err("setup_unknown_approval".into());
        }
        Ok(())
    }
    pub(super) fn load(file: &Path) -> Result<Self> {
        let raw = inputs::read_private(file, 64 * 1024)
            .map_err(|_| Failure::new("setup_private_answers_file_required"))?;
        let value: Self =
            serde_json::from_slice(&raw).map_err(|_| Failure::new("setup_answers_invalid"))?;
        value.validate()?;
        Ok(value)
    }
}
fn interactive(root: &Path) -> Result<(Answers, Option<String>)> {
    println!(
        "Welcome to Styx. This setup connects only the computers and capabilities you approve."
    );
    println!("1. Set up this computer as the hub (Styx Gateway)\n2. Join an existing hub");
    let role = match prompt::line("Role", Some("1"))?.as_str() {
        "1" => Role::Hub,
        "2" => Role::Join,
        _ => return Err("setup_role_invalid".into()),
    };
    println!(
        "Styx checks that your installed files are authentic. You need the publisher public key file and the fingerprint from the download page / release notes."
    );
    let inferred = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent()?.parent().map(Path::to_path_buf))
        .filter(|p| p.join("manifest.json").is_file());
    let payload_dir = if let Some(path) = inferred {
        println!("Installed Styx files: {}", path.display());
        path
    } else {
        PathBuf::from(prompt::line("Installed payload directory", None)?)
    };
    let publisher = publisher_default(&payload_dir);
    let payload = Payload {
        payload_dir,
        publisher_file: prompt::line(
            "Publisher public PEM file",
            publisher.as_ref().and_then(|p| p.to_str()),
        )?
        .into(),
        expected_publisher: normalize_publisher_pin(&prompt::line(
            "Publisher fingerprint shown on the download page / release notes (colons and spaces optional)",
            None,
        )?),
    };
    let mut networks = Vec::new();
    let mut tunnel = None;
    let mut join_link_file = None;
    let mut pasted_link = None;
    let mut port = default_port();
    if role == Role::Hub {
        port = prompt::line("Hub HTTPS port", Some("22022"))?
            .parse()
            .map_err(|_| Failure::new("setup_port_invalid"))?;
        println!(
            "Choose the networks other computers will use to reach this one, e.g. your home Wi-Fi or a VPN. Select up to four; the default is none. Styx opens no router ports."
        );
        let addresses = match inputs::private_addresses() {
            Ok(addresses) => addresses
                .into_iter()
                .filter(|address| inputs::suggested_interface(&address.interface))
                .collect::<Vec<_>>(),
            Err(_) => {
                println!(
                    "Private address discovery is unavailable here. Continue with no private addresses; this hub will accept joins only on this computer."
                );
                Vec::new()
            }
        };
        for (i, address) in addresses.iter().enumerate() {
            let kind = inputs::interface_kind(&address.interface)
                .map(|kind| format!(" ({kind})"))
                .unwrap_or_default();
            println!("{}. {}{kind} {}", i + 1, address.interface, address.address);
        }
        let selection = prompt::line(
            "Network numbers, separated by commas (empty for none)",
            None,
        )?;
        if !selection.is_empty() {
            for part in selection.split(',') {
                let index = part
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| Failure::new("setup_network_choices_invalid"))?;
                networks.push(
                    addresses
                        .get(
                            index
                                .checked_sub(1)
                                .ok_or_else(|| Failure::new("setup_network_choices_invalid"))?,
                        )
                        .ok_or_else(|| Failure::new("setup_network_choices_invalid"))?
                        .address,
                );
            }
        }
        println!(
            "ChatGPT connects with a Secure MCP Tunnel. Create a tunnel in your account using https://developers.openai.com/api/docs/guides/secure-mcp-tunnels . Styx hides your API key as you type and saves it privately."
        );
        if prompt::confirm("Configure a tunnel now? Choose no to skip for now")? {
            tunnel = Some(Tunnel {
                id: prompt::line("Tunnel ID", None)?,
                api_key_file: None,
            });
        }
    } else {
        println!(
            "Paste the one-use styx://join link from your hub (Styx Gateway). You will check its address and security fingerprint before connecting."
        );
        let link = prompt::line("Join link", None)?;
        // Keep the link only in memory until the numbered plan is approved.
        let file = root.join(format!("inputs/pasted-join-link-{}", now_ms()?));
        pasted_link = Some(link);
        join_link_file = Some(file);
    }
    let label = prompt::line("This computer's label", Some(&hostname()))?;
    println!(
        "Choose a folder for commands and Browser Automation. Use a dedicated folder such as ~/Styx so Browser Automation can keep your private Styx files separate."
    );
    let workspace = PathBuf::from(prompt::line(
        "Workspace folder",
        home()?.join("Styx").to_str(),
    )?);
    let browser_executable = browser_default();
    let browser = if let Some(path) = &browser_executable {
        println!("Detected browser: {}", path.display());
        prompt::confirm("Enable Browser Automation for this computer?")?
    } else {
        println!(
            "Chrome/Edge was not found. Browser Automation is off; install a supported browser before enabling it."
        );
        false
    };
    println!(
        "Computer Use can observe and act on your desktop after the platform's permission checks. Enable it only for a desktop session you intend to share."
    );
    let computer = prompt::confirm("Enable Computer Use for this computer?")?;
    let answers = Answers {
        schema: 1,
        role,
        payload,
        label,
        workspace,
        shell: shell_default(),
        browser,
        browser_executable,
        computer,
        port,
        networks,
        join_link_file,
        tunnel,
        plugin: None,
        approve: BTreeSet::new(),
    };
    answers.validate()?;
    Ok((answers, pasted_link))
}

pub(super) struct Session {
    pub root: PathBuf,
    pub answers: Answers,
    automated: bool,
    plan_approved: bool,
    mutation: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Session {
    pub fn consent(&self, action: &str, explanation: &str) -> Result<()> {
        if !self.automated && self.plan_approved {
            return Ok(());
        }
        self.decision(action, explanation)
    }
    fn decision(&self, action: &str, explanation: &str) -> Result<()> {
        println!("{explanation}");
        let yes = if self.automated {
            let yes = self.answers.approve.contains(action);
            println!("Proceed? [answers: {}]", if yes { "yes" } else { "no" });
            yes
        } else {
            prompt::confirm("Proceed?")?
        };
        if yes {
            Ok(())
        } else {
            Err(Failure::new("setup_step_not_authorized"))
        }
    }
    fn input(&self, name: &str) -> PathBuf {
        self.root.join("inputs").join(name)
    }
    fn json_new(&self, name: &str, value: &impl Serialize) -> Result<()> {
        let raw = serde_json::to_vec_pretty(value)
            .map_err(|_| Failure::new("setup_input_serialization_failed"))?;
        inputs::write_new(&self.input(name), &raw)
            .map_err(|_| Failure::unknown("setup_input_publication_unknown"))
    }
    fn begin(&self, action: &str) -> Result<()> {
        if self.input(&format!("{action}.started")).exists() {
            return Err(Failure::unknown("setup_previous_outcome_unknown"));
        }
        inputs::write_new(&self.input(&format!("{action}.started")), b"dispatched\n")
            .map_err(|_| Failure::unknown("setup_dispatch_fence_failed"))?;
        self.mutation
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }
    fn done(&self, action: &str) -> Result<()> {
        inputs::write_new(&self.input(&format!("{action}.done")), b"completed\n")
            .map_err(|_| Failure::unknown("setup_result_publication_unknown"))?;
        self.mutation
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(())
    }
    fn completed(&self, action: &str) -> bool {
        inputs::read_private(&self.input(&format!("{action}.done")), 64)
            .is_ok_and(|raw| raw == b"completed\n")
    }
    fn require_known(&self, action: &str) -> Result<()> {
        if self.input(&format!("{action}.started")).exists() && !self.completed(action) {
            Err(Failure::unknown("setup_previous_outcome_unknown"))
        } else {
            Ok(())
        }
    }
    fn skip(&self, step: &str) {
        println!("{step}: already complete; keeping existing state.");
    }
}

async fn desired_running(
    session: &Session,
    path: &Path,
    component: native::NativeComponent,
    step: &str,
) -> Result<()> {
    session.require_known(step)?;
    let status = native::inspect_completed(path)
        .await
        .map_err(Failure::native)?;
    if status.admission_fenced {
        return Err(Failure::unknown("setup_native_admission_fenced"));
    }
    let desired = match component {
        native::NativeComponent::Host => status.desired.host,
        native::NativeComponent::Gateway => status.desired.gateway,
    }
    .ok_or_else(|| Failure::new("setup_role_missing"))?;
    if desired.manager != NativeManager::ForegroundCli {
        return Err("setup_foreground_requires_foreground_owned_root".into());
    }
    if desired.run == NativeRunDesired::Running {
        return Ok(());
    }
    session.begin(step)?;
    let tx = format!("setup-{step}-{}", now_ms()?)
        .try_into()
        .map_err(|_| Failure::new("setup_transaction_id_invalid"))?;
    // A fresh foreground root has no prior transaction. On resume the stored
    // original step is fenced; we never mint a replacement after dispatch.
    let plan = native::plan(
        path,
        native::NativeDesiredChange {
            component,
            run: NativeRunDesired::Running,
            transaction_id: tx,
            sequence: 1,
        },
    )
    .await
    .map_err(Failure::native)?;
    native::apply(path, &plan.plan_file)
        .await
        .map_err(Failure::native)?;
    session.done(step)
}

struct Foreground {
    cancel: CancellationToken,
    stops: Vec<CancellationToken>,
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    events: tokio::task::JoinHandle<()>,
    send: tokio::sync::mpsc::Sender<styx_runtime::foreground::ForegroundEvent>,
}
fn runtime_event_line(event: &styx_runtime::foreground::ForegroundEvent) -> String {
    let prefix = if event.device_id.is_some() {
        "This computer"
    } else {
        "Runtime"
    };
    match event.reason {
        Some(reason) => format!("{prefix}: {} ({reason})", event.event),
        None => format!("{prefix}: {}", event.event),
    }
}
impl Foreground {
    fn new() -> Self {
        let (send, mut receive) =
            tokio::sync::mpsc::channel::<styx_runtime::foreground::ForegroundEvent>(32);
        let events = tokio::spawn(async move {
            while let Some(event) = receive.recv().await {
                println!("{}", runtime_event_line(&event));
            }
        });
        Self {
            cancel: CancellationToken::new(),
            stops: Vec::new(),
            tasks: Vec::new(),
            events,
            send,
        }
    }
    fn gateway(&mut self, path: PathBuf) {
        let cancel = self.cancel.child_token();
        self.stops.push(cancel.clone());
        let events = self.send.clone();
        self.tasks.push(tokio::spawn(async move {
            let outcome = styx_runtime::foreground::gateway_run(&path, cancel, events)
                .await
                .map_err(|e| Failure::new(e.code()))?;
            if outcome.is_complete() {
                Ok(())
            } else {
                Err(Failure::unknown("setup_gateway_cleanup_unconfirmed"))
            }
        }));
    }
    fn host(&mut self, path: PathBuf) {
        let cancel = self.cancel.child_token();
        self.stops.push(cancel.clone());
        let events = self.send.clone();
        self.tasks.push(tokio::spawn(async move {
            let outcome = styx_runtime::foreground::host_run(
                &path,
                styx_runtime::foreground::HostWireMode::PairedV3,
                cancel,
                events,
            )
            .await
            .map_err(|e| Failure::new(e.code()))?;
            if outcome.is_complete() {
                Ok(())
            } else {
                Err(Failure::unknown("setup_host_cleanup_unconfirmed"))
            }
        }));
    }
    async fn stop(self) -> Result<()> {
        let mut failure = None;
        for (task, stop) in self.tasks.into_iter().zip(self.stops).rev() {
            stop.cancel();
            match task.await {
                Ok(Ok(())) => (),
                Ok(Err(e)) => {
                    failure.get_or_insert(e);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| Failure::unknown("setup_foreground_join_failed"));
                }
            }
        }
        self.cancel.cancel();
        drop(self.send);
        self.events
            .await
            .map_err(|_| Failure::unknown("setup_event_join_failed"))?;
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
async fn service(
    session: &Session,
    path: &Path,
    role: native::NativeComponent,
    step: &str,
) -> Result<()> {
    use native::service::{ServiceAction, manage};
    let observed = manage(path, ServiceAction::Status, role, None, None)
        .await
        .map_err(Failure::native)?;
    if observed.os["installed"] == true
        && observed.os["active"] == "active"
        && observed.os["enabled"] == true
    {
        session.skip(step);
        return Ok(());
    }
    session.consent(step, "Install, start and enable this role as your systemd --user service. It starts at user login; Styx never uses sudo or enables linger.")?;
    for (name, action) in [
        ("install", ServiceAction::Install),
        ("start", ServiceAction::Start),
        ("enable", ServiceAction::Enable),
    ] {
        let before = manage(path, ServiceAction::Status, role, None, None)
            .await
            .map_err(Failure::native)?;
        let done = match action {
            ServiceAction::Install => before.os["installed"] == true,
            ServiceAction::Start => before.os["active"] == "active",
            ServiceAction::Enable => before.os["enabled"] == true,
            _ => false,
        };
        let action_name = format!("{step}-{name}-r{}", before.revision);
        if done {
            session.skip(&action_name);
            continue;
        }
        session.begin(&action_name)?;
        let tx = format!("setup-{step}-{name}-{}", now_ms()?)
            .try_into()
            .map_err(|_| Failure::new("setup_transaction_id_invalid"))?;
        manage(path, action, role, Some(tx), Some(before.revision))
            .await
            .map_err(Failure::native)?;
        session.done(&action_name)?;
    }
    Ok(())
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
async fn service(_: &Session, _: &Path, _: native::NativeComponent, _: &str) -> Result<()> {
    Err("setup_user_services_unsupported".into())
}

async fn wait_gateway(path: &Path) -> Result<Value> {
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match admin::observe(path).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if tokio::time::Instant::now() >= until {
                    return Err(Failure::admin(e));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
fn deployment_host(session: &Session, origin: &str, ca_hash: &str) -> Value {
    let a = &session.answers;
    let mut host =
        json!({"label":a.label, "cwd":a.workspace, "shell":a.shell, "computer":a.computer});
    if a.browser {
        host["browser"] = json!({"enabled":true,"headless":true,"persistLogin":false,"channel":"chrome","executablePath":a.browser_executable});
    }
    json!({"schema":1,"mode":"join-existing", "gateway":{"url":origin,"caFile":session.input("join-ca.pem"),"expectedCaSha256":ca_hash},"host":host,"runtimeSelectionFile":session.input("runtime-selection.json"),"invitationFile":session.input("invitation")})
}
fn plugin_questions(label: &str) -> Result<Plugin> {
    println!(
        "Choose a display name that differs from any Styx plugin already installed in your ChatGPT account."
    );
    Ok(Plugin {
        display_name: prompt::line("Plugin display name", Some(&format!("Styx ({label})")))?,
        output: prompt::line(
            "New plugin output directory (must end in styx-native)",
            home()?.join("Styx/plugin/styx-native").to_str(),
        )?
        .into(),
        wait: false,
    })
}
fn plan_steps(answers: &Answers, foreground: bool, root: &Path) -> Vec<String> {
    let mut steps = vec![
        format!(
            "Save your choices and connection details privately in {}.",
            root.display()
        ),
        format!(
            "Check the signed Styx files in {} against your publisher fingerprint.",
            answers.payload.payload_dir.display()
        ),
        format!(
            "Use {} for commands and Browser Automation; create it privately if needed.",
            answers.workspace.display()
        ),
    ];
    if answers.role == Role::Hub {
        let networks = if answers.networks.is_empty() {
            "only on this computer".to_owned()
        } else {
            format!(
                "on this computer and {}",
                answers
                    .networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        steps.push(format!(
            "Set up the hub (Styx Gateway) on HTTPS port {} {networks}.",
            answers.port
        ));
        if answers.tunnel.is_some() {
            steps.push("Connect ChatGPT through a Secure MCP Tunnel and save its API key privately. Briefly stop and restart an existing hub service if configuration requires it.".into());
        }
        steps.push(if foreground { "Run the hub in this terminal until Ctrl-C." } else { "Install, start and enable the hub as your systemd user service at login. No sudo or linger." }.into());
        steps.push("Pair this computer with its own hub using its exact local identity.".into());
    } else {
        steps.push("Save your join link privately, check the other hub's security fingerprint and comparison code with you, then pair this computer after approval.".into());
    }
    steps.push(format!(
        "Enable commands for “{}”; Browser Automation {}; Computer Use {}.",
        answers.label,
        if answers.browser { "on" } else { "off" },
        if answers.computer { "on" } else { "off" }
    ));
    steps.push(if foreground { "Run this computer's connection in this terminal until Ctrl-C." } else { "Install, start and enable this computer's connection as your systemd user service at login. No sudo or linger." }.into());
    steps.push(
        if answers.role == Role::Hub {
            "Wait for the hub to confirm this computer is connected."
        } else {
            "Show how to check this computer's connection on the hub."
        }
        .into(),
    );
    if let Some(plugin) = &answers.plugin {
        steps.push(format!("Write the ChatGPT plugin “{}” to {} and a ZIP beside it, then show you how to install it. Nothing is uploaded.", plugin.display_name, plugin.output.display()));
    } else if answers.role == Role::Hub && answers.tunnel.is_none() {
        steps.push("Leave ChatGPT off for now and show how to connect it later.".into());
    }
    steps
}
async fn pair(session: &Session, gateway: Option<&Path>) -> Result<Option<String>> {
    let host = session.root.join("host");
    let mut joined = None;
    if host.exists() {
        session.require_known("host-running")?;
        let state = native::inspect_completed(&host)
            .await
            .map_err(Failure::native)?;
        if state.admission_fenced {
            return Err(Failure::unknown("setup_native_admission_fenced"));
        }
        if state
            .desired
            .host
            .is_some_and(|d| d.manager == NativeManager::PersistentService)
        {
            session.skip("Computer paired and running as a user service");
            let raw = inputs::read_private(&session.input("host-public-identity.json"), 16384)
                .map_err(|_| Failure::unknown("setup_original_host_identity_missing"))?;
            let public: Value = serde_json::from_slice(&raw)
                .map_err(|_| Failure::unknown("setup_original_host_identity_invalid"))?;
            let device: styx_contracts::identity::DeviceId = public["device_id"]
                .as_str()
                .ok_or_else(|| Failure::unknown("setup_original_host_identity_invalid"))?
                .to_owned()
                .try_into()
                .map_err(|_| Failure::unknown("setup_original_host_identity_invalid"))?;
            return Ok(Some(device.as_str().to_owned()));
        }
        let report = native_join::inspect(&host).await.map_err(Failure::join)?;
        if !session.input("host-public-identity.json").exists() {
            session.consent(
                "request",
                "Keep this computer's existing pairing identity. No new pairing request is sent.",
            )?;
            session.json_new("host-public-identity.json", &report)?;
        }
        if report.status == "ready_to_connect" {
            session.skip("Computer pairing");
            return Ok(Some(report.device_id.as_str().to_owned()));
        }
        if gateway.is_none() {
            println!(
                "Comparison code: {}",
                report.comparison_code.as_deref().unwrap_or("unavailable")
            );
        }
        joined = Some(report);
    }
    if joined.is_none() {
        if !session.input("host-deployment.json").exists() {
            if let Some(gateway) = gateway {
                if !session.input("join-link").exists() {
                    session.consent("invite", "Create a one-use local invitation for this computer. It will be stored only in private setup inputs.")?;
                    session.begin("local-invite")?;
                    admin::invite_with_options(
                        gateway,
                        &session.input("invitation-source"),
                        600,
                        Some(admin::InvitationOrigin::Loopback),
                        Some(&session.input("join-link")),
                    )
                    .await
                    .map_err(Failure::admin)?;
                    session.done("local-invite")?;
                } else {
                    session.skip("Local invitation publication");
                }
            }
            let link_path = if gateway.is_some() {
                session.input("join-link")
            } else {
                session
                    .answers
                    .join_link_file
                    .clone()
                    .ok_or_else(|| Failure::new("setup_join_link_required"))?
            };
            let bytes = inputs::read_private(&link_path, 32768)
                .map_err(|_| Failure::new("setup_private_join_link_required"))?;
            let inspected = inputs::JoinLink::inspect(
                std::str::from_utf8(&bytes)
                    .map_err(|_| Failure::new("setup_join_link_invalid"))?
                    .trim(),
                now_ms()?,
            )?;
            let preview = inspected.preview();
            if gateway.is_none() {
                println!(
                    "Hub address: {}\nSecurity fingerprint (CA SHA256): {}",
                    preview["origin"].as_str().unwrap_or("unavailable"),
                    preview["caSha256"].as_str().unwrap_or("unavailable")
                );
                session.decision("trust", "Check this address and security fingerprint on your trusted hub. Trust this hub and save its connection details?")?;
            } else {
                // Local trust is covered by the plan. Automation still requires
                // its explicit trust approval; link validation is identical.
                session.consent(
                    "trust",
                    "Use this computer's own hub security identity for local pairing.",
                )?;
            }
            session.begin("join-input")?;
            let origin = inspected.accept(
                preview["origin"]
                    .as_str()
                    .ok_or_else(|| Failure::new("setup_join_origin_missing"))?,
                preview["caSha256"].as_str(),
                now_ms()?,
                &session.input("join-ca.pem"),
                &session.input("invitation"),
            )?;
            session.json_new(
                "host-deployment.json",
                &deployment_host(
                    session,
                    &origin,
                    preview["caSha256"]
                        .as_str()
                        .ok_or_else(|| Failure::new("setup_join_ca_missing"))?,
                ),
            )?;
            session.done("join-input")?;
        } else {
            session.skip("Computer connection settings");
        }
        session.consent(
            "request",
            "Create a private identity for this computer and ask the confirmed hub to pair it.",
        )?;
        session.begin("request")?;
        let report = native_join::request(
            &session.root,
            std::ffi::OsStr::new("host"),
            &session.input("host-deployment.json"),
        )
        .await
        .map_err(Failure::join)?;
        session.json_new("host-public-identity.json", &report)?;
        joined = Some(report);
        session.done("request")?;
    }
    let joined = joined.ok_or_else(|| Failure::unknown("setup_join_report_missing"))?;
    let device = joined.device_id.as_str().to_owned();
    if gateway.is_none() {
        println!(
            "This computer: {device}\nComparison code: {}",
            joined.comparison_code.as_deref().unwrap_or("unavailable")
        );
    }
    if let Some(gateway) = gateway {
        if !session.completed("approve") {
            let pending = admin::pending(gateway).await.map_err(Failure::admin)?;
            let exact = pending.pending.unwrap_or_default().into_iter().find(|p| {
                Some(p.request_id.as_str()) == joined.request_id.as_deref()
                    && p.device_id == joined.device_id
                    && p.fingerprint == joined.fingerprint
                    && Some(p.comparison_code.as_str()) == joined.comparison_code.as_deref()
            });
            let p = exact
                .ok_or_else(|| Failure::unknown("setup_pending_request_not_found_check_hub"))?;
            session.consent("approve", "Approve this computer with the Browser Automation and Computer Use choices shown in the plan.")?;
            session.begin("approve")?;
            admin::approve(
                gateway,
                admin::ApprovalSelection {
                    request_id: p.request_id,
                    device_id: p.device_id,
                    fingerprint: p.fingerprint,
                    comparison_code: p.comparison_code,
                    enable_browser: session.answers.browser,
                    enable_computer: session.answers.computer,
                },
            )
            .await
            .map_err(Failure::admin)?;
            session.done("approve")?;
        } else {
            session.skip("Local computer approval");
        }
    } else {
        println!(
            "On the hub, run styx invite and compare this code before approving. Waiting for that approval; Ctrl-C stops waiting."
        );
        session.decision("claim", "Check that this comparison code matches the one on your hub before it approves this computer. Continue pairing?")?;
    }
    if gateway.is_some() {
        session.consent("claim", "Finish pairing this computer after the hub approves it. If a request has an uncertain result, setup stops so it cannot pair twice.")?;
    }
    // A recorded 202 is a known awaiting-approval outcome. Only that exact
    // response permits another claim poll after an interruption.
    let mut attempt = 0u16;
    while session.input(&format!("claim-{attempt}.started")).exists() {
        let pending = inputs::read_private(&session.input(&format!("claim-{attempt}.pending")), 64)
            .map_err(|_| Failure::unknown("setup_claim_previous_outcome_unknown"))?;
        if pending != b"awaiting_approval\n" {
            return Err(Failure::unknown("setup_claim_previous_outcome_unknown"));
        }
        attempt = attempt
            .checked_add(1)
            .ok_or_else(|| Failure::new("setup_claim_poll_budget_exhausted"))?;
    }
    loop {
        let step = format!("claim-{attempt}");
        session.begin(&step)?;
        let claimed = native_join::claim(&host).await.map_err(Failure::join)?;
        if matches!(claimed.status, "ready_to_connect" | "already_ready") {
            session.done(&step)?;
            session.done("claim")?;
            break;
        }
        if claimed.status != "awaiting_approval" {
            return Err(Failure::unknown("setup_claim_outcome_unknown"));
        }
        inputs::write_new(
            &session.input(&format!("claim-{attempt}.pending")),
            b"awaiting_approval\n",
        )
        .map_err(|_| Failure::unknown("setup_claim_pending_receipt_failed"))?;
        session
            .mutation
            .store(false, std::sync::atomic::Ordering::Release);
        tokio::time::sleep(Duration::from_secs(1)).await;
        attempt = attempt
            .checked_add(1)
            .ok_or_else(|| Failure::new("setup_claim_poll_budget_exhausted"))?;
    }
    Ok(Some(device))
}

async fn execute(session: &mut Session, foreground: bool, running: &mut Foreground) -> Result<()> {
    let a = session.answers.clone();
    let root = session.root.clone();
    let gateway = root.join("gateway");
    let host = root.join("host");
    if !session.input("runtime-selection.json").exists() {
        session.consent("payload", "Check the installed Styx files against the publisher fingerprint you supplied and remember which version to run.")?;
        let selection = styx_runtime::release::inspect_selection(
            &a.payload.payload_dir,
            &a.payload.publisher_file,
            &a.payload.expected_publisher,
        )
        .await
        .map_err(|e| Failure::new(e.code()))?;
        session.json_new("runtime-selection.json", &selection)?;
    } else {
        let raw = inputs::read_private(&session.input("runtime-selection.json"), 1024 * 1024)
            .map_err(|_| Failure::new("setup_selection_unavailable"))?;
        let selection =
            serde_json::from_slice(&raw).map_err(|_| Failure::new("setup_selection_invalid"))?;
        let verified = styx_runtime::release::verify_selected(&selection)
            .map_err(|e| Failure::new(e.code()))?;
        let selected = verified
            .runtime_selection()
            .map_err(|e| Failure::new(e.code()))?;
        if Path::new(&selected.payload_path) != a.payload.payload_dir
            || Path::new(&selected.publisher_file) != a.payload.publisher_file
            || selected.publisher_spki_sha256.to_hex() != a.payload.expected_publisher
        {
            return Err("setup_existing_payload_selection_differs".into());
        }
        session.skip("Installed Styx version");
    }
    if !a.workspace.exists() {
        session.consent(
            "workspace",
            "Create the selected workspace as a private directory.",
        )?;
        inputs::private_directory(&a.workspace)
            .map_err(|_| Failure::new("setup_private_workspace_failed"))?;
    }
    if a.browser
        && (root.starts_with(&a.workspace) || a.payload.payload_dir.starts_with(&a.workspace))
    {
        return Err("setup_browser_workspace_contains_private_state".into());
    }
    if !session.input("setup-intent.json").exists() {
        session.json_new("setup-intent.json", &session.answers)?;
    }
    if a.role == Role::Hub {
        if !gateway.exists() {
            session.consent("gateway", "Create this hub with a private security identity and the network addresses you selected.")?;
            if !session.input("gateway-deployment.json").exists() {
                let mut endpoint = json!({"url":format!("https://127.0.0.1:{}/", a.port), "listenHost":"127.0.0.1"});
                if !a.networks.is_empty() {
                    endpoint["allowRemoteHosts"] = json!(true);
                    endpoint["lanAddresses"] = json!(a.networks);
                }
                session.json_new(
                    "gateway-deployment.json",
                    &json!({"schema":1,"mode":"create-local","gateway":endpoint}),
                )?;
            }
            session.begin("gateway-bootstrap")?;
            native_gateway::bootstrap(
                &root,
                std::ffi::OsStr::new("gateway"),
                &session.input("gateway-deployment.json"),
                &session.input("runtime-selection.json"),
            )
            .await
            .map_err(Failure::bootstrap)?;
            session.done("gateway-bootstrap")?;
        } else {
            native::inspect(&gateway, None)
                .await
                .map_err(Failure::native)?;
            session.skip("Hub configuration");
        }
        if let Some(tunnel) = &a.tunnel {
            let status = serde_json::to_value(
                styx_runtime::foreground::tunnel::status(&gateway)
                    .await
                    .map_err(|e| Failure::new(e.code()))?,
            )
            .map_err(|_| Failure::new("setup_tunnel_status_failed"))?;
            if status["status"] == "configured" {
                if status["tunnelId"] != tunnel.id {
                    return Err("setup_existing_tunnel_differs".into());
                }
                session.skip("Tunnel configuration");
            } else {
                session.consent("tunnel", "Save the tunnel API key privately. If the hub service is running, stop it briefly to configure ChatGPT, then restart it.")?;
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                if !foreground {
                    let status = native::service::manage(
                        &gateway,
                        native::service::ServiceAction::Status,
                        native::NativeComponent::Gateway,
                        None,
                        None,
                    )
                    .await
                    .map_err(Failure::native)?;
                    if status.os["active"] == "active" {
                        let step = format!("tunnel-gateway-stop-r{}", status.revision);
                        session.begin(&step)?;
                        let tx = format!("setup-{step}")
                            .try_into()
                            .map_err(|_| Failure::new("setup_transaction_id_invalid"))?;
                        native::service::manage(
                            &gateway,
                            native::service::ServiceAction::Stop,
                            native::NativeComponent::Gateway,
                            Some(tx),
                            Some(status.revision),
                        )
                        .await
                        .map_err(Failure::native)?;
                        session.done(&step)?;
                    }
                }
                if let Some(key) = &tunnel.api_key_file {
                    session.begin("tunnel")?;
                    styx_runtime::foreground::tunnel::configure(
                        &gateway, &tunnel.id, key, true, true,
                    )
                    .map_err(|e| Failure::new(e.code()))?;
                } else {
                    if session.automated {
                        return Err("setup_private_tunnel_key_file_required".into());
                    }
                    inputs::configure_hidden_tunnel(
                        &gateway,
                        &tunnel.id,
                        &session.input("temporary-tunnel-key"),
                        || session.begin("tunnel").map_err(|e| e.code),
                    )?;
                }
                session.done("tunnel")?;
            }
        } else {
            println!("ChatGPT tunnel: skipped for now. Run styx setup again to configure it.");
        }
        if foreground {
            session.consent("gateway-run", "Run this hub in this terminal until Ctrl-C.")?;
            desired_running(
                session,
                &gateway,
                native::NativeComponent::Gateway,
                "gateway-running",
            )
            .await?;
            println!(
                "Later run: styx gateway run --state-dir {}",
                gateway.display()
            );
            running.gateway(gateway.clone());
        } else {
            service(
                session,
                &gateway,
                native::NativeComponent::Gateway,
                "gateway-service",
            )
            .await?;
        }
        wait_gateway(&gateway).await?;
    }
    let device = pair(session, (a.role == Role::Hub).then_some(gateway.as_path())).await?;
    if a.role == Role::Hub {
        println!("Pairing this computer with its own hub… done");
    }
    if foreground {
        session.consent("host-run", "Run this computer's connection in this terminal until Ctrl-C. Keep its pairing for the next run.")?;
        desired_running(
            session,
            &host,
            native::NativeComponent::Host,
            "host-running",
        )
        .await?;
        println!("Later run: styx host run --state-dir {}", host.display());
        running.host(host.clone());
    } else {
        service(
            session,
            &host,
            native::NativeComponent::Host,
            "host-service",
        )
        .await?;
    }
    if a.role == Role::Hub {
        println!(
            "Waiting for the hub to see this computer connected for commands{}…",
            if a.browser {
                " and Browser Automation"
            } else {
                ""
            }
        );
        let until = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let observed = admin::observe(&gateway).await.map_err(Failure::admin)?;
            if observed["environments"].as_array().is_some_and(|envs| {
                envs.iter().any(|env| {
                    device
                        .as_ref()
                        .is_none_or(|id| env["environment_id"] == *id)
                        && env["exec"]["connection"] == "connected"
                        && (!a.browser || env["browser"]["connection"] == "connected")
                })
            }) {
                println!("This computer connected (confirmed by the hub).");
                break;
            }
            if tokio::time::Instant::now() >= until {
                return Err("setup_computer_connection_timeout_check_status".into());
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        if a.tunnel.is_some() {
            connect_chatgpt(session, &gateway).await?;
        }
    } else {
        println!(
            "This computer has started. On the hub, run styx status to check its commands and Browser Automation connection."
        );
    }
    println!(
        "Setup complete. {}",
        if a.role == Role::Hub {
            "This hub and this computer's connection are running."
        } else {
            "This computer's connection is running; check its connection on the hub."
        }
    );
    println!(
        "Commands: on · Browser Automation: {} · Computer Use: {}",
        if a.browser { "on" } else { "off" },
        if a.computer { "on" } else { "off" }
    );
    println!("Check Styx: styx status --root {}", root.display());
    if a.role == Role::Hub {
        println!(
            "Add another computer: styx invite --root {}",
            root.display()
        );
        if a.tunnel.is_none() {
            println!(
                "Connect ChatGPT later: styx setup --root {}",
                root.display()
            );
        }
    }
    Ok(())
}

async fn connect_chatgpt(session: &mut Session, gateway: &Path) -> Result<()> {
    println!(
        "Waiting for the ChatGPT tunnel to be ready… You will then install the plugin in ChatGPT."
    );
    let until = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let status = serde_json::to_value(
            styx_runtime::foreground::tunnel::status(gateway)
                .await
                .map_err(|e| Failure::new(e.code()))?,
        )
        .map_err(|_| Failure::new("setup_tunnel_status_failed"))?;
        if status["transport"] == "ready" {
            break;
        }
        if tokio::time::Instant::now() >= until {
            return Err("setup_tunnel_not_ready_check_status".into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if session.input("plugin-intent.json").exists() {
        let raw = inputs::read_private(&session.input("plugin-intent.json"), 16384)
            .map_err(|_| Failure::new("setup_plugin_intent_unavailable"))?;
        let plugin: Plugin = serde_json::from_slice(&raw)
            .map_err(|_| Failure::new("setup_plugin_intent_invalid"))?;
        if session
            .answers
            .plugin
            .as_ref()
            .is_some_and(|p| p.output != plugin.output || p.display_name != plugin.display_name)
        {
            return Err("setup_existing_plugin_differs".into());
        }
        session.answers.plugin = Some(plugin);
    }
    let plugin = session
        .answers
        .plugin
        .as_ref()
        .ok_or_else(|| Failure::new("setup_plugin_choices_required"))?;
    if !session.completed("plugin") {
        session.consent("plugin", "Check the hub connection and create the ChatGPT plugin folder and ZIP. No secret is included and nothing is uploaded.")?;
        let discovery = admin::observe(gateway).await.map_err(Failure::admin)?;
        if !session.input("plugin-intent.json").exists() {
            session.json_new("plugin-intent.json", plugin)?;
        }
        session.begin("plugin")?;
        plugin_package::write(
            &plugin.output,
            &plugin.display_name,
            &session
                .answers
                .tunnel
                .as_ref()
                .ok_or_else(|| Failure::new("setup_tunnel_missing"))?
                .id,
            &discovery,
        )?;
        session.done("plugin")?;
    } else {
        let discovery = admin::observe(gateway).await.map_err(Failure::admin)?;
        plugin_package::verify_existing(
            &plugin.output,
            &plugin.display_name,
            &session
                .answers
                .tunnel
                .as_ref()
                .ok_or_else(|| Failure::new("setup_tunnel_missing"))?
                .id,
            &discovery,
        )?;
        session.skip("Plugin export");
    }
    println!(
        "Plugin ZIP: {}\nIn ChatGPT: open Settings > Apps, use the supported plugin upload/import workflow, upload this ZIP, review the connection, and install it in the intended account/workspace. Start a new conversation with this plugin enabled.\nFirst test prompt: List my Styx computers",
        plugin.output.with_extension("zip").display()
    );
    let baseline = styx_runtime::foreground::tunnel::request_observation(gateway)
        .map_err(|e| Failure::new(e.code()))?["requests"]
        .as_u64()
        .unwrap_or(0);
    let wait = if session.automated {
        plugin.wait
    } else {
        prompt::confirm("Wait for the first request from ChatGPT? Ctrl-C stops waiting")?
    };
    if wait {
        // The transport observation is supplied only by the Gateway-owned tunnel
        // ingress, never inferred from local discovery or user confirmation.
        loop {
            let observation = styx_runtime::foreground::tunnel::request_observation(gateway)
                .map_err(|e| Failure::new(e.code()))?;
            if observation["requests"].as_u64().unwrap_or(0) > baseline {
                println!("ChatGPT connected: the hub received a request through the tunnel.");
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

pub(super) async fn run(
    root: Option<PathBuf>,
    answers_file: Option<PathBuf>,
    foreground_mode: bool,
    exit_when_connected: bool,
) -> Result<()> {
    let root = root.map(Ok).unwrap_or_else(root_default)?;
    if !root.is_absolute() {
        return Err("setup_absolute_root_required".into());
    }
    let automated = answers_file.is_some();
    if !automated && !prompt::terminal() {
        return Err("setup_noninteractive_requires_answers".into());
    }
    let intent = root.join("inputs/setup-intent.json");
    let (mut answers, pasted_link) = if let Some(path) = answers_file {
        (Answers::load(&path)?, None)
    } else if intent.exists() {
        println!(
            "Resuming existing setup. Existing identities and unknown outcomes are never replayed."
        );
        (Answers::load(&intent)?, None)
    } else {
        interactive(&root)?
    };
    if intent.exists() && answers.role == Role::Hub && answers.tunnel.is_none() {
        if let Ok(status) = styx_runtime::foreground::tunnel::status(&root.join("gateway")).await {
            let status = serde_json::to_value(status)
                .map_err(|_| Failure::new("setup_tunnel_status_failed"))?;
            if status["status"] == "configured" {
                answers.tunnel = Some(Tunnel {
                    id: status["tunnelId"]
                        .as_str()
                        .ok_or_else(|| Failure::new("setup_tunnel_status_failed"))?
                        .into(),
                    api_key_file: None,
                });
            }
        }
        if answers.tunnel.is_none()
            && !automated
            && prompt::confirm("Configure the previously skipped ChatGPT tunnel now?")?
        {
            println!(
                "Secure MCP Tunnel guide: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels"
            );
            answers.tunnel = Some(Tunnel {
                id: prompt::line("Tunnel ID", None)?,
                api_key_file: None,
            });
        }
    }
    if !automated && answers.tunnel.is_some() && answers.plugin.is_none() {
        let plugin_intent = root.join("inputs/plugin-intent.json");
        answers.plugin = Some(if plugin_intent.exists() {
            let raw = inputs::read_private(&plugin_intent, 16384)
                .map_err(|_| Failure::new("setup_plugin_intent_unavailable"))?;
            serde_json::from_slice(&raw).map_err(|_| Failure::new("setup_plugin_intent_invalid"))?
        } else {
            plugin_questions(&answers.label)?
        });
    }
    answers.validate()?;
    if answers.browser
        && (root.starts_with(&answers.workspace)
            || answers.payload.payload_dir.starts_with(&answers.workspace))
    {
        return Err("setup_browser_workspace_contains_private_state".into());
    }
    if automated {
        if answers.role == Role::Join
            && !root.join("host").exists()
            && answers.join_link_file.is_none()
        {
            return Err("setup_join_link_required".into());
        }
        if let Some(tunnel) = &answers.tunnel {
            if tunnel.api_key_file.is_none() {
                let status = styx_runtime::foreground::tunnel::status(&root.join("gateway"))
                    .await
                    .map_err(|_| Failure::new("setup_private_tunnel_key_file_required"))?;
                let status = serde_json::to_value(status)
                    .map_err(|_| Failure::new("setup_tunnel_status_failed"))?;
                if status["tunnelId"] != tunnel.id {
                    return Err("setup_private_tunnel_key_file_required".into());
                }
            }
            if answers.plugin.is_none() && !root.join("inputs/plugin-intent.json").exists() {
                return Err("setup_plugin_choices_required".into());
            }
        }
    }
    let mut session = Session {
        root,
        answers,
        automated,
        plan_approved: false,
        mutation: Default::default(),
    };
    if intent.exists() {
        let existing = Answers::load(&intent)?;
        // Tunnel/plugin can be supplied on a later pass; established role and
        // Host intent cannot silently select a new identity or deployment.
        if existing.role != session.answers.role
            || existing.payload != session.answers.payload
            || existing.shell != session.answers.shell
            || existing.browser_executable != session.answers.browser_executable
            || existing.label != session.answers.label
            || existing.workspace != session.answers.workspace
            || existing.browser != session.answers.browser
            || existing.computer != session.answers.computer
            || existing.port != session.answers.port
            || existing.networks != session.answers.networks
        {
            return Err("setup_existing_choices_differ_retire_role_explicitly".into());
        }
    }
    let foreground = foreground_mode || !cfg!(all(target_os = "linux", target_env = "gnu"));
    if !automated {
        println!("Styx will do the following (completed steps will be kept):");
        for (index, step) in plan_steps(&session.answers, foreground, &session.root)
            .iter()
            .enumerate()
        {
            println!("{}. {step}", index + 1);
        }
        if !prompt::confirm_default("Set up Styx now?", true)? {
            return Err("setup_cancelled".into());
        }
        session.plan_approved = true;
    }
    if !intent.exists() {
        session.consent("inputs", "Create protected setup input directories and retain these choices for interruption recovery.")?;
        inputs::private_directory(&session.root.join("inputs"))
            .map_err(|_| Failure::new("setup_private_inputs_failed"))?;
    }
    if let Some(link) = pasted_link {
        inputs::write_new(
            session
                .answers
                .join_link_file
                .as_ref()
                .ok_or_else(|| Failure::new("setup_join_link_required"))?,
            link.as_bytes(),
        )
        .map_err(|_| Failure::new("setup_join_link_save_failed"))?;
    }
    if foreground {
        println!(
            "Terminal mode: keep this window open. Ctrl-C stops Styx safely. Background services are not installed."
        );
    }
    let mut running = Foreground::new();
    let mutation = session.mutation.clone();
    let (mut outcome, interrupted) = {
        let work = execute(&mut session, foreground, &mut running);
        tokio::pin!(work);
        tokio::select! {
            result = &mut work => (result, false),
            signal = tokio::signal::ctrl_c() => {
                let result = if mutation.load(std::sync::atomic::Ordering::Acquire) {
                    Err(Failure::unknown("setup_interrupted_check_original_step"))
                } else if signal.is_err() { Err(Failure::new("setup_signal_failed")) }
                else { println!("Stopped waiting. Setup progress is saved; run styx status to check connection."); Ok(()) };
                (result, true)
            }
        }
    };
    if outcome.is_ok() && foreground && !exit_when_connected && !interrupted {
        println!("Styx is running in this terminal. Press Ctrl-C to stop it safely.");
        if tokio::signal::ctrl_c().await.is_err() {
            outcome = Err(Failure::new("setup_signal_failed"));
        }
    }
    let cleanup = running.stop().await;
    outcome?;
    cleanup
}

pub(super) async fn invite(root: Option<PathBuf>) -> Result<()> {
    if !prompt::terminal() {
        return Err("invite_interactive_terminal_required".into());
    }
    let root = root.map(Ok).unwrap_or_else(root_default)?;
    let answers = Answers::load(&root.join("inputs/setup-intent.json"))?;
    if answers.role != Role::Hub {
        return Err("invite_requires_local_hub".into());
    }
    let session = Session {
        root,
        answers,
        automated: false,
        plan_approved: false,
        mutation: Default::default(),
    };
    let gateway = session.root.join("gateway");
    let observed = admin::observe(&gateway).await.map_err(Failure::admin)?;
    let origins = observed["origins"]
        .as_array()
        .ok_or_else(|| Failure::new("invite_origins_unavailable"))?;
    println!(
        "Choose an origin reachable from the other computer. Loopback is for this computer only; use a selected private network for another computer."
    );
    for (i, origin) in origins.iter().enumerate() {
        println!("{}. {}", i + 1, origin.as_str().unwrap_or("unknown"));
    }
    let index = prompt::line("Origin number", None)?
        .parse::<usize>()
        .map_err(|_| Failure::new("invite_origin_invalid"))?;
    let origin = origins
        .get(
            index
                .checked_sub(1)
                .ok_or_else(|| Failure::new("invite_origin_invalid"))?,
        )
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::new("invite_origin_invalid"))?;
    let selection = if index == 1 {
        admin::InvitationOrigin::Loopback
    } else {
        let address = origin
            .strip_prefix("https://")
            .and_then(|s| s.split(':').next())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Failure::new("invite_origin_invalid"))?;
        admin::InvitationOrigin::Address(address)
    };
    // A prior unknown invitation cannot be evaded by inventing another name.
    for entry in std::fs::read_dir(session.root.join("inputs"))
        .map_err(|_| Failure::new("invite_inputs_unavailable"))?
    {
        let entry = entry.map_err(|_| Failure::new("invite_inputs_unavailable"))?;
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with("invite-export-")
            && let Some(step) = name.strip_suffix(".started")
            && !session.completed(step)
        {
            return Err(Failure::unknown(
                "invite_previous_outcome_unknown_check_original_files",
            ));
        }
    }
    session.consent("invite", "Create a secret one-use invitation, valid for ten minutes, and print its join link in this terminal. Transfer it only through a trusted private channel.")?;
    let step = format!("invite-export-{}", now_ms()?);
    let invitation = session.input(&format!("{step}.token"));
    let link = session.input(&format!("{step}.link"));
    session.begin(&step)?;
    admin::invite_with_options(&gateway, &invitation, 600, Some(selection), Some(&link))
        .await
        .map_err(Failure::admin)?;
    session.done(&step)?;
    let link_bytes = inputs::read_private(&link, 32768)
        .map_err(|_| Failure::unknown("invite_link_publication_unknown"))?;
    println!(
        "{}",
        std::str::from_utf8(&link_bytes)
            .map_err(|_| Failure::unknown("invite_link_publication_unknown"))?
    );
    println!(
        "On the other computer:\nApp: choose Join an existing Styx and paste this link.\nCLI: run styx setup, choose Join an existing hub and paste this link.\nCompare the code shown there with this hub before approving."
    );
    if !prompt::confirm("Wait for a pending request and review approval? Ctrl-C stops waiting")? {
        return Ok(());
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        let pending = admin::pending(&gateway)
            .await
            .map_err(Failure::admin)?
            .pending
            .unwrap_or_default();
        if !pending.is_empty() {
            for (i, p) in pending.iter().enumerate() {
                println!(
                    "{}. Computer {}\n   Request {}\n   Fingerprint {}\n   Comparison code {}\n   Requested: Browser {}, Computer Use {}",
                    i + 1,
                    p.device_id.as_str(),
                    p.request_id,
                    p.fingerprint.to_hex(),
                    p.comparison_code,
                    p.browser_requested,
                    p.computer_requested
                );
            }
            let index = prompt::line("Request number to review", None)?
                .parse::<usize>()
                .map_err(|_| Failure::new("invite_pending_selection_invalid"))?;
            let p = pending
                .into_iter()
                .nth(
                    index
                        .checked_sub(1)
                        .ok_or_else(|| Failure::new("invite_pending_selection_invalid"))?,
                )
                .ok_or_else(|| Failure::new("invite_pending_selection_invalid"))?;
            if !prompt::confirm(
                "Does this exact computer's comparison code match the other computer?",
            )? {
                return Err("invite_comparison_not_confirmed".into());
            }
            let browser = p.browser_requested && prompt::confirm("Approve Browser Automation?")?;
            let computer = p.computer_requested && prompt::confirm("Approve Computer Use?")?;
            session.consent(
                "approve",
                "Approve only this computer with the capabilities just selected.",
            )?;
            let step = format!("invite-export-approve-{}", p.request_id);
            session.begin(&step)?;
            admin::approve(
                &gateway,
                admin::ApprovalSelection {
                    request_id: p.request_id,
                    device_id: p.device_id,
                    fingerprint: p.fingerprint,
                    comparison_code: p.comparison_code,
                    enable_browser: browser,
                    enable_computer: computer,
                },
            )
            .await
            .map_err(Failure::admin)?;
            session.done(&step)?;
            println!("Approved. The other computer can now finish pairing and connect.");
            return Ok(());
        }
        if tokio::time::Instant::now() >= until {
            return Err("invite_expired_without_request".into());
        }
        tokio::select! { signal=tokio::signal::ctrl_c()=>{signal.map_err(|_| Failure::new("setup_signal_failed"))?; println!("Stopped waiting. The original invitation files are retained."); return Ok(());}, _=tokio::time::sleep(Duration::from_secs(1))=>() }
    }
}

/// Stop and remove this computer's Styx login services (Linux). Data folders
/// stay in place. Each step reads the current state first; an "unknown" reply
/// is accepted only when Styx's own records show that step committed.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) async fn uninstall(root: Option<PathBuf>, yes: bool) -> Result<()> {
    use native::service::{ServiceAction, manage};
    let root = root.map(Ok).unwrap_or_else(root_default)?;
    let roles: Vec<_> = [
        ("This computer", "host", native::NativeComponent::Host),
        (
            "Hub (Styx Gateway)",
            "gateway",
            native::NativeComponent::Gateway,
        ),
    ]
    .into_iter()
    .filter(|(_, dir, _)| root.join(dir).is_dir())
    .collect();
    if roles.is_empty() {
        return Err("uninstall_nothing_set_up".into());
    }
    println!(
        "Styx will stop and remove its login services for {}.",
        root.display()
    );
    println!("Your settings, pairing and workspace stay on disk; nothing is deleted.");
    if !yes {
        if !prompt::terminal() {
            return Err("uninstall_confirmation_required_use_yes".into());
        }
        if !prompt::confirm("Uninstall Styx services now?")? {
            return Err("setup_cancelled".into());
        }
    }
    for (label, dir, component) in &roles {
        let path = root.join(dir);
        for _ in 0..4 {
            let before = manage(&path, ServiceAction::Status, *component, None, None)
                .await
                .map_err(Failure::native)?;
            let os = &before.os;
            let desired = serde_json::to_value(&before.desired)
                .map_err(|_| Failure::new("uninstall_state_invalid"))?;
            let running = desired[dir]["run"] == "running"
                || !matches!(os["active"].as_str(), Some("inactive" | "failed") | None);
            let action = if os["installed"] != true {
                break;
            } else if running {
                ServiceAction::Stop
            } else if os["enabled"] == true {
                ServiceAction::Disable
            } else {
                ServiceAction::Uninstall
            };
            let name = match action {
                ServiceAction::Stop => "stop",
                ServiceAction::Disable => "disable",
                _ => "uninstall",
            };
            let tx = format!("uninstall-{dir}-{name}-{}", now_ms()?)
                .try_into()
                .map_err(|_| Failure::new("setup_transaction_id_invalid"))?;
            let stopping = action == ServiceAction::Stop;
            match manage(&path, action, *component, Some(tx), Some(before.revision)).await {
                Ok(_) => println!("{label}: {name} done."),
                Err(error) => {
                    // Never replay: continue only if this exact step committed.
                    // Status reads can fail briefly while systemd reloads units
                    // after enable/disable; reading again is not an action.
                    let mut after = None;
                    for _ in 0..25 {
                        if let Ok(report) =
                            manage(&path, ServiceAction::Status, *component, None, None).await
                        {
                            after = Some(report);
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    let after = after.ok_or_else(|| Failure::native(error))?;
                    if after.revision <= before.revision {
                        return Err(Failure::unknown("uninstall_step_outcome_unknown"));
                    }
                    println!("{label}: {name} done (confirmed from Styx's records).");
                }
            }
            if stopping {
                // The stopping service still reads its records while it exits;
                // the next step must not overlap that exit.
                let until = std::time::Instant::now() + Duration::from_secs(15);
                while !running_roles(&path).is_empty() {
                    if std::time::Instant::now() >= until {
                        return Err(Failure::unknown("uninstall_role_did_not_exit"));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        let after = manage(&path, ServiceAction::Status, *component, None, None)
            .await
            .map_err(Failure::native)?;
        if after.os["installed"] == true {
            return Err(Failure::unknown("uninstall_service_still_installed"));
        }
    }
    let remaining = running_roles(&root);
    if !remaining.is_empty() {
        println!("Still running for this setup (process ids): {remaining:?}");
        return Err(Failure::unknown("uninstall_processes_remain"));
    }
    println!("Styx services are removed and no Styx process is running for this setup.");
    println!(
        "Kept on disk: {} (settings and pairing). Delete it yourself only if you will not reuse this setup.",
        root.display()
    );
    if let Ok(answers) = Answers::load(&root.join("inputs/setup-intent.json")) {
        println!("Also kept: workspace {}", answers.workspace.display());
        println!(
            "          installed files {}",
            answers.payload.payload_dir.display()
        );
        if let Some(plugin) = answers.plugin {
            println!(
                "          ChatGPT plugin export {}",
                plugin.output.display()
            );
        }
    }
    Ok(())
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(super) async fn uninstall(_: Option<PathBuf>, _: bool) -> Result<()> {
    println!("On macOS and Windows, quit Styx from its menu and uninstall the App.");
    Err("uninstall_use_the_app".into())
}
/// Service processes started for this root (`__service-run --state-dir <root>/...`).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn running_roles(root: &Path) -> Vec<u32> {
    let prefix = root.as_os_str().as_encoded_bytes();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|raw| {
                let args: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
                args.iter().any(|a| *a == b"__service-run")
                    && args
                        .windows(2)
                        .any(|w| w[0] == b"--state-dir" && w[1].starts_with(prefix))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Value {
        json!({"schema":1,"role":"hub","payload":{"payload_dir":"/p/runtime","publisher_file":"/p/publisher.pem","expected_publisher":"a".repeat(64)},"label":"workstation","workspace":"/p/work","shell":"/bin/bash","approve":[]})
    }
    #[test]
    fn plan_consent_never_supplies_automation_approval_or_new_identity_decisions() {
        let mut session = Session {
            root: PathBuf::from("/private/profile"),
            answers: serde_json::from_value(valid()).unwrap(),
            automated: false,
            plan_approved: true,
            mutation: Default::default(),
        };
        assert!(session.consent("payload", "Check installed files").is_ok());
        session.automated = true;
        assert_eq!(
            session
                .consent("payload", "Check installed files")
                .unwrap_err()
                .code,
            "setup_step_not_authorized"
        );
        assert_eq!(
            session
                .decision("trust", "Trust this hub?")
                .unwrap_err()
                .code,
            "setup_step_not_authorized"
        );
        session.answers.approve.insert("payload".into());
        assert!(session.consent("payload", "Check installed files").is_ok());
        assert!(session.decision("trust", "Trust this hub?").is_err());
    }
    #[test]
    fn publisher_prompt_defaults_only_when_one_candidate_exists() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "setup-publisher-{}-{}",
                std::process::id(),
                now_ms().unwrap()
            ));
        let payload = root.join("runtime");
        inputs::private_directory(&payload).unwrap();
        assert!(publisher_default(&payload).is_none());
        inputs::write_new(&root.join("publisher.pem"), b"public fixture").unwrap();
        assert_eq!(
            publisher_default(&payload),
            Some(root.join("publisher.pem"))
        );
        inputs::write_new(
            &payload.join("publisher-dev.pem"),
            b"another public fixture",
        )
        .unwrap();
        assert!(publisher_default(&payload).is_none());
        std::fs::remove_file(root.join("publisher.pem")).unwrap();
        assert_eq!(
            publisher_default(&payload),
            Some(payload.join("publisher-dev.pem"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn publisher_pin_accepts_printed_fingerprint_without_deriving_trust() {
        let printed = vec!["AA"; 32].join(": ");
        assert_eq!(normalize_publisher_pin(&printed), "a".repeat(64));
        let mut value = valid();
        value["payload"]["expected_publisher"] = json!(printed);
        let answers: Answers = serde_json::from_value(value).unwrap();
        answers.validate().unwrap();
        assert_eq!(answers.payload.expected_publisher, "a".repeat(64));
        let mut value = valid();
        value["payload"]["expected_publisher"] = json!("not a fingerprint");
        assert!(
            serde_json::from_value::<Answers>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    #[test]
    fn host_runtime_events_identify_this_computer() {
        let mut event = styx_runtime::foreground::ForegroundEvent {
            schema: 1,
            event: "connecting",
            reason: None,
            device_id: Some("setup-computer".to_owned().try_into().unwrap()),
            connection_generation: None,
        };
        assert_eq!(runtime_event_line(&event), "This computer: connecting");
        event.reason = Some("waiting");
        assert_eq!(
            runtime_event_line(&event),
            "This computer: connecting (waiting)"
        );
        event.device_id = None;
        event.event = "gateway_loading";
        event.reason = None;
        assert_eq!(runtime_event_line(&event), "Runtime: gateway_loading");
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[tokio::test]
    async fn setup_clean_foreground_stop_then_rerun_keeps_committed_intent() {
        use styx_contracts::native_management::{NativeDeploymentMode, NativeManager};
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "setup-clean-stop-{}-{}",
                std::process::id(),
                now_ms().unwrap()
            ));
        inputs::private_directory(&root.join("inputs")).unwrap();
        let session = Session {
            root: root.clone(),
            answers: serde_json::from_value(valid()).unwrap(),
            automated: true,
            plan_approved: false,
            mutation: Default::default(),
        };
        for (name, mode, component, deployment) in [
            (
                "gateway",
                NativeDeploymentMode::CreateLocal,
                native::NativeComponent::Gateway,
                json!({"schema":1,"mode":"create-local","gateway":{"url":"https://127.0.0.1:22122/","runtime":{}}}),
            ),
            (
                "host",
                NativeDeploymentMode::JoinExisting,
                native::NativeComponent::Host,
                json!({"schema":1,"mode":"join-existing","gateway":{"url":"https://127.0.0.1:22122/"},"host":{"computer":false}}),
            ),
        ] {
            let file = session.input(&format!("{name}.json"));
            inputs::write_new(&file, &serde_json::to_vec(&deployment).unwrap()).unwrap();
            let path = root.join(name);
            native::initialize(
                &root,
                std::ffi::OsStr::new(name),
                &file,
                native::NativeCreateOptions {
                    mode,
                    manager: NativeManager::ForegroundCli,
                    host: name == "host",
                    gateway: name == "gateway",
                },
            )
            .await
            .unwrap();
            let step = format!("{name}-running");
            desired_running(&session, &path, component, &step)
                .await
                .unwrap();
            let before = std::fs::read(path.join("state.json")).unwrap();
            // Role shutdown joins its tasks without changing desired Running.
            // Reopening the actual C07 transaction reproduces the reported fence.
            Foreground::new().stop().await.unwrap();
            assert!(native::inspect(&path, None).await.unwrap().admission_fenced);
            for _ in 0..2 {
                desired_running(&session, &path, component, &step)
                    .await
                    .unwrap();
                assert_eq!(std::fs::read(path.join("state.json")).unwrap(), before);
            }
            // A complete native tip does not excuse a lost setup completion.
            std::fs::remove_file(session.input(&format!("{step}.done"))).unwrap();
            let error = desired_running(&session, &path, component, &step)
                .await
                .unwrap_err();
            assert_eq!(error.exit, 4);
            assert_eq!(error.code, "setup_previous_outcome_unknown");
            assert_eq!(std::fs::read(path.join("state.json")).unwrap(), before);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn answers_reject_unknown_fields_invalid_choices_and_embedded_secrets() {
        let parse = |value: Value| -> bool {
            serde_json::from_value::<Answers>(value)
                .ok()
                .is_some_and(|a| a.validate().is_ok())
        };
        assert!(parse(valid()));
        for field in ["api_key", "password", "unexpected"] {
            let mut v = valid();
            v[field] = json!("secret-must-not-be-accepted");
            assert!(!parse(v));
        }
        for changes in [
            json!({"schema":2}),
            json!({"role":"other"}),
            json!({"workspace":"relative"}),
            json!({"networks":["8.8.8.8"]}),
            json!({"networks":["10.0.0.1","10.0.0.1"]}),
            json!({"browser":true}),
            json!({"role":"join","tunnel":{"id":format!("tunnel_{}","a".repeat(32))}}),
            json!({"approve":["everything"]}),
        ] {
            let mut v = valid();
            v.as_object_mut()
                .unwrap()
                .extend(changes.as_object().unwrap().clone());
            assert!(!parse(v));
        }
    }
    #[test]
    fn resume_dispatch_without_receipt_is_never_replayed() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "setup-resume-{}-{}",
                std::process::id(),
                now_ms().unwrap()
            ));
        inputs::private_directory(&root.join("inputs")).unwrap();
        let session = Session {
            root: root.clone(),
            answers: serde_json::from_value(valid()).unwrap(),
            automated: true,
            plan_approved: false,
            mutation: Default::default(),
        };
        for step in [
            "payload",
            "workspace",
            "gateway-bootstrap",
            "tunnel",
            "gateway-service-install",
            "gateway-service-start",
            "gateway-service-enable",
            "local-invite",
            "join-input",
            "request",
            "approve",
            "claim",
            "host-service-install",
            "host-service-start",
            "host-service-enable",
            "plugin",
        ] {
            assert!(!session.completed(step));
            session
                .begin(step)
                .unwrap_or_else(|_| panic!("first dispatch"));
            assert_eq!(session.begin(step).err().unwrap().exit, 4);
            session
                .done(step)
                .unwrap_or_else(|_| panic!("completion receipt"));
            assert!(session.completed(step));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

use super::{Failure, Result, home, inputs, now_ms, plugin_package, prompt};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(in crate::cli) enum Role {
    Hub,
    Gateway,
    Join,
}
impl Role {
    pub(in crate::cli) fn owns_gateway(self) -> bool {
        matches!(self, Self::Hub | Self::Gateway)
    }
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::cli) struct Payload {
    pub payload_dir: PathBuf,
    pub publisher_file: PathBuf,
    #[serde(deserialize_with = "deserialize_publisher_pin")]
    pub expected_publisher: String,
}
pub(in crate::cli) fn normalize_publisher_pin(value: &str) -> String {
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
pub(super) fn publisher_default(payload: &Path) -> Option<PathBuf> {
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
pub(in crate::cli) struct Tunnel {
    pub id: String,
    pub api_key_file: Option<PathBuf>,
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::cli) struct Plugin {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<styx_runtime::management::plugin_presentation::Profile>,
    pub output: PathBuf,
    #[serde(default)]
    pub wait: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::cli) struct Answers {
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
fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(inputs::os_hostname)
        .unwrap_or_else(|| "This computer".into())
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
    pub(super) fn validate(&self) -> Result<()> {
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
        if self.role == Role::Gateway
            && (self.browser
                || self.computer
                || self.browser_executable.is_some()
                || self.join_link_file.is_some())
        {
            return Err("setup_gateway_only_cannot_enable_host".into());
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
                || inputs::plugin_display_name(&plugin.display_name).is_none()
                || plugin.profile.as_ref().is_some_and(|p| {
                    p.presentation.display_name != plugin.display_name
                        || p.clone().normalized().is_err()
                }))
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
    pub(in crate::cli) fn load(file: &Path) -> Result<Self> {
        let raw = inputs::read_private(file, 512 * 1024)
            .map_err(|_| Failure::new("setup_private_answers_file_required"))?;
        let value: Self =
            serde_json::from_slice(&raw).map_err(|_| Failure::new("setup_answers_invalid"))?;
        value.validate()?;
        Ok(value)
    }
}
pub(super) fn interactive(root: &Path) -> Result<(Answers, Option<String>)> {
    prompt::section("Styx setup");
    prompt::info("Connect only the computers and capabilities you approve.");
    prompt::section("This computer's role");
    let role = match prompt::select(
        "Role",
        &[
            "Hub (Gateway and this computer)",
            "Join an existing Gateway",
            "Gateway only (headless VM; pair other computers later)",
        ],
        0,
    )? {
        0 => Role::Hub,
        1 => Role::Join,
        2 => Role::Gateway,
        _ => return Err("setup_role_invalid".into()),
    };
    prompt::section("Trusted release");
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
    if role.owns_gateway() {
        prompt::section("Gateway network");
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
        let choices = addresses
            .iter()
            .map(|address| {
                let kind = inputs::interface_kind(&address.interface)
                    .map(|kind| format!(" ({kind})"))
                    .unwrap_or_default();
                format!("{}{kind} {}", address.interface, address.address)
            })
            .collect::<Vec<_>>();
        for index in prompt::networks(&choices)? {
            networks.push(addresses[index].address);
        }
        prompt::section("ChatGPT connection");
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
    prompt::section("Computer name");
    let label = prompt::line("This computer's label", Some(&hostname()))?;
    let (workspace, browser_executable, browser, computer) = if role == Role::Gateway {
        (root.join("unused-host-workspace"), None, false, false)
    } else {
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
        (workspace, browser_executable, browser, computer)
    };
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
pub(super) fn plan_steps(answers: &Answers, foreground: bool, root: &Path) -> Vec<String> {
    let mut steps = vec![
        format!(
            "Save your choices and connection details privately in {}.",
            root.display()
        ),
        format!(
            "Check the signed Styx files in {} against your publisher fingerprint.",
            answers.payload.payload_dir.display()
        ),
    ];
    if answers.role != Role::Gateway {
        steps.push(format!(
            "Use {} for commands and Browser Automation; create it privately if needed.",
            answers.workspace.display()
        ));
    }
    if answers.role.owns_gateway() {
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
        if answers.role == Role::Hub {
            steps
                .push("Pair this computer with its own hub using its exact local identity.".into());
        }
    } else {
        steps.push("Save your join link privately, check the other hub's security fingerprint and comparison code with you, then pair this computer after approval.".into());
    }
    if answers.role != Role::Gateway {
        steps.push(format!(
            "Enable commands for “{}”; Browser Automation {}; Computer Use {}.",
            answers.label,
            if answers.browser { "on" } else { "off" },
            if answers.computer { "on" } else { "off" }
        ));
        steps.push(if foreground { "Run this computer's connection in this terminal until Ctrl-C." } else { "Install, start and enable this computer's connection as your systemd user service at login. No sudo or linger." }.into());
        steps.push(
            if answers.role.owns_gateway() {
                "Wait for the hub to confirm this computer is connected."
            } else {
                "Show how to check this computer's connection on the hub."
            }
            .into(),
        );
    }
    if let Some(plugin) = &answers.plugin {
        steps.push(format!("Keep legacy ZIP settings for “{}” at {}. Only automated answers explicitly approving plugin export can write that ZIP; Custom MCP does not use it.", plugin.display_name, plugin.output.display()));
    }
    if answers.tunnel.is_some() {
        steps.push(format!("Save the Styx upload icon in {} and show the Custom MCP > Tunnel connection steps. Nothing is uploaded or installed automatically.", root.join("chatgpt/styx-icon.png").display()));
    } else if answers.role == Role::Hub {
        steps.push("Leave ChatGPT off for now and show how to connect it later.".into());
    }
    steps
}

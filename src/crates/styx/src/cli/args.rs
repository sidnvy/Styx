use clap::{Parser, Subcommand, ValueEnum};
#[cfg(target_os = "windows")]
use std::process::ExitCode;
use std::{ffi::OsString, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "styx",
    version,
    about = "Styx native Gateway, Host and management CLI"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}
#[derive(Subcommand)]
pub(super) enum ComputersCommand {
    /// Revoke one paired computer by exact label or device id.
    Remove {
        selector: String,
        #[arg(long)]
        yes: bool,
        /// Allow revoking this hub's own local computer.
        #[arg(long)]
        include_this_computer: bool,
    },
}
#[derive(Subcommand)]
pub(super) enum PluginCommand {
    /// Show the saved identity, presentation and icon fingerprint.
    Show,
    /// Edit plugin details; an existing identity is retained.
    Configure {
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        short_description: Option<String>,
        #[arg(long)]
        long_description: Option<String>,
        #[arg(long, conflicts_with = "default_icon")]
        icon_file: Option<PathBuf>,
        #[arg(long)]
        default_icon: bool,
        /// For first creation, use the identity of the existing plugin to update.
        #[arg(long)]
        plugin_id: Option<String>,
        #[arg(long)]
        preview_file: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Export the saved details and this hub's verified connection, without uploading.
    Export {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        preview_file: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Subcommand)]
pub(super) enum LocalAppCommand {
    Status {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
pub(super) enum Command {
    /// Quit the current user's native Windows App through its original owner.
    Quit {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Read the local native Windows App owner without contacting a Gateway.
    App {
        #[command(subcommand)]
        command: LocalAppCommand,
    },
    /// Install a verified Linux CLI into your private bin directory.
    Install {
        #[arg(long)]
        payload_dir: PathBuf,
        #[arg(long)]
        publisher_file: PathBuf,
        #[arg(long)]
        expected_publisher: String,
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        #[arg(long)]
        authorize: bool,
    },
    /// Configure or export this hub's plugin name, descriptions and icon.
    Plugin {
        #[arg(long, global = true, conflicts_with = "gateway_state_dir")]
        root: Option<PathBuf>,
        /// Owner-only Gateway profile for a Gateway installed without styx setup.
        #[arg(long, global = true)]
        gateway_state_dir: Option<PathBuf>,
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Guided first-run setup; noninteractive use requires a private answers file.
    Setup {
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        answers: Option<PathBuf>,
        /// Keep roles in this process instead of installing Linux user services.
        #[arg(long)]
        foreground: bool,
        /// Test mode: stop and join foreground roles after connection is observed.
        #[arg(long, requires = "foreground", requires = "answers", hide = true)]
        exit_when_connected: bool,
    },
    /// Invite another computer to this hub and optionally review its request.
    Invite {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// List paired computers, or revoke one computer's pairing on this hub.
    Computers {
        #[arg(long, global = true)]
        root: Option<PathBuf>,
        /// Include historical revoked pairings in the list.
        #[arg(long)]
        all: bool,
        #[command(subcommand)]
        command: Option<ComputersCommand>,
    },
    /// Stop and remove this computer's Styx login services; data stays on disk.
    Uninstall {
        #[arg(long)]
        root: Option<PathBuf>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Upgrade Linux services to a signed payload, keeping this computer paired.
    Upgrade {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        publisher_file: Option<PathBuf>,
        #[arg(long)]
        expected_publisher: Option<String>,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Back up stopped role roots, then set up or join again normally.
    Role {
        #[command(subcommand)]
        command: RoleCommand,
    },
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    #[command(name = "__service-run", hide = true)]
    ServiceRun {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, value_enum)]
        role: NativeComponentArg,
    },
    /// Explicit native user-service lifecycle; never enables linger or sudo.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    Service {
        #[arg(value_enum)]
        action: ServiceActionArg,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, value_enum)]
        component: NativeComponentArg,
        #[arg(long)]
        transaction_id: Option<String>,
        #[arg(long)]
        expected_revision: Option<u64>,
        #[arg(long)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Review/observe a fixed launchd definition, or stop its original Gateway.
    /// Does not install, enable, start, or adopt an App-managed profile.
    #[cfg(target_os = "macos")]
    #[command(name = "service")]
    MacService {
        #[arg(value_enum)]
        action: MacServiceActionArg,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, value_enum)]
        component: NativeComponentArg,
        #[arg(long)]
        transaction_id: Option<String>,
        #[arg(long)]
        expected_revision: Option<u64>,
        /// Original-publisher signed candidate, only for prepare-runtime-repair.
        #[arg(long)]
        runtime_selection_file: Option<PathBuf>,
        #[arg(long)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Private native App owned-child transport, never a network endpoint.
    #[command(name = "__app-core", hide = true)]
    AppCore {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(
            long,
            required_unless_present = "runtime_selection_file",
            conflicts_with = "runtime_selection_file"
        )]
        deployment_file: Option<PathBuf>,
        #[arg(long)]
        runtime_selection_file: Option<PathBuf>,
    },
    // Fixed read-only worker mode; there are no target/credential/path options.
    #[command(name = "__linux-desktop-probe", hide = true)]
    LinuxDesktopProbe,
    #[command(name = "__linux-desktop-watch", hide = true)]
    LinuxDesktopWatch,
    #[command(name = "__linux-desktop-association", hide = true)]
    LinuxDesktopAssociation {
        #[arg(long)]
        candidate: String,
    },
    #[command(name = "__linux-desktop-association-check", hide = true)]
    LinuxDesktopAssociationCheck {
        #[arg(long)]
        candidate: String,
    },
    /// Print build and contract identity; never claims a running service.
    BuildInfo {
        #[arg(long)]
        json: bool,
    },
    /// Run the explicitly configured native Host in this foreground process.
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    /// Run the protected paired Gateway in this foreground process.
    Gateway {
        #[command(subcommand)]
        command: GatewayCommand,
    },
    /// Verify an offline release using an externally trusted public publisher pin.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Initialize a fresh native configuration root; never adopts legacy state.
    Init {
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long)]
        deployment_file: PathBuf,
        #[arg(long, value_enum)]
        mode: NativeModeArg,
        #[arg(long, value_enum)]
        manager: NativeManagerArg,
        #[arg(long)]
        host: bool,
        #[arg(long)]
        gateway: bool,
        #[arg(long)]
        json: bool,
    },
    /// Apply an exact reviewed native plan; no services are started here.
    Apply {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Reconcile the original native transaction; never mint a replacement ID.
    Recover {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect a native transaction without applying or recovering it.
    Transaction {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Review configuration intent and unresolved legacy steps without executing them.
    Plan {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long,requires_all=["component","run","transaction_id","sequence"])]
        native: bool,
        #[arg(long, value_enum, requires = "native")]
        component: Option<NativeComponentArg>,
        #[arg(long, value_enum, requires = "native")]
        run: Option<NativeRunArg>,
        #[arg(long, requires = "native")]
        transaction_id: Option<String>,
        #[arg(long,requires="native",value_parser=clap::value_parser!(u64).range(1..))]
        sequence: Option<u64>,
    },
    /// Inspect the existing deployment without connecting or starting services.
    Status {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, conflicts_with = "state_dir")]
        root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long, requires = "state_dir")]
        native: bool,
    },
    /// Validate a profile, or inspect OS desktop candidates without granting access.
    Doctor {
        #[arg(
            long,
            required_unless_present = "desktop_sessions",
            conflicts_with = "desktop_sessions"
        )]
        state_dir: Option<PathBuf>,
        /// Linux OS candidates only; does not attach or authorize a desktop.
        #[arg(long)]
        desktop_sessions: bool,
        /// Stream unverified Linux OS candidates; cancellation fences the source.
        #[arg(long, requires = "desktop_sessions")]
        watch: bool,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum NativeModeArg {
    CreateLocal,
    JoinExisting,
}
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum NativeManagerArg {
    ForegroundCli,
    AppManaged,
    PersistentService,
}
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum NativeComponentArg {
    Host,
    Gateway,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum ServiceActionArg {
    Install,
    Status,
    Enable,
    Disable,
    Start,
    Stop,
    Uninstall,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl ServiceActionArg {
    pub(super) fn native(self) -> styx_runtime::management::native::service::ServiceAction {
        use styx_runtime::management::native::service::ServiceAction;
        match self {
            Self::Install => ServiceAction::Install,
            Self::Status => ServiceAction::Status,
            Self::Enable => ServiceAction::Enable,
            Self::Disable => ServiceAction::Disable,
            Self::Start => ServiceAction::Start,
            Self::Stop => ServiceAction::Stop,
            Self::Uninstall => ServiceAction::Uninstall,
        }
    }
}
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum MacServiceActionArg {
    Definition,
    Status,
    PrepareInstall,
    PrepareFirstStart,
    /// Prepare same-identity recovery of a registered but failed inactive Gateway.
    PrepareRecovery,
    PrepareRuntimeRepair,
    /// Recover the exact original target; never reissue an uncertain admin request.
    RecoverRuntimeRepair,
    Stop,
    Start,
    Enable,
    Disable,
    Uninstall,
}
#[cfg(target_os = "macos")]
impl MacServiceActionArg {
    pub(super) fn native(self) -> styx_runtime::management::native::service::ServiceAction {
        use styx_runtime::management::native::service::ServiceAction;
        match self {
            Self::Definition => ServiceAction::Definition,
            Self::Status => ServiceAction::Status,
            Self::PrepareInstall => ServiceAction::PrepareInstall,
            Self::PrepareFirstStart => ServiceAction::PrepareFirstStart,
            Self::PrepareRecovery => ServiceAction::PrepareRecovery,
            Self::PrepareRuntimeRepair => ServiceAction::PrepareRuntimeRepair,
            Self::RecoverRuntimeRepair => ServiceAction::RecoverRuntimeRepair,
            Self::Stop => ServiceAction::Stop,
            Self::Start => ServiceAction::Start,
            Self::Enable => ServiceAction::Enable,
            Self::Disable => ServiceAction::Disable,
            Self::Uninstall => ServiceAction::Uninstall,
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum NativeRunArg {
    Running,
    Stopped,
}
impl Cli {
    /// SCM must attach on the original process main thread before Tokio exists.
    #[cfg(target_os = "windows")]
    pub(crate) fn dispatch_windows_service(&self) -> Option<ExitCode> {
        let Command::ServiceRun { state_dir, role } = &self.command else {
            return None;
        };
        Some(super::native_recovery_result(
            styx_runtime::management::native::service::dispatch(state_dir, role.native()),
            true,
            "Original Windows service dispatcher and drain observations:",
        ))
    }
    pub(crate) fn is_desktop_probe_worker(&self) -> bool {
        matches!(
            self.command,
            Command::LinuxDesktopProbe
                | Command::LinuxDesktopWatch
                | Command::LinuxDesktopAssociation { .. }
        )
    }
}
#[derive(Subcommand)]
pub(super) enum RoleCommand {
    Retire {
        #[arg(long)]
        state_dir: PathBuf,
        /// Explicitly retire a Join attempt, or an unfinished Hub local pairing on POSIX.
        #[arg(long)]
        setup_root: Option<PathBuf>,
        #[arg(long)]
        gateway_state_dir: Option<PathBuf>,
        #[arg(long)]
        allow_other_devices: bool,
        #[arg(long)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
pub(super) enum HostCommand {
    /// Explicit native enrollment; does not start or install a Host.
    Join {
        #[command(subcommand)]
        command: HostJoinCommand,
    },
    /// Explicit current-user transient action; no autostart or installation.
    Start {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, required = true)]
        transient: bool,
        #[arg(long)]
        json: bool,
    },
    /// Observe scoped user units; never starts or adopts one.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, required = true)]
        transient: bool,
        #[arg(long)]
        owner_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Run {
        #[arg(long)]
        state_dir: PathBuf,
    },
    Stop {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, requires_all = ["state_dir", "owner_file", "expected_invocation"])]
        transient: bool,
        #[arg(long, requires = "transient")]
        owner_file: Option<PathBuf>,
        #[arg(long, requires = "transient")]
        expected_invocation: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Pause {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Resume {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
pub(super) enum HostJoinCommand {
    /// Create a fresh private Host identity and request Gateway approval once.
    Request {
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long)]
        deployment_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Claim an approved credential and verify current authenticated self state.
    Claim {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(super) enum GatewayInviteOrigin {
    Loopback,
    Lan,
}
#[derive(Subcommand)]
pub(super) enum GatewayCommand {
    /// Configure the Gateway-owned Secure MCP Tunnel transport.
    Tunnel {
        #[command(subcommand)]
        command: GatewayTunnelCommand,
    },
    /// Create one invitation and publish its secret only to a new private file.
    Invite {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        invitation_file: PathBuf,
        #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(60..=600))]
        ttl_seconds: u64,
        /// Origin to report for the Host deployment (default: LAN when enabled).
        #[arg(long, value_enum)]
        origin: Option<GatewayInviteOrigin>,
        /// Select one of the Gateway's configured private IPv4 addresses.
        #[arg(long, conflicts_with = "origin")]
        origin_address: Option<std::net::Ipv4Addr>,
        /// Export a secret styx://join link to a new private file.
        #[arg(long)]
        app_link_file: Option<PathBuf>,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Observe authoritative pending identities; never approves or claims them.
    Pending {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Approve exactly one explicitly compared pending identity.
    Approve {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        comparison_code: String,
        #[arg(long)]
        enable_computer: bool,
        #[arg(long)]
        enable_browser: bool,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Reject exactly one explicitly compared pending identity.
    Reject {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        comparison_code: String,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Initialize fresh Gateway-only foreground configuration; no service launch or legacy adoption.
    Bootstrap {
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long)]
        deployment_file: PathBuf,
        #[arg(long)]
        runtime_selection_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Run {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(super) enum GatewayTunnelCommand {
    Configure {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        tunnel_id: String,
        #[arg(long)]
        api_key_file: PathBuf,
        #[arg(long)]
        auto_start: bool,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Remove {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum ReleaseCommand {
    /// Native App bootstrap metadata; payload verification belongs to install/update.
    #[command(hide = true)]
    InstalledSelection {
        #[arg(long)]
        payload_dir: PathBuf,
        #[arg(long)]
        publisher_file: PathBuf,
        #[arg(long)]
        expected_publisher: String,
    },
    /// Commit a verified runtime selection for a stopped fresh foreground profile.
    Select {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        runtime_selection_file: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Copy a verified runtime to a new private version directory; never activates it.
    Stage {
        #[arg(long)]
        payload_dir: PathBuf,
        #[arg(long)]
        publisher_file: PathBuf,
        #[arg(long)]
        expected_publisher: String,
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Read-only signature and payload verification; never installs or runs it.
    Verify {
        #[arg(long)]
        payload_dir: PathBuf,
        #[arg(long)]
        publisher_file: PathBuf,
        /// Public SHA256 pin from trusted external policy, not from the payload.
        #[arg(long)]
        expected_publisher: String,
        #[arg(long)]
        json: bool,
        /// Emit verified runtime selection data for the native App bootstrap.
        #[arg(long)]
        runtime_selection: bool,
    },
}

impl NativeModeArg {
    pub(super) fn native(self) -> styx_contracts::native_management::NativeDeploymentMode {
        use styx_contracts::native_management::NativeDeploymentMode;
        match self {
            Self::CreateLocal => NativeDeploymentMode::CreateLocal,
            Self::JoinExisting => NativeDeploymentMode::JoinExisting,
        }
    }
}
impl NativeManagerArg {
    pub(super) fn native(self) -> styx_contracts::native_management::NativeManager {
        use styx_contracts::native_management::NativeManager;
        match self {
            Self::ForegroundCli => NativeManager::ForegroundCli,
            Self::AppManaged => NativeManager::AppManaged,
            Self::PersistentService => NativeManager::PersistentService,
        }
    }
}
impl NativeComponentArg {
    pub(super) fn native(self) -> styx_runtime::management::native::NativeComponent {
        use styx_runtime::management::native::NativeComponent;
        match self {
            Self::Host => NativeComponent::Host,
            Self::Gateway => NativeComponent::Gateway,
        }
    }
}
impl NativeRunArg {
    pub(super) fn native(self) -> styx_contracts::native_management::NativeRunDesired {
        use styx_contracts::native_management::NativeRunDesired;
        match self {
            Self::Running => NativeRunDesired::Running,
            Self::Stopped => NativeRunDesired::Stopped,
        }
    }
}

//! First-run orchestration over the existing native actors. Input receipts are
//! resumability fences, never an alternative enrollment or management ledger.
#[path = "setup/answers.rs"]
mod answers;
#[path = "setup/chatgpt.rs"]
mod chatgpt;
#[path = "setup/foreground.rs"]
mod foreground;
#[path = "setup/invite.rs"]
mod invite_cmd;
#[path = "setup/uninstall.rs"]
mod uninstall_cmd;

pub(super) use answers::*;
use chatgpt::*;
pub(super) use foreground::*;
pub(super) use invite_cmd::*;
pub(super) use uninstall_cmd::*;

use super::{plugin_package, setup_prompt as prompt};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use styx_contracts::native_management::NativeManager;
use styx_runtime::management::{
    native, native_gateway, native_gateway_admin as admin, native_join, setup as inputs,
};

enum FailureOwner {
    #[allow(dead_code)]
    Native(native::NativeManagementError),
    Join(native_join::JoinError),
    #[allow(dead_code)]
    Bootstrap(native_gateway::BootstrapError),
    #[allow(dead_code)]
    Admin(admin::AdminError),
}

pub(super) struct Failure {
    pub code: &'static str,
    pub exit: u8,
    // Unknown errors may own the original coordinator/OS job. Retain them until
    // the CLI's explicit whole-process teardown, just like native_recovery_result.
    _owner: Option<FailureOwner>,
}
impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl Failure {
    pub fn hint(&self) -> Option<&'static str> {
        if let Some(FailureOwner::Join(error)) = &self._owner
            && let Some(hint) = error.hint()
        {
            return Some(hint);
        }
        match self.code {
            "setup_pairing_rejected" => Some(
                "The hub rejected this request; no access was granted. To apply again, explicitly retire this stopped Join setup and use a new invitation. Existing records are kept.",
            ),
            "setup_retirement_unknown" => Some(
                "A role change has an unconfirmed result. Existing records are kept. Inspect that result before continuing; setup will not replay the previous attempt.",
            ),
            "gateway_listen_failed" | "gateway_lan_listen_failed" => Some(
                "The hub could not open its network port. Check whether another program is using it, then choose a free port.",
            ),
            "setup_gateway_unavailable" => Some(
                "The hub is not responding. Check styx status and the hub service logs; another program may be using the selected port.",
            ),
            "native_release_publisher_untrusted" | "native_release_payload_integrity" => Some(
                "The installed Styx files did not match the trusted publisher or signature. Check the fingerprint against the download page / release notes and obtain the matching signed download.",
            ),
            "setup_tunnel_client_missing" => Some(
                "This signed runtime does not include an available ChatGPT tunnel component. Use the Gateway package with tunnel-client, then resume this same setup. Keep your saved tunnel ID and API key.",
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
    pub(super) fn unknown(code: &'static str) -> Self {
        Self {
            code,
            exit: 4,
            _owner: None,
        }
    }
    pub(super) fn native(value: native::NativeManagementError) -> Self {
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
            _owner: Some(FailureOwner::Native(value)),
        }
    }
    fn join(value: native_join::JoinError) -> Self {
        Self {
            code: value.code(),
            exit: value.exit_code(),
            _owner: Some(FailureOwner::Join(value)),
        }
    }
    fn bootstrap(value: native_gateway::BootstrapError) -> Self {
        Self {
            code: value.code(),
            exit: value.exit_code(),
            _owner: Some(FailureOwner::Bootstrap(value)),
        }
    }
    pub(super) fn admin(value: admin::AdminError) -> Self {
        Self {
            code: value.code(),
            exit: value.exit_code(),
            _owner: Some(FailureOwner::Admin(value)),
        }
    }
}

fn setup_guard_failure(error: styx_runtime::management::role_retire::RetireError) -> Failure {
    if error.code == "setup_retirement_unknown" {
        Failure::unknown(error.code)
    } else {
        Failure::new(error.code)
    }
}
impl From<&'static str> for Failure {
    fn from(value: &'static str) -> Self {
        match value {
            "plugin_profile_save_unconfirmed_check_before_retry" | "plugin_publication_unknown" => {
                Self::unknown(value)
            }
            _ => Self::new(value),
        }
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
pub(super) fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::new("setup_clock_unavailable"))?
            .as_millis(),
    )
    .map_err(|_| Failure::new("setup_clock_unavailable"))
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
        prompt::success(&format!(
            "{step}: already complete; keeping existing state."
        ));
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
        if report.status == "rejected" {
            return Err(rejected_join(session, &report));
        }
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
        if claimed.status == "rejected" {
            return Err(rejected_join(session, &claimed));
        }
        if claimed.status.is_ready() {
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

// A native rejected report is backed by the actor's durable seed/request proof.
// Also bind it to the original setup receipt before classifying the old attempt.
fn rejected_join(session: &Session, report: &native_join::JoinReport) -> Failure {
    let bound = inputs::read_private(&session.input("host-public-identity.json"), 16384)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .zip(serde_json::to_value(report).ok())
        .is_some_and(|(original, rejected)| rejection_matches(&original, &rejected));
    if bound {
        Failure::new("setup_pairing_rejected")
    } else {
        Failure::unknown("setup_rejection_binding_unconfirmed")
    }
}

fn rejection_matches(original: &Value, rejected: &Value) -> bool {
    rejected.get("status").and_then(Value::as_str) == Some("rejected")
        && ["device_id", "fingerprint", "request_id"]
            .iter()
            .all(|key| {
                original
                    .get(key)
                    .is_some_and(|value| !value.is_null() && rejected.get(key) == Some(value))
            })
}

async fn execute(session: &mut Session, foreground: bool, running: &mut Foreground) -> Result<()> {
    let a = session.answers.clone();
    let root = session.root.clone();
    let gateway = root.join("gateway");
    let host = root.join("host");
    if !session.input("runtime-selection.json").exists() {
        session.consent(
            "payload",
            "Read the installed Styx version using the publisher fingerprint you supplied.",
        )?;
        let selection = styx_runtime::release::installed_selection(
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
        let verified =
            styx_runtime::release::load_selected(&selection).map_err(|e| Failure::new(e.code()))?;
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
    if a.role != Role::Gateway && !a.workspace.exists() {
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
    if a.role.owns_gateway() {
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
    if a.role == Role::Gateway {
        if a.tunnel.is_some() {
            connect_chatgpt(session, &gateway).await?;
        }
        println!(
            "Gateway-only setup complete. No local Host, command executor, browser or desktop was installed."
        );
        println!("Check Styx: styx status --root {}", root.display());
        println!("Add a computer: styx invite --root {}", root.display());
        return Ok(());
    }
    let device = pair(
        session,
        (a.role.owns_gateway()).then_some(gateway.as_path()),
    )
    .await?;
    if a.role.owns_gateway() {
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
    if a.role.owns_gateway() {
        println!(
            "Waiting for the hub to see this computer connected for commands{}…",
            if a.browser {
                " and Browser Automation"
            } else {
                ""
            }
        );
        wait_computer(&gateway, device.as_deref(), a.browser).await?;
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
        if a.role.owns_gateway() {
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
    if a.role.owns_gateway() {
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

pub(super) async fn run(
    root: Option<PathBuf>,
    answers_file: Option<PathBuf>,
    foreground_mode: bool,
    exit_when_connected: bool,
) -> Result<()> {
    // console restores termios before raising SIGINT on Ctrl-C. Register the
    // same Tokio signal handling used by the running setup before prompts too,
    // so a read error can unwind Dialoguer and restore the terminal cursor.
    #[cfg(unix)]
    let _prompt_interrupt = if prompt::enhanced() {
        Some(
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| Failure::new("setup_signal_failed"))?,
        )
    } else {
        None
    };
    #[cfg(windows)]
    let _prompt_interrupt = if prompt::enhanced() {
        Some(tokio::signal::windows::ctrl_c().map_err(|_| Failure::new("setup_signal_failed"))?)
    } else {
        None
    };
    let root = root.map(Ok).unwrap_or_else(root_default)?;
    if !root.is_absolute() {
        return Err("setup_absolute_root_required".into());
    }
    let mut container_guard = if root.exists() {
        Some(
            styx_runtime::management::role_retire::SetupContainerGuard::acquire(&root)
                .map_err(setup_guard_failure)?,
        )
    } else {
        None
    };
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
    if intent.exists() && answers.role.owns_gateway() && answers.tunnel.is_none() {
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
    require_tunnel_client(&answers, &root).await?;
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
        if let Some(tunnel) = &answers.tunnel
            && tunnel.api_key_file.is_none()
        {
            let status = styx_runtime::foreground::tunnel::status(&root.join("gateway"))
                .await
                .map_err(|_| Failure::new("setup_private_tunnel_key_file_required"))?;
            let status = serde_json::to_value(status)
                .map_err(|_| Failure::new("setup_tunnel_status_failed"))?;
            if status["tunnelId"] != tunnel.id {
                return Err("setup_private_tunnel_key_file_required".into());
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
        prompt::section("Review setup");
        prompt::info("Completed steps will be kept. Styx will:");
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
        if container_guard.is_none() {
            inputs::private_directory(&session.root)
                .map_err(|_| Failure::new("setup_private_inputs_failed"))?;
            container_guard = Some(
                styx_runtime::management::role_retire::SetupContainerGuard::acquire(&session.root)
                    .map_err(setup_guard_failure)?,
            );
            if intent.exists() {
                return Err("setup_container_changed".into());
            }
        }
        inputs::private_directory(&session.root.join("inputs"))
            .map_err(|_| Failure::new("setup_private_inputs_failed"))?;
    }
    container_guard
        .as_ref()
        .ok_or_else(|| Failure::new("setup_container_refused"))?
        .validate()
        .map_err(setup_guard_failure)?;
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

#[cfg(test)]
#[path = "setup/tests.rs"]
mod tests;

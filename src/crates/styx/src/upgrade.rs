//! Linux updates run as one short-lived OS job. The native transaction journal
//! owns effects; the installer keeps only its target, original settings and one
//! pending dispatch so an interrupted call is observed before any new action.
use super::setup::Failure;
use std::path::PathBuf;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) use linux::{apply, run};
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(super) async fn run(
    _: PathBuf,
    _: Option<PathBuf>,
    _: Option<String>,
    _: Option<PathBuf>,
    _: bool,
    _: Option<PathBuf>,
) -> Result<(), Failure> {
    Err(Failure::new("upgrade_linux_user_services_required"))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use super::*;
    use crate::cli::{install, setup, setup_prompt as prompt};
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use serde_json::Value;
    use std::path::Path;
    use styx_contracts::native_management::{
        NativeAutostartDesired, NativeComponentDesired, NativeManager, NativeRunDesired,
        NativeRuntimeSelection,
    };
    use styx_runtime::{
        management::{
            native::{
                self, NativeComponent,
                service::{ServiceAction, ServiceReport, manage},
            },
            native_gateway_admin as admin, setup as inputs,
        },
        release,
        store::PrivateRoot,
    };
    type Result<T> = std::result::Result<T, Failure>;

    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    enum Role {
        Gateway,
        Host,
    }
    impl Role {
        fn name(self) -> &'static str {
            match self {
                Self::Gateway => "gateway",
                Self::Host => "host",
            }
        }
        fn component(self) -> NativeComponent {
            match self {
                Self::Gateway => NativeComponent::Gateway,
                Self::Host => NativeComponent::Host,
            }
        }
        fn desired(self, report: &ServiceReport) -> Result<NativeComponentDesired> {
            match self {
                Self::Gateway => report.desired.gateway,
                Self::Host => report.desired.host,
            }
            .ok_or_else(|| Failure::new("upgrade_role_missing"))
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Original {
        role: Role,
        selection: NativeRuntimeSelection,
        version: String,
        running: bool,
        enabled: bool,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CommandLink {
        bin: PathBuf,
        previous: Option<PathBuf>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Plan {
        schema: u16,
        target: NativeRuntimeSelection,
        version: String,
        roles: Vec<Original>,
        command: CommandLink,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pending {
        role: Role,
        action: String,
        transaction_id: String,
        revision: u64,
    }

    fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
        let bytes = inputs::read_private(path, 1024 * 1024)
            .map_err(|_| Failure::new("upgrade_input_unavailable"))?;
        serde_json::from_slice(&bytes).map_err(|_| Failure::new("upgrade_input_invalid"))
    }
    fn write(path: &Path, value: &impl Serialize) -> Result<()> {
        let bytes =
            serde_json::to_vec_pretty(value).map_err(|_| Failure::new("upgrade_input_invalid"))?;
        inputs::write_new(path, &bytes)
            .map_err(|_| Failure::unknown("upgrade_input_publication_unknown"))
    }
    fn replace_input(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
        let temporary = root.join(format!(".{name}.upgrade"));
        match std::fs::remove_file(&temporary) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Failure::unknown("upgrade_input_publication_unknown")),
        }
        write(&temporary, value)?;
        std::fs::rename(&temporary, root.join(name))
            .and_then(|()| std::fs::File::open(root)?.sync_all())
            .map_err(|_| Failure::unknown("upgrade_input_publication_unknown"))
    }
    // The caller holds the inputs writer. A retained update plan (or the
    // same-release path) can finish either publication after interruption.
    fn complete_install(root: &Path, plan: &Plan, mut answers: setup::Answers) -> Result<()> {
        install::link(
            Path::new(&plan.target.payload_path),
            &plan.command.bin,
            plan.command.previous.as_deref(),
        )?;
        answers.payload.payload_dir = plan.target.payload_path.clone().into();
        answers.payload.publisher_file = plan.target.publisher_file.clone().into();
        let inputs = root.join("inputs");
        replace_input(&inputs, "runtime-selection.json", &plan.target)?;
        replace_input(&inputs, "setup-intent.json", &answers)
    }
    fn remove(path: &Path) -> Result<()> {
        std::fs::remove_file(path).map_err(|_| Failure::unknown("upgrade_input_cleanup_unknown"))
    }
    fn directory(root: &Path) -> PathBuf {
        root.join("inputs/update")
    }
    fn same_release(old: &NativeRuntimeSelection, new: &NativeRuntimeSelection) -> bool {
        old.manifest_sha256 == new.manifest_sha256
    }
    async fn status(root: &Path, role: Role, tx: Option<&str>) -> Result<ServiceReport> {
        let tx = tx
            .map(|v| v.to_owned().try_into())
            .transpose()
            .map_err(|_| Failure::new("upgrade_input_invalid"))?;
        manage(
            &root.join(role.name()),
            ServiceAction::Status,
            role.component(),
            tx,
            None,
        )
        .await
        .map_err(Failure::native)
    }
    fn satisfied(role: Role, action: ServiceAction, report: &ServiceReport) -> Result<bool> {
        let desired = role.desired(report)?;
        let os = &report.os;
        let stopped = desired.run == NativeRunDesired::Stopped
            && os["main_pid"] == 0
            && (os["active"] == "inactive" || (os["active"] == "failed" && os["cgroup"] == ""));
        Ok(match action {
            ServiceAction::Install => {
                desired.manager == NativeManager::PersistentService && os["installed"] == true
            }
            ServiceAction::Start => {
                desired.run == NativeRunDesired::Running
                    && os["active"] == "active"
                    && os["main_pid"].as_u64().is_some_and(|p| p != 0)
            }
            ServiceAction::Enable => {
                desired.autostart == NativeAutostartDesired::Enabled && os["enabled"] == true
            }
            ServiceAction::Stop => stopped,
            ServiceAction::Disable => {
                desired.autostart == NativeAutostartDesired::Disabled && os["enabled"] == false
            }
            ServiceAction::Uninstall => {
                desired.manager == NativeManager::ForegroundCli
                    && desired.run == NativeRunDesired::Stopped
                    && desired.autostart == NativeAutostartDesired::Disabled
                    && os["installed"] == false
                    && os["active"] == "not_installed"
                    && os["main_pid"] == 0
            }
            ServiceAction::Status => false,
        })
    }
    fn service_action(name: &str) -> Result<Option<ServiceAction>> {
        Ok(Some(match name {
            "stop" => ServiceAction::Stop,
            "disable" => ServiceAction::Disable,
            "uninstall" => ServiceAction::Uninstall,
            "install" => ServiceAction::Install,
            "enable" => ServiceAction::Enable,
            "start" => ServiceAction::Start,
            "select" => return Ok(None),
            _ => return Err(Failure::new("upgrade_input_invalid")),
        }))
    }
    fn committed(observation: &Value, tx: &str) -> bool {
        (observation["transaction_id"] == tx
            && observation["status"] == "committed"
            && matches!(
                observation["state_scope"].as_str(),
                Some("committed_target" | "transaction_target")
            ))
            || (observation["transaction"]["transaction_id"] == tx
                && observation["transaction"]["observed_stage"] == "committed"
                && observation["transaction"]["receipt"]["stage"] == "committed")
    }
    fn settled_current(role: Role, report: &ServiceReport) -> Result<bool> {
        let desired = role.desired(report)?;
        if report.os["installed"] == false {
            return satisfied(role, ServiceAction::Uninstall, report);
        }
        let run = if desired.run == NativeRunDesired::Running {
            ServiceAction::Start
        } else {
            ServiceAction::Stop
        };
        let enabled = if desired.autostart == NativeAutostartDesired::Enabled {
            ServiceAction::Enable
        } else {
            ServiceAction::Disable
        };
        Ok(satisfied(role, run, report)?
            && (report.os["installed"] == false || satisfied(role, enabled, report)?))
    }
    fn service_confirmed(pending: &Pending, after: &ServiceReport) -> Result<bool> {
        let Some(action) = service_action(&pending.action)? else {
            return Ok(false);
        };
        if !after
            .transaction_observation
            .as_ref()
            .is_some_and(|v| committed(v, &pending.transaction_id))
        {
            return Ok(false);
        }
        // A later authorized change does not erase the original committed
        // transaction. Observe its currently settled OS state, then reconcile
        // the update from that state; never require an old revision forever.
        Ok(satisfied(pending.role, action, after)?
            || (after.revision > pending.revision.saturating_add(1)
                && settled_current(pending.role, after)?))
    }
    async fn settle(root: &Path, work: &Path, plan: &Plan) -> Result<()> {
        let path = work.join("pending.json");
        if !path
            .try_exists()
            .map_err(|_| Failure::new("upgrade_input_unavailable"))?
        {
            return Ok(());
        }
        let pending: Pending = read(&path)?;
        if !plan.roles.iter().any(|r| r.role == pending.role) {
            return Err(Failure::new("upgrade_input_invalid"));
        }
        let after = status(root, pending.role, Some(&pending.transaction_id)).await;
        // Publication of the input may have been followed by process exit
        // before dispatch. Only the native owner can establish that absence.
        match native::transaction_not_dispatched(
            &root.join(pending.role.name()),
            &pending.transaction_id,
            pending.revision,
        )
        .await
        {
            Ok(true) => return remove(&path),
            Ok(false) => {}
            Err(error) if error.code() == "native_management_busy" => {}
            Err(error) => return Err(Failure::native(error)),
        }
        let after = after?;
        let confirmed = if service_action(&pending.action)?.is_some() {
            service_confirmed(&pending, &after)?
        } else {
            after
                .transaction_observation
                .as_ref()
                .is_some_and(|v| committed(v, &pending.transaction_id))
                && same_release(
                    &admin::committed_runtime_selection(&root.join(pending.role.name()))
                        .await
                        .map_err(Failure::admin)?,
                    &plan.target,
                )
        };
        if !confirmed {
            eprintln!(
                "The original {} {} is unconfirmed. Inspect transaction {} before resuming this update.",
                pending.role.name(),
                pending.action,
                pending.transaction_id
            );
            return Err(Failure::unknown("upgrade_original_operation_unconfirmed"));
        }
        remove(&path)
    }
    fn pending(work: &Path, role: Role, action: &str, revision: u64) -> Result<Pending> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Failure::new("upgrade_clock_unavailable"))?
            .as_nanos();
        let pending = Pending {
            role,
            action: action.into(),
            revision,
            transaction_id: format!("update-{}-{action}-{timestamp}", role.name()),
        };
        write(&work.join("pending.json"), &pending)?;
        Ok(pending)
    }
    fn finish(work: &Path, outcome: Result<()>) -> Result<()> {
        match outcome {
            Ok(()) => remove(&work.join("pending.json")),
            Err(error) => {
                // A definite refusal has no unknown effect to preserve. Native
                // Unknown retains its one original dispatch until observation.
                if error.exit != 4 {
                    remove(&work.join("pending.json"))?;
                }
                Err(error)
            }
        }
    }
    async fn service_step(
        root: &Path,
        work: &Path,
        role: Role,
        action: ServiceAction,
        before: ServiceReport,
    ) -> Result<()> {
        let pending = pending(
            work,
            role,
            setup::service_action_name(action),
            before.revision,
        )?;
        let tx = pending
            .transaction_id
            .try_into()
            .map_err(|_| Failure::new("upgrade_input_invalid"))?;
        let outcome = manage(
            &root.join(role.name()),
            action,
            role.component(),
            Some(tx),
            Some(before.revision),
        )
        .await
        .map(|_| ())
        .map_err(Failure::native);
        finish(work, outcome)
    }
    async fn restore(root: &Path, work: &Path, plan: &Plan) -> Result<()> {
        for original in &plan.roles {
            let role = original.role;
            for action in [
                ServiceAction::Install,
                if original.enabled {
                    ServiceAction::Enable
                } else {
                    ServiceAction::Disable
                },
                if original.running {
                    ServiceAction::Start
                } else {
                    ServiceAction::Stop
                },
            ] {
                let before = status(root, role, None).await?;
                if !satisfied(role, action, &before)? {
                    service_step(root, work, role, action, before).await?;
                }
            }
            if role == Role::Gateway && original.running {
                setup::wait_gateway(&root.join("gateway")).await?;
            }
        }
        Ok(())
    }
    async fn execute(root: &Path, work: &Path, plan: &Plan) -> Result<()> {
        settle(root, work, plan).await?;
        for original in plan.roles.iter().rev() {
            let role = original.role;
            let selected = admin::committed_runtime_selection(&root.join(role.name()))
                .await
                .map_err(Failure::admin)?;
            if same_release(&selected, &plan.target) {
                continue;
            }
            setup::uninstall_role(
                &root.join(role.name()),
                role.name(),
                role.component(),
                async |action, before| service_step(root, work, role, action, before).await,
            )
            .await?;
        }
        for original in &plan.roles {
            let role = original.role;
            let path = root.join(role.name());
            let selected = admin::committed_runtime_selection(&path)
                .await
                .map_err(Failure::admin)?;
            if same_release(&selected, &plan.target) {
                continue;
            }
            let before = status(root, role, None).await?;
            let sequence = before
                .revision
                .checked_add(1)
                .ok_or_else(|| Failure::new("upgrade_sequence_exhausted"))?;
            let pending = pending(work, role, "select", before.revision)?;
            let outcome = native::update::select_runtime(
                &path,
                &work.join("selection.json"),
                &pending.transaction_id,
                sequence,
            )
            .await
            .map(|_| ())
            .map_err(Failure::native);
            finish(work, outcome)?;
        }
        restore(root, work, plan).await
    }
    async fn validate_roles(root: &Path, plan: &Plan) -> Result<()> {
        if plan.schema != 2 || plan.roles.is_empty() {
            return Err(Failure::new("upgrade_input_invalid"));
        }
        for original in &plan.roles {
            let current = admin::committed_runtime_selection(&root.join(original.role.name()))
                .await
                .map_err(Failure::admin)?;
            if current != original.selection && current != plan.target {
                return Err(Failure::new("upgrade_recorded_state_changed"));
            }
        }
        Ok(())
    }
    pub(in crate::cli) async fn apply(root: PathBuf) -> Result<()> {
        let input_root = PrivateRoot::open(root.join("inputs"))
            .map_err(|_| Failure::new("upgrade_private_inputs_required"))?;
        let _lease = input_root
            .try_configuration_writer()
            .map_err(|_| Failure::new("upgrade_busy"))?;
        let work = directory(&root);
        let plan: Plan = read(&work.join("plan.json"))?;
        validate_roles(&root, &plan).await?;
        let selection: NativeRuntimeSelection = read(&work.join("selection.json"))?;
        if selection != plan.target {
            return Err(Failure::new("upgrade_recorded_state_changed"));
        }
        release::verify_selected(&plan.target).map_err(|e| Failure::new(e.code()))?;
        if let Err(error) = execute(&root, &work, &plan).await {
            let mut unchanged = error.exit != 4 && !work.join("pending.json").exists();
            for original in &plan.roles {
                unchanged &= admin::committed_runtime_selection(&root.join(original.role.name()))
                    .await
                    .is_ok_and(|v| v == original.selection);
            }
            if unchanged {
                restore(&root, &work, &plan).await?;
                eprintln!(
                    "The update stopped before replacing any Runtime; original services were restored."
                );
            }
            return Err(error);
        }
        let answers = setup::Answers::load(&root.join("inputs/setup-intent.json"))?;
        if answers.role == setup::Role::Hub
            && plan.roles.iter().any(|r| r.role == Role::Host && r.running)
            && plan
                .roles
                .iter()
                .any(|r| r.role == Role::Gateway && r.running)
        {
            let identity: Value = read(&root.join("inputs/host-public-identity.json"))?;
            let device = identity["device_id"]
                .as_str()
                .ok_or_else(|| Failure::new("upgrade_device_identity_unavailable"))?;
            setup::wait_computer(&root.join("gateway"), Some(device), answers.browser).await?;
        }
        complete_install(&root, &plan, answers)?;
        remove(&work.join("plan.json"))?;
        remove(&work.join("selection.json"))?;
        println!(
            "Styx updated to {}. Settings, pairing and service preferences were kept.",
            plan.version
        );
        Ok(())
    }
    fn job(root: &Path) -> Result<tokio::process::Command> {
        let mut command = tokio::process::Command::new("/usr/bin/systemd-run");
        let digest =
            styx_contracts::identity::Sha256Digest::of_bytes(root.as_os_str().as_encoded_bytes())
                .to_hex();
        command.args([
            "--user",
            "--wait",
            "--collect",
            "--service-type=exec",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
        ]);
        command.arg(format!("--unit=styx-update-{}", &digest[..16]));
        command.arg("--");
        command.arg(
            std::env::current_exe().map_err(|_| Failure::new("upgrade_executable_unavailable"))?,
        );
        command.arg("__upgrade-apply").arg("--root").arg(root);
        // The OS owns the job; no inherited terminal, Exec pipe or Host cgroup
        // remains necessary after submission.
        let runtime = PathBuf::from(format!("/run/user/{}", nix::unistd::getuid().as_raw()));
        command.env("XDG_RUNTIME_DIR", &runtime);
        command.env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/bus", runtime.display()),
        );
        Ok(command)
    }
    pub(in crate::cli) async fn run(
        payload: PathBuf,
        publisher_file: Option<PathBuf>,
        expected_publisher: Option<String>,
        root: Option<PathBuf>,
        yes: bool,
        bin: Option<PathBuf>,
    ) -> Result<()> {
        let root = root.map(Ok).unwrap_or_else(setup::root_default)?;
        if !root.is_absolute() || !payload.is_absolute() {
            return Err(Failure::new("upgrade_absolute_paths_required"));
        }
        let input_root = PrivateRoot::open(root.join("inputs"))
            .map_err(|_| Failure::new("upgrade_private_inputs_required"))?;
        let lease = input_root
            .try_configuration_writer()
            .map_err(|_| Failure::new("upgrade_busy"))?;
        let answers = setup::Answers::load(&root.join("inputs/setup-intent.json"))?;
        let publisher = publisher_file.unwrap_or_else(|| answers.payload.publisher_file.clone());
        let pin = setup::normalize_publisher_pin(
            &expected_publisher.unwrap_or_else(|| answers.payload.expected_publisher.clone()),
        );
        let target = release::inspect_selection(&payload, &publisher, &pin)
            .await
            .map_err(|e| Failure::new(e.code()))?;
        let version = release::verify_selected(&target)
            .map_err(|e| Failure::new(e.code()))?
            .report()
            .version;
        let bin = bin.map(Ok).unwrap_or_else(install::default_bin)?;
        let work = directory(&root);
        let saved = work.join("plan.json");
        let resume = saved
            .try_exists()
            .map_err(|_| Failure::new("upgrade_input_unavailable"))?;
        let plan = if resume {
            let plan: Plan = read(&saved)?;
            if plan.target != target || plan.command.bin != bin {
                return Err(Failure::new("upgrade_recorded_state_changed"));
            }
            validate_roles(&root, &plan).await?;
            plan
        } else {
            let mut roles = Vec::new();
            for role in [Role::Gateway, Role::Host] {
                let path = root.join(role.name());
                if !path.is_dir() {
                    continue;
                }
                let selection = admin::committed_runtime_selection(&path)
                    .await
                    .map_err(Failure::admin)?;
                if selection.publisher_spki_sha256 != target.publisher_spki_sha256 {
                    return Err(Failure::new("upgrade_different_publisher_refused"));
                }
                let report = status(&root, role, None).await?;
                let desired = role.desired(&report)?;
                if desired.manager != NativeManager::PersistentService
                    || report.os["installed"] != true
                {
                    return Err(Failure::new("upgrade_existing_linux_services_required"));
                }
                if report.os["enabled"].as_bool().is_none()
                    || !matches!(
                        report.os["active"].as_str(),
                        Some("active" | "inactive" | "failed")
                    )
                {
                    return Err(Failure::new("upgrade_service_state_unsettled"));
                }
                roles.push(Original {
                    role,
                    version: release::load_selected(&selection)
                        .map_err(|e| Failure::new(e.code()))?
                        .report()
                        .version,
                    selection,
                    running: desired.run == NativeRunDesired::Running
                        || report.os["active"] == "active",
                    enabled: report.os["enabled"] == true,
                });
            }
            if roles.is_empty() {
                return Err(Failure::new("upgrade_nothing_set_up"));
            }
            let previous = install::previous_command(&bin, Some(&answers.payload), &pin).await?;
            Plan {
                schema: 2,
                target,
                version,
                roles,
                command: CommandLink { bin, previous },
            }
        };
        if !resume
            && plan
                .roles
                .iter()
                .all(|r| same_release(&r.selection, &plan.target))
        {
            complete_install(&root, &plan, answers)?;
            println!(
                "Styx {} is already selected; the CLI entry is up to date.",
                plan.version
            );
            return Ok(());
        }
        for original in &plan.roles {
            println!(
                "{}: {} -> {}",
                original.role.name(),
                original.version,
                plan.version
            );
        }
        if !yes {
            if !prompt::terminal() {
                return Err(Failure::new("upgrade_confirmation_required_use_yes"));
            }
            if !prompt::confirm("Update Styx now, preserving settings and pairing?")? {
                return Err(Failure::new("setup_cancelled"));
            }
        }
        if !resume {
            inputs::private_directory(&work)
                .map_err(|_| Failure::new("upgrade_input_unavailable"))?;
            if work.join("pending.json").exists() {
                return Err(Failure::unknown("upgrade_original_operation_unconfirmed"));
            }
            if work.join("selection.json").exists() {
                remove(&work.join("selection.json"))?;
            }
            write(&work.join("selection.json"), &plan.target)?;
            write(&saved, &plan)?;
        }
        drop(lease);
        println!(
            "The system service manager will complete this update, including restarting Styx."
        );
        let result = job(&root)?
            .status()
            .await
            .map_err(|_| Failure::unknown("upgrade_job_submission_unconfirmed"))?;
        if result.success() {
            println!("Styx updated to {}.", plan.version);
            Ok(())
        } else {
            eprintln!(
                "The update did not report success. Its systemd journal and saved update plan were retained."
            );
            Err(Failure::unknown("upgrade_job_not_completed"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        use styx_contracts::native_management::NativeDesired;

        fn completion_fixture(name: &str) -> (PathBuf, Plan, Value) {
            let root = std::env::temp_dir().join(format!(
                "styx-update-inputs-{}-{}-{name}",
                std::process::id(),
                setup::now_ms().unwrap()
            ));
            inputs::private_directory(&root.join("inputs/update")).unwrap();
            for release in ["old", "new"] {
                inputs::private_directory(&root.join(release).join("runtime/bin")).unwrap();
                inputs::write_new(&root.join(release).join("runtime/bin/styx"), b"fixture")
                    .unwrap();
                inputs::write_new(&root.join(release).join("publisher.pem"), b"publisher").unwrap();
            }
            let old = root.join("old/runtime");
            let target: NativeRuntimeSelection = serde_json::from_value(json!({
                "schema":1,"payload_path":root.join("new/runtime"),
                "payload_root":{"platform":"linux","device":1,"inode":2,"uid":1000},
                "manifest_sha256":"b".repeat(64),
                "publisher_file":root.join("new/publisher.pem"),
                "publisher_spki_sha256":"a".repeat(64)
            }))
            .unwrap();
            let mut previous = target.clone();
            previous.payload_path = old.to_str().unwrap().into();
            previous.publisher_file = root.join("old/publisher.pem").to_str().unwrap().into();
            previous.manifest_sha256 = serde_json::from_value(json!("c".repeat(64))).unwrap();
            let answers: setup::Answers = serde_json::from_value(json!({
                "schema":1,"role":"hub","label":"Keep my computer",
                "workspace":root.join("workspace"),"shell":"/bin/bash",
                "exec":false,"browser":true,"browser_executable":"/usr/bin/chromium",
                "computer":true,"port":23456,"networks":["10.20.30.40"],
                "payload":{"payload_dir":old,"publisher_file":previous.publisher_file,
                    "expected_publisher":"a".repeat(64)}
            }))
            .unwrap();
            write(&root.join("inputs/setup-intent.json"), &answers).unwrap();
            write(&root.join("inputs/runtime-selection.json"), &previous).unwrap();
            let plan = Plan {
                schema: 2,
                target,
                version: "0.5.0".into(),
                roles: vec![Original {
                    role: Role::Host,
                    selection: previous,
                    version: "0.5.0-rc.1".into(),
                    running: true,
                    enabled: true,
                }],
                command: CommandLink {
                    bin: root.join("bin"),
                    previous: Some(old.clone()),
                },
            };
            install::link(&old, &plan.command.bin, None).unwrap();
            let mut expected = serde_json::to_value(answers).unwrap();
            expected["payload"]["payload_dir"] = json!(plan.target.payload_path);
            expected["payload"]["publisher_file"] = json!(plan.target.publisher_file);
            (root, plan, expected)
        }
        fn assert_setup_inputs(root: &Path, plan: &Plan, expected: Value) {
            let answers = setup::Answers::load(&root.join("inputs/setup-intent.json")).unwrap();
            assert_eq!(serde_json::to_value(&answers).unwrap(), expected);
            let selection: NativeRuntimeSelection =
                read(&root.join("inputs/runtime-selection.json")).unwrap();
            assert_eq!(selection, plan.target);
            assert!(answers.payload.publisher_file.is_file());
            assert!(answers.payload.payload_dir.join("bin/styx").is_file());
            assert_eq!(
                std::fs::read_link(plan.command.bin.join("styx")).unwrap(),
                answers.payload.payload_dir.join("bin/styx")
            );
        }
        #[test]
        fn successful_and_same_release_updates_refresh_setup_consumers() {
            for same in [false, true] {
                let (root, mut plan, expected) =
                    completion_fixture(if same { "same" } else { "new" });
                if same {
                    plan.roles[0].selection = plan.target.clone();
                }
                let inputs = PrivateRoot::open(root.join("inputs")).unwrap();
                let _lease = inputs.try_configuration_writer().unwrap();
                let answers = setup::Answers::load(&root.join("inputs/setup-intent.json")).unwrap();
                complete_install(&root, &plan, answers).unwrap();
                std::fs::remove_dir_all(root.join("old")).unwrap();
                assert_setup_inputs(&root, &plan, expected);
                std::fs::remove_dir_all(root).unwrap();
            }
        }
        #[test]
        fn interrupted_input_publication_finishes_with_the_retained_plan() {
            let (root, plan, expected) = completion_fixture("interrupted");
            let inputs = PrivateRoot::open(root.join("inputs")).unwrap();
            let _lease = inputs.try_configuration_writer().unwrap();
            let saved = directory(&root).join("plan.json");
            write(&saved, &plan).unwrap();
            let temporary = root.join("inputs/.setup-intent.json.upgrade");
            std::fs::create_dir(&temporary).unwrap();
            let answers = setup::Answers::load(&root.join("inputs/setup-intent.json")).unwrap();
            assert_eq!(complete_install(&root, &plan, answers).unwrap_err().exit, 4);
            let selection: NativeRuntimeSelection =
                read(&root.join("inputs/runtime-selection.json")).unwrap();
            assert_eq!(selection, plan.target);
            let answers = setup::Answers::load(&root.join("inputs/setup-intent.json")).unwrap();
            assert_eq!(answers.payload.payload_dir, root.join("old/runtime"));
            std::fs::remove_dir(&temporary).unwrap();
            inputs::write_new(&temporary, b"interrupted private write").unwrap();
            let resumed: Plan = read(&saved).unwrap();
            complete_install(&root, &resumed, answers).unwrap();
            std::fs::remove_dir_all(root.join("old")).unwrap();
            assert_setup_inputs(&root, &resumed, expected);
            std::fs::remove_dir_all(root).unwrap();
        }

        fn report(run: NativeRunDesired, active: &str, revision: u64) -> ServiceReport {
            ServiceReport {
                schema: 1,
                operation: "status",
                configuration_only: false,
                transaction_id: None,
                revision,
                operations_replayed: false,
                desired: NativeDesired {
                    gateway: None,
                    host: Some(NativeComponentDesired {
                        manager: NativeManager::PersistentService,
                        run,
                        autostart: NativeAutostartDesired::Enabled,
                    }),
                },
                os: json!({"installed":true, "enabled":true, "active":active,
                    "main_pid":if active == "active" { 42 } else { 0 }}),
                transaction_observation: Some(json!({"transaction":{
                    "transaction_id":"original", "observed_stage":"committed",
                    "receipt":{"stage":"committed"}}})),
            }
        }
        fn stopped_dispatch() -> Pending {
            Pending {
                role: Role::Host,
                action: "stop".into(),
                transaction_id: "original".into(),
                revision: 84,
            }
        }
        #[test]
        fn recovered_stop_is_not_tied_forever_to_revision_85() {
            let stopped = stopped_dispatch();
            assert!(
                service_confirmed(&stopped, &report(NativeRunDesired::Stopped, "inactive", 85))
                    .unwrap()
            );
            assert!(
                service_confirmed(&stopped, &report(NativeRunDesired::Running, "active", 86))
                    .unwrap()
            );
            assert!(
                !service_confirmed(
                    &stopped,
                    &report(NativeRunDesired::Running, "deactivating", 86)
                )
                .unwrap()
            );
            assert!(
                !service_confirmed(&stopped, &report(NativeRunDesired::Running, "active", 85))
                    .unwrap()
            );
        }
        #[test]
        fn newer_current_state_never_substitutes_for_original_commit() {
            let mut current = report(NativeRunDesired::Running, "active", 86);
            current.transaction_observation = Some(json!({"transaction":{
                "transaction_id":"another", "observed_stage":"committed",
                "receipt":{"stage":"committed"}}}));
            assert!(!service_confirmed(&stopped_dispatch(), &current).unwrap());
            current.transaction_observation = Some(json!({"transaction":{
                "transaction_id":"original", "observed_stage":"applied",
                "receipt":{"stage":"applied"}}}));
            assert!(!service_confirmed(&stopped_dispatch(), &current).unwrap());
        }
        #[test]
        fn committed_uninstall_confirms_the_absent_unit() {
            let mut current = report(NativeRunDesired::Stopped, "not_installed", 85);
            let desired = current.desired.host.as_mut().unwrap();
            desired.manager = NativeManager::ForegroundCli;
            desired.autostart = NativeAutostartDesired::Disabled;
            current.os = json!({"installed":false, "enabled":null,
                "active":"not_installed", "main_pid":0, "cgroup":""});
            let mut pending = stopped_dispatch();
            pending.action = "uninstall".into();
            assert!(service_confirmed(&pending, &current).unwrap());
            assert!(settled_current(Role::Host, &current).unwrap());
            current.os["main_pid"] = json!(42);
            assert!(!service_confirmed(&pending, &current).unwrap());
        }
        #[test]
        fn service_start_requires_a_real_process() {
            let mut current = report(NativeRunDesired::Running, "active", 85);
            assert!(satisfied(Role::Host, ServiceAction::Start, &current).unwrap());
            current.os["main_pid"] = json!(0);
            assert!(!satisfied(Role::Host, ServiceAction::Start, &current).unwrap());
        }
        #[test]
        fn job_uses_system_service_manager_without_inheriting_stdio() {
            let root = Path::new("/private/profile with spaces");
            let command = job(root).unwrap();
            let args = command
                .as_std()
                .get_args()
                .map(|v| v.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(args.contains(&"--user".into()));
            assert!(args.contains(&"--wait".into()));
            assert!(args.contains(&"--property=StandardOutput=journal".into()));
            assert!(!args.contains(&"--pipe".into()));
            assert!(!args.contains(&"--scope".into()));
            assert_eq!(
                &args[args.len() - 3..],
                &["__upgrade-apply", "--root", "/private/profile with spaces"]
            );
        }
        #[test]
        fn only_unknown_dispatch_survives_for_observation() {
            let root = std::env::temp_dir().join(format!(
                "styx-update-{}-{}",
                std::process::id(),
                setup::now_ms().unwrap()
            ));
            inputs::private_directory(&root).unwrap();
            pending(&root, Role::Host, "stop", 84).unwrap();
            assert!(finish(&root, Err(Failure::unknown("fixture_unknown"))).is_err());
            assert!(root.join("pending.json").exists());
            assert!(finish(&root, Err(Failure::new("fixture_refused"))).is_err());
            assert!(!root.join("pending.json").exists());
            pending(&root, Role::Host, "start", 85).unwrap();
            finish(&root, Ok(())).unwrap();
            assert!(!root.join("pending.json").exists());
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

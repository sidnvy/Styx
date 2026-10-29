//! Linux upgrade orchestration. Immutable input/dispatch receipts supplement,
//! but never replace, the native transaction chain and fresh OS observations.
use super::setup::Failure;
use std::path::PathBuf;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) use linux::run;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(super) async fn run(
    _: PathBuf,
    _: Option<PathBuf>,
    _: Option<String>,
    _: Option<PathBuf>,
    _: bool,
) -> Result<(), Failure> {
    Err(Failure::new("upgrade_linux_user_services_required"))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use super::*;
    use crate::cli::{setup, setup_prompt as prompt};
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use serde_json::Value;
    use std::path::Path;
    use styx_contracts::native_management::{
        NativeComponentDesired, NativeManager, NativeRunDesired, NativeRuntimeSelection,
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

    #[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
        installed: bool,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Plan {
        schema: u16,
        target: NativeRuntimeSelection,
        version: String,
        roles: Vec<Original>,
    }
    impl Plan {
        fn text(&self) -> String {
            let changes = self
                .roles
                .iter()
                .map(|role| format!("{}: {} -> {}", role.role.name(), role.version, self.version))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "Styx upgrade\n{changes}\nComputers stay paired; ChatGPT keeps working after the restart.\nServices restart gateway first; original running/enabled settings are restored."
            )
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Dispatch {
        transaction_id: String,
        revision: u64,
    }

    fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
        let raw = inputs::read_private(path, 1024 * 1024)
            .map_err(|_| Failure::new("upgrade_receipt_unavailable"))?;
        serde_json::from_slice(&raw).map_err(|_| Failure::new("upgrade_receipt_invalid"))
    }
    fn write(path: &Path, value: &impl Serialize) -> Result<()> {
        let raw = serde_json::to_vec_pretty(value)
            .map_err(|_| Failure::new("upgrade_receipt_invalid"))?;
        inputs::write_new(path, &raw)
            .map_err(|_| Failure::unknown("upgrade_receipt_publication_unknown"))
    }
    fn mark(path: &Path) -> Result<()> {
        write(path, &true)
    }
    fn marked(path: &Path) -> Result<bool> {
        if path
            .try_exists()
            .map_err(|_| Failure::new("upgrade_receipt_unavailable"))?
        {
            read(path)
        } else {
            Ok(false)
        }
    }
    fn shell_path(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }
    fn publisher_matches(old: &NativeRuntimeSelection, new: &NativeRuntimeSelection) -> Result<()> {
        if old.publisher_spki_sha256 != new.publisher_spki_sha256 {
            return Err(Failure::new("upgrade_different_publisher_refused"));
        }
        Ok(())
    }
    fn already_selected(old: &NativeRuntimeSelection, new: &NativeRuntimeSelection) -> bool {
        old.manifest_sha256 == new.manifest_sha256
    }
    fn require_change(same: bool, resumable: bool) -> Result<()> {
        if same && !resumable {
            return Err(Failure::new("upgrade_already_running"));
        }
        Ok(())
    }
    async fn status(root: &Path, role: Role) -> Result<ServiceReport> {
        manage(
            &root.join(role.name()),
            ServiceAction::Status,
            role.component(),
            None,
            None,
        )
        .await
        .map_err(Failure::native)
    }
    fn satisfied(role: Role, action: ServiceAction, report: &ServiceReport) -> Result<bool> {
        use styx_contracts::native_management::NativeAutostartDesired;
        let desired = role.desired(report)?;
        let os = &report.os;
        let stopped = desired.run == NativeRunDesired::Stopped
            && matches!(os["active"].as_str(), Some("inactive" | "failed"));
        Ok(match action {
            ServiceAction::Install => {
                desired.manager == NativeManager::PersistentService && os["installed"] == true
            }
            ServiceAction::Start => {
                desired.run == NativeRunDesired::Running && os["active"] == "active"
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
                    && os["installed"] == false
                    && stopped
            }
            ServiceAction::Status => false,
        })
    }
    fn transaction_committed(observation: &Value, tx: &str) -> bool {
        (observation["transaction_id"] == tx
            && observation["status"] == "committed"
            && observation["state_scope"] == "committed_target")
            || (observation["transaction"]["transaction_id"] == tx
                && observation["transaction"]["observed_stage"] == "committed"
                && observation["transaction"]["receipt"]["stage"] == "committed")
    }
    async fn confirm_step(
        root: &Path,
        role: Role,
        action: ServiceAction,
        dispatch: &Dispatch,
    ) -> Result<()> {
        let path = root.join(role.name());
        let tx: styx_contracts::identity::TransactionId = dispatch
            .transaction_id
            .clone()
            .try_into()
            .map_err(|_| Failure::new("upgrade_receipt_invalid"))?;
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Ok(after) = manage(
                &path,
                ServiceAction::Status,
                role.component(),
                Some(tx.clone()),
                None,
            )
            .await
                && after.revision == dispatch.revision.saturating_add(1)
                && satisfied(role, action, &after)?
                && after
                    .transaction_observation
                    .as_ref()
                    .is_some_and(|v| transaction_committed(v, &dispatch.transaction_id))
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= until {
                eprintln!(
                    "Unconfirmed {} {}. Inspect the original transaction:\nstyx transaction --state-dir '{}' --transaction-id '{}' --json\nPreserve the receipt and check the service logs before recovery; no action was replayed.",
                    role.name(),
                    setup::service_action_name(action),
                    path.display(),
                    dispatch.transaction_id
                );
                return Err(Failure::unknown("upgrade_service_outcome_unknown"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    // A definite refusal before effects may be retried with a fresh dispatch.
    // An unresolved or committed dispatch always keeps its original identity.
    fn dispatch_name(receipts: &Path, base: &str) -> Result<String> {
        for attempt in 0u64.. {
            let name = format!("{base}-{attempt}");
            if !marked(&receipts.join(format!("{name}.failed.json")))? {
                return Ok(name);
            }
        }
        Err(Failure::new("upgrade_attempt_exhausted"))
    }
    fn selection_dispatched(receipts: &Path) -> Result<bool> {
        for entry in
            std::fs::read_dir(receipts).map_err(|_| Failure::new("upgrade_receipt_unavailable"))?
        {
            let entry = entry.map_err(|_| Failure::new("upgrade_receipt_unavailable"))?;
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("select-")
                && let Some(base) = name.strip_suffix(".started.json")
                && !marked(&receipts.join(format!("{base}.failed.json")))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn service_step(
        root: &Path,
        receipts: &Path,
        phase: &str,
        role: Role,
        action: ServiceAction,
        before: ServiceReport,
    ) -> Result<()> {
        let name = dispatch_name(
            receipts,
            &format!(
                "{phase}-{}-{}",
                role.name(),
                setup::service_action_name(action)
            ),
        )?;
        let started = receipts.join(format!("{name}.started.json"));
        let done = receipts.join(format!("{name}.done.json"));
        if marked(&done)? {
            return Err(Failure::new("upgrade_recorded_service_changed"));
        }
        if started.exists() {
            confirm_step(root, role, action, &read(&started)?).await?;
        } else {
            let dispatch = Dispatch {
                transaction_id: format!("upgrade-{}-{}", setup::now_ms()?, name),
                revision: before.revision,
            };
            write(&started, &dispatch)?;
            let tx = dispatch
                .transaction_id
                .clone()
                .try_into()
                .map_err(|_| Failure::new("upgrade_receipt_invalid"))?;
            match manage(
                &root.join(role.name()),
                action,
                role.component(),
                Some(tx),
                Some(before.revision),
            )
            .await
            {
                Ok(_) => (),
                Err(error) => {
                    // A still-owned native operation must survive until process
                    // teardown. On the next invocation only observations run.
                    if error.requires_process_teardown() {
                        return Err(Failure::native(error));
                    }
                    if error.exit_code() != 4 {
                        mark(&receipts.join(format!("{name}.failed.json")))?;
                        return Err(Failure::native(error));
                    }
                    confirm_step(root, role, action, &dispatch).await?;
                }
            }
        }
        mark(&done)?;
        println!(
            "{}: {} done.",
            role.name(),
            setup::service_action_name(action)
        );
        Ok(())
    }
    // Settle interrupted dispatches before choosing the next action from state.
    // Otherwise an already changed desired state could hide an uncertain OS step.
    async fn settle(root: &Path, receipts: &Path, phase: &str, roles: &[Original]) -> Result<()> {
        for original in roles {
            let role = original.role;
            for action in [
                ServiceAction::Stop,
                ServiceAction::Disable,
                ServiceAction::Uninstall,
                ServiceAction::Install,
                ServiceAction::Start,
                ServiceAction::Enable,
            ] {
                let name = dispatch_name(
                    receipts,
                    &format!(
                        "{phase}-{}-{}",
                        role.name(),
                        setup::service_action_name(action)
                    ),
                )?;
                let started = receipts.join(format!("{name}.started.json"));
                let done = receipts.join(format!("{name}.done.json"));
                if started.exists()
                    && !marked(&done)?
                    && !marked(&receipts.join(format!("{name}.failed.json")))?
                {
                    confirm_step(root, role, action, &read(&started)?).await?;
                    mark(&done)?;
                }
            }
        }
        Ok(())
    }
    async fn restore(root: &Path, receipts: &Path, phase: &str, roles: &[Original]) -> Result<()> {
        restore_roles(roles, async |role, action| {
            let before = status(root, role).await?;
            if !satisfied(role, action, &before)? {
                service_step(root, receipts, phase, role, action, before).await?;
            }
            if action == ServiceAction::Start && role == Role::Gateway {
                setup::wait_gateway(&root.join("gateway")).await?;
            }
            Ok(())
        })
        .await
    }
    async fn restore_roles(
        roles: &[Original],
        mut step: impl AsyncFnMut(Role, ServiceAction) -> Result<()>,
    ) -> Result<()> {
        // Plan order is gateway, host. Stopped and disabled roles stay that way.
        for original in roles {
            if original.installed {
                for (action, wanted) in [
                    (ServiceAction::Install, true),
                    (ServiceAction::Start, original.running),
                    (ServiceAction::Enable, original.enabled),
                ] {
                    if wanted {
                        step(original.role, action).await?;
                    }
                }
            }
        }
        Ok(())
    }
    fn rollback_allowed(select_dispatched: bool, failure: &Failure) -> bool {
        !select_dispatched && failure.exit != 4
    }

    async fn execute(root: &Path, receipts: &Path, plan: &Plan) -> Result<()> {
        settle(root, receipts, "remove", &plan.roles).await?;
        // Stop host first. Roles already selected on resume are never removed.
        for original in plan.roles.iter().rev() {
            let role = original.role;
            let selected = admin::committed_runtime_selection(&root.join(role.name()))
                .await
                .map_err(Failure::admin)?;
            if already_selected(&selected, &plan.target) {
                println!(
                    "{}: new selection already committed; skipping removal and select.",
                    role.name()
                );
                continue;
            }
            setup::uninstall_role(
                &root.join(role.name()),
                role.name(),
                role.component(),
                async |action, before| {
                    service_step(root, receipts, "remove", role, action, before).await
                },
            )
            .await?;
        }
        for original in &plan.roles {
            let role = original.role;
            let path = root.join(role.name());
            let selected = admin::committed_runtime_selection(&path)
                .await
                .map_err(Failure::admin)?;
            if already_selected(&selected, &plan.target) {
                continue;
            }
            let name = dispatch_name(receipts, &format!("select-{}", role.name()))?;
            let started = receipts.join(format!("{name}.started.json"));
            if started.exists() {
                let dispatch: Dispatch = read(&started)?;
                eprintln!(
                    "Selection outcome is unconfirmed. Inspect the original transaction:\nstyx transaction --state-dir '{}' --transaction-id '{}' --json\nDo not repeat release select. After resolving this transaction, rerun the same upgrade command.",
                    path.display(),
                    dispatch.transaction_id
                );
                return Err(Failure::unknown("upgrade_selection_outcome_unknown"));
            }
            let before = status(root, role).await?;
            let sequence = before
                .revision
                .checked_add(1)
                .ok_or_else(|| Failure::new("upgrade_sequence_exhausted"))?;
            let dispatch = Dispatch {
                transaction_id: format!("upgrade-select-{}-{}", role.name(), setup::now_ms()?),
                revision: before.revision,
            };
            write(&started, &dispatch)?;
            if let Err(error) = native::update::select_runtime(
                &path,
                &receipts.join("selection.json"),
                &dispatch.transaction_id,
                sequence,
            )
            .await
            {
                let failure = Failure::native(error);
                if failure.exit != 4 {
                    mark(&receipts.join(format!("{name}.failed.json")))?;
                }
                return Err(failure);
            }
        }
        settle(root, receipts, "restore", &plan.roles).await?;
        restore(root, receipts, "restore", &plan.roles).await
    }

    pub(in crate::cli) async fn run(
        payload: PathBuf,
        publisher_file: Option<PathBuf>,
        expected_publisher: Option<String>,
        root: Option<PathBuf>,
        yes: bool,
    ) -> Result<()> {
        let root = root.map(Ok).unwrap_or_else(setup::root_default)?;
        if !root.is_absolute() || !payload.is_absolute() {
            return Err(Failure::new("upgrade_absolute_paths_required"));
        }
        let answers = setup::Answers::load(&root.join("inputs/setup-intent.json"))?;
        let input_root = PrivateRoot::open(root.join("inputs"))
            .map_err(|_| Failure::new("upgrade_private_inputs_required"))?;
        let _lease = input_root
            .try_configuration_writer()
            .map_err(|_| Failure::new("upgrade_busy"))?;
        let publisher_file =
            publisher_file.unwrap_or_else(|| answers.payload.publisher_file.clone());
        let pin = setup::normalize_publisher_pin(
            &expected_publisher.unwrap_or_else(|| answers.payload.expected_publisher.clone()),
        );
        let target = release::inspect_selection(&payload, &publisher_file, &pin)
            .await
            .map_err(|e| Failure::new(e.code()))?;
        let version = release::verify_selected(&target)
            .map_err(|e| Failure::new(e.code()))?
            .report()
            .version;
        let upgrades = root
            .join("inputs")
            .join(format!("upgrade-{}", target.manifest_sha256.to_hex()));
        let mut round = 0u64;
        loop {
            let path = upgrades.join(format!("attempt-{round}"));
            if !marked(&path.join("rolled-back.json"))? {
                break;
            }
            round = round
                .checked_add(1)
                .ok_or_else(|| Failure::new("upgrade_attempt_exhausted"))?;
        }
        let receipts = upgrades.join(format!("attempt-{round}"));
        let saved = receipts.join("plan.json");
        let resume = saved.exists() && !marked(&receipts.join("complete.json"))?;
        let mut roles = Vec::new();
        for role in [Role::Gateway, Role::Host] {
            let path = root.join(role.name());
            if !path.is_dir() {
                continue;
            }
            let selection = admin::committed_runtime_selection(&path)
                .await
                .map_err(Failure::admin)?;
            publisher_matches(&selection, &target)?;
            let report = status(&root, role).await?;
            let desired = role.desired(&report)?;
            if !resume
                && (desired.manager != NativeManager::PersistentService
                    || report.os["installed"] != true)
            {
                return Err(Failure::new("upgrade_existing_linux_services_required"));
            }
            if !resume
                && (report.os["enabled"].as_bool().is_none()
                    || !matches!(
                        report.os["active"].as_str(),
                        Some("active" | "inactive" | "failed")
                    ))
            {
                return Err(Failure::new("upgrade_service_state_unsettled"));
            }
            roles.push(Original {
                role,
                version: release::verify_selected(&selection)
                    .map_err(|e| Failure::new(e.code()))?
                    .report()
                    .version,
                selection,
                running: desired.run == NativeRunDesired::Running
                    || report.os["active"] == "active",
                enabled: report.os["enabled"] == true,
                installed: report.os["installed"] == true,
            });
        }
        if roles.is_empty() {
            return Err(Failure::new("upgrade_nothing_set_up"));
        }
        let same = roles
            .iter()
            .all(|r| already_selected(&r.selection, &target));
        if same && !resume {
            println!("Already running {version}.");
        }
        require_change(same, resume)?;
        let plan = if resume {
            let saved: Plan = read(&saved)?;
            if saved.schema != 1
                || saved.target != target
                || saved.roles.len() != roles.len()
                || !saved.roles.iter().zip(&roles).all(|(old, current)| {
                    old.role == current.role
                        && (old.selection == current.selection || current.selection == target)
                })
            {
                return Err(Failure::new("upgrade_recorded_state_changed"));
            }
            saved
        } else {
            Plan {
                schema: 1,
                target,
                version,
                roles,
            }
        };
        println!("{}", plan.text());
        for original in &plan.roles {
            println!("Old payload kept: {}", original.selection.payload_path);
        }
        if !yes {
            if !prompt::terminal() {
                return Err(Failure::new("upgrade_confirmation_required_use_yes"));
            }
            if !prompt::confirm("Upgrade Styx now?")? {
                return Err(Failure::new("setup_cancelled"));
            }
        }
        inputs::private_directory(&receipts)
            .map_err(|_| Failure::new("upgrade_private_receipts_required"))?;
        if !saved.exists() {
            write(&saved, &plan)?;
        }
        if !receipts.join("selection.json").exists() {
            write(&receipts.join("selection.json"), &plan.target)?;
        }
        println!(
            "Resume command: styx upgrade --payload {} --publisher-file {} --expected-publisher {} --root {} --yes",
            shell_path(&payload),
            shell_path(&publisher_file),
            pin,
            shell_path(&root)
        );
        // Once rollback starts, a rerun must finish restoring the old services,
        // rather than reversing direction into selection halfway through it.
        let rolling_back = marked(&receipts.join("rollback.json"))?;
        let outcome = if rolling_back {
            Err(Failure::new("upgrade_previous_attempt_failed"))
        } else {
            execute(&root, &receipts, &plan).await
        };
        if let Err(error) = outcome {
            let select_dispatched = selection_dispatched(&receipts)?
                || plan
                    .roles
                    .iter()
                    .any(|r| already_selected(&r.selection, &plan.target));
            if !select_dispatched && !rolling_back {
                mark(&receipts.join("rollback.json"))?;
            }
            if rolling_back || rollback_allowed(select_dispatched, &error) {
                settle(&root, &receipts, "remove", &plan.roles).await?;
                settle(&root, &receipts, "rollback", &plan.roles).await?;
                match restore(&root, &receipts, "rollback", &plan.roles).await {
                    Ok(()) => {
                        mark(&receipts.join("rolled-back.json"))?;
                        eprintln!(
                            "Upgrade failed before selection; the old services and their running/enabled settings were restored."
                        );
                    }
                    Err(recovery) => {
                        eprintln!(
                            "Restoring the old services stopped. Rerun the same upgrade command to finish recovery."
                        );
                        return Err(recovery);
                    }
                }
            } else {
                eprintln!(
                    "Upgrade stopped. Rerun the same styx upgrade --payload '{}' --root '{}' --yes command to observe recorded steps and resume. Unconfirmed steps require the transaction inspection printed above; they are never replayed.",
                    payload.display(),
                    root.display()
                );
            }
            return Err(error);
        }
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
            if let Err(error) =
                setup::wait_computer(&root.join("gateway"), Some(device), answers.browser).await
            {
                eprintln!(
                    "The new services are selected, but reconnection was not confirmed. Run styx status --root '{}' and rerun the same upgrade command to wait again.",
                    root.display()
                );
                return Err(error);
            }
        } else if answers.role == setup::Role::Join {
            println!(
                "This computer has started. On the hub, run styx status to confirm its connection (the same observation used by setup)."
            );
        }
        mark(&receipts.join("complete.json"))?;
        println!(
            "Upgrade complete: {}. Old payload directories are untouched; delete them only when you no longer need them.",
            plan.version
        );
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        use styx_contracts::{identity::Sha256Digest, native_management::NativeRootIdentity};

        fn selection(name: &str) -> NativeRuntimeSelection {
            NativeRuntimeSelection {
                schema: 1,
                payload_path: format!("/private/{name}"),
                payload_root: NativeRootIdentity::Linux {
                    device: 1,
                    inode: 2,
                    uid: 1000,
                },
                manifest_sha256: Sha256Digest::of_bytes(name.as_bytes()),
                publisher_file: "/private/publisher.pem".into(),
                publisher_spki_sha256: Sha256Digest::of_bytes(b"publisher"),
            }
        }
        fn original(role: Role, running: bool, enabled: bool) -> Original {
            Original {
                role,
                selection: selection("old"),
                version: "1.0".into(),
                installed: true,
                running,
                enabled,
            }
        }
        #[test]
        fn refuses_different_publisher() {
            let old = selection("old");
            let mut new = selection("new");
            new.publisher_spki_sha256 = Sha256Digest::of_bytes(b"other publisher");
            assert_eq!(
                publisher_matches(&old, &new).unwrap_err().code,
                "upgrade_different_publisher_refused"
            );
        }
        #[test]
        fn refuses_same_manifest_without_pending_upgrade() {
            let current = selection("old");
            assert_eq!(
                require_change(already_selected(&current, &current), false)
                    .unwrap_err()
                    .code,
                "upgrade_already_running"
            );
            assert!(require_change(true, true).is_ok());
        }
        #[test]
        fn plan_shows_versions_roles_and_pairing_continuity() {
            let plan = Plan {
                schema: 1,
                target: selection("new"),
                version: "2.0".into(),
                roles: vec![
                    original(Role::Gateway, true, true),
                    original(Role::Host, true, false),
                ],
            };
            let text = plan.text();
            assert!(text.contains("gateway: 1.0 -> 2.0"));
            assert!(text.contains("host: 1.0 -> 2.0"));
            assert!(
                text.contains("Computers stay paired; ChatGPT keeps working after the restart.")
            );
            assert!(text.contains("original running/enabled settings"));
        }
        #[test]
        fn resume_skips_role_already_on_new_selection() {
            let target = selection("new");
            let current = [selection("new"), selection("old")];
            let needing_select = current
                .iter()
                .enumerate()
                .filter(|(_, current)| !already_selected(current, &target))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            assert_eq!(needing_select, vec![1]);
        }
        #[test]
        fn revision_or_os_success_alone_never_proves_unknown_dispatch_committed() {
            assert!(!transaction_committed(
                &json!({"revision":4,"status":"committed"}),
                "original"
            ));
            assert!(!transaction_committed(
                &json!({"transaction_id":"different","status":"committed","state_scope":"committed_target"}),
                "original"
            ));
            assert!(!transaction_committed(
                &json!({"transaction":{"transaction_id":"original","observed_stage":"applied"}}),
                "original"
            ));
            assert!(transaction_committed(
                &json!({"transaction":{"transaction_id":"original","observed_stage":"committed","receipt":{"stage":"committed"}}}),
                "original"
            ));
        }
        #[test]
        fn dispatch_retries_only_definite_refusals_and_keeps_unknown_identity() {
            let root = std::env::temp_dir().join(format!(
                "styx-upgrade-dispatch-{}-{}",
                std::process::id(),
                setup::now_ms().unwrap()
            ));
            inputs::private_directory(&root).unwrap();
            let first = dispatch_name(&root, "select-host").unwrap();
            write(
                &root.join(format!("{first}.started.json")),
                &Dispatch {
                    transaction_id: "original".into(),
                    revision: 1,
                },
            )
            .unwrap();
            assert_eq!(dispatch_name(&root, "select-host").unwrap(), first);
            assert!(selection_dispatched(&root).unwrap());
            mark(&root.join(format!("{first}.failed.json"))).unwrap();
            assert!(!selection_dispatched(&root).unwrap());
            assert_ne!(dispatch_name(&root, "select-host").unwrap(), first);
            std::fs::remove_dir_all(root).unwrap();
        }
        #[test]
        fn cli_upgrade_requires_payload_and_accepts_trust_overrides() {
            use clap::Parser;
            assert!(crate::cli::Cli::try_parse_from(["styx", "upgrade"]).is_err());
            assert!(
                crate::cli::Cli::try_parse_from([
                    "styx",
                    "upgrade",
                    "--payload",
                    "/private/new",
                    "--publisher-file",
                    "/private/publisher.pem",
                    "--expected-publisher",
                    &"a".repeat(64),
                    "--root",
                    "/private/profile",
                    "--yes"
                ])
                .is_ok()
            );
        }
        #[tokio::test]
        async fn rollback_before_select_restores_fixture_and_preserves_old_selection() {
            let root = std::env::temp_dir().join(format!(
                "styx-upgrade-rollback-{}-{}",
                std::process::id(),
                setup::now_ms().unwrap()
            ));
            inputs::private_directory(&root).unwrap();
            let roles = vec![
                original(Role::Gateway, true, true),
                original(Role::Host, false, false),
            ];
            // Fixture represents roles removed before a known pre-select failure.
            // Selections are immutable inputs; service effects are recorded apart.
            for original in &roles {
                write(
                    &root.join(format!("{}.json", original.role.name())),
                    &original.selection,
                )
                .unwrap();
            }
            let failure = Failure::new("fixture_disable_refused_before_effect");
            assert!(rollback_allowed(false, &failure));
            let mut effects = Vec::new();
            restore_roles(&roles, async |role, action| {
                let effect = format!("{}-{}", role.name(), setup::service_action_name(action));
                write(&root.join(&effect), &true)?;
                effects.push(effect);
                Ok(())
            })
            .await
            .unwrap();
            assert_eq!(
                effects,
                [
                    "gateway-install",
                    "gateway-start",
                    "gateway-enable",
                    "host-install"
                ]
            );
            for original in &roles {
                let selected: NativeRuntimeSelection =
                    read(&root.join(format!("{}.json", original.role.name()))).unwrap();
                assert_eq!(selected, original.selection);
            }
            assert!(!rollback_allowed(true, &failure));
            assert!(!rollback_allowed(
                false,
                &Failure::unknown("fixture_unknown")
            ));
            std::fs::remove_dir_all(root).unwrap();
        }

        /// Explicit owned Linux acceptance: real signed executables, user manager,
        /// sockets and authenticated hub observations. Never runs in base tests.
        #[tokio::test]
        #[ignore = "requires signed old/new payloads and an owned systemd user session"]
        async fn upgrade_hub_requires_systemd_user() {
            use std::os::unix::fs::MetadataExt;
            let env_path = |name| PathBuf::from(std::env::var(name).expect(name));
            let old = env_path("STYX_UPGRADE_OLD_PAYLOAD");
            let new = env_path("STYX_UPGRADE_NEW_PAYLOAD");
            let publisher = env_path("STYX_UPGRADE_PUBLISHER");
            let pin = std::env::var("STYX_UPGRADE_PIN").expect("STYX_UPGRADE_PIN");
            let temp = std::env::temp_dir().join(format!(
                "styx-upg-{}-{}",
                std::process::id(),
                setup::now_ms().unwrap()
            ));
            inputs::private_directory(&temp).unwrap();
            let root = temp.join("profile");
            let answers = temp.join("answers.json");
            write(&answers, &json!({
                "schema":1,"role":"hub","label":"Upgrade scenario",
                "payload":{"payload_dir":old,"publisher_file":publisher,"expected_publisher":pin},
                "workspace":temp.join("work"),"shell":"/bin/sh","port":22123,
                "browser":false,"computer":false,"networks":[],
                "approve":["inputs","payload","workspace","gateway","gateway-service","invite","trust","request","approve","claim","host-service"]
            })).unwrap();
            let outcome: Result<()> = async {
                setup::run(Some(root.clone()), Some(answers), false, false).await?;
                let identity: Value = read(&root.join("inputs/host-public-identity.json"))?;
                let ready_before: Value = read(&root.join("host/host-ready-v1.json"))?;
                let credentials =
                    inputs::read_private(&root.join("host/host-credential.token"), 4096).unwrap();
                let old_selection = admin::committed_runtime_selection(&root.join("gateway"))
                    .await
                    .map_err(Failure::admin)?;
                let new_selection = release::inspect_selection(&new, &publisher, &pin)
                    .await
                    .map_err(|e| Failure::new(e.code()))?;
                if already_selected(&old_selection, &new_selection) {
                    return Err(Failure::new("scenario_payloads_must_differ"));
                }
                run(new.clone(), None, None, Some(root.clone()), true).await?;
                for role in [Role::Gateway, Role::Host] {
                    let report = status(&root, role).await?;
                    if report.os["active"] != "active" || report.os["enabled"] != true {
                        return Err(Failure::new("scenario_new_services_not_running"));
                    }
                    let pid = report.os["main_pid"]
                        .as_u64()
                        .ok_or_else(|| Failure::new("scenario_service_pid_unavailable"))?;
                    let running = std::fs::metadata(format!("/proc/{pid}/exe"))
                        .map_err(|_| Failure::new("scenario_process_unavailable"))?;
                    let expected = std::fs::metadata(new.join("bin/styx"))
                        .map_err(|_| Failure::new("scenario_binary_unavailable"))?;
                    if (running.dev(), running.ino()) != (expected.dev(), expected.ino()) {
                        return Err(Failure::new("scenario_running_old_binary"));
                    }
                    let selected = admin::committed_runtime_selection(&root.join(role.name()))
                        .await
                        .map_err(Failure::admin)?;
                    if selected != new_selection {
                        return Err(Failure::new("scenario_selection_mismatch"));
                    }
                }
                let ready_after: Value = read(&root.join("host/host-ready-v1.json"))?;
                if ready_after["device_id"] != ready_before["device_id"]
                    || ready_after["device_id"] != identity["device_id"]
                    || credentials
                        != inputs::read_private(&root.join("host/host-credential.token"), 4096)
                            .unwrap()
                {
                    return Err(Failure::new("scenario_pairing_changed"));
                }
                setup::wait_computer(&root.join("gateway"), identity["device_id"].as_str(), false)
                    .await?;
                release::verify_selected(&old_selection).map_err(|e| Failure::new(e.code()))?;
                Ok(())
            }
            .await;
            // Cleanup also runs on a reported scenario failure. Keep private
            // evidence on disk for the reviewer; do not erase unknown outcomes.
            let cleanup = if outcome.as_ref().err().is_some_and(|e| e.exit == 4) {
                Err(Failure::unknown(
                    "scenario_cleanup_requires_original_resolution",
                ))
            } else {
                setup::uninstall(Some(root.clone()), true).await
            };
            eprintln!("Upgrade scenario private evidence: {}", temp.display());
            assert!(outcome.is_ok(), "{outcome:?}");
            assert!(cleanup.is_ok(), "{cleanup:?}");
        }
    }
}

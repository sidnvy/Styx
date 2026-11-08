//! Real TLS/paired Host/Core refusal and owner cleanup; synthetic unavailable
//! native source. No native executor, desktop permission or platform PASS.
use super::*;
use crate::{
    gateway::{
        auth::{AuthenticatedGatewayPrincipal, VerifiedGatewayOwner},
        http::lifecycle::OwnerCleanup,
    },
    host::{coordinator::HostCoordinator, protocol::computer::ComputerBootstrap},
    providers::cua::{OwnedCuaConfig, TrustedCuaLaunch},
};
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use styx_contracts::{
    error::ErrorCategory,
    operation::{ExecutionLiveness, OperationState, OutputDrain},
};
use styx_core::operations::OwnerLease;

pub(super) struct Factory {
    config: OwnedCuaConfig,
    mode: AtomicU8,
    preparations: AtomicUsize,
    entered: tokio::sync::Notify,
    released: (Mutex<bool>, Condvar),
}
impl Factory {
    pub(super) async fn new(host: &HostCoordinator, root: &Path) -> Arc<Self> {
        let session = host.install_desktop_refusal_fixture().await;
        // The pinned native image is never launched: this source refuses first.
        let image_root = root.join("refusal-driver-input");
        std::fs::create_dir(&image_root).unwrap();
        std::fs::set_permissions(&image_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let image = image_root.join("never-executed-cua");
        std::fs::copy("/bin/true", &image).unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
        let driver = Arc::new(
            PrivateRoot::open(&image_root)
                .unwrap()
                .payload_inventory(Default::default())
                .unwrap()
                .pin_executable("never-executed-cua")
                .unwrap(),
        );
        let uid = nix::unistd::Uid::current().as_raw();
        let runtime_dir = std::path::PathBuf::from(format!("/run/user/{uid}"));
        Arc::new(Self {
            config: OwnedCuaConfig {
                driver,
                launch: TrustedCuaLaunch {
                    session,
                    uid,
                    session_bus: runtime_dir.join("bus"),
                    runtime_dir,
                    wayland_display: "wayland-0".into(),
                    hyprland_instance: "fixture-never-launched".into(),
                    compositor_peer: (std::process::id(), 1),
                },
                workspace: root.to_path_buf(),
                home: root.to_path_buf(),
                rpc_timeout: Duration::from_secs(2),
            },
            mode: AtomicU8::new(0),
            preparations: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            released: (Mutex::new(false), Condvar::new()),
        })
    }
}
impl ComputerBootstrap for Factory {
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedCuaConfig, ErrorCategory> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        let mut config = self.config.clone();
        let name = Sha256Digest::of_bytes(owner.owner_id().as_str().as_bytes()).to_hex();
        config.workspace = config.workspace.join(format!("workspace-{name}"));
        config.home = config.home.join(format!("home-{name}"));
        Ok(config)
    }
    fn validate_control(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
        match self.mode.load(Ordering::SeqCst) {
            1 => Err(ErrorCategory::ResultUnknown),
            2 => {
                self.entered.notify_one();
                let (lock, changed) = &self.released;
                let (released, timeout) = changed
                    .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |v| !*v)
                    .unwrap();
                assert!(
                    *released && !timeout.timed_out(),
                    "bounded original validator released"
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
fn params(name: &'static str, device: &DeviceId) -> rmcp::model::CallToolRequestParams {
    rmcp::model::CallToolRequestParams::new(name).with_arguments(
        json!({"environment_id":device.as_str()})
            .as_object()
            .unwrap()
            .clone(),
    )
}
fn text(result: rmcp::model::CallToolResult) -> Value {
    serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
}
pub(super) async fn exercise(
    backend: Arc<PairedGatewayBackend>,
    host: &HostCoordinator,
    factory: Arc<Factory>,
    principal: &AuthenticatedGatewayPrincipal,
    owner: &VerifiedGatewayOwner,
    device: &DeviceId,
) {
    for (index, name) in ["list_windows", "list_apps"].into_iter().enumerate() {
        let result = text(
            backend
                .call_tool(owner, params(name, device))
                .await
                .unwrap(),
        );
        assert_eq!(
            result["error"], "computer_not_dispatched",
            "known source refusal needs a settled original reservation"
        );
        assert_eq!(result["uncertain"], false);
        let (records, workers) = host.desktop_refusal_records();
        assert_eq!(workers, 0, "no Cua native executor was started");
        assert_eq!(records.len(), index + 1);
        assert!(records.iter().all(|s| s.state == OperationState::Cancelled
            && s.liveness == ExecutionLiveness::NotStarted
            && s.output_drain == OutputDrain::NotOpened));
        if index == 1 {
            assert_ne!(
                records[0].id, records[1].id,
                "new explicit read prepares a distinct Core reservation"
            );
        }
    }
    assert_eq!(factory.preparations.load(Ordering::SeqCst), 2);

    let unknown_owner = principal.new_mcp_session_owner().unwrap();
    factory.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        text(
            backend
                .call_tool(&unknown_owner, params("list_windows", device))
                .await
                .unwrap()
        )["uncertain"],
        true
    );
    let (records, _) = host.desktop_refusal_records();
    assert_eq!(
        records
            .iter()
            .filter(|s| s.state == OperationState::Reserved)
            .count(),
        1
    );
    factory.mode.store(0, Ordering::SeqCst);
    let blocked = text(
        backend
            .call_tool(&unknown_owner, params("list_apps", device))
            .await
            .unwrap(),
    );
    assert_eq!(blocked["error"], "outcome_unknown");
    assert_eq!(
        factory.preparations.load(Ordering::SeqCst),
        3,
        "Unknown must not reopen"
    );

    let lost_owner = principal.new_mcp_session_owner().unwrap();
    factory.mode.store(2, Ordering::SeqCst);
    let task_backend = backend.clone();
    let task_owner = lost_owner.clone();
    let task_device = device.clone();
    let pending = tokio::spawn(async move {
        task_backend
            .call_tool(&task_owner, params("list_windows", &task_device))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), factory.entered.notified())
        .await
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    {
        let (lock, changed) = &factory.released;
        *lock.lock().unwrap() = true;
        changed.notify_all();
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (records, _) = host.desktop_refusal_records();
        if records
            .iter()
            .filter(|s| s.state == OperationState::Cancelled)
            .count()
            == 3
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "original Host cancellation completes despite lost public waiter"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    factory.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        text(
            backend
                .call_tool(&lost_owner, params("list_apps", device))
                .await
                .unwrap()
        )["error"],
        "outcome_unknown"
    );
    assert_eq!(
        factory.preparations.load(Ordering::SeqCst),
        4,
        "lost response cannot reopen"
    );
    for exact_owner in [owner, &unknown_owner, &lost_owner] {
        assert_eq!(
            backend
                .cleanup_owner(exact_owner, Duration::from_secs(5))
                .await,
            OwnerCleanup::Complete,
            "normal owner drain must release even a never-dispatched Cancelled reservation"
        );
    }
    let (records, workers) = host.desktop_refusal_records();
    assert!(records.is_empty());
    assert_eq!(workers, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback/LAN sockets and one assigned private IPv4; synthetic unavailable desktop source, no native executor"]
async fn gateway_computer_refusal_settles_original_reservation_without_replay() {
    gateway_lan_scenario_inner(vec![lan_ip()], false, true).await;
}

//! App-owned local Gateway: one original scope, one worker, original settlement.
//! The Host keeps its existing enrollment authority; this is composition only.
use super::*;
use crate::{
    management::native_join_http,
    store::RawFile,
    tls::{GatewayClientTls, GatewayLeafPin, TrustAnchorPin},
};
use std::io::Cursor;

pub(super) struct LocalGateway {
    pub origin: String,
    pub ca: String,
    pub ca_sha: String,
    tls: GatewayClientTls,
    inputs: Vec<RawFile>,
    migration: Option<Arc<crate::store::committed_runtime_native::NativeCommittedRuntimeSnapshot>>,
    running: Option<RunningGateway>,
    observed: watch::Receiver<bool>,
    ready: watch::Sender<bool>,
    pub cleanup: Option<foreground::GatewayForegroundOutcome>,
    retained: Option<native::NativeManagementError>,
    startup_failure: Option<foreground::AppGatewayError>,
    failed: bool,
    pub scope: Arc<HostScope>,
}
struct RunningGateway {
    worker: JoinHandle<Result<foreground::GatewayForegroundOutcome, foreground::AppGatewayError>>,
    events: JoinHandle<()>,
    cancel: CancellationToken,
    _cancel_on_drop: tokio_util::sync::DropGuard,
}
impl LocalGateway {
    pub async fn open(scope: Arc<HostScope>) -> Result<Self, AppError> {
        scope.validate()?;
        let root = scope
            .root
            .get()
            .ok_or(AppError("app_gateway_not_configured"))?;
        let inputs = [
            "deployment.json",
            "gateway-ca.pem",
            "gateway-chain.pem",
            "gateway-admin.token",
        ]
        .iter()
        .map(|name| {
            root.read_raw(name, 1024 * 1024)
                .map_err(|_| AppError("app_gateway_input_refused"))
        })
        .collect::<Result<Vec<_>, _>>()?;
        let deployment: Value = serde_json::from_slice(inputs[0].bytes())
            .map_err(|_| AppError("app_gateway_input_refused"))?;
        let origin = deployment["gateway"]["url"]
            .as_str()
            .ok_or(AppError("app_gateway_input_refused"))?
            .to_owned();
        let ca = String::from_utf8(inputs[1].bytes().to_vec())
            .map_err(|_| AppError("app_gateway_input_refused"))?;
        let anchors = rustls_pemfile::certs(&mut Cursor::new(ca.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppError("app_gateway_input_refused"))?;
        let chain = rustls_pemfile::certs(&mut Cursor::new(inputs[2].bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppError("app_gateway_input_refused"))?;
        if anchors.len() != 1 || chain.len() != 2 || chain[1] != anchors[0] {
            return Err(AppError("app_gateway_input_refused"));
        }
        let anchor = TrustAnchorPin::from_certificate_der(&anchors[0]);
        let ca_sha = anchor.as_hex();
        let tls = GatewayClientTls::from_pinned_ca_pem(
            ca.as_bytes(),
            anchor,
            Some(GatewayLeafPin::from_certificate_der(&chain[0])),
        )
        .map_err(|_| AppError("app_gateway_input_refused"))?;
        let (ready, observed) = watch::channel(false);
        let result = Self {
            scope,
            origin,
            ca,
            ca_sha,
            tls,
            inputs,
            migration: None,
            running: None,
            observed,
            ready,
            cleanup: None,
            retained: None,
            startup_failure: None,
            failed: false,
        };
        result.validate()?;
        Ok(result)
    }
    /// Original local endpoint, not the fresh sibling Gateway layout.
    pub async fn open_migrated(scope: Arc<HostScope>) -> Result<Self, AppError> {
        tokio::task::spawn_blocking(move || {
            scope.validate()?;
            let snapshot = Arc::new(
                crate::store::committed_runtime_native::NativeCommittedRuntimeSnapshot::open(
                    scope.state_dir(),
                )
                .map_err(|_| AppError("app_gateway_input_refused"))?,
            );
            let inspection =
                migrated::inspect(scope.clone())?.ok_or(AppError("app_gateway_input_refused"))?;
            if inspection.topology != migrated::Topology::SharedLocal {
                return Err(AppError("app_gateway_input_refused"));
            }
            let endpoint: styx_contracts::native_management::NativeGatewayEndpointBinding =
                serde_json::from_slice(
                    snapshot
                        .endpoint_binding()
                        .ok_or(AppError("app_gateway_input_refused"))?,
                )
                .map_err(|_| AppError("app_gateway_input_refused"))?;
            let chain = snapshot
                .endpoint_chain()
                .ok_or(AppError("app_gateway_input_refused"))?;
            let certs = rustls_pemfile::certs(&mut Cursor::new(chain))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AppError("app_gateway_input_refused"))?;
            if certs.len() != 2 {
                return Err(AppError("app_gateway_input_refused"));
            }
            let gateway = PrivateRoot::open(scope.state_dir().join("gateway"))
                .map_err(|_| AppError("app_gateway_input_refused"))?;
            let original_ca = gateway
                .read_raw("certificate.pem", 128 * 1024)
                .map_err(|_| AppError("app_gateway_input_refused"))?;
            let anchors = rustls_pemfile::certs(&mut Cursor::new(original_ca.bytes()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AppError("app_gateway_input_refused"))?;
            if anchors.len() != 1
                || anchors[0] != certs[1]
                || endpoint.anchor_sha256
                    != styx_contracts::identity::Sha256Digest::of_bytes(&certs[1])
                || endpoint.leaf_sha256
                    != styx_contracts::identity::Sha256Digest::of_bytes(&certs[0])
            {
                return Err(AppError("app_gateway_input_refused"));
            }
            let ca = String::from_utf8(original_ca.bytes().to_vec())
                .map_err(|_| AppError("app_gateway_input_refused"))?;
            let anchor = TrustAnchorPin::from_certificate_der(&anchors[0]);
            let ca_sha = anchor.as_hex();
            let tls = GatewayClientTls::from_pinned_ca_pem(
                ca.as_bytes(),
                anchor,
                Some(GatewayLeafPin::from_certificate_der(&certs[0])),
            )
            .map_err(|_| AppError("app_gateway_input_refused"))?;
            let (ready, observed) = watch::channel(false);
            snapshot
                .revalidate()
                .map_err(|_| AppError("app_gateway_input_changed"))?;
            scope.validate()?;
            Ok(Self {
                origin: endpoint.origin,
                ca,
                ca_sha,
                tls,
                inputs: vec![],
                migration: Some(snapshot),
                running: None,
                observed,
                ready,
                cleanup: None,
                retained: None,
                startup_failure: None,
                failed: false,
                scope,
            })
        })
        .await
        .map_err(|_| AppError("app_gateway_reader_failed"))?
    }
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }
    pub fn validate(&self) -> Result<(), AppError> {
        self.scope.validate()?;
        if self.failed || self.retained.is_some() || self.startup_failure.is_some() {
            return Err(AppError("app_gateway_fenced"));
        }
        if let Some(original) = &self.migration {
            return original
                .revalidate()
                .map_err(|_| AppError("app_gateway_input_changed"));
        }
        let root = self
            .scope
            .root
            .get()
            .ok_or(AppError("app_gateway_not_configured"))?;
        for original in &self.inputs {
            let current = root
                .read_raw(original.relative_path(), 1024 * 1024)
                .map_err(|_| AppError("app_gateway_input_changed"))?;
            if current.observation() != original.observation()
                || current.bytes() != original.bytes()
            {
                return Err(AppError("app_gateway_input_changed"));
            }
        }
        Ok(())
    }
    fn management_error(&mut self, e: native::NativeManagementError) -> AppError {
        let code = e.code();
        if e.exit_code() == 4 {
            self.retained = Some(e);
        }
        AppError(code)
    }
    pub async fn start(&mut self) -> Result<(), AppError> {
        self.validate()?;
        if let Some(role) = &self.running {
            return if role.worker.is_finished() || !*self.observed.borrow() {
                Err(AppError("app_gateway_not_ready"))
            } else {
                Ok(())
            };
        }
        let report = native::inspect_gateway_for_app(self.scope.clone())
            .await
            .map_err(|e| self.management_error(e))?;
        if report.admission_fenced {
            return Err(AppError("app_transaction_fenced"));
        }
        if report
            .desired
            .gateway
            .is_none_or(|g| g.run != NativeRunDesired::Running)
        {
            if self.migration.is_some() {
                return Err(AppError("app_shared_gateway_plan_required"));
            }
            let change = native::NativeDesiredChange {
                component: native::NativeComponent::Gateway,
                run: NativeRunDesired::Running,
                transaction_id: uuid::Uuid::new_v4()
                    .to_string()
                    .try_into()
                    .expect("UUID identity"),
                sequence: report
                    .revision
                    .checked_add(1)
                    .ok_or(AppError("app_revision_exhausted"))?,
            };
            let plan = native::plan_for_app(self.scope.clone(), change)
                .await
                .map_err(|e| self.management_error(e))?;
            native::apply_for_app(self.scope.clone(), &plan.plan_file)
                .await
                .map_err(|e| self.management_error(e))?;
        }
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let scope = self.scope.clone();
        let (events, mut received) = mpsc::channel::<foreground::ForegroundEvent>(32);
        let ready = self.ready.clone();
        ready.send_replace(false);
        let event_task = tokio::spawn(async move {
            while let Some(event) = received.recv().await {
                if event.event == "gateway_listening" {
                    ready.send_replace(true);
                } else if matches!(event.event, "gateway_stopped" | "gateway_inputs_changed") {
                    ready.send_replace(false);
                }
            }
            ready.send_replace(false);
        });
        let worker = tokio::spawn(async move {
            foreground::gateway_run_for_app(scope, worker_cancel, events).await
        });
        self.running = Some(RunningGateway {
            worker,
            events: event_task,
            _cancel_on_drop: cancel.clone().drop_guard(),
            cancel,
        });
        // Readiness wait owns no role; timeout leaves the exact worker retained
        // for settlement and never dispatches enrollment to an unknown listener.
        let ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if *self.observed.borrow() { return Ok(true); }
                if self.running.as_ref().is_none_or(|r| r.worker.is_finished()) { return Ok(false); }
                tokio::select! { changed = self.observed.changed() => { if changed.is_err() { return Err(AppError("app_gateway_start_failed")); } }, _ = tokio::time::sleep(Duration::from_millis(50)) => {} }
            }
        }).await.map_err(|_| AppError("app_gateway_start_timeout"))??;
        if !ready {
            // Join the original finished role outside the readiness timeout so
            // that it cannot drop a settlement waiter and lose error custody.
            // settle retains the original startup error and its authority.
            self.settle().await?;
            self.failed = true;
            return Err(AppError("app_gateway_start_failed"));
        }
        Ok(())
    }
    pub async fn admin_once(&mut self, approve: bool, body: &Value) -> Result<Value, AppError> {
        self.validate()?;
        if self.running.as_ref().is_none_or(|r| r.worker.is_finished()) || !*self.observed.borrow()
        {
            return Err(AppError("app_gateway_not_ready"));
        }
        let origin =
            url::Url::parse(&self.origin).map_err(|_| AppError("app_gateway_input_refused"))?;
        let body = zeroize::Zeroizing::new(
            serde_json::to_vec(body).map_err(|_| AppError("app_input_invalid"))?,
        );
        // Latch before dispatch: any lost/invalid reply keeps this original role
        // fenced. No retry of invitation or approval, including after restart.
        if self.migration.is_some() {
            return Err(AppError("app_migrated_pairing_already_committed"));
        }
        self.failed = true;
        let response = native_join_http::exchange_local_admin(
            &origin,
            &self.tls,
            approve,
            &body,
            self.inputs[3].bytes(),
        )
        .await
        .map_err(|_| AppError("app_local_pairing_result_unknown"))?;
        if response.status != 200 {
            return Err(AppError("app_local_pairing_refused"));
        }
        let result = serde_json::from_slice(&response.body)
            .map_err(|_| AppError("app_local_pairing_result_unknown"))?;
        self.failed = false;
        self.validate()?;
        Ok(result)
    }
    pub fn is_fenced(&self) -> bool {
        self.failed
            || self.retained.is_some()
            || self.startup_failure.is_some()
            || self
                .running
                .as_ref()
                .is_some_and(|r| r.worker.is_finished())
    }
    pub fn status(&self) -> Value {
        json!({"origin":self.origin,"running":self.running.as_ref().is_some_and(|r| !r.worker.is_finished()),"listening":*self.observed.borrow(),"admission_fenced":self.is_fenced(),"cleanup":self.cleanup})
    }
    pub async fn settle(&mut self) -> Result<(), AppError> {
        if let Some(role) = self.running.take() {
            role.cancel.cancel();
            let outcome = role.worker.await;
            let events = role.events.await;
            match outcome {
                Ok(Ok(outcome)) => {
                    let complete = outcome.is_complete() && events.is_ok();
                    self.cleanup = Some(outcome);
                    if !complete {
                        self.failed = true;
                        return Err(AppError("app_gateway_cleanup_unknown"));
                    }
                }
                Ok(Err(error)) => {
                    let code = error.code();
                    self.startup_failure = Some(error);
                    self.failed = true;
                    return Err(AppError(code));
                }
                Err(_) => {
                    self.failed = true;
                    return Err(AppError("app_gateway_cleanup_unknown"));
                }
            }
        }
        Ok(())
    }
}

impl HostApp {
    pub(super) async fn load_local_gateway(
        &mut self,
        scope: Arc<HostScope>,
    ) -> Result<LocalGateway, AppError> {
        native::inspect_gateway_for_app(scope.clone())
            .await
            .map_err(|e| self.management_error(e))?;
        LocalGateway::open(scope).await
    }
    pub(super) async fn create_local(&mut self, input: LocalInput) -> Result<(), AppError> {
        self.available()?;
        if self.scope.root.get().is_some()
            || self.local_gateway.is_some()
            || self.input_writer.is_some()
        {
            return Err(AppError("app_setup_already_exists"));
        }
        if input.port < 1024 {
            return Err(AppError("app_input_invalid"));
        }
        let selection = self
            .runtime_selection_file
            .clone()
            .ok_or(AppError("app_runtime_selection_invalid"))?;
        let choice = JoinInput {
            approved_gateway_origin: String::new(),
            approved_ca_sha256: None,
            label: input.label,
            computer: input.computer,
            browser: input.browser,
            browser_channel: input.browser_channel,
            persist_login: input.persist_login,
        };
        validate_choice(&choice)?;
        let scope = Arc::new(self.scope.gateway_sibling()?);
        if scope.root.get().is_some() {
            return Err(AppError("app_setup_already_exists"));
        }
        let parent = &self.scope.container.parent;
        parent
            .ensure_absent("app-local-gateway-input-v1.json")
            .map_err(|_| AppError("app_setup_already_exists"))?;
        let origin = format!("https://127.0.0.1:{}", input.port);
        let deployment = serde_json::to_vec(&json!({"schema":1,"mode":"create-local","gateway":{"url":origin,"listenHost":"127.0.0.1","allowRemoteHosts":false}}))
            .map_err(|_| AppError("app_input_invalid"))?;
        // One container input writer covers BOTH fixed role inputs. Child
        // configuration writers remain the original C07/enrollment owners.
        self.input_writer = Some(
            parent
                .try_configuration_writer()
                .map_err(|_| AppError("app_input_writer_busy"))?,
        );
        self.unknown = true;
        parent
            .create_app_gateway_input(
                self.input_writer
                    .as_ref()
                    .ok_or(AppError("app_input_writer_busy"))?,
                &deployment,
            )
            .map_err(|_| AppError("app_local_input_unknown"))?;
        let input_path = self
            .scope
            .container
            .parent_path
            .join("app-local-gateway-input-v1.json");
        if let Err(error) = crate::management::native_gateway::bootstrap_for_app(
            scope.clone(),
            &input_path,
            &selection,
        )
        .await
        {
            let code = error.code();
            self.retained = Some(RetainedFailure::Bootstrap(error));
            return Err(AppError(code));
        }
        self.local_gateway = Some(self.load_local_gateway(scope).await?);
        let gateway = self
            .local_gateway
            .as_mut()
            .ok_or(AppError("app_gateway_not_configured"))?;
        gateway.start().await?;
        let invitation = gateway
            .admin_once(false, &json!({"ttl_seconds":600}))
            .await?;
        let secret = zeroize::Zeroizing::new(
            invitation["invitation"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(AppError("app_local_pairing_result_unknown"))?
                .to_owned(),
        );
        let (origin, ca, ca_sha) = (
            gateway.origin.clone(),
            gateway.ca.clone(),
            gateway.ca_sha.clone(),
        );
        let (computer, browser) = (choice.computer, choice.browser);
        self.write_join_input(choice, origin, ca_sha, secret, ca)?;
        let joined = native_join::request_for_app(self.scope.clone(), &self.deployment_file)
            .await
            .map_err(|e| self.join_error(e))?;
        let request = joined
            .request_id
            .as_ref()
            .ok_or(AppError("app_local_pairing_result_unknown"))?;
        let approved = self.local_gateway.as_mut().ok_or(AppError("app_gateway_not_configured"))?
            .admin_once(true, &json!({"request_id":request,"fingerprint":joined.fingerprint,"enable_computer":computer,"enable_browser":browser})).await?;
        if approved["status"] != "approved"
            || approved["device_id"] != json!(joined.device_id)
            || approved["fingerprint"] != json!(joined.fingerprint)
        {
            return Err(AppError("app_local_pairing_result_unknown"));
        }
        let claimed = native_join::claim_for_app(self.scope.clone())
            .await
            .map_err(|e| self.join_error(e))?;
        if claimed.status != "ready_to_connect"
            || claimed.device_id != joined.device_id
            || claimed.fingerprint != joined.fingerprint
        {
            return Err(AppError("app_local_pairing_result_unknown"));
        }
        self.read_configuration().await?;
        self.enrollment =
            Some(serde_json::to_value(claimed).map_err(|_| AppError("app_response_invalid"))?);
        self.unknown = false;
        Ok(())
    }
}

//! Android callbacks use the same Core ledger, caller leases and Host-owned jobs.
use super::*;
use crate::host::{
    android::{AndroidPlatform, caller_key},
    protocol::wire::{AndroidCommand, OwnerRef},
    settings::AndroidStatus,
};
use serde_json::{Value, json};
use styx_contracts::capability::{Authorization, Availability, CapabilityDescriptor, Scope};
use styx_contracts::error::Recovery;

impl HostCoordinator {
    pub(crate) async fn run_android(
        &self,
        owner: OwnerLease,
        reference: OwnerRef,
        command: AndroidCommand,
        platform: Arc<dyn AndroidPlatform>,
    ) -> Result<Value, CoordinatorError> {
        command.validate()?;
        let capability = command.capability()?;
        let readiness: AndroidStatus =
            serde_json::from_value(platform.execute("status", json!({}))?)
                .map_err(|_| ErrorCategory::ProtocolMismatch)?;
        if !readiness.accessibility {
            return Err(ErrorCategory::PermissionRequired.into());
        }
        if readiness.device_locked {
            return Err(ErrorCategory::SessionLocked.into());
        }
        let execution = self.execution_before(None).await?;
        let payload = serde_json::to_vec(&command).map_err(|_| ErrorCategory::InvalidRequest)?;
        let permit = {
            let mut state = self.inner.state.lock().expect("Host state mutex");
            if state.shutting_down {
                return Err(CoordinatorError::Busy);
            }
            let facts = AdmissionFacts {
                device_id: self.inner.bootstrap_device.clone(),
                grant_revision: state.facts.grant_revision,
                local_policy_allowed: true,
                descriptor: CapabilityDescriptor {
                    contract_version: styx_contracts::CONTRACT_VERSION,
                    capability_id: capability,
                    scope: Scope::Host,
                    provider_id: "android".to_owned().try_into().expect("fixed provider"),
                    configured: true,
                    remote_grant: true,
                    availability: Availability::Available,
                    authorization: Authorization::Granted,
                    target_session: None,
                    reason: None,
                    observed_at: self.now().0,
                    observation_generation: 0,
                    recovery: Recovery::None,
                },
                session_state: None,
                current_observation: None,
            };
            let context = PreparedContext {
                device_id: facts.device_id.clone(),
                grant_revision: facts.grant_revision,
                session: None,
                observation: None,
                capability,
                deadline: None,
                disconnect_policy: DisconnectPolicy::RetainForOwner,
            };
            let snapshot =
                state
                    .ledger
                    .prepare_android_request(&owner, context, payload, self.now())?;
            match state.ledger.dispatch(
                &owner,
                &snapshot.id,
                snapshot.payload_digest,
                &facts,
                self.now(),
            )? {
                DispatchDisposition::ExecuteOnce(permit) => permit,
                DispatchDisposition::Existing(_) => return Err(ErrorCategory::StateConflict.into()),
            }
        };
        let inner = self.inner.clone();
        let (sender, receiver) = oneshot::channel();
        // A socket drop loses the waiter, not the one original platform invocation.
        {
            let mut jobs = self.inner.jobs.lock().expect("Host jobs mutex");
            while jobs.try_join_next().is_some() {}
            jobs.spawn(async move {
            let _execution = execution;
            let id = permit.id().clone();
            let result = tokio::task::spawn_blocking(move || {
                let command: AndroidCommand = serde_json::from_slice(permit.payload())
                    .map_err(|_| ErrorCategory::ProtocolMismatch)?;
                let mut arguments = command.arguments;
                arguments.insert("__caller_id".into(), json!(caller_key(&reference)));
                platform.execute(&command.name, Value::Object(arguments))
            }).await;
            let mut output = match result {
                Ok(Ok(value)) => value,
                _ => json!({"ok":false,"error":{"code":"android_result_unknown","message":"The original Android request has no confirmed result.","uncertain":true}}),
            };
            let outcome = if output.get("ok").and_then(Value::as_bool) == Some(true) {
                RequestResult::Succeeded
            } else if output.pointer("/error/uncertain").and_then(Value::as_bool) == Some(false) {
                RequestResult::Failed
            } else {
                RequestResult::Unknown
            };
            let recorded = inner.state.lock().expect("Host state mutex")
                .ledger.record_android_result(&id, outcome, inner.now());
            if let Some(object) = output.as_object_mut() {
                object.insert("operation_id".into(), json!(id));
            }
            let result = recorded.map(|_| output).map_err(CoordinatorError::from);
            let _ = sender.send(result);
        });
        }
        receiver.await.map_err(|_| CoordinatorError::ResponseLost)?
    }
}

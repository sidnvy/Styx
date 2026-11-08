//! Native App adapters to the existing Gateway admin and Tunnel owners.
//! No remote hub credentials, second configuration store, or implicit approvals.
use super::*;
use crate::management::native_gateway_admin as admin;
use styx_contracts::identity::{DeviceId, Sha256Digest};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Approval {
    authorize: bool,
    request_id: String,
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    comparison_code: String,
    enable_computer: bool,
    enable_browser: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Revoke {
    authorize: bool,
    device_id: DeviceId,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Rejection {
    authorize: bool,
    request_id: String,
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    comparison_code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorized {
    authorize: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelSave {
    authorize: bool,
    tunnel_id: String,
    api_key: Option<String>,
}
impl HostApp {
    fn gateway_admin_error(&mut self, error: admin::AdminError) -> AppError {
        // Retain a lost mutation outcome; the GUI cannot repeat it on this owner.
        if error.exit_code() == 4 {
            self.unknown = true;
        }
        AppError(error.code())
    }
    pub(super) async fn gateway_ui_request(
        &mut self,
        operation: Operation,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        self.available()?;
        let gateway = self
            .local_gateway
            .as_ref()
            .ok_or(AppError("managed_on_hub"))?;
        gateway.validate()?;
        let scope = gateway.scope.clone();
        match operation {
            Operation::Computers => {
                let rows = admin::computers_for_app(scope.clone())
                    .await
                    .map_err(|e| self.gateway_admin_error(e))?;
                scope.validate()?;
                let local = self
                    .enrollment
                    .as_ref()
                    .and_then(|e| e["device_id"].as_str());
                let rows: Vec<Value> = rows
                    .into_iter()
                    .filter(|r| r.status == "approved")
                    .map(|r| {
                        json!({"device_id":r.device_id,"label":r.label,"platform":r.platform,
                        "online":r.connections.exec,"connections":r.connections,
                        "is_local":local == Some(r.device_id.as_str())})
                    })
                    .collect();
                Ok(json!({"devices":rows}))
            }
            Operation::PendingComputers => {
                let report = admin::pending_for_app(scope.clone())
                    .await
                    .map_err(|e| self.gateway_admin_error(e))?;
                scope.validate()?;
                serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))
            }
            Operation::InviteComputer => {
                let selected: Authorized = decode_input(&input)?;
                if !selected.authorize {
                    return Err(AppError("app_confirmation_required"));
                }
                let gateway = self
                    .local_gateway
                    .as_mut()
                    .ok_or(AppError("managed_on_hub"))?;
                let origin = gateway.invitation_origin()?;
                let dispatched_wall_ms = now_ms()?;
                self.unknown = true;
                let reply = gateway
                    .admin_once(
                        false,
                        &json!({"ttl_seconds":pairing_link::MAX_LIFETIME_MS / 1000}),
                    )
                    .await?;
                let secret = reply["invitation"]
                    .as_str()
                    .ok_or(AppError("app_local_pairing_result_unknown"))?;
                let gateway_expires = reply["expires_at"]
                    .as_u64()
                    .ok_or(AppError("app_local_pairing_result_unknown"))?;
                if reply["one_use"] != true {
                    return Err(AppError("app_local_pairing_result_unknown"));
                }
                // The original Gateway confirmed the mutation. A local
                // expiry or link-rendering error does not make it uncertain.
                self.unknown = false;
                let now = now_ms()?;
                let expires =
                    pairing_link::local_export_expiry(gateway_expires, dispatched_wall_ms, now)
                        .map_err(|e| AppError(e.code()))?;
                let link = pairing_link::build(&origin, secret, expires, &gateway.ca, now)
                    .map_err(|e| AppError(e.code()))?;
                Ok(json!({"link":link.as_str(),"expiresAt":expires,"origin":origin}))
            }
            Operation::ApproveComputer => {
                let choice: Approval = decode_input(&input)?;
                if !choice.authorize {
                    return Err(AppError("app_confirmation_required"));
                }
                let report = admin::approve_for_app(
                    scope.clone(),
                    admin::ApprovalSelection {
                        request_id: choice.request_id,
                        device_id: choice.device_id,
                        fingerprint: choice.fingerprint,
                        comparison_code: choice.comparison_code,
                        enable_computer: choice.enable_computer,
                        enable_browser: choice.enable_browser,
                    },
                )
                .await
                .map_err(|e| self.gateway_admin_error(e))?;
                scope.validate()?;
                serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))
            }
            Operation::RejectComputer => {
                let choice: Rejection = decode_input(&input)?;
                if !choice.authorize {
                    return Err(AppError("app_confirmation_required"));
                }
                let report = admin::reject_for_app(
                    scope.clone(),
                    admin::RejectionSelection {
                        request_id: choice.request_id,
                        device_id: choice.device_id,
                        fingerprint: choice.fingerprint,
                        comparison_code: choice.comparison_code,
                    },
                )
                .await
                .map_err(|e| self.gateway_admin_error(e))?;
                scope.validate()?;
                serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))
            }
            Operation::RevokeComputer => {
                let choice: Revoke = decode_input(&input)?;
                if !choice.authorize {
                    return Err(AppError("app_confirmation_required"));
                }
                let local = self
                    .enrollment
                    .as_ref()
                    .and_then(|e| e["device_id"].as_str())
                    .ok_or(AppError("app_local_identity_unavailable"))?;
                if choice.device_id.as_str() == local {
                    return Err(AppError("app_cannot_revoke_this_computer"));
                }
                let report = admin::revoke_for_app(scope.clone(), choice.device_id)
                    .await
                    .map_err(|e| self.gateway_admin_error(e))?;
                scope.validate()?;
                serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))
            }
            Operation::TunnelStatus => {
                let status = foreground::tunnel::status(&scope.state_dir)
                    .await
                    .map_err(|e| AppError(e.code()))?;
                scope.validate()?;
                serde_json::to_value(status).map_err(|_| AppError("app_response_invalid"))
            }
            Operation::TunnelSave => {
                let choice: TunnelSave = decode_input(&input)?;
                let secret = choice.api_key.map(zeroize::Zeroizing::new);
                if !choice.authorize {
                    return Err(AppError("app_confirmation_required"));
                }
                // Validate before interrupting either role. The existing selected
                // release remains the only executable authority.
                foreground::tunnel::validate_configuration(
                    &choice.tunnel_id,
                    secret.as_deref().map(|s| s.as_str()),
                )
                .map_err(|e| AppError(e.code()))?;
                let available = foreground::tunnel::status(&scope.state_dir)
                    .await
                    .map_err(|e| AppError(e.code()))?;
                if !available.available {
                    return Err(AppError("tunnel_client_unavailable"));
                }
                if secret.is_none() && available.tunnel_id.is_none() {
                    return Err(AppError("invalid_tunnel_runtime_key"));
                }
                let resume_host = self.running.is_some();
                self.settle_all().await?;
                scope.validate()?;
                let path = scope.state_dir.clone();
                // An interrupted/durability-unknown write must not be replayed.
                self.unknown = true;
                let configured = tokio::task::spawn_blocking(move || {
                    foreground::tunnel::configure_secret(
                        &path,
                        &choice.tunnel_id,
                        secret.as_deref().map(|s| s.as_str()),
                        true,
                        true,
                    )
                })
                .await
                .map_err(|_| AppError("tunnel_configuration_worker_failed"))?
                .map_err(|e| AppError(e.code()))?;
                scope.validate()?;
                self.unknown = false;
                self.local_gateway
                    .as_mut()
                    .ok_or(AppError("managed_on_hub"))?
                    .start()
                    .await?;
                if resume_host {
                    self.connect_host().await?;
                }
                serde_json::to_value(configured).map_err(|_| AppError("app_response_invalid"))
            }
            _ => unreachable!(),
        }
    }
}

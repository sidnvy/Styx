//! Owner-only local Gateway plugin editor. Host-only Apps never edit a remote hub.
use super::*;
use crate::management::{
    native_gateway_admin, plugin_package, plugin_presentation as presentation,
};
use base64::{Engine, engine::general_purpose::STANDARD};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    mode: String,
    account_label: String,
    plugin_url: String,
    revision: u64,
    plugin_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    authorize: bool,
    presentation: presentation::Presentation,
    selection: Selection,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    authorize: bool,
}
impl HostApp {
    pub(super) async fn plugin_request(
        &self,
        operation: Operation,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        self.available()?;
        let gateway = self
            .local_gateway
            .as_ref()
            .ok_or(AppError("plugin_managed_on_gateway"))?;
        gateway.scope.validate()?;
        let directory = gateway.scope.state_dir.join("plugin-presentation");
        let discovery = native_gateway_admin::observe(&gateway.scope.state_dir)
            .await
            .map_err(|_| AppError("plugin_gateway_discovery_required"))?;
        gateway.scope.validate()?;
        if matches!(operation, Operation::PluginSave) {
            let save: Save = decode_input(&input)?;
            if !save.authorize
                || save.selection.mode != "update"
                || !save.selection.account_label.is_empty()
                || !save.selection.plugin_url.is_empty()
            {
                return Err(AppError("plugin_confirmation_required"));
            }
            let profile = presentation::Profile {
                id: save.selection.plugin_id,
                presentation: save.presentation,
            };
            presentation::save(&directory, save.selection.revision, profile).map_err(AppError)?;
        }
        let saved = presentation::load(&directory).map_err(AppError)?;

        if matches!(operation, Operation::PluginExport) {
            let export: Export = decode_input(&input)?;
            if !export.authorize {
                return Err(AppError("plugin_confirmation_required"));
            }
            let saved = saved.ok_or(AppError("plugin_save_required"))?;
            let tunnel = discovery["tunnel_id"]
                .as_str()
                .ok_or(AppError("plugin_tunnel_not_configured"))?;
            let archive =
                plugin_package::archive(&saved.profile, tunnel, &discovery).map_err(AppError)?;
            return Ok(
                json!({"archiveBase64":STANDARD.encode(archive),"pluginId":saved.profile.id,"installed":false}),
            );
        }
        let revision = saved.as_ref().map_or(0, |s| s.revision);
        let profile = saved
            .as_ref()
            .map(|s| s.profile.clone())
            .unwrap_or_else(|| presentation::Profile::initial("Styx"));
        Ok(
            json!({"plugin":{"required":true,"profileSaved":saved.is_some(),"contextChanged":false,"presentation":profile.presentation,"defaultIcon":presentation::Icon::from_bytes(presentation::DEFAULT_ICON).map_err(AppError)?,"connection":{"tunnelId":discovery["tunnel_id"]},"selection":{"mode":"update","accountLabel":"","pluginUrl":"","revision":revision,"pluginId":profile.id}}}),
        )
    }
}

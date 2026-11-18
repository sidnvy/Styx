//! The installed App bundle supplies executable code for a newly configured
//! App-managed Host. The original pairing profile holds data and identity, not
//! a second executable installation under runtime-versions.
use super::runtime_update::SelectionPin;
use super::*;
use crate::release;
use styx_contracts::management::ReaderContract;

impl HostApp {
    /// Validate the installed App's own Runtime for setup, without copying
    /// it to Application Support or publishing another Runtime selection.
    pub(super) async fn bootstrap_runtime_selection(
        &mut self,
        require_tunnel: bool,
    ) -> Result<(), AppError> {
        self.available()?;
        if self.scope.root.get().is_some()
            || self.local_gateway.is_some()
            || self.input_writer.is_some()
            || self.scope.gateway_sibling()?.root.get().is_some()
        {
            return Err(AppError("app_setup_already_exists"));
        }
        let input = self
            .runtime_selection_file
            .as_ref()
            .ok_or(AppError("app_runtime_selection_invalid"))?;
        let pinned = SelectionPin::open(input)?;
        let installed =
            release::load_selected(&pinned.selection).map_err(|e| AppError(e.code()))?;
        if !installed
            .supports_state_reader(ReaderContract::NativePairingLifecycleStateV1)
            .map_err(|e| AppError(e.code()))?
        {
            return Err(AppError("app_runtime_reader_unsupported"));
        }
        if require_tunnel {
            installed
                .worker_image(styx_contracts::native_release::NativeExternalWorker::TunnelClient)
                .map_err(|_| AppError("tunnel_client_unavailable"))?;
        }
        pinned.validate()?;
        self.scope.validate()?;
        // runtime_selection_file already points at the installed bundle
        // candidate. No App-managed bootstrap Runtime copy is ever created.
        Ok(())
    }
}

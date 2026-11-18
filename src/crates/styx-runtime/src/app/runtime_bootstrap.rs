//! The installed App bundle supplies executable code for a newly configured
//! App-managed Host. The original pairing profile holds data and identity, not
//! a second executable installation under runtime-versions.
use super::*;
use crate::{release, store::RawFile};
use styx_contracts::management::ReaderContract;
use styx_contracts::native_management::NativeRuntimeSelection;

pub(super) struct SelectionPin {
    root: PrivateRoot,
    pub(super) file: RawFile,
    pub(super) selection: NativeRuntimeSelection,
}
impl SelectionPin {
    pub(super) fn open(path: &Path) -> Result<Self, AppError> {
        let root = PrivateRoot::open(
            path.parent()
                .ok_or(AppError("app_runtime_selection_invalid"))?,
        )
        .map_err(|_| AppError("app_runtime_selection_invalid"))?;
        let file = root
            .read_raw(
                Path::new(
                    path.file_name()
                        .ok_or(AppError("app_runtime_selection_invalid"))?,
                ),
                65536,
            )
            .map_err(|_| AppError("app_runtime_selection_invalid"))?;
        let selection = serde_json::from_slice(file.bytes())
            .map_err(|_| AppError("app_runtime_selection_invalid"))?;
        Ok(Self {
            root,
            file,
            selection,
        })
    }
    pub(super) fn validate(&self) -> Result<(), AppError> {
        same_file(&self.root, &self.file)
    }
}
pub(super) fn same_file(root: &PrivateRoot, file: &RawFile) -> Result<(), AppError> {
    let current = root
        .read_raw(file.relative_path(), 65536)
        .map_err(|_| AppError("app_runtime_input_changed"))?;
    if current.observation() != file.observation() || current.bytes() != file.bytes() {
        return Err(AppError("app_runtime_input_changed"));
    }
    Ok(())
}

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

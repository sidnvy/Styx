//! First-setup immutable Runtime input. The resulting selection is not a
//! canonical profile or activation proof; existing C07/enrollment creates those.
use super::runtime_update::SelectionPin;
use super::*;
use crate::release;
use std::ffi::OsStr;
use styx_contracts::{identity::Sha256Digest, management::ReaderContract};

struct Bootstrap {
    scope: Arc<HostScope>,
    writer: ConfigurationWriterGuard,
    source: SelectionPin,
}

enum Failure {
    Refused(AppError),
    Incomplete(AppError),
}

/// Deterministic names bind one first-setup copy attempt to the signed manifest.
/// A failed name is never replaced by another random name on the next launch.
fn names(manifest: Sha256Digest) -> (String, String) {
    let version = format!("bootstrap-{}", manifest.to_hex());
    let input = Sha256Digest::of_bytes(
        format!("styx-app-bootstrap-selection-v1:{}", manifest.to_hex()).as_bytes(),
    );
    (version, format!("{}.json", input.to_hex()))
}

impl Bootstrap {
    fn validate(&self) -> Result<(), AppError> {
        self.scope.validate()?;
        self.writer
            .validate()
            .map_err(|_| AppError("app_runtime_bootstrap_writer_changed"))?;
        self.source.validate()
    }

    fn validate_result(
        &self,
        selected: &SelectionPin,
        version_path: &Path,
    ) -> Result<(), AppError> {
        let input = &self.source.selection;
        let selection = &selected.selection;
        if selection.schema != 1
            || selection.manifest_sha256 != input.manifest_sha256
            || selection.publisher_spki_sha256 != input.publisher_spki_sha256
            || Path::new(&selection.payload_path) != version_path.join("payload")
            || Path::new(&selection.publisher_file) != version_path.join("publisher.pem")
        {
            return Err(AppError("app_runtime_bootstrap_changed"));
        }
        let release = release::load_selected(selection).map_err(|e| AppError(e.code()))?;
        if !release
            .supports_state_reader(ReaderContract::NativePairingLifecycleStateV1)
            .map_err(|e| AppError(e.code()))?
        {
            return Err(AppError("app_runtime_reader_unsupported"));
        }
        selected.validate()?;
        self.validate()
    }

    async fn run(self) -> Result<PathBuf, Failure> {
        self.validate().map_err(Failure::Refused)?;
        let source = release::load_selected(&self.source.selection)
            .map_err(|e| Failure::Refused(AppError(e.code())))?;
        if !source
            .supports_state_reader(ReaderContract::NativePairingLifecycleStateV1)
            .map_err(|e| Failure::Refused(AppError(e.code())))?
        {
            return Err(Failure::Refused(AppError("app_runtime_reader_unsupported")));
        }
        self.publish(source).await.map_err(Failure::Incomplete)
    }

    async fn publish(self, source: release::VerifiedNativeRelease) -> Result<PathBuf, AppError> {
        let versions = self
            .scope
            .container
            .parent
            .prepare_app_runtime_directory(&self.writer, "runtime-versions")
            .map_err(|_| AppError("app_runtime_bootstrap_storage_unknown"))?;
        let versions_path = self.scope.container.parent_path.join("runtime-versions");
        let (version_name, input_name) = names(self.source.selection.manifest_sha256);
        let version_path = versions_path.join(&version_name);
        let input_path = versions_path.join(&input_name);

        if versions.ensure_absent(&input_name).is_err() {
            // Only a fully published immutable result may be observed again.
            // This does not resume or repeat the original copy operation.
            let completed = SelectionPin::open(&input_path)
                .map_err(|_| AppError("app_runtime_bootstrap_unknown"))?;
            self.validate_result(&completed, &version_path)?;
            source.revalidate().map_err(|e| AppError(e.code()))?;
            return Ok(input_path);
        }
        versions
            .ensure_absent(&version_name)
            .map_err(|_| AppError("app_runtime_bootstrap_unknown"))?;
        self.validate()?;
        let staged = release::stage_installed(
            Path::new(&self.source.selection.payload_path),
            Path::new(&self.source.selection.publisher_file),
            &self.source.selection.publisher_spki_sha256.to_hex(),
            &versions_path,
            OsStr::new(&version_name),
        )
        .await
        .map_err(|e| AppError(e.code()))?;
        source.revalidate().map_err(|e| AppError(e.code()))?;
        self.validate()?;
        let bytes =
            serde_json::to_vec(&staged).map_err(|_| AppError("app_runtime_bootstrap_unknown"))?;
        self.scope
            .container
            .parent
            .publish_app_runtime_file(&self.writer, &versions, &input_name, &bytes)
            .map_err(|_| AppError("app_runtime_bootstrap_unknown"))?;
        let completed = SelectionPin::open(&input_path)
            .map_err(|_| AppError("app_runtime_bootstrap_unknown"))?;
        self.validate_result(&completed, &version_path)?;
        if completed.selection != staged {
            return Err(AppError("app_runtime_bootstrap_changed"));
        }
        Ok(input_path)
    }
}

impl HostApp {
    /// Called only for a user-selected fresh CreateLocal/Join, before publishing
    /// either role's input. Existing configured profiles keep their C07 choice.
    pub(super) async fn bootstrap_runtime_selection(&mut self) -> Result<(), AppError> {
        self.available()?;
        if self.scope.root.get().is_some()
            || self.local_gateway.is_some()
            || self.input_writer.is_some()
            || self.scope.gateway_sibling()?.root.get().is_some()
        {
            return Err(AppError("app_setup_already_exists"));
        }
        let selection = self
            .runtime_selection_file
            .clone()
            .ok_or(AppError("app_runtime_selection_invalid"))?;
        for name in ["app-join-input-v1.json", "app-local-gateway-input-v1.json"] {
            self.scope
                .container
                .parent
                .ensure_absent(name)
                .map_err(|_| AppError("app_runtime_bootstrap_unknown"))?;
        }
        let scope = self.scope.clone();
        // This retained task owns the exact scope and writer until the one
        // stage completes. Losing the UI waiter cannot free the instance lease
        // while the original release::stage blocking copy is still running.
        let job = tokio::spawn(async move {
            let source = SelectionPin::open(&selection).map_err(Failure::Refused)?;
            let writer = scope
                .container
                .parent
                .try_configuration_writer()
                .map_err(|_| Failure::Refused(AppError("app_input_writer_busy")))?;
            Bootstrap {
                scope,
                writer,
                source,
            }
            .run()
            .await
        });
        let result = match job.await {
            Ok(result) => result,
            Err(_) => Err(Failure::Incomplete(AppError(
                "app_runtime_bootstrap_unknown",
            ))),
        };
        match result {
            Ok(input) => {
                self.scope.validate()?;
                self.runtime_selection_file = Some(input);
                Ok(())
            }
            Err(Failure::Refused(error)) => Err(error),
            Err(Failure::Incomplete(error)) => {
                // No setup write may continue after an uncertain copy. A later
                // process may only observe the same fully published result.
                self.unknown = true;
                self.enrollment = Some(AppEnrollment::incomplete(error.code()));
                Err(error)
            }
        }
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "runtime_bootstrap_tests.rs"]
mod tests;

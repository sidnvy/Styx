//! Maintenance-only validation materials. This is neither an ordinary profile
//! conversion nor permission to start a Host, acquire a lease or grant dispatch.
use super::*;
use crate::migration::legacy_service::RetiredCredentialReadBinding;

pub struct LoadedMaintenanceProfile {
    // No Deref, into_inner, Clone, Serialize or ordinary-profile getter.
    original: LoadedLegacyProfile,
}
/// All original config/state/identity/CA/publisher/active inputs remain checked.
/// Only the one fixed retired token locator and verified candidate workers differ.
pub(crate) fn load_for_migration_validation(
    state_dir: &Path,
    binding: Arc<RetiredCredentialReadBinding>,
) -> Result<LoadedMaintenanceProfile, ProfileError> {
    let original = load_source(
        state_dir,
        GatewayWireMode::PairedV3,
        ProfileSource::Maintenance(binding),
    )?;
    Ok(LoadedMaintenanceProfile { original })
}
impl LoadedMaintenanceProfile {
    pub fn host_base_dir(&self) -> &Path {
        self.original.host_base_dir()
    }
    pub(crate) fn preservation_entries(&self) -> &[PreservationEntry] {
        &self.original.diagnostics().preservation
    }
    /// Exact original signed closure plus candidate, independent of the one
    /// canonical state replacement. This does not skip any executable inventory.
    pub(crate) fn revalidate_worker_closures(&self) -> Result<(), ProfileError> {
        self.original.inventory.revalidate()
    }
    pub fn device_id(&self) -> &DeviceId {
        self.original.device_id()
    }
    pub fn endpoint(&self) -> &LinkEndpoint {
        self.original.endpoint()
    }
    pub fn paired_gateway_namespace(&self) -> GatewayId {
        self.original.paired_gateway_namespace()
    }
    pub fn tls(&self) -> &GatewayClientTls {
        self.original.tls()
    }
    pub fn bearer(&self) -> &SecretBearer {
        self.original.bearer()
    }
    pub fn executor_enabled(&self) -> bool {
        self.original.executor_enabled()
    }
    pub fn executor_config(&self) -> Result<OwnedExecutorConfig, ProfileError> {
        self.original.executor_config()
    }
    pub fn revalidate(&self) -> Result<(), ProfileError> {
        self.original.revalidate()
    }
}

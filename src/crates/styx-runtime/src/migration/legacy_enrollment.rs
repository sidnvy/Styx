//! Historical enrollment preflight under the original configuration fence.
//! This does not stop the old Gateway, publish a native ledger or grant access.
use super::legacy_service::TransitionError;
pub use crate::enrollment::legacy_import::{LegacyImportSummary, PreparationBlocker};
use crate::{
    enrollment::legacy_import::{self, LegacyImportSnapshot},
    store::{ConfigurationMaintenance, PrivateRoot},
};
use std::{path::Path, sync::Arc};

/// Retains original raw files, token inventory and the active maintenance
/// borrow. There is no DTO conversion to Core authority or ordinary startup.
pub struct LegacyEnrollmentSnapshot<'m> {
    original: LegacyImportSnapshot<'m>,
}
fn classify(error: legacy_import::LegacyImportError) -> TransitionError {
    use legacy_import::LegacyImportError as E;
    match error {
        E::Invalid | E::Maintenance => TransitionError::Conflict,
        E::Changed => TransitionError::Unknown,
        E::Unavailable => TransitionError::Unavailable,
        E::Capacity | E::Unsettled => TransitionError::Busy,
        E::Unsupported => TransitionError::Unsupported,
    }
}
impl<'m> LegacyEnrollmentSnapshot<'m> {
    pub fn capture(
        state_dir: &Path,
        original: Arc<PrivateRoot>,
        maintenance: &'m ConfigurationMaintenance,
    ) -> Result<Self, TransitionError> {
        legacy_import::capture(state_dir, original, maintenance)
            .map(|original| Self { original })
            .map_err(classify)
    }
    /// Non-sensitive diagnostics explicitly retain original-Gateway settlement
    /// and native-import flags as false. A clean report is not admission.
    pub fn summary(&self) -> Result<LegacyImportSummary, TransitionError> {
        self.original.summary().map_err(classify)
    }
    pub fn revalidate(&self) -> Result<(), TransitionError> {
        self.original.revalidate().map_err(classify)
    }
    /// Historical inputs may be prepared only after every explicit blocker is
    /// resolved. Success still does not attest physical old-writer settlement.
    pub fn validate_preparation(&self) -> Result<(), TransitionError> {
        self.original.validate_preparation().map_err(classify)
    }
}

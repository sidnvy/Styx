//! Same-writer maintenance composition. Constructing this plan starts no
//! listener/Host and never authorizes ordinary admission or final C07 commit.
use super::*;
use crate::{
    enrollment::service::EnrollmentService,
    foreground::profile::LoadedMaintenanceProfile,
    gateway::auth::GatewayBearerPolicy,
    store::{
        ExecutionLeaseGuard, PrivateRoot,
        enrollment::{EnrollmentJournal, JournalError, JournalResult, OwnedEnrollmentJournal},
        legacy_handoff::PreparedNativeCutover,
    },
    tls::{GatewayLeafPin, GatewayServerTls, PrivateKeyPem},
};
use std::{
    net::SocketAddr,
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    identity::{DeviceId, Sha256Digest},
    native_management::NativeGatewayEndpointBinding,
};
use styx_core::enrollment::Limits;
use zeroize::Zeroizing;

/// Not Clone/Serde and no external constructor: the original writer, physical
/// dual-scope proof and exact retained preparation cannot be supplied by a DTO.
pub(crate) struct GatewayMaintenanceBinding {
    original: Arc<SettledLegacyRuntime>,
    prepared: Arc<PreparedNativeCutover>,
    profile: Arc<LoadedMaintenanceProfile>,
}
impl GatewayMaintenanceBinding {
    pub(crate) fn selected_device(&self) -> &DeviceId {
        self.profile.device_id()
    }

    pub(crate) fn validate_owner(&self, owner: &OwnedConfigurationRoot) -> JournalResult<()> {
        if !owner.same_authority(self.original.configuration_root()) {
            return Err(JournalError::Conflict);
        }
        self.original
            .original_fence()
            .validate_prepared_cutover(&self.prepared)?;
        if owner.ensure_admission().is_ok() {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
    /// After final commit the retired maintenance fence is intentionally no
    /// longer usable. Match the retained preparation and same writer instead.
    pub(crate) fn validate_committed(
        &self,
        proof: &crate::store::legacy_handoff::CommittedNativeCutover,
        owner: &OwnedConfigurationRoot,
    ) -> JournalResult<()> {
        if !owner.same_authority(self.original.configuration_root())
            || !proof.matches_prepared(&self.prepared)
            || proof.transaction_id() != self.prepared.transaction_id()
        {
            return Err(JournalError::Conflict);
        }
        proof.validate_owner(owner)
    }
    /// No second namespace/writer and no fresh legacy snapshot after canonical
    /// conversion. Recheck the original baseline on both sides of the operation.
    pub(crate) fn with_journal<T>(
        &self,
        store: &mut OwnedEnrollmentJournal,
        operation: impl FnOnce(&mut EnrollmentJournal<'_>) -> JournalResult<T>,
    ) -> JournalResult<T> {
        let owner = store.configuration_root();
        self.validate_owner(&owner)?;
        let result = store.with_historical_journal(
            self.original.original_fence().maintenance(),
            |journal| {
                self.validate_history(journal)?;
                let result = operation(journal);
                self.validate_history(journal)?;
                result
            },
        );
        self.validate_owner(&owner)?;
        result
    }
    fn validate_history(&self, journal: &mut EnrollmentJournal<'_>) -> JournalResult<()> {
        let facts = journal.resync_historical()?.ok_or(JournalError::Conflict)?;
        let committed = facts.committed.as_ref().ok_or(JournalError::Conflict)?;
        if facts.body.schema != 2
            || &facts.body.migration != self.prepared.transaction_id()
            || facts.digest != self.prepared.history_baseline_sha256()
            || committed.digest()? != self.prepared.history_committed_sha256()
        {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
}

/// Owned, unstarted Gateway plan. A subsequent owned network driver must retain
/// every field until listener/transport/executor cleanup has actually joined.
/// This object alone is not a successful paired validation receipt.
#[must_use]
pub struct PreparedGatewayValidation {
    pub(super) state_path: std::path::PathBuf,
    pub(super) original: Arc<SettledLegacyRuntime>,
    pub(super) prepared: Arc<PreparedNativeCutover>,
    pub(super) preservation: Arc<OriginalPreservation>,
    pub(super) profile: Arc<LoadedMaintenanceProfile>,
    pub(super) gateway: PrivateRoot,
    pub(super) lease: ExecutionLeaseGuard,
    pub(super) service: EnrollmentService,
    pub(super) tls: Arc<GatewayServerTls>,
    pub(super) policy: Arc<GatewayBearerPolicy>,
    pub(super) model_token: Zeroizing<String>,
    pub(super) endpoint: NativeGatewayEndpointBinding,
    pub(super) address: SocketAddr,
    pub(super) host_header: String,
}
fn original_token(raw: &[u8]) -> Result<&str, TransitionError> {
    let value = std::str::from_utf8(raw)
        .map_err(|_| TransitionError::Conflict)?
        .trim();
    if !(32..=4096).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(TransitionError::Conflict);
    }
    Ok(value)
}
impl PreparedLegacyCutover {
    /// Consume the existing imported enrollment authority once. No re-pairing,
    /// clearing of the migration fence, alternate port or credential creation.
    /// Build BEFORE canonical replacement; the retained maintenance profile is
    /// deliberately not a general post-Applied legacy-schema bypass.
    pub fn prepare_gateway_validation(
        &self,
        history: OwnedEnrollmentJournal,
    ) -> Result<PreparedGatewayValidation, TransitionError> {
        if self.report().applied_sha256.is_some() {
            return Err(TransitionError::Conflict);
        }
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| TransitionError::Unsupported)?;
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err(TransitionError::Unsupported);
        }
        if self
            .validation_prepared
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TransitionError::Conflict);
        }
        tokio::task::block_in_place(|| {
            handle.block_on(self.original.revalidate())?;
            self.original
                .original_fence()
                .validate_prepared_cutover(&self.prepared)
                .map_err(|_| TransitionError::Unknown)?;
            self.preservation.revalidate_except_canonical()?;
            let profile = Arc::new(
                self.original
                    .maintenance_profile(&self._state_dir)
                    .map_err(|_| TransitionError::Unknown)?,
            );
            profile.revalidate().map_err(|_| TransitionError::Unknown)?;
            if !profile.executor_enabled() {
                return Err(TransitionError::Unsupported);
            }
            let binding_raw = self
                .prepared
                .endpoint_binding()
                .ok_or(TransitionError::Unsupported)?;
            let endpoint: NativeGatewayEndpointBinding =
                serde_json::from_slice(binding_raw).map_err(|_| TransitionError::Conflict)?;
            let chain = self
                .prepared
                .endpoint_chain()
                .ok_or(TransitionError::Conflict)?;
            let key = self
                .prepared
                .endpoint_key()
                .ok_or(TransitionError::Conflict)?;
            let now = i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| TransitionError::Conflict)?
                    .as_secs(),
            )
            .map_err(|_| TransitionError::Conflict)?;
            if endpoint.schema != 1
                || &endpoint.transaction_id != self.prepared.transaction_id()
                || endpoint.candidate_manifest_sha256
                    != self.original.target().report().manifest_sha256
                || endpoint.chain_sha256 != Sha256Digest::of_bytes(chain)
                || now < endpoint.not_before_unix
                || now >= endpoint.not_after_unix
                || profile.tls().configured_leaf().is_some()
                || profile.tls().configured_anchors().len() != 1
                || profile.tls().configured_anchors()[0].as_hex() != endpoint.anchor_sha256.to_hex()
            {
                return Err(TransitionError::Conflict);
            }
            let origin =
                url::Url::parse(&endpoint.origin).map_err(|_| TransitionError::Conflict)?;
            let mut original_origin = url::Url::parse(profile.endpoint().as_str())
                .map_err(|_| TransitionError::Conflict)?;
            original_origin
                .set_scheme("https")
                .map_err(|_| TransitionError::Conflict)?;
            let ip: std::net::IpAddr = origin
                .host_str()
                .ok_or(TransitionError::Conflict)?
                .parse()
                .map_err(|_| TransitionError::Unsupported)?;
            let port = origin.port().ok_or(TransitionError::Conflict)?;
            if origin.scheme() != "https"
                || origin.origin() != original_origin.origin()
                || !ip.is_ipv4()
                || !ip.is_loopback()
                || port < 1024
                || origin.path() != "/"
                || origin.query().is_some()
                || origin.fragment().is_some()
                || !origin.username().is_empty()
                || origin.password().is_some()
            {
                return Err(TransitionError::Conflict);
            }
            let host_header = format!("{ip}:{port}");
            let leaf = GatewayLeafPin::parse_hex(&endpoint.leaf_sha256.to_hex())
                .map_err(|_| TransitionError::Conflict)?;
            let key = PrivateKeyPem::from_protected_reader_bytes(key.to_vec())
                .map_err(|_| TransitionError::Conflict)?;
            let tls = Arc::new(
                GatewayServerTls::from_pem(chain, &key, leaf)
                    .map_err(|_| TransitionError::Conflict)?,
            );
            let gateway = PrivateRoot::open(self._state_dir.join("gateway"))
                .map_err(|_| TransitionError::Conflict)?;
            let lease = gateway
                .try_execution_lease()
                .map_err(|_| TransitionError::Busy)?;
            let admin_raw = gateway
                .read_raw("admin.token", 8192)
                .map_err(|_| TransitionError::Conflict)?;
            let model_raw = gateway
                .read_raw("model.token", 8192)
                .map_err(|_| TransitionError::Conflict)?;
            let admin = original_token(admin_raw.bytes())?;
            let model = original_token(model_raw.bytes())?;
            let policy = Arc::new(
                GatewayBearerPolicy::new(
                    model.as_bytes(),
                    vec![host_header.clone()],
                    vec![endpoint.origin.clone()],
                )
                .map_err(|_| TransitionError::Conflict)?,
            );
            let binding = GatewayMaintenanceBinding {
                original: self.original.clone(),
                prepared: self.prepared.clone(),
                profile: profile.clone(),
            };
            let service = EnrollmentService::recover_for_migration(
                history,
                binding,
                admin.as_bytes(),
                Sha256Digest::of_bytes(model.as_bytes()),
                vec![host_header.clone()],
                Limits::default(),
            )
            .map_err(|_| TransitionError::Unknown)?;
            let plan = PreparedGatewayValidation {
                state_path: self._state_dir.clone(),
                original: self.original.clone(),
                prepared: self.prepared.clone(),
                preservation: self.preservation.clone(),
                profile,
                gateway,
                lease,
                service,
                tls,
                policy,
                model_token: Zeroizing::new(model.to_owned()),
                endpoint,
                address: SocketAddr::new(ip, port),
                host_header,
            };
            plan.lease
                .validate()
                .map_err(|_| TransitionError::Unknown)?;
            plan.profile
                .revalidate()
                .map_err(|_| TransitionError::Unknown)?;
            plan.preservation.revalidate_except_canonical()?;
            plan.original
                .original_fence()
                .validate_prepared_cutover(&plan.prepared)
                .map_err(|_| TransitionError::Unknown)?;
            handle.block_on(plan.original.revalidate())?;
            Ok(plan)
        })
    }
}

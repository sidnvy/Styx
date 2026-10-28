//! Move-owned bootstrap resource for static services. No self-reference, cloned
//! writer description, second filesystem implementation or network authority.
use super::*;

pub struct OwnedEnrollmentJournal {
    owner: crate::store::OwnedConfigurationRoot,
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    budget: JournalBudget,
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    namespace: (u64, u64),
}
impl OwnedEnrollmentJournal {
    pub fn open_existing(
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        Self::from_configuration(
            crate::store::OwnedConfigurationRoot::open_existing(root, writer)?,
            budget,
        )
    }
    /// Trusted bootstrap composes typed adapters under one move-owned writer.
    /// Only one enrollment handle/ledger can be minted by a configuration root.
    pub fn from_configuration(
        owner: crate::store::OwnedConfigurationRoot,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            let namespace = owner.claim_namespace(
                crate::store::secure_journal::NamespaceName::EnrollmentV1,
                budget,
            )?;
            Ok(Self {
                owner,
                budget,
                namespace,
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (owner, budget);
            Err(JournalError::Unsupported)
        }
    }
    pub(crate) fn configuration_root(&self) -> crate::store::OwnedConfigurationRoot {
        self.owner.clone()
    }
    pub fn with_journal<T>(
        &mut self,
        operation: impl FnOnce(&mut EnrollmentJournal<'_>) -> JournalResult<T>,
    ) -> JournalResult<T> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.owner.with_state(|state| {
                state.ordinary_admission()?;
                let mut journal = EnrollmentJournal {
                    root: &state.root,
                    writer: &mut state.writer,
                    budget: self.budget,
                    namespace: self.namespace,
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    historical_transaction: None,
                };
                journal.scan()?;
                let result = operation(&mut journal);
                journal.scan()?;
                result
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = operation;
            Err(JournalError::Unsupported)
        }
    }
}

/// Public display metadata only; never device authentication or a grant.
pub(crate) struct ApprovedDevice {
    pub device_id: styx_contracts::identity::DeviceId,
    pub fingerprint: Sha256Digest,
    pub label: String,
}
impl EnrollmentJournal<'_> {
    /// Read-only display projection for role retirement. Caller first verifies
    /// the complete journal using existing bootstrap/Core recovery under this
    /// same writer. This view exposes no credential/profile material or grant.
    pub(crate) fn approved_devices(&self) -> JournalResult<Vec<ApprovedDevice>> {
        use std::collections::{BTreeMap, BTreeSet};
        let observed = self.scan()?;
        let committed: BTreeSet<_> = observed
            .files
            .iter()
            .filter_map(|file| file.name.strip_suffix(".committed"))
            .collect();
        let mut intents = Vec::new();
        for file in &observed.files {
            if let Some(stem) = file.name.strip_suffix(".intent")
                && committed.contains(stem)
            {
                intents.push(contract::decode(file.bytes()).map_err(|_| JournalError::Unknown)?);
            }
        }
        intents.sort_by_key(|intent| intent.expected_revision);
        let mut devices = BTreeMap::new();
        for intent in intents {
            match intent.mutation {
                Mutation::Approve { device, .. } => {
                    devices.insert(device.id.clone(), device);
                }
                Mutation::Revoke { device, .. } => {
                    devices.remove(&device);
                }
                _ => (),
            }
        }
        #[derive(Deserialize)]
        struct Profile {
            device_id: styx_contracts::identity::DeviceId,
            fingerprint: Sha256Digest,
            label: String,
        }
        devices
            .into_values()
            .map(|device| {
                let bytes = self.read_material(&MaterialRef {
                    kind: MaterialKind::Profile,
                    digest: device.profile.0,
                })?;
                let profile: Profile =
                    serde_json::from_slice(&bytes).map_err(|_| JournalError::Unknown)?;
                if profile.device_id != device.id
                    || profile.fingerprint != device.fingerprint
                    || profile.label.trim().is_empty()
                    || profile.label.len() > 128
                    || profile.label.chars().any(char::is_control)
                {
                    return Err(JournalError::Unknown);
                }
                Ok(ApprovedDevice {
                    device_id: device.id,
                    fingerprint: device.fingerprint,
                    label: profile.label,
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "owned_tests.rs"]
mod tests;

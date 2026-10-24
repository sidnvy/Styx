//! Shared management inspection. Raw legacy bytes remain the source of truth.
//!
//! This adapter performs no migration, configuration writes, service launch or
//! implicit recovery. A read is not a management-writer handoff. Private files
//! are reobserved before returning; that is not a transactional snapshot against
//! an uncoordinated legacy writer. CLI and future UI use this same entry point.
pub mod native;
use crate::store::{PrivateRoot, RawFile, StoreError};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
};
use std::{collections::BTreeSet, fmt, path::Path};
use styx_contracts::identity::Sha256Digest;
use styx_core::management::{
    deployment::*,
    plan::{self, Component, PlanAction},
};
use tokio::sync::Semaphore;

const FILE_LIMIT: usize = 1024 * 1024;
const MAX_STEPS: usize = 64;
// A cancelled read waiter cannot release this permit while its blocking reader
// is still executing. No unbounded blocking work or request queue is admitted.
static READERS: Semaphore = Semaphore::const_new(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagementError {
    #[error("management platform unsupported")]
    Unsupported,
    #[error("protected management input unavailable")]
    ProtectedRead,
    #[error("management source schema or binding invalid")]
    Invalid,
    #[error("management source changed")]
    Changed,
    #[error("management reader capacity reached")]
    Busy,
    #[error("management reader failed")]
    ReaderFailed,
}
impl ManagementError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "management_platform_unsupported",
            Self::ProtectedRead => "management_protected_read",
            Self::Invalid => "management_source_invalid",
            Self::Changed => "management_source_changed",
            Self::Busy => "management_reader_busy",
            Self::ReaderFailed => "management_reader_failed",
        }
    }
}
impl From<StoreError> for ManagementError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::Unsupported => Self::Unsupported,
            StoreError::Changed => Self::Changed,
            _ => Self::ProtectedRead,
        }
    }
}
type Result<T> = std::result::Result<T, ManagementError>;

// Unknown JSON values are skipped by Serde, never round-tripped through Value
// or floating point. The retained RawFile includes all original bytes, including
// unknown fields, whitespace and integers outside the IEEE754 exact range.
#[derive(Deserialize)]
struct Deployment {
    schema: u32,
    mode: String,
    gateway: Gateway,
    host: Option<Host>,
    #[serde(rename = "pairingMode")]
    pairing_mode: Option<String>,
    #[serde(rename = "invitationFile")]
    invitation_file: Option<String>,
}
#[derive(Deserialize)]
struct Gateway {
    url: String,
    runtime: Option<Box<serde_json::value::RawValue>>,
    #[serde(rename = "listenHost")]
    listen_host: Option<String>,
    #[serde(rename = "deviceIngress")]
    device_ingress: Option<Ingress>,
    openssl: Option<String>,
    #[serde(rename = "opensslConfig")]
    openssl_config: Option<String>,
    #[serde(rename = "allowRemoteHosts")]
    allow_remote_hosts: Option<bool>,
}
#[derive(Deserialize)]
struct Ingress {
    schema: u32,
    enabled: bool,
}
#[derive(Deserialize)]
struct Host {
    computer: bool,
    browser: Option<Browser>,
}
#[derive(Deserialize)]
struct Browser {
    enabled: bool,
}
#[derive(Deserialize)]
struct State {
    schema: u32,
    mode: String,
    #[serde(rename = "configSha256")]
    config_sha256: Sha256Digest,
    #[serde(deserialize_with = "bounded_steps")]
    steps: Vec<LegacyStep>,
    #[serde(rename = "appPreferences")]
    app_preferences: Option<AppPreferences>,
    #[serde(rename = "onboardingDecisions")]
    decisions: Option<Decisions>,
}
#[derive(Deserialize)]
struct AppPreferences {
    #[serde(rename = "loginAtStartup")]
    login_at_startup: Option<AppLogin>,
}
#[derive(Deserialize)]
struct AppLogin {
    #[serde(rename = "desiredEnabled")]
    desired_enabled: bool,
    registration: Option<Box<serde_json::value::RawValue>>,
    #[serde(rename = "lastOperation")]
    last_operation: LastOperation,
}
#[derive(Deserialize)]
struct LastOperation {
    status: String,
}
#[derive(Deserialize)]
struct Decisions {
    background: Option<BackgroundChoice>,
}
#[derive(Deserialize)]
struct BackgroundChoice {
    choice: String,
    #[serde(rename = "configSha256")]
    config_sha256: Sha256Digest,
}
#[derive(Deserialize)]
struct LegacyStep {
    id: String,
    status: String,
}
fn bounded_steps<'de, D: de::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<LegacyStep>, D::Error> {
    struct Steps;
    impl<'de> Visitor<'de> for Steps {
        type Value = Vec<LegacyStep>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded management steps")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(step) = seq.next_element()? {
                if out.len() == MAX_STEPS {
                    return Err(de::Error::custom("management_steps_capacity"));
                }
                out.push(step);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Steps)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceBinding {
    pub deployment_schema: u32,
    pub deployment_sha256: Sha256Digest,
    pub state_schema: u32,
    pub state_sha256: Sha256Digest,
    pub consistency: &'static str,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Roles {
    pub gateway: &'static str,
    pub host: &'static str,
    pub exec: &'static str,
    pub computer: &'static str,
    pub browser: &'static str,
    pub device_ingress: &'static str,
    pub readiness: &'static str,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepInspection {
    pub id: String,
    pub recorded_status: String,
    pub projected_status: String,
    pub requires: Vec<String>,
    pub replay_authorized: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppLoginInspection {
    pub desired_enabled: Option<bool>,
    pub last_recorded_operation: Option<String>,
    pub registration_observed: &'static str,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewStep {
    pub component: &'static str,
    pub action: &'static str,
    pub requires: Vec<String>,
    pub authorization_required: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagementInspection {
    pub schema: u32,
    pub source_contract: &'static str,
    pub validation_scope: &'static str,
    pub source: SourceBinding,
    pub mode: String,
    pub roles: Roles,
    pub steps: Vec<StepInspection>,
    pub review_plan: Vec<ReviewStep>,
    pub needs_explicit_decision: Vec<&'static str>,
    pub background_choice: &'static str,
    pub background_configuration_bound: bool,
    pub app_login: AppLoginInspection,
    pub host_manager: &'static str,
    pub gateway_manager: &'static str,
    pub host_desired_run: &'static str,
    pub gateway_desired_run: &'static str,
    pub management_guards: Vec<&'static str>,
    pub plan_execution: &'static str,
    pub runtime_health: &'static str,
    pub account_acceptance: &'static str,
}
// These are legacy lock names, not names supplied by a remote request. Their
// presence is an observation only; this adapter never deletes or steals a lock.
const GUARDS: &[&str] = &[
    "advance.lock",
    "background.lock",
    "capabilities.lock",
    "foreground.lock",
    "foreground-recovery.lock",
    "mac-signing-registration-recovery.lock",
];
struct Loaded {
    root: PrivateRoot,
    deployment: RawFile,
    state: RawFile,
    inspection: ManagementInspection,
}
fn capability_intent(value: CapabilityIntent) -> &'static str {
    match value {
        CapabilityIntent::Enabled => "enabled",
        CapabilityIntent::Requested => "requested",
        CapabilityIntent::Disabled => "disabled",
    }
}
fn component_name(value: Component) -> &'static str {
    match value {
        Component::Gateway => "gateway",
        Component::Host => "host",
    }
}
fn action_name(value: PlanAction) -> &'static str {
    match value {
        PlanAction::ReviewOriginalBindings => "review_original_bindings",
        PlanAction::ReviewExistingOwnership => "review_existing_ownership",
        PlanAction::PrepareRuntime => "prepare_runtime",
        PlanAction::PrepareConfiguration => "prepare_configuration",
        PlanAction::ConfigureManager => "configure_manager",
        PlanAction::InstallPersistentService => "install_persistent_service",
        PlanAction::SetAutostart => "set_autostart",
        PlanAction::PersistDesiredState => "persist_desired_state",
        PlanAction::StartOwnedRuntime => "start_owned_runtime",
        PlanAction::VerifyRunning => "verify_running",
        PlanAction::PrepareIngress => "prepare_ingress",
        PlanAction::VerifyIngress => "verify_ingress",
        PlanAction::PairLocal => "pair_local",
        PlanAction::CreateInvitation => "create_invitation",
        PlanAction::RequestApproval => "request_approval",
        PlanAction::ClaimCredential => "claim_credential",
        PlanAction::ValidatePreservedPairing => "validate_preserved_pairing",
        PlanAction::FenceNewWork => "fence_new_work",
        PlanAction::ObserveOwnedWork => "observe_owned_work",
        PlanAction::StopOwnedRuntime => "stop_owned_runtime",
        PlanAction::VerifyStopped => "verify_stopped",
    }
}
fn invalid<T>(_: T) -> ManagementError {
    ManagementError::Invalid
}
fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(invalid)
}
fn guards(root: &PrivateRoot) -> Result<Vec<&'static str>> {
    GUARDS
        .iter()
        .filter_map(|name| match root.ensure_absent(name) {
            Ok(()) => None,
            Err(StoreError::Changed) => Some(Ok(*name)),
            Err(value) => Some(Err(value.into())),
        })
        .collect()
}
fn load(path: &Path) -> Result<Loaded> {
    let root = PrivateRoot::open(path)?;
    let deployment = root.read_raw("deployment.json", FILE_LIMIT)?;
    let state = root.read_raw("state.json", FILE_LIMIT)?;
    let d: Deployment = decode(deployment.bytes())?;
    let s: State = decode(state.bytes())?;
    let local = match d.mode.as_str() {
        "create-local" => true,
        "join-existing" => false,
        _ => return Err(ManagementError::Invalid),
    };
    if d.schema != 1
        || s.schema != 1
        || s.mode != d.mode
        || s.config_sha256 != Sha256Digest::of_bytes(deployment.bytes())
        || d.host.is_none() && (!local || d.gateway.runtime.is_none())
        || d.host.is_none() && (d.pairing_mode.is_some() || d.invitation_file.is_some())
        || !local
            && (d.gateway.runtime.is_some()
                || d.gateway.device_ingress.is_some()
                || d.gateway.openssl.is_some()
                || d.gateway.openssl_config.is_some()
                || d.gateway.listen_host.is_some()
                || d.gateway.allow_remote_hosts.is_some()
                || d.pairing_mode.as_deref() == Some("owner-local"))
        || d.pairing_mode
            .as_deref()
            .is_some_and(|m| !matches!(m, "manual" | "owner-local"))
        || d.invitation_file.is_some() && local
        || d.gateway
            .device_ingress
            .as_ref()
            .is_some_and(|i| i.schema != 1)
    {
        return Err(ManagementError::Invalid);
    }
    let url = url::Url::parse(&d.gateway.url).map_err(invalid)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ManagementError::Invalid);
    }
    let mut seen = BTreeSet::new();
    let mut steps = Vec::new();
    let mut prefix = Vec::new();
    for step in s.steps {
        if step.id.is_empty()
            || step.id.len() > 128
            || !step
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !seen.insert(step.id.clone())
            || !matches!(
                step.status.as_str(),
                "pending"
                    | "running"
                    | "succeeded"
                    | "failed"
                    | "blocked"
                    | "uncertain"
                    | "skipped"
                    | "awaiting_approval"
            )
        {
            return Err(ManagementError::Invalid);
        }
        let projected = if step.status == "running" {
            "uncertain".to_owned()
        } else {
            step.status.clone()
        };
        steps.push(StepInspection {
            id: step.id.clone(),
            recorded_status: step.status,
            projected_status: projected,
            requires: prefix.clone(),
            replay_authorized: false,
        });
        prefix.push(step.id);
    }
    let login = s.app_preferences.and_then(|x| x.login_at_startup);
    if login.as_ref().is_some_and(|x| {
        !matches!(
            x.last_operation.status.as_str(),
            "running" | "succeeded" | "needs_attention"
        ) || x
            .registration
            .as_ref()
            .is_some_and(|r| !r.get().trim_start().starts_with('{'))
    }) {
        return Err(ManagementError::Invalid);
    }
    let choice = s.decisions.and_then(|x| x.background);
    let bound = choice
        .as_ref()
        .is_some_and(|x| x.config_sha256 == s.config_sha256);
    let background = if bound {
        match choice.as_ref().map(|x| x.choice.as_str()) {
            Some("foreground") => "foreground",
            Some("login") => "login",
            _ => "not_decided",
        }
    } else {
        "not_decided"
    };
    let host = d.host.as_ref();
    // Only Core derives roles and future action dependencies. Legacy observations
    // do not supply explicit manager/run/autostart, even if a service succeeded.
    let unspecified = ComponentIntent {
        manager: ManagerMode::Unspecified,
        run: RunDesired::Unspecified,
        autostart: AutostartDesired::Unspecified,
    };
    let binding = LegacySourceBinding {
        deployment_schema: 1,
        deployment_raw_sha256: Sha256Digest::of_bytes(deployment.bytes()),
        state_schema: 1,
        state_raw_sha256: Sha256Digest::of_bytes(state.bytes()),
    };
    let intent = DeploymentIntent {
        mode: if local {
            DeploymentMode::CreateLocal
        } else {
            DeploymentMode::JoinExisting
        },
        gateway: if local { Some(unspecified) } else { None },
        host: host.map(|h| HostIntent {
            component: unspecified,
            computer_requested: h.computer,
            browser_requested: h.browser.as_ref().is_some_and(|b| b.enabled),
        }),
        pairing: if host.is_none() {
            PairingIntent::None
        } else if steps.iter().any(|x| {
            matches!(x.id.as_str(), "host.pair" | "host.claim") && x.recorded_status == "succeeded"
        }) {
            PairingIntent::PreserveExisting
        } else {
            PairingIntent::Unspecified
        },
        device_ingress: if !local {
            IngressIntent::NotHosted
        } else if d.gateway.device_ingress.as_ref().is_some_and(|i| i.enabled)
            || d.gateway.listen_host.as_deref().unwrap_or("127.0.0.1") != "127.0.0.1"
        {
            IngressIntent::ConfiguredUnverified
        } else {
            IngressIntent::LoopbackOnly
        },
        legacy_source: Some(binding),
    };
    let planned = plan::plan_deployment(&intent).map_err(invalid)?;
    let roles = Roles {
        gateway: match planned.roles.gateway {
            GatewayRole::Local => "local",
            GatewayRole::External => "external",
        },
        host: match planned.roles.host {
            HostRole::Local => "local",
            HostRole::Disabled => "disabled",
        },
        exec: capability_intent(planned.roles.exec),
        computer: capability_intent(planned.roles.computer),
        browser: capability_intent(planned.roles.browser),
        device_ingress: match planned.roles.device_ingress {
            IngressIntent::NotHosted => "not_hosted",
            IngressIntent::LoopbackOnly => "loopback_only",
            IngressIntent::ConfiguredUnverified => "configured_unverified",
        },
        readiness: "not_inferred",
    };
    let review_plan = planned
        .steps
        .iter()
        .map(|s| ReviewStep {
            component: component_name(s.id.component),
            action: action_name(s.id.action),
            requires: s
                .requires
                .iter()
                .map(|id| {
                    format!(
                        "{}.{}",
                        component_name(id.component),
                        action_name(id.action)
                    )
                })
                .collect(),
            authorization_required: s.authorization_required,
        })
        .collect();
    let needs_explicit_decision = planned
        .needs_explicit_decision
        .into_iter()
        .map(component_name)
        .collect();
    let inspection = ManagementInspection {
        schema: 1,
        source_contract: "legacy_js_v1_read_only_projection",
        validation_scope: "known_fields_only_not_execution_or_identity_authority",
        source: SourceBinding {
            deployment_schema: 1,
            deployment_sha256: Sha256Digest::of_bytes(deployment.bytes()),
            state_schema: 1,
            state_sha256: Sha256Digest::of_bytes(state.bytes()),
            consistency: "per_file_stable_not_transactional",
        },
        mode: d.mode,
        roles,
        steps,
        review_plan,
        needs_explicit_decision,
        background_choice: background,
        background_configuration_bound: bound,
        app_login: AppLoginInspection {
            desired_enabled: login.as_ref().map(|x| x.desired_enabled),
            last_recorded_operation: login.map(|x| x.last_operation.status),
            registration_observed: "not_observed",
        },
        host_manager: if host.is_some() {
            "unspecified"
        } else {
            "disabled"
        },
        gateway_manager: if local { "unspecified" } else { "external" },
        host_desired_run: if host.is_some() {
            "unspecified"
        } else {
            "disabled"
        },
        gateway_desired_run: if local { "unspecified" } else { "external" },
        management_guards: guards(&root)?,
        plan_execution: "not_authorized_read_only",
        runtime_health: "not_observed",
        account_acceptance: "NOT RUN",
    };
    Ok(Loaded {
        root,
        deployment,
        state,
        inspection,
    })
}
impl Loaded {
    fn finish(self) -> Result<ManagementInspection> {
        for original in [&self.deployment, &self.state] {
            let current = self.root.read_raw(original.relative_path(), FILE_LIMIT)?;
            if original.sha256() != current.sha256()
                || original.observation() != current.observation()
            {
                return Err(ManagementError::Changed);
            }
        }
        if guards(&self.root)? != self.inspection.management_guards {
            return Err(ManagementError::Changed);
        }
        Ok(self.inspection)
    }
}
pub async fn inspect_deployment(state_dir: &Path) -> Result<ManagementInspection> {
    let permit = READERS.try_acquire().map_err(|_| ManagementError::Busy)?;
    let path = state_dir.to_owned();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        load(&path)?.finish()
    })
    .await
    .map_err(|_| ManagementError::ReaderFailed)?
}

#[cfg(test)]
mod tests;

//! Deterministic review plan, not an execution journal or a trusted authorization.
//! Runtime checks original bytes, single configuration writer and unresolved
//! transactions before executing. No plan step fabricates OS health/success.
use super::deployment::*;
use styx_contracts::error::ErrorCategory;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Component {
    Gateway,
    Host,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanAction {
    ReviewOriginalBindings,
    ReviewExistingOwnership,
    PrepareRuntime,
    PrepareConfiguration,
    ConfigureManager,
    InstallPersistentService,
    SetAutostart,
    PersistDesiredState,
    StartOwnedRuntime,
    VerifyRunning,
    PrepareIngress,
    VerifyIngress,
    PairLocal,
    CreateInvitation,
    RequestApproval,
    ClaimCredential,
    ValidatePreservedPairing,
    FenceNewWork,
    ObserveOwnedWork,
    StopOwnedRuntime,
    VerifyStopped,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StepId {
    pub component: Component,
    pub action: PlanAction,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    pub id: StepId,
    pub requires: Vec<StepId>,
    /// A review requirement, never a credential or proof of user consent.
    pub authorization_required: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentPlan {
    pub schema: u32,
    pub intent: DeploymentIntent,
    pub roles: DeploymentRoles,
    pub steps: Vec<PlannedStep>,
    /// These are unresolved user choices, not defaults inferred from old steps
    /// or App login preferences. Their components have only read-only review.
    pub needs_explicit_decision: Vec<Component>,
    /// No conversion of configured/prepared into Ready/Healthy is possible.
    pub health: Readiness,
}
fn push(steps: &mut Vec<PlannedStep>, component: Component, action: PlanAction) {
    let authorization_required = !matches!(
        action,
        PlanAction::ReviewOriginalBindings
            | PlanAction::ReviewExistingOwnership
            | PlanAction::ObserveOwnedWork
            | PlanAction::VerifyRunning
            | PlanAction::VerifyStopped
            | PlanAction::VerifyIngress
            | PlanAction::ValidatePreservedPairing
    );
    // A bounded linear topological order deliberately records all previous
    // dependencies, matching review intent without parallel mutation hazards.
    let requires = steps.iter().map(|s| s.id).collect();
    steps.push(PlannedStep {
        id: StepId { component, action },
        requires,
        authorization_required,
    });
}
fn manager(steps: &mut Vec<PlannedStep>, component: Component, intent: ComponentIntent) {
    push(steps, component, PlanAction::ConfigureManager);
    if intent.manager == ManagerMode::PersistentService {
        push(steps, component, PlanAction::InstallPersistentService);
    }
    push(steps, component, PlanAction::SetAutostart);
}
fn stop(steps: &mut Vec<PlannedStep>, component: Component) {
    push(steps, component, PlanAction::FenceNewWork);
    push(steps, component, PlanAction::ObserveOwnedWork);
    // Durably establish stopped intent before changing manager settings or
    // requesting physical stop. An enabled autostart preference is not --now.
    push(steps, component, PlanAction::PersistDesiredState);
    push(steps, component, PlanAction::ConfigureManager);
    push(steps, component, PlanAction::SetAutostart);
    // Never install a service or mint a credential in a stopped-only plan.
    push(steps, component, PlanAction::StopOwnedRuntime);
    push(steps, component, PlanAction::VerifyStopped);
}
/// Pure rendering of explicitly supplied desired state. In particular this does
/// not infer a default manager, auto-pair imported devices, create tunnels or
/// plugins for a joined Host, acquire locks, or authorize execution.
pub fn plan_deployment(intent: &DeploymentIntent) -> Result<DeploymentPlan, ErrorCategory> {
    let roles = intent.roles()?;
    let mut steps = Vec::new();
    let mut needs_explicit_decision = Vec::new();
    if let Some(gateway) = intent.gateway {
        push(
            &mut steps,
            Component::Gateway,
            PlanAction::ReviewOriginalBindings,
        );
        if !gateway.is_explicit() {
            push(
                &mut steps,
                Component::Gateway,
                PlanAction::ReviewExistingOwnership,
            );
            needs_explicit_decision.push(Component::Gateway);
        } else if gateway.run == RunDesired::Stopped {
            stop(&mut steps, Component::Gateway);
        } else {
            push(&mut steps, Component::Gateway, PlanAction::PrepareRuntime);
            push(
                &mut steps,
                Component::Gateway,
                PlanAction::PrepareConfiguration,
            );
            manager(&mut steps, Component::Gateway, gateway);
            push(
                &mut steps,
                Component::Gateway,
                PlanAction::PersistDesiredState,
            );
            push(
                &mut steps,
                Component::Gateway,
                PlanAction::StartOwnedRuntime,
            );
            push(&mut steps, Component::Gateway, PlanAction::VerifyRunning);
            if intent.device_ingress == IngressIntent::ConfiguredUnverified {
                push(&mut steps, Component::Gateway, PlanAction::PrepareIngress);
                push(&mut steps, Component::Gateway, PlanAction::VerifyIngress);
            }
        }
    }
    if let Some(host) = intent.host {
        push(
            &mut steps,
            Component::Host,
            PlanAction::ReviewOriginalBindings,
        );
        let unresolved_pairing = host.component.run == RunDesired::Running
            && (intent.pairing == PairingIntent::Unspecified
                || (matches!(
                    intent.pairing,
                    PairingIntent::OwnerLocal | PairingIntent::ManualLocal
                ) && !intent
                    .gateway
                    .is_some_and(|g| g.is_explicit() && g.run == RunDesired::Running)));
        if !host.component.is_explicit() || unresolved_pairing {
            push(
                &mut steps,
                Component::Host,
                PlanAction::ReviewExistingOwnership,
            );
            needs_explicit_decision.push(Component::Host);
        } else if host.component.run == RunDesired::Stopped {
            stop(&mut steps, Component::Host);
        } else {
            push(&mut steps, Component::Host, PlanAction::PrepareRuntime);
            push(
                &mut steps,
                Component::Host,
                PlanAction::PrepareConfiguration,
            );
            match intent.pairing {
                PairingIntent::OwnerLocal => {
                    push(&mut steps, Component::Host, PlanAction::PairLocal)
                }
                PairingIntent::ManualLocal => {
                    push(&mut steps, Component::Host, PlanAction::CreateInvitation);
                    push(&mut steps, Component::Host, PlanAction::RequestApproval);
                    push(&mut steps, Component::Host, PlanAction::ClaimCredential);
                }
                PairingIntent::ExternalOwner => {
                    push(&mut steps, Component::Host, PlanAction::RequestApproval);
                    push(&mut steps, Component::Host, PlanAction::ClaimCredential);
                }
                PairingIntent::PreserveExisting => push(
                    &mut steps,
                    Component::Host,
                    PlanAction::ValidatePreservedPairing,
                ),
                PairingIntent::None | PairingIntent::Unspecified => {
                    return Err(ErrorCategory::InvalidRequest);
                }
            }
            manager(&mut steps, Component::Host, host.component);
            push(&mut steps, Component::Host, PlanAction::PersistDesiredState);
            push(&mut steps, Component::Host, PlanAction::StartOwnedRuntime);
            push(&mut steps, Component::Host, PlanAction::VerifyRunning);
        }
    }
    Ok(DeploymentPlan {
        schema: 1,
        intent: intent.clone(),
        roles,
        steps,
        needs_explicit_decision,
        health: Readiness::NotObserved,
    })
}

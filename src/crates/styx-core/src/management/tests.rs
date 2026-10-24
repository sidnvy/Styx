//! Domain scenarios only: raw hashes are bindings, never a filesystem import,
//! observed OS health, native service acceptance or authorized mutation proof.
use super::{deployment::*, plan::*};
use styx_contracts::{error::ErrorCategory, identity::Sha256Digest};

fn foreground() -> ComponentIntent {
    ComponentIntent {
        manager: ManagerMode::ForegroundCli,
        run: RunDesired::Running,
        autostart: AutostartDesired::Disabled,
    }
}
fn joined() -> DeploymentIntent {
    DeploymentIntent {
        mode: DeploymentMode::JoinExisting,
        gateway: None,
        host: Some(HostIntent {
            component: foreground(),
            computer_requested: false,
            browser_requested: true,
        }),
        pairing: PairingIntent::ExternalOwner,
        device_ingress: IngressIntent::NotHosted,
        legacy_source: None,
    }
}
fn actions(plan: &DeploymentPlan, component: Component) -> Vec<PlanAction> {
    plan.steps
        .iter()
        .filter(|s| s.id.component == component)
        .map(|s| s.id.action)
        .collect()
}

#[test]
fn join_is_host_only_and_configuration_never_proves_runtime_or_permission_health() {
    let intent = joined();
    let plan = plan_deployment(&intent).unwrap();
    assert_eq!(plan, plan_deployment(&intent).unwrap());
    assert_eq!(plan.roles.gateway, GatewayRole::External);
    assert_eq!(plan.roles.host, HostRole::Local);
    assert_eq!(plan.roles.browser, CapabilityIntent::Requested);
    assert_eq!(plan.roles.computer, CapabilityIntent::Disabled);
    assert_eq!(plan.health, Readiness::NotObserved);
    assert_eq!(plan.roles.readiness, Readiness::NotObserved);
    assert!(plan.steps.iter().all(|s| s.id.component == Component::Host));
    assert!(!actions(&plan, Component::Host).iter().any(|a| matches!(
        a,
        PlanAction::CreateInvitation
            | PlanAction::PairLocal
            | PlanAction::PrepareIngress
            | PlanAction::InstallPersistentService
    )));
    assert_eq!(
        plan.intent.host.unwrap().component.manager,
        ManagerMode::ForegroundCli
    );
    // Every dependency is an earlier distinct step. A plan is not itself a
    // dispatch capability, and no step carries a successful execution result.
    let mut seen = std::collections::BTreeSet::new();
    for step in &plan.steps {
        assert!(step.requires.iter().all(|r| seen.contains(r)));
        assert!(seen.insert(step.id));
    }
    for mutate in [
        |x: &mut DeploymentIntent| x.gateway = Some(foreground()),
        |x: &mut DeploymentIntent| x.device_ingress = IngressIntent::ConfiguredUnverified,
        |x: &mut DeploymentIntent| x.pairing = PairingIntent::OwnerLocal,
        |x: &mut DeploymentIntent| x.host = None,
    ] {
        let mut invalid = intent.clone();
        mutate(&mut invalid);
        assert!(matches!(
            plan_deployment(&invalid),
            Err(ErrorCategory::InvalidRequest)
        ));
    }
    let mut local = intent;
    local.mode = DeploymentMode::CreateLocal;
    local.gateway = Some(foreground());
    local.device_ingress = IngressIntent::LoopbackOnly;
    local.host = None;
    local.pairing = PairingIntent::None;
    let gateway_only = plan_deployment(&local).unwrap();
    assert_eq!(gateway_only.roles.host, HostRole::Disabled);
    assert_eq!(gateway_only.roles.exec, CapabilityIntent::Disabled);
    assert!(
        gateway_only
            .steps
            .iter()
            .all(|s| s.id.component == Component::Gateway)
    );
    assert_eq!(gateway_only.health, Readiness::NotObserved);
}

#[test]
fn explicit_manager_and_desired_stop_survive_planning_without_implicit_promotion_or_restart() {
    for manager in [
        ManagerMode::ForegroundCli,
        ManagerMode::AppManaged,
        ManagerMode::PersistentService,
    ] {
        let mut intent = joined();
        intent.pairing = PairingIntent::PreserveExisting;
        intent.host.as_mut().unwrap().component.manager = manager;
        let plan = plan_deployment(&intent).unwrap();
        assert_eq!(plan.intent.host.unwrap().component.manager, manager);
        assert_eq!(
            actions(&plan, Component::Host).contains(&PlanAction::InstallPersistentService),
            manager == ManagerMode::PersistentService
        );
        assert!(!actions(&plan, Component::Host).iter().any(|a| matches!(
            a,
            PlanAction::RequestApproval | PlanAction::ClaimCredential | PlanAction::PairLocal
        )));
        intent.host.as_mut().unwrap().component.run = RunDesired::Stopped;
        let stopped = plan_deployment(&intent).unwrap();
        let actions = actions(&stopped, Component::Host);
        assert!(!actions.iter().any(|a| matches!(
            a,
            PlanAction::StartOwnedRuntime
                | PlanAction::InstallPersistentService
                | PlanAction::PrepareRuntime
                | PlanAction::ClaimCredential
        )));
        let pos = |action| actions.iter().position(|a| *a == action).unwrap();
        assert!(pos(PlanAction::FenceNewWork) < pos(PlanAction::PersistDesiredState));
        assert!(pos(PlanAction::PersistDesiredState) < pos(PlanAction::StopOwnedRuntime));
        assert!(pos(PlanAction::StopOwnedRuntime) < pos(PlanAction::VerifyStopped));
        assert_eq!(
            stopped.intent.host.unwrap().component.run,
            RunDesired::Stopped
        );
    }
    let mut intent = joined();
    let c = &mut intent.host.as_mut().unwrap().component;
    c.manager = ManagerMode::PersistentService;
    c.run = RunDesired::Stopped;
    c.autostart = AutostartDesired::Enabled;
    let stopped = plan_deployment(&intent).unwrap();
    assert!(actions(&stopped, Component::Host).contains(&PlanAction::SetAutostart));
    assert!(!actions(&stopped, Component::Host).contains(&PlanAction::StartOwnedRuntime));
    intent.host.as_mut().unwrap().component.run = RunDesired::Running;
    intent.host.as_mut().unwrap().component.autostart = AutostartDesired::Disabled;
    let running = plan_deployment(&intent).unwrap();
    assert!(actions(&running, Component::Host).contains(&PlanAction::StartOwnedRuntime));
    assert!(!actions(&running, Component::Host).contains(&PlanAction::StopOwnedRuntime));
    intent.host.as_mut().unwrap().component.manager = ManagerMode::ForegroundCli;
    intent.host.as_mut().unwrap().component.autostart = AutostartDesired::Enabled;
    assert!(matches!(
        plan_deployment(&intent),
        Err(ErrorCategory::InvalidRequest)
    ));
}

#[test]
fn unspecified_legacy_preferences_are_review_only_and_never_become_service_desired_state() {
    for component in [
        ComponentIntent {
            manager: ManagerMode::Unspecified,
            ..foreground()
        },
        ComponentIntent {
            run: RunDesired::Unspecified,
            ..foreground()
        },
        ComponentIntent {
            autostart: AutostartDesired::Unspecified,
            ..foreground()
        },
        ComponentIntent {
            manager: ManagerMode::Unspecified,
            run: RunDesired::Unspecified,
            autostart: AutostartDesired::Unspecified,
        },
    ] {
        let mut intent = joined();
        intent.host.as_mut().unwrap().component = component;
        let plan = plan_deployment(&intent).unwrap();
        assert_eq!(plan.needs_explicit_decision, vec![Component::Host]);
        assert!(plan.steps.iter().all(|s| !s.authorization_required));
        assert_eq!(
            actions(&plan, Component::Host),
            vec![
                PlanAction::ReviewOriginalBindings,
                PlanAction::ReviewExistingOwnership
            ]
        );
        assert_eq!(plan.intent.host.unwrap().component, component);
    }
    let mut intent = joined();
    intent.pairing = PairingIntent::Unspecified;
    let plan = plan_deployment(&intent).unwrap();
    assert_eq!(plan.needs_explicit_decision, vec![Component::Host]);
    assert!(plan.steps.iter().all(|s| !s.authorization_required));
    // Local pairing must not be planned against a Gateway whose ownership or
    // manager choice is unresolved, even though a Host's own fields are explicit.
    intent.mode = DeploymentMode::CreateLocal;
    intent.device_ingress = IngressIntent::LoopbackOnly;
    intent.pairing = PairingIntent::OwnerLocal;
    intent.gateway = Some(ComponentIntent {
        manager: ManagerMode::Unspecified,
        ..foreground()
    });
    let plan = plan_deployment(&intent).unwrap();
    assert_eq!(
        plan.needs_explicit_decision,
        vec![Component::Gateway, Component::Host]
    );
    assert!(plan.steps.iter().all(|s| !s.authorization_required));
    intent.gateway = Some(ComponentIntent {
        run: RunDesired::Stopped,
        ..foreground()
    });
    assert!(matches!(
        plan_deployment(&intent),
        Err(ErrorCategory::StateConflict)
    ));
}

#[test]
fn both_raw_file_bindings_cover_legacy_unknown_fields_and_lossless_integer_bytes() {
    // Illustrative RawFile inputs remain external to this Core. We deliberately
    // do not parse JSON into floats or normalize/re-emit unknown preferences.
    let deployment =
        br#"{ "schema":1,"mode":"join-existing","unknown":{"large":18446744073709551617} }"#;
    let state=br#"{"schema":1,"configSha256":"opaque","unknown":9007199254740993,"appPreferences":{"loginAtStartup":{"desiredEnabled":true}}}"#;
    let original_deployment = deployment.to_vec();
    let original_state = state.to_vec();
    let binding = LegacySourceBinding {
        deployment_schema: 1,
        deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
        state_schema: 1,
        state_raw_sha256: Sha256Digest::of_bytes(state),
    };
    let mut intent = joined();
    intent.legacy_source = Some(binding);
    intent.pairing = PairingIntent::PreserveExisting;
    intent.host.as_mut().unwrap().component = ComponentIntent {
        manager: ManagerMode::Unspecified,
        run: RunDesired::Unspecified,
        autostart: AutostartDesired::Unspecified,
    };
    let first = plan_deployment(&intent).unwrap();
    assert_eq!(first.intent.legacy_source, Some(binding));
    assert_eq!(first.needs_explicit_decision, vec![Component::Host]);
    assert_eq!(deployment.as_slice(), original_deployment.as_slice());
    assert_eq!(state.as_slice(), original_state.as_slice());
    let changed = LegacySourceBinding {
        state_raw_sha256: Sha256Digest::of_bytes(
            b"same configuration, changed original state bytes",
        ),
        ..binding
    };
    intent.legacy_source = Some(changed);
    assert_ne!(first, plan_deployment(&intent).unwrap());
    intent.legacy_source = Some(LegacySourceBinding {
        deployment_schema: 2,
        ..binding
    });
    assert!(matches!(
        plan_deployment(&intent),
        Err(ErrorCategory::CapabilityUnsupported)
    ));
    intent.legacy_source = Some(LegacySourceBinding {
        state_schema: 2,
        ..binding
    });
    assert!(matches!(
        plan_deployment(&intent),
        Err(ErrorCategory::CapabilityUnsupported)
    ));
}

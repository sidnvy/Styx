//! DTO boundary checks only. Real paired owner authority/effects must be covered
//! by the Gateway HTTP -> paired WSS -> native executor integration journey.
use super::*;

#[test]
fn paired_wire_preserves_v2_bytes_and_typed_v3_contract() {
    // These exact original v2 fields/order remain unchanged; v3-only revision
    // must not appear (even as null) in an old negotiation response.
    let v2 = Reply::Negotiated {
        version: 2,
        challenge: "fixture-side-effect-free-challenge".into(),
        device_id: "owned-protocol-device".try_into().unwrap(),
        host_generation: "protocol-host-generation".try_into().unwrap(),
        connection_generation: "connection-a".try_into().unwrap(),
        features: vec!["prepare_start".into(), "read".into()],
        write: true,
        terminate: true,
        read_resume: false,
        owner_issuance: "bootstrap_preverified_only".into(),
        grant_revision: None,
    };
    let bytes = serde_json::to_string(&v2).unwrap();
    assert_eq!(
        bytes,
        r#"{"status":"negotiated","version":2,"challenge":"fixture-side-effect-free-challenge","device_id":"owned-protocol-device","host_generation":"protocol-host-generation","connection_generation":"connection-a","features":["prepare_start","read"],"write":true,"terminate":true,"read_resume":false,"owner_issuance":"bootstrap_preverified_only"}"#
    );
    assert!(matches!(
        serde_json::from_str::<Reply>(&bytes).unwrap(),
        Reply::Negotiated {
            grant_revision: None,
            ..
        }
    ));

    let request = r#"{"request_id":"request-a","connection_generation":"connection-a","call":{"owner_open":{"owner":{"owner_id":"mcp-session:owned-a","owner_epoch":"owner-epoch-a"},"grant_revision":7}}}"#;
    let parsed: Request = serde_json::from_str(request).unwrap();
    assert!(matches!(
        &parsed.call,
        Call::OwnerOpen {
            grant_revision: 7,
            ..
        }
    ));
    assert_eq!(serde_json::to_string(&parsed).unwrap(), request);
    let forged = request.replace(
        "\"owner_epoch\":\"owner-epoch-a\"",
        "\"owner_epoch\":\"owner-epoch-a\",\"admin\":true",
    );
    assert!(serde_json::from_str::<Request>(&forged).is_err());
    let unknown = request.replace(
        "\"grant_revision\":7",
        "\"grant_revision\":7,\"skip_auth\":true",
    );
    assert!(serde_json::from_str::<Request>(&unknown).is_err());

    let reply = Reply::OwnerRevoked {
        owner: OwnerRef {
            owner_id: "mcp-session:owned-a".try_into().unwrap(),
            owner_epoch: "owner-epoch-a".try_into().unwrap(),
        },
        fenced: true,
        cleanup: "unknown".into(),
    };
    let bytes = serde_json::to_vec(&reply).unwrap();
    assert!(
        matches!(serde_json::from_slice::<Reply>(&bytes).unwrap(), Reply::OwnerRevoked { fenced: true, cleanup, .. } if cleanup == "unknown")
    );
    // Revoke acknowledgement intentionally contains no synthetic process exit.
    assert!(!String::from_utf8(bytes).unwrap().contains("exit"));
}

#[tokio::test]
async fn actual_host_registry_turnover_compacts_only_complete_and_rejects_old_actions() {
    let (host, device, generation) = registry_host();
    let protocol = host
        .paired_protocol(PairedTrustedProfile {
            endpoint: "wss://localhost/owner-turnover".into(),
            gateway_namespace: "owner-turnover-gateway".try_into().unwrap(),
            device_id: device,
            host_generation: generation,
        })
        .unwrap();
    let epoch: GatewayEpoch = "owner-turnover-process".try_into().unwrap();
    protocol.accept_epoch(&epoch).unwrap();
    let owner = |n| OwnerRef {
        owner_id: format!("fixture:owner-{n}").try_into().unwrap(),
        owner_epoch: paired_owner_epoch(&epoch, n),
    };
    for n in 1..=1100 {
        let reference = owner(n);
        assert!(
            matches!(
                protocol.control(&Call::OwnerOpen {
                    owner: reference.clone(),
                    grant_revision: 1
                }),
                Some(Reply::OwnerOpened { .. })
            ),
            "OwnerOpen {n}"
        );
        assert!(matches!(
            protocol.control(&Call::OwnerRevoke {
                owner: reference.clone()
            }),
            Some(Reply::OwnerRevoked { fenced: true, .. })
        ));
        assert!(protocol.owner(&reference).is_err());
        assert!(matches!(
            protocol
                .handle(Call::OwnerCleanup {
                    owner: reference,
                    timeout_ms: 5000
                })
                .await,
            Reply::OwnerCleanup { complete: true, .. }
        ));
        assert!(
            protocol.owners.lock().unwrap().owners.is_empty(),
            "old 128 lifetime cap must not accumulate"
        );
    }
    assert!(matches!(
        protocol.control(&Call::OwnerOpen {
            owner: owner(1),
            grant_revision: 1
        }),
        Some(Reply::Error {
            category: ErrorCategory::Unauthorized,
            ..
        })
    ));
    assert!(protocol.owner(&owner(1)).is_err());
    // No new epoch can revive the old key, and the retired epoch is refused.
    protocol
        .accept_epoch(&"owner-turnover-next-process".try_into().unwrap())
        .unwrap();
    assert!(protocol.accept_epoch(&epoch).is_err());
    assert!(matches!(
        protocol.control(&Call::OwnerOpen {
            owner: owner(1),
            grant_revision: 1
        }),
        Some(Reply::Error {
            category: ErrorCategory::Unauthorized,
            ..
        })
    ));
    host.shutdown_owned(Duration::from_secs(5)).await.unwrap();
}

fn registry_host() -> (
    crate::host::bootstrap::OwnedExecHost,
    DeviceId,
    HostGeneration,
) {
    use styx_contracts::{capability::*, error::Recovery};
    use styx_core::policy::AdmissionFacts;
    let device: DeviceId = "owner-turnover-device".try_into().unwrap();
    let generation: HostGeneration = "owner-turnover-host".try_into().unwrap();
    let host = crate::host::bootstrap::OwnedExecHost::reserve(
        generation.clone(),
        AdmissionFacts {
            device_id: device.clone(),
            grant_revision: 1,
            local_policy_allowed: true,
            descriptor: CapabilityDescriptor {
                contract_version: 1,
                capability_id: CapabilityId::ExecRun,
                scope: Scope::Host,
                provider_id: "codex".try_into().unwrap(),
                configured: true,
                remote_grant: true,
                availability: Availability::Available,
                authorization: Authorization::Granted,
                target_session: None,
                reason: None,
                observed_at: 1,
                observation_generation: 1,
                recovery: Recovery::None,
            },
            session_state: None,
            current_observation: None,
        },
        4,
    )
    .unwrap()
    .without_executor()
    .unwrap();
    (host, device, generation)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tokio::test]
async fn unknown_cleanup_retains_profile_record_until_inflight_preparation_and_release_join() {
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct Profiles {
        entered: tokio::sync::Notify,
        gate: (Mutex<bool>, Condvar),
        released: AtomicUsize,
    }
    impl browser::BrowserBootstrap for Profiles {
        fn prepare_profile(
            &self,
            _: &OwnerLease,
        ) -> Result<crate::providers::browser::OwnedBrowserConfig, ErrorCategory> {
            self.entered.notify_one();
            let (lock, wake) = &self.gate;
            let mut done = lock.lock().unwrap();
            while !*done {
                done = wake.wait(done).unwrap();
            }
            Err(ErrorCategory::IntegrityFailure) // original preparation never dispatches
        }
        fn validate_control(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
        fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
        fn release_profile(&self, _: &OwnerLease) {
            self.released.fetch_add(1, Ordering::Relaxed);
        }
    }
    let (host, device, generation) = registry_host();
    let facts = styx_core::policy::AdmissionFacts {
        device_id: device.clone(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: styx_contracts::capability::CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::BrowserHeadless,
            scope: styx_contracts::capability::Scope::Browser,
            provider_id: "owned-browser".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: styx_contracts::capability::Availability::Available,
            authorization: styx_contracts::capability::Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 1,
            observation_generation: 1,
            recovery: styx_contracts::error::Recovery::None,
        },
        session_state: None,
        current_observation: None,
    };
    host.authority()
        .configure_browser(facts.clone(), host.reserve_browser_io().unwrap())
        .unwrap();
    let source = Arc::new(Profiles {
        entered: tokio::sync::Notify::new(),
        gate: (Mutex::new(false), Condvar::new()),
        released: AtomicUsize::new(0),
    });
    let protocol = host
        .paired_protocol(PairedTrustedProfile {
            endpoint: "wss://localhost/profile-release".into(),
            gateway_namespace: "profile-release".try_into().unwrap(),
            device_id: device,
            host_generation: generation,
        })
        .unwrap()
        .with_browser_profiles(source.clone())
        .unwrap();
    let epoch = "profile-release-epoch".try_into().unwrap();
    protocol.accept_epoch(&epoch).unwrap();
    let owner = OwnerRef {
        owner_id: "fixture:profile".try_into().unwrap(),
        owner_epoch: paired_owner_epoch(&epoch, 1),
    };
    assert!(matches!(
        protocol.control(&Call::OwnerOpen {
            owner: owner.clone(),
            grant_revision: 1
        }),
        Some(Reply::OwnerOpened { .. })
    ));
    let prepare = protocol.handle(Call::Browser {
        owner: owner.clone(),
        grant_revision: 1,
        timeout_ms: 1000,
        command: BrowserCommand::PrepareOpen,
    });
    tokio::pin!(prepare);
    let wait = async {
        source.entered.notified().await;
    };
    tokio::pin!(wait);
    tokio::select! { _=&mut wait=>{}, _=&mut prepare=>panic!("preparation must remain in flight") }
    protocol
        .control(&Call::OwnerRevoke {
            owner: owner.clone(),
        })
        .unwrap();
    let first = protocol
        .handle(Call::OwnerCleanup {
            owner: owner.clone(),
            timeout_ms: 20,
        })
        .await;
    assert!(matches!(
        first,
        Reply::OwnerCleanup {
            complete: false,
            ..
        }
    ));
    assert_eq!(source.released.load(Ordering::Relaxed), 0);
    assert_eq!(protocol.owners.lock().unwrap().owners.len(), 1);
    *source.gate.0.lock().unwrap() = true;
    source.gate.1.notify_all();
    prepare.await;
    assert!(matches!(
        protocol
            .handle(Call::OwnerCleanup {
                owner: owner.clone(),
                timeout_ms: 5000
            })
            .await,
        Reply::OwnerCleanup { complete: true, .. }
    ));
    assert_eq!(source.released.load(Ordering::Relaxed), 1);
    assert!(protocol.owners.lock().unwrap().owners.is_empty());
    assert!(protocol.owner(&owner).is_err());
    host.shutdown_owned(Duration::from_secs(5)).await.unwrap();
}

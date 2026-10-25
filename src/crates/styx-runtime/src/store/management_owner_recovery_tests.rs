//! Contract checks for the Windows/legacy-JS time boundary. Synthetic raw
//! timestamps only: these are not Windows boot or process-settlement evidence.
use super::*;

fn windows_stamp(seconds: i64, nanos: i64) -> NativeRetirementFileStamp {
    NativeRetirementFileStamp::Windows {
        volume_serial: 12,
        file_id: 34,
        owner_sid: "S-1-5-21-1234".into(),
        nlink: 1,
        byte_len: 4,
        modified_seconds: seconds,
        modified_nanoseconds: nanos,
        changed_seconds: seconds,
        changed_nanoseconds: nanos,
        sha256: Sha256Digest::of_bytes(b"lock"),
    }
}

#[test]
fn windows_raw_epoch_matches_original_unix_plan_without_rewriting_stamp() {
    // 2000-01-01T00:00:00.1234567Z: two independently specified epochs.
    let stamp = windows_stamp(12_591_158_400, 123_456_700);
    let before = serde_json::to_vec(&stamp).unwrap();
    let hash = Sha256Digest::of_bytes(b"synthetic-authorized-material");
    let device: styx_contracts::identity::DeviceId =
        "styx-1234567890abcdef12345678".try_into().unwrap();
    let mut plan = serde_json::json!({
        "schema": 1,
        "action": "retire_legacy_foreground_owner",
        "stateDir": std::env::temp_dir(),
        "deviceId": device,
        "identitySha256": hash,
        "configurationHash": hash,
        "currentBoot": {"platform":"win32", "id":"synthetic-boot", "startedAt":946_684_801_000_u64},
        "previousOwnerPid": 42,
        "files": [{"name":"foreground.lock", "ino":"34", "dev":"12", "sha256":stamp.content_sha256(), "modifiedAt":946_684_800_123_u64}],
        "previousWorkOutcome":"unknown_not_replayed",
        "identityMutation":"none",
        "requiresExplicitAuthorization":true
    });
    let mut intent = LegacyOwnerRecoveryIntent {
        schema: 2,
        kind: RecoveryKind::LegacyOwnerRecovery,
        transaction_id: "epoch-boundary".try_into().unwrap(),
        sequence: 1,
        config_root: styx_contracts::native_management::NativeRootIdentity::Windows {
            volume_serial: 12,
            file_id: 56,
            owner_sid: "S-1-5-21-1234".into(),
        },
        deployment_raw_sha256: hash,
        before_state_sha256: hash,
        candidate_manifest_sha256: hash,
        publisher_spki_sha256: hash,
        previous_boot: None,
        current_boot: RecoveryBoot {
            id: "synthetic-boot".into(),
            started_at_ms: 946_684_801_000,
        },
        basis: None,
        restart: RecoveryRestartBinding::ForegroundOnlyNoInstalledManager,
        successor_retirement_intent_sha256: hash,
        originals: vec![RecoveryOriginalBinding {
            name: RecoveryOriginalName::Lock,
            stamp,
        }],
        guards: vec![],
        startup_checkpoint: None,
    };
    let bind = |intent: &mut LegacyOwnerRecoveryIntent, plan: &serde_json::Value| {
        let raw = serde_json::to_vec(plan).unwrap();
        intent.basis = Some(RecoveryBasis::ExplicitLegacyMaintenance {
            plan_sha256: Sha256Digest::of_bytes(&raw),
            device_id: device.clone(),
            identity_json_sha256: hash,
            configuration_hash: hash,
            observer_pid: 42,
        });
        raw
    };
    let raw = bind(&mut intent, &plan);
    validate_authorization_plan(&intent, Some(&raw)).unwrap();
    assert_eq!(
        serde_json::to_vec(&intent.originals[0].stamp).unwrap(),
        before
    );

    // A native FILETIME value cannot masquerade as Node's Unix milliseconds.
    plan["files"][0]["modifiedAt"] = serde_json::json!(12_591_158_400_123_u64);
    let raw = bind(&mut intent, &plan);
    assert!(validate_authorization_plan(&intent, Some(&raw)).is_err());
    // A file at/after the authorized boot still fails after correct conversion.
    plan["files"][0]["modifiedAt"] = serde_json::json!(946_684_800_123_u64);
    plan["currentBoot"]["startedAt"] = serde_json::json!(946_684_800_000_u64);
    intent.current_boot.started_at_ms = 946_684_800_000;
    let raw = bind(&mut intent, &plan);
    assert!(validate_authorization_plan(&intent, Some(&raw)).is_err());
}

#[test]
fn windows_epoch_projection_keeps_subseconds_and_refuses_invalid_raw_time() {
    assert_eq!(
        file_tuple(&windows_stamp(11_644_473_600, 0)).unwrap(),
        (12, 34, 0, 0)
    );
    assert_eq!(
        file_tuple(&windows_stamp(0, 100)).unwrap(),
        (12, 34, -11_644_473_600, 100)
    );
    assert!(file_tuple(&windows_stamp(-1, 0)).is_err());
    assert!(file_tuple(&windows_stamp(i64::MIN, 0)).is_err());
    assert!(file_tuple(&windows_stamp(11_644_473_600, -1)).is_err());
    assert!(file_tuple(&windows_stamp(11_644_473_600, 1_000_000_000)).is_err());
}

struct StartupFixture {
    intent: LegacyOwnerRecoveryIntent,
    entries: Vec<(String, Vec<u8>)>,
    phases: Vec<(String, Vec<u8>)>,
}
fn observation(entries: &[(String, Vec<u8>)]) -> JournalObservation {
    JournalObservation {
        total_bytes: entries.iter().map(|(_, b)| b.len()).sum(),
        files: entries
            .iter()
            .map(
                |(name, bytes)| crate::store::secure_journal::ObservedJournalFile {
                    name: name.clone(),
                    bytes: bytes.clone(),
                },
            )
            .collect(),
    }
}
fn bound_stamp(bytes: &[u8], id: u64) -> NativeRetirementFileStamp {
    let mut stamp = windows_stamp(13_437_223_590, 0); // Unix 1792749990, before test boot.
    if let NativeRetirementFileStamp::Windows {
        file_id,
        byte_len,
        sha256,
        ..
    } = &mut stamp
    {
        *file_id = id;
        *byte_len = bytes.len() as u64;
        *sha256 = Sha256Digest::of_bytes(bytes);
    }
    stamp
}
impl StartupFixture {
    fn new() -> Self {
        let hash = Sha256Digest::of_bytes(b"synthetic-package-and-policy");
        let id: TransactionId = "original-startup-checkpoint".try_into().unwrap();
        let device: styx_contracts::identity::DeviceId =
            "styx-1234567890abcdef12345678".try_into().unwrap();
        let boot = RecoveryBoot {
            id: "wmi-lastboot-unix-micros:1792750000000000".into(),
            started_at_ms: 1_792_750_000_000,
        };
        let link = b"synthetic-shortcut-bytes-not-a-Windows-Shell-fixture";
        let checkpoint = WindowsStartupCheckpoint {
            original_link: bound_stamp(link, 90),
            startup_directory: "C:\\owned\\Startup".into(),
            target: "C:\\owned\\Styx.exe".into(),
            arguments: "--startup --state-dir C:\\owned\\state".into(),
            working_directory: "C:\\owned".into(),
            desired_enabled: true,
            app: WindowsRestartProcess {
                pid: 100,
                birth_filetime: 134_372_236_050_000_000,
            },
            core: WindowsRestartProcess {
                pid: 101,
                birth_filetime: 134_372_236_060_000_000,
            },
            original_package_sha256: hash,
            original_app_sha256: hash,
            original_publisher_spki_sha256: hash,
        };
        let originals = [
            (
                RecoveryOriginalName::Lock,
                b"original-lock-bytes".as_slice(),
            ),
            (
                RecoveryOriginalName::Observer,
                b"original-observer-bytes".as_slice(),
            ),
        ];
        let mut entries = Vec::new();
        let bindings = originals
            .iter()
            .enumerate()
            .map(|(n, (name, bytes))| {
                entries.push((member(&id, name.suffix()), bytes.to_vec()));
                RecoveryOriginalBinding {
                    name: *name,
                    stamp: bound_stamp(bytes, 40 + n as u64),
                }
            })
            .collect::<Vec<_>>();
        let guards = [
            RecoveryGuardName::Advance,
            RecoveryGuardName::Background,
            RecoveryGuardName::Capabilities,
            RecoveryGuardName::Foreground,
        ]
        .into_iter()
        .map(|name| {
            let raw = format!("owned-guard-{}-original-only", name.suffix()).into_bytes();
            let binding = RecoveryGuardBinding {
                name,
                sha256: Sha256Digest::of_bytes(&raw),
                byte_len: raw.len() as u64,
            };
            entries.push((member(&id, name.suffix()), raw));
            binding
        })
        .collect::<Vec<_>>();
        let plan=serde_json::to_vec(&serde_json::json!({
            "schema":2,"action":"retire_legacy_foreground_owner_after_windows_restart",
            "stateDir":std::env::temp_dir(),"deviceId":device,"identitySha256":hash,"configurationHash":hash,
            "currentBoot":{"platform":"win32","id":boot.id,"startedAt":boot.started_at_ms},
            "previousOwnerPid":101,
            "files":bindings.iter().map(|b| {
                let (dev,ino,_,_)=file_tuple(&b.stamp).unwrap();
                serde_json::json!({"name":b.name.source_name(),"ino":ino.to_string(),"dev":dev.to_string(),"sha256":b.stamp.content_sha256(),"modifiedAt":1_792_749_990_000_u64})
            }).collect::<Vec<_>>(),
            "previousWorkOutcome":"unknown_not_replayed","identityMutation":"none","requiresExplicitAuthorization":true,
            "startupCheckpointSha256":Sha256Digest::of_bytes(&serde_json::to_vec(&checkpoint).unwrap())
        })).unwrap();
        let intent = LegacyOwnerRecoveryIntent {
            schema: 3,
            kind: RecoveryKind::LegacyOwnerRecovery,
            transaction_id: id.clone(),
            sequence: 1,
            config_root: styx_contracts::native_management::NativeRootIdentity::Windows {
                volume_serial: 12,
                file_id: 55,
                owner_sid: "S-1-5-21-1234".into(),
            },
            deployment_raw_sha256: hash,
            before_state_sha256: hash,
            candidate_manifest_sha256: hash,
            publisher_spki_sha256: hash,
            previous_boot: None,
            current_boot: boot.clone(),
            basis: Some(RecoveryBasis::ExplicitLegacyMaintenance {
                plan_sha256: Sha256Digest::of_bytes(&plan),
                device_id: device,
                identity_json_sha256: hash,
                configuration_hash: hash,
                observer_pid: 101,
            }),
            restart: RecoveryRestartBinding::WindowsStartupExclusion,
            successor_retirement_intent_sha256: hash,
            originals: bindings,
            guards,
            startup_checkpoint: Some(checkpoint.clone()),
        };
        let raw_intent = serde_json::to_vec(&intent).unwrap();
        entries.insert(0, (member(&id, "intent"), raw_intent.clone()));
        entries.push((member(&id, "authorization-plan"), plan));
        entries.push((member(&id, "startup-original"), link.to_vec()));
        // Explicit required order independent of the production stage iterator.
        let stages = [
            (OwnerRecoveryStage::Prepared, "prepared"),
            (OwnerRecoveryStage::RestartExcluded, "restart-excluded"),
            (OwnerRecoveryStage::BootObserved, "boot-observed"),
            (OwnerRecoveryStage::Archived, "archived"),
            (OwnerRecoveryStage::GuardsHeld, "guards-held"),
        ];
        let mut phases = Vec::new();
        let mut previous = None;
        for (stage, suffix) in stages {
            let archived = matches!(
                stage,
                OwnerRecoveryStage::Archived | OwnerRecoveryStage::GuardsHeld
            );
            let phase = RecoveryPhase {
                schema: 3,
                kind: RecoveryKind::LegacyOwnerRecovery,
                transaction_id: id.clone(),
                sequence: 1,
                raw_intent_sha256: Sha256Digest::of_bytes(&raw_intent),
                stage,
                previous,
                originals: if archived {
                    intent
                        .originals
                        .iter()
                        .map(|b| RecoveryOriginalPost {
                            name: b.name,
                            stamp: b.stamp.clone(),
                        })
                        .collect()
                } else {
                    vec![]
                },
                guards: if stage == OwnerRecoveryStage::GuardsHeld {
                    intent
                        .guards
                        .iter()
                        .enumerate()
                        .map(|(n, g)| {
                            let raw = &entries
                                .iter()
                                .find(|(name, _)| *name == member(&id, g.name.suffix()))
                                .unwrap()
                                .1;
                            RecoveryGuardPost {
                                name: g.name,
                                stamp: bound_stamp(raw, 200 + n as u64),
                            }
                        })
                        .collect()
                } else {
                    vec![]
                },
                startup_post: if stage == OwnerRecoveryStage::Prepared {
                    None
                } else {
                    Some(checkpoint.original_link.clone())
                },
                boot_observation: if matches!(
                    stage,
                    OwnerRecoveryStage::Prepared | OwnerRecoveryStage::RestartExcluded
                ) {
                    None
                } else {
                    Some(RecoveryBoot {
                        id: "wmi-lastboot-unix-micros:1792750010000000".into(),
                        started_at_ms: 1_792_750_010_000,
                    })
                },
            };
            let raw = serde_json::to_vec(&phase).unwrap();
            previous = Some(Sha256Digest::of_bytes(&raw));
            phases.push((member(&id, suffix), raw));
        }
        Self {
            intent,
            entries,
            phases,
        }
    }
    fn prefix(&self, count: usize) -> JournalObservation {
        let mut all = self.entries.clone();
        all.extend_from_slice(&self.phases[..count]);
        observation(&all)
    }
}

#[test]
fn startup_checkpoint_keeps_one_ordered_chain_and_original_bytes() {
    let f = StartupFixture::new();
    valid_intent(&f.intent).unwrap();
    // Different process IDs may share one clock tick; parent/owner proof is an
    // adapter responsibility, not a strict timestamp ordering invented here.
    let mut same_tick = f.intent.clone();
    let checkpoint = same_tick.startup_checkpoint.as_mut().unwrap();
    checkpoint.core.birth_filetime = checkpoint.app.birth_filetime;
    valid_intent(&same_tick).unwrap();
    checkpoint_before_app_is_rejected(&same_tick);

    for count in 0..=5 {
        let scan = f.prefix(count);
        let before = scan
            .files
            .iter()
            .map(|f| (f.name.clone(), f.bytes().to_vec()))
            .collect::<Vec<_>>();
        let original = original(&scan, &f.intent.transaction_id).unwrap();
        assert_eq!(original.phases.len(), count);
        assert_eq!(original.raw_intent, f.entries[0].1);
        assert_eq!(
            scan.files
                .iter()
                .map(|f| (f.name.clone(), f.bytes().to_vec()))
                .collect::<Vec<_>>(),
            before
        );
    }
    // A prepared receipt never stands in for a boot observation.
    let mut skipped = f.entries.clone();
    skipped.extend([f.phases[0].clone(), f.phases[3].clone()]);
    assert!(original(&observation(&skipped), &f.intent.transaction_id).is_err());
    let mut missing = f.prefix(1);
    missing
        .files
        .retain(|v| v.name != member(&f.intent.transaction_id, "startup-original"));
    assert!(original(&missing, &f.intent.transaction_id).is_err());
}

#[test]
fn startup_checkpoint_rejects_wrong_boot_post_and_old_plan_authority() {
    let f = StartupFixture::new();
    for new_micros in [
        1_792_749_999_000_000_u64,
        1_792_750_000_000_000,
        1_792_750_000_000_100,
    ] {
        let mut scan = f.prefix(3);
        let raw = &mut scan
            .files
            .iter_mut()
            .find(|v| v.name == f.phases[2].0)
            .unwrap()
            .bytes;
        let mut p: RecoveryPhase = serde_json::from_slice(raw).unwrap();
        p.boot_observation = Some(RecoveryBoot {
            id: format!("wmi-lastboot-unix-micros:{new_micros}"),
            started_at_ms: new_micros / 1000,
        });
        *raw = serde_json::to_vec(&p).unwrap();
        assert!(original(&scan, &f.intent.transaction_id).is_err());
    }
    for change_identity in [false, true] {
        let mut scan = f.prefix(3);
        let raw = &mut scan
            .files
            .iter_mut()
            .find(|v| v.name == f.phases[2].0)
            .unwrap()
            .bytes;
        let mut p: RecoveryPhase = serde_json::from_slice(raw).unwrap();
        if let Some(NativeRetirementFileStamp::Windows {
            file_id,
            changed_seconds,
            ..
        }) = &mut p.startup_post
        {
            if change_identity {
                *file_id += 1;
            } else {
                *changed_seconds += 1;
            }
        }
        *raw = serde_json::to_vec(&p).unwrap();
        assert!(original(&scan, &f.intent.transaction_id).is_err());
    }
    let plan_raw = &f
        .entries
        .iter()
        .find(|(n, _)| *n == member(&f.intent.transaction_id, "authorization-plan"))
        .unwrap()
        .1;
    let mut plan: serde_json::Value = serde_json::from_slice(plan_raw).unwrap();
    plan["schema"] = serde_json::json!(1);
    plan["action"] = serde_json::json!("retire_legacy_foreground_owner");
    plan.as_object_mut()
        .unwrap()
        .remove("startupCheckpointSha256");
    let raw = serde_json::to_vec(&plan).unwrap();
    let mut intent = f.intent.clone();
    if let Some(RecoveryBasis::ExplicitLegacyMaintenance { plan_sha256, .. }) = &mut intent.basis {
        *plan_sha256 = Sha256Digest::of_bytes(&raw);
    }
    assert!(validate_authorization_plan(&intent, Some(&raw)).is_err());
    for schema in [1, 2] {
        let mut old = f.intent.clone();
        old.schema = schema;
        assert!(valid_intent(&old).is_err());
    }
    let mut foreign = f.intent.clone();
    foreign.config_root = styx_contracts::native_management::NativeRootIdentity::Linux {
        device: 12,
        inode: 55,
        uid: 1000,
    };
    assert!(valid_intent(&foreign).is_err());
}

#[test]
fn startup_partial_preparation_only_resumes_exact_original_request_before_prepared() {
    let f = StartupFixture::new();
    let mut expected = f.entries.clone();
    expected.push(f.phases[0].clone());
    for count in 1..=f.entries.len() {
        let scan = observation(&f.entries[..count]);
        let baseline = incomplete_startup_preparation(&scan, &f.intent, &expected)
            .unwrap()
            .unwrap();
        assert!(baseline.files.is_empty());
        // No caller bytes or journal members were rewritten by inspection.
        assert_eq!(scan.files.len(), count);
    }
    assert!(
        incomplete_startup_preparation(&f.prefix(1), &f.intent, &expected)
            .unwrap()
            .is_none()
    );
    let missing_intent = observation(&f.entries[1..]);
    assert!(incomplete_startup_preparation(&missing_intent, &f.intent, &expected).is_err());
    let mut changed = observation(&f.entries);
    changed.files[1].bytes.push(0);
    assert!(incomplete_startup_preparation(&changed, &f.intent, &expected).is_err());
    let mut later = f.entries.clone();
    later.push(f.phases[1].clone());
    assert!(incomplete_startup_preparation(&observation(&later), &f.intent, &expected).is_err());
}

fn checkpoint_before_app_is_rejected(intent: &LegacyOwnerRecoveryIntent) {
    let mut bad = intent.clone();
    let checkpoint = bad.startup_checkpoint.as_mut().unwrap();
    checkpoint.core.birth_filetime = checkpoint.app.birth_filetime - 1;
    assert!(valid_intent(&bad).is_err());
}

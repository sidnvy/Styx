//! Synthetic private roots and real child exits; not Core enrollment acceptance,
//! faulting hardware or live-profile migration. Child helper is not a product skip.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
        process::Command,
    };
    use styx_contracts::enrollment::{IntentBody, Mutation};
    const IDENTITY: &[u8] = b"synthetic identity original\0\xff\n";
    const LEGACY: &[u8] = b"{ \"version\": 1, \"unknown\": 9007199254740993 }\n";
    const PROFILE: &[u8] = b"synthetic public profile original bytes\n";
    const TOKEN: &[u8] = b"synthetic-token-not-real-credential";
    const SEALED: &[u8] = b"synthetic sealed bytes not RSA evidence";
    fn root(parent: &Path) -> PathBuf {
        let p = parent.join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            ("identity.fixture", IDENTITY),
            ("legacy.fixture.json", LEGACY),
        ] {
            fs::write(p.join(name), bytes).unwrap();
            fs::set_permissions(p.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        p
    }
    fn materials() -> Vec<MaterialRef> {
        [
            (MaterialKind::Profile, PROFILE),
            (MaterialKind::Token, TOKEN),
            (MaterialKind::Sealed, SEALED),
        ]
        .into_iter()
        .map(|(kind, b)| MaterialRef {
            kind,
            digest: Sha256Digest::of_bytes(b),
        })
        .collect()
    }
    fn intent(sequence: u64) -> Vec<u8> {
        // This is a store-layer DTO fixture, NOT Core attestation that these
        // materials are required for a policy transition or valid enrollment.
        contract::encode(&IntentBody {
            schema: 1,
            gateway_epoch: "fixture-epoch".try_into().unwrap(),
            transaction: format!("fixture-transaction-{sequence}")
                .try_into()
                .unwrap(),
            sequence,
            expected_revision: sequence - 1,
            prepared_at: 42,
            required_materials: materials(),
            mutation: Mutation::CloseWindow { scope: None },
        })
        .unwrap()
    }
    fn fill(j: &mut EnrollmentJournal<'_>) {
        for (kind, bytes) in [
            (MaterialKind::Profile, PROFILE),
            (MaterialKind::Token, TOKEN),
            (MaterialKind::Sealed, SEALED),
        ] {
            j.put_material(kind, bytes).unwrap();
        }
    }
    fn observe_private_files(root: &Path) {
        assert_eq!(fs::read(root.join("identity.fixture")).unwrap(), IDENTITY);
        assert_eq!(fs::read(root.join("legacy.fixture.json")).unwrap(), LEGACY);
        use std::os::unix::fs::MetadataExt;
        for item in fs::read_dir(root.join(NAMESPACE)).unwrap() {
            let item = item.unwrap();
            let m = fs::symlink_metadata(item.path()).unwrap();
            assert!(m.is_file());
            assert_eq!(m.nlink(), 1);
            assert_eq!(m.mode() & 0o7777, 0o600);
        }
    }
    #[test]
    #[ignore = "helper: requires STYX_TEST_ENROLLMENT_CHILD_ROOT/CUT; only parent-owned process-crash matrix"]
    fn journal_crash_child() {
        let path = PathBuf::from(std::env::var("STYX_TEST_ENROLLMENT_CHILD_ROOT").unwrap());
        let cut = std::env::var("STYX_TEST_ENROLLMENT_CUT").unwrap();
        let r = PrivateRoot::open(&path).unwrap();
        let mut writer = r.try_configuration_writer().unwrap();
        let mut j = EnrollmentJournal::open(&r, &mut writer, JournalBudget::default()).unwrap();
        if cut.starts_with("material:") {
            let reference = MaterialRef {
                kind: MaterialKind::Token,
                digest: Sha256Digest::of_bytes(TOKEN),
            };
            j.write(&material_name(&reference), TOKEN, &|at| {
                if cut == format!("material:{at}") {
                    std::process::exit(73)
                }
            })
            .unwrap();
        }
        fill(&mut j);
        let fault = |phase: &str, at: &str| {
            if cut == format!("{phase}:{at}") {
                std::process::exit(73)
            }
        };
        let prepared = j.prepare_observing(&intent(1), None, &fault).unwrap();
        j.commit_observing(&prepared, &fault).unwrap();
    }
    #[test]
    #[ignore = "requires STYX_TEST_ENROLLMENT_ROOT; owned Linux file/process-crash journal scenario"]
    fn immutable_material_commit_chain_and_process_crash_recovery() {
        let base = PathBuf::from(std::env::var("STYX_TEST_ENROLLMENT_ROOT").unwrap());
        fs::create_dir_all(&base).unwrap();
        // One complete append/restart journey and independent byte observations.
        let path = root(&base);
        let r = PrivateRoot::open(&path).unwrap();
        let mut writer = r.try_configuration_writer().unwrap();
        let mut j = EnrollmentJournal::open(&r, &mut writer, JournalBudget::default()).unwrap();
        fill(&mut j);
        let original = intent(1);
        let p = j.prepare(&original, None).unwrap();
        assert!(j.reconcile(&p.binding.transaction).unwrap().is_none());
        let c = j.commit(&p).unwrap();
        assert_eq!(j.commit(&p).unwrap(), c);
        assert_eq!(
            fs::read(
                path.join(NAMESPACE)
                    .join(record_name(&p.binding.transaction, "intent"))
            )
            .unwrap(),
            original
        );
        let p2 = j.prepare(&intent(2), Some(c.digest().unwrap())).unwrap();
        let c2 = j.commit(&p2).unwrap();
        assert_eq!(
            j.reconcile(&p.binding.transaction).unwrap(),
            Some(c.clone())
        );
        assert_eq!(
            j.reconcile(&p2.binding.transaction).unwrap(),
            Some(c2.clone())
        );
        let mut changed = p.clone();
        changed.binding.required_materials.clear();
        assert_eq!(j.commit(&changed), Err(JournalError::Conflict));
        let mut altered = contract::decode(&original).unwrap();
        altered.prepared_at += 1;
        assert_eq!(
            j.prepare(&contract::encode(&altered).unwrap(), None),
            Err(JournalError::Conflict)
        );
        assert_eq!(
            j.put_material(MaterialKind::Token, &vec![0; 4097]),
            Err(JournalError::InvalidInput)
        );
        let mut wrongchain = contract::decode(&intent(3)).unwrap();
        wrongchain.expected_revision = 20;
        let pp = j
            .prepare(
                &contract::encode(&wrongchain).unwrap(),
                Some(c2.digest().unwrap()),
            )
            .unwrap();
        assert_eq!(j.commit(&pp), Err(JournalError::Conflict));
        // Core may consume sequence without advancing revision, and may
        // restart into a new epoch. Disk authority follows revision/hash chain.
        let mut gap = contract::decode(&intent(7)).unwrap();
        gap.expected_revision = 2;
        gap.gateway_epoch = "restarted-epoch".try_into().unwrap();
        let gap = j
            .prepare(&contract::encode(&gap).unwrap(), Some(c2.digest().unwrap()))
            .unwrap();
        let c3 = j.commit(&gap).unwrap();
        let mut fork = contract::decode(&intent(8)).unwrap();
        fork.expected_revision = 2;
        let fork = j
            .prepare(
                &contract::encode(&fork).unwrap(),
                Some(c3.digest().unwrap()),
            )
            .unwrap();
        assert_eq!(j.commit(&fork), Err(JournalError::Conflict));
        let mut reused = contract::decode(&intent(7)).unwrap();
        reused.transaction = "reused-sequence".try_into().unwrap();
        reused.expected_revision = 3;
        let reused = j
            .prepare(
                &contract::encode(&reused).unwrap(),
                Some(c3.digest().unwrap()),
            )
            .unwrap();
        assert_eq!(j.commit(&reused), Err(JournalError::Conflict));
        // Self-inconsistent approved token DTO is refused by storage too;
        // this synthetic negative control is not RSA approval evidence.
        let profile = styx_contracts::enrollment::OpaqueProfileRef(Sha256Digest::of_bytes(PROFILE));
        let mut bad = contract::decode(&intent(3)).unwrap();
        bad.transaction = "fixture-token-mismatch".try_into().unwrap();
        bad.mutation = Mutation::Approve {
            request: "fixture-request".try_into().unwrap(),
            target: styx_contracts::enrollment::CredentialTarget {
                request: "fixture-request".try_into().unwrap(),
                device: "fixture-device".try_into().unwrap(),
                fingerprint: Sha256Digest::of_bytes(b"fixture-spki"),
                profile: profile.clone(),
                pending_facts_digest: Sha256Digest::of_bytes(b"fixture-pending"),
            },
            device: styx_contracts::enrollment::Device {
                id: "fixture-device".try_into().unwrap(),
                fingerprint: Sha256Digest::of_bytes(b"fixture-spki"),
                grant: styx_contracts::enrollment::Grant {
                    computer: false,
                    browser: false,
                },
                generation: "fixture-generation".into(),
                credential: styx_contracts::enrollment::CredentialRef(Sha256Digest::of_bytes(
                    TOKEN,
                )),
                credential_hash: Sha256Digest::of_bytes(b"different-token"),
                profile,
                revoked: false,
            },
            sealed: styx_contracts::enrollment::SealedCredentialRef(Sha256Digest::of_bytes(SEALED)),
            claim_expires: 50,
        };
        let bad = j
            .prepare(&contract::encode(&bad).unwrap(), Some(c2.digest().unwrap()))
            .unwrap();
        assert_eq!(j.commit(&bad), Err(JournalError::Conflict));
        observe_private_files(&path);
        drop(writer);
        drop(r);
        let r = PrivateRoot::open(&path).unwrap();
        let mut writer = r.try_configuration_writer().unwrap();
        let mut j = EnrollmentJournal::open(&r, &mut writer, JournalBudget::default()).unwrap();
        assert_eq!(j.reconcile(&p2.binding.transaction).unwrap(), Some(c2));
        drop(writer);
        // True separate process termination at each actual persistence boundary.
        let mut crash_roots = vec![];
        for phase in ["material", "intent", "prepared", "committed"] {
            for at in ["write", "file_sync", "rename", "directory_sync"] {
                let path = root(&base);
                let cut = format!("{phase}:{at}");
                let output = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "store::enrollment::tests::linux::journal_crash_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("STYX_TEST_ENROLLMENT_CHILD_ROOT", &path)
                    .env("STYX_TEST_ENROLLMENT_CUT", &cut)
                    .output()
                    .unwrap();
                fs::write(path.join("child.stdout"), &output.stdout).unwrap();
                fs::write(path.join("child.stderr"), &output.stderr).unwrap();
                assert_eq!(output.status.code(), Some(73), "cut={cut}");
                observe_private_files(&path);
                let namespace = path.join(NAMESPACE);
                for (kind, bytes) in [
                    (MaterialKind::Profile, PROFILE),
                    (MaterialKind::Token, TOKEN),
                    (MaterialKind::Sealed, SEALED),
                ] {
                    let reference = MaterialRef {
                        kind,
                        digest: Sha256Digest::of_bytes(bytes),
                    };
                    let filename = namespace.join(material_name(&reference));
                    if filename.exists() {
                        assert_eq!(fs::read(filename).unwrap(), bytes);
                    }
                }
                let intent_name =
                    record_name(&"fixture-transaction-1".try_into().unwrap(), "intent");
                if namespace.join(&intent_name).exists() {
                    assert_eq!(fs::read(namespace.join(intent_name)).unwrap(), intent(1));
                }
                if matches!(at, "write" | "file_sync") {
                    assert!(
                        fs::read_dir(&namespace).unwrap().any(|e| e
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .ends_with(".temporary")),
                        "unknown temporary evidence must remain"
                    );
                }
                let committed_name =
                    record_name(&"fixture-transaction-1".try_into().unwrap(), "committed");
                let committed_exists = namespace.join(committed_name).exists();
                let r = PrivateRoot::open(&path).unwrap();
                let mut writer = r.try_configuration_writer().unwrap();
                let mut j =
                    EnrollmentJournal::open(&r, &mut writer, JournalBudget::default()).unwrap();
                let result = j
                    .reconcile(&"fixture-transaction-1".try_into().unwrap())
                    .unwrap();
                assert_eq!(result.is_some(), committed_exists);
                if let Some(c) = result {
                    assert_eq!(c.binding.intent_digest, Sha256Digest::of_bytes(&intent(1)));
                }
                // Reconcile cannot upgrade prepared-only into committed.
                assert_eq!(
                    namespace
                        .join(record_name(
                            &"fixture-transaction-1".try_into().unwrap(),
                            "committed"
                        ))
                        .exists(),
                    committed_exists
                );
                crash_roots.push((cut, path));
            }
        }
        let genesis = root(&base);
        let g = PrivateRoot::open(&genesis).unwrap();
        let mut gw = g.try_configuration_writer().unwrap();
        let mut gj = EnrollmentJournal::open(&g, &mut gw, JournalBudget::default()).unwrap();
        fill(&mut gj);
        let mut first = contract::decode(&intent(5)).unwrap();
        first.expected_revision = 0;
        let first = gj
            .prepare(&contract::encode(&first).unwrap(), None)
            .unwrap();
        gj.commit(&first).unwrap();
        drop(gw);
        // Another root's writer cannot authorize namespace creation.
        let left = root(&base);
        let right = root(&base);
        let left_root = PrivateRoot::open(&left).unwrap();
        let right_root = PrivateRoot::open(&right).unwrap();
        let mut wrong_writer = right_root.try_configuration_writer().unwrap();
        assert!(matches!(
            EnrollmentJournal::open(&left_root, &mut wrong_writer, JournalBudget::default()),
            Err(JournalError::Unknown)
        ));
        assert!(!left.join(NAMESPACE).exists());
        // Bad aliases/private metadata and full scan budget fail closed.
        for attack in ["symlink", "hardlink", "mode"] {
            let path = root(&base);
            let r = PrivateRoot::open(&path).unwrap();
            let mut writer = r.try_configuration_writer().unwrap();
            let mut j = EnrollmentJournal::open(&r, &mut writer, JournalBudget::default()).unwrap();
            let reference = j.put_material(MaterialKind::Token, TOKEN).unwrap();
            let file = path.join(NAMESPACE).join(material_name(&reference));
            match attack {
                "symlink" => {
                    fs::remove_file(&file).unwrap();
                    symlink(path.join("identity.fixture"), &file).unwrap();
                }
                "hardlink" => fs::hard_link(&file, path.join("token-alias")).unwrap(),
                _ => fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap(),
            }
            assert!(matches!(
                j.read_material(&reference),
                Err(JournalError::Unknown)
            ));
            assert!(matches!(j.scan(), Err(JournalError::Unknown)));
        }
        let path = root(&base);
        let r = PrivateRoot::open(&path).unwrap();
        let mut writer = r.try_configuration_writer().unwrap();
        let mut j = EnrollmentJournal::open(
            &r,
            &mut writer,
            JournalBudget {
                max_files: 1,
                max_bytes: 1024,
                max_file_bytes: 1024,
            },
        )
        .unwrap();
        j.put_material(MaterialKind::Token, TOKEN).unwrap();
        assert_eq!(
            j.put_material(MaterialKind::Sealed, SEALED),
            Err(JournalError::BudgetExceeded)
        );
        println!(
            "Linux journal owned fixture={}: immutable exact raw intent, content-addressed materials, commit-only authority, hash-chain restart/reconcile, 16 real process exits with independent file oracle, orphan retention, unsafe aliases/modes and bounded-capacity refusal PASS; synthetic store layer only; no Core/credential/TLS/native/powerloss acceptance; crash roots={}",
            base.display(),
            crash_roots.len()
        );
    }
}

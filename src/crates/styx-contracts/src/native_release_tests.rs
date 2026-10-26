//! Pure manifest admission examples. Dummy byte digests are not an upstream
//! signature, license review, real package closure or executable acceptance.
use super::*;
use serde_json::json;

fn member(path: &str, executable: bool) -> NativeReleaseMember {
    NativeReleaseMember {
        path: path.into(),
        size: 1,
        sha256: Sha256Digest::of_bytes(path.as_bytes()),
        executable,
    }
}
fn preview() -> NativeReleaseManifest {
    let source_digest = Sha256Digest::of_bytes(b"source-inputs");
    let mut source = member("source-inputs.json", false);
    source.sha256 = source_digest;
    NativeReleaseManifest {
        schema: 2,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        component: NativeReleaseComponent::Styx,
        scope: NativeReleaseScope::ConfigurationPreview,
        minimum_reader: NativeReleaseReader::NativeReleaseV1,
        target: NativeReleaseTarget::LinuxX86_64Gnu,
        version: "0.4.0-dev.1".into(),
        entrypoint: "bin/styx".into(),
        source: NativeReleaseSource {
            revision: "1234567890abcdef1234567890abcdef12345678".into(),
            inputs_sha256: source_digest,
        },
        contracts: NativeReleaseContracts {
            control: 1,
            management_state: 2,
        },
        files: vec![member("bin/styx", true), member("LICENSE", false), source],
        external_workers: vec![],
        worker_closures: vec![],
    }
}
fn runtime(target: NativeReleaseTarget, kinds: &[NativeExternalWorker]) -> NativeReleaseManifest {
    let mut manifest = preview();
    manifest.scope = NativeReleaseScope::RuntimeCandidate;
    manifest.minimum_reader = NativeReleaseReader::NativeRuntimeV1;
    manifest.target = target;
    manifest.entrypoint = target.entrypoint().into();
    manifest.files[0] = member(target.entrypoint(), true);
    manifest.external_workers = kinds.to_vec();
    for &kind in kinds {
        let prefix = kind.prefix();
        let entrypoint = kind.entrypoint(target);
        let mut members = vec![entrypoint.clone()];
        match kind {
            NativeExternalWorker::CodexExec => members.extend([
                format!("{prefix}/licenses/codex-LICENSE"),
                format!("{prefix}/licenses/codex-NOTICE"),
            ]),
            NativeExternalWorker::CuaNative => {
                members.push(format!("{prefix}/licenses/cua-LICENSE"))
            }
            NativeExternalWorker::BrowserNode22 => {
                members.extend([
                    format!("{prefix}/licenses/node-LICENSE"),
                    format!("{prefix}/provenance/node.json"),
                ]);
                // These spellings were checked against the retained signed source
                // manifest. Bytes and package provenance require later artifact tests.
                for package in [
                    "@playwright/mcp",
                    "playwright",
                    "playwright-core",
                    "@modelcontextprotocol/sdk",
                ] {
                    for file in ["package.json", "LICENSE"] {
                        members.push(format!(
                            "{prefix}/packages/styx-browser-provider/node_modules/{package}/{file}"
                        ));
                    }
                }
                members.push(format!(
                    "{prefix}/packages/styx-browser-provider/node_modules/playwright/lib/index.js"
                ));
            }
        }
        manifest.files.extend(
            members
                .iter()
                .map(|path| member(path, path.as_str() == entrypoint.as_str())),
        );
        manifest.worker_closures.push(NativeWorkerClosure {
            kind,
            version: "1.2.3".into(),
            source_manifest_sha256: Sha256Digest::of_bytes(b"original signed manifest"),
            source_publisher_spki_sha256: Sha256Digest::of_bytes(b"original SPKI"),
            entrypoint,
            members,
        });
    }
    manifest
}
fn replace_member(manifest: &mut NativeReleaseManifest, old: &str, new: &str) {
    manifest
        .files
        .iter_mut()
        .find(|file| file.path == old)
        .unwrap()
        .path = new.into();
    for closure in &mut manifest.worker_closures {
        for path in &mut closure.members {
            if path == old {
                *path = new.into();
            }
        }
    }
}

#[test]
fn preview_wire_shape_and_reader_barrier_remain_configuration_only() {
    let original = preview();
    original.validate().unwrap();
    let raw = serde_json::to_value(&original).unwrap();
    assert_eq!(
        raw,
        json!({
            "schema":2,"runtime_format":"native_rust_v1","component":"styx",
            "scope":"configuration_preview","minimum_reader":"native_release_v1",
            "target":"x86_64-unknown-linux-gnu","version":"0.4.0-dev.1","entrypoint":"bin/styx",
            "source":{"revision":"1234567890abcdef1234567890abcdef12345678","inputs_sha256":Sha256Digest::of_bytes(b"source-inputs").to_hex()},
            "contracts":{"control":1,"management_state":2},"external_workers":[],
            "files":[{"path":"bin/styx","size":1,"sha256":Sha256Digest::of_bytes(b"bin/styx").to_hex(),"executable":true},
                     {"path":"LICENSE","size":1,"sha256":Sha256Digest::of_bytes(b"LICENSE").to_hex(),"executable":false},
                     {"path":"source-inputs.json","size":1,"sha256":Sha256Digest::of_bytes(b"source-inputs").to_hex(),"executable":false}]
        })
    );
    // An omitted new field parses without changing the old serialized object.
    let decoded: NativeReleaseManifest = serde_json::from_value(raw).unwrap();
    decoded.validate().unwrap();
    let mut incompatible = original.clone();
    incompatible.minimum_reader = NativeReleaseReader::NativeRuntimeV1;
    assert!(incompatible.validate().is_err());
    let mut incompatible = runtime(NativeReleaseTarget::LinuxX86_64Gnu, &[]);
    incompatible.minimum_reader = NativeReleaseReader::NativeReleaseV1;
    assert!(incompatible.validate().is_err());
    let mut changed_digest = original;
    changed_digest.source.inputs_sha256 = Sha256Digest::of_bytes(b"other inputs");
    assert!(changed_digest.validate().is_err());
}

#[test]
fn runtime_closure_is_exact_platform_bound_and_does_not_replace_mac_app_cua() {
    let kinds = [
        NativeExternalWorker::CodexExec,
        NativeExternalWorker::BrowserNode22,
        NativeExternalWorker::CuaNative,
    ];
    runtime(NativeReleaseTarget::LinuxX86_64Gnu, &kinds)
        .validate()
        .unwrap();
    runtime(NativeReleaseTarget::WindowsX86_64Msvc, &kinds)
        .validate()
        .unwrap();
    runtime(NativeReleaseTarget::MacosX86_64, &kinds[..2])
        .validate()
        .unwrap();
    runtime(NativeReleaseTarget::MacosAarch64, &[])
        .validate()
        .unwrap(); // Gateway-only is not Host readiness.
    assert!(
        runtime(NativeReleaseTarget::MacosX86_64, &kinds)
            .validate()
            .is_err()
    );
    assert!(
        runtime(NativeReleaseTarget::MacosAarch64, &kinds)
            .validate()
            .is_err()
    );
    let mut wrong_image = runtime(
        NativeReleaseTarget::WindowsX86_64Msvc,
        &[NativeExternalWorker::CodexExec],
    );
    replace_member(
        &mut wrong_image,
        "workers/codex-exec/bin/codex.exe",
        "workers/codex-exec/bin/codex",
    );
    wrong_image.worker_closures[0].entrypoint = "workers/codex-exec/bin/codex".into();
    assert!(wrong_image.validate().is_err());
    let mut missing_license = runtime(
        NativeReleaseTarget::LinuxX86_64Gnu,
        &[NativeExternalWorker::BrowserNode22],
    );
    let license = "workers/browser-node22/packages/styx-browser-provider/node_modules/@playwright/mcp/LICENSE";
    missing_license.files.retain(|file| file.path != license);
    missing_license.worker_closures[0]
        .members
        .retain(|path| path != license);
    assert!(missing_license.validate().is_err());
    let mut unallocated = runtime(NativeReleaseTarget::LinuxX86_64Gnu, &[]);
    unallocated
        .files
        .push(member("workers/codex-exec/bin/codex", true));
    assert!(unallocated.validate().is_err());
}

#[test]
fn signed_members_cannot_masquerade_cross_closure_or_escape_runtime_budget() {
    let initial = runtime(
        NativeReleaseTarget::LinuxX86_64Gnu,
        &[
            NativeExternalWorker::CodexExec,
            NativeExternalWorker::BrowserNode22,
        ],
    );
    let original_js = "workers/browser-node22/packages/styx-browser-provider/node_modules/playwright/lib/index.js";
    for illegal in [
        "workers/browser-node22/packages/styx-browser-provider/node_modules/../../bin/host.mjs",
        "workers/browser-node22/packages/styx-browser-provider/node_modules/@scope/../host.mjs",
        "workers/browser-node22/packages/styx-browser-provider/node_modules/pkg/file@evil",
        "workers/codex-exec/host.mjs",
        "host.mjs",
        "workers/browser-node22/bin/node.exe",
    ] {
        let mut escape = initial.clone();
        replace_member(&mut escape, original_js, illegal);
        assert!(escape.validate().is_err(), "accepted invalid member");
    }
    let mut executable_js = initial.clone();
    executable_js
        .files
        .iter_mut()
        .find(|file| file.path == original_js)
        .unwrap()
        .executable = true;
    assert!(executable_js.validate().is_err());
    let mut reused = initial.clone();
    reused.worker_closures[1]
        .members
        .push("workers/codex-exec/bin/codex".into());
    assert!(reused.validate().is_err());
    let mut duplicated = initial.clone();
    duplicated
        .external_workers
        .push(NativeExternalWorker::CodexExec);
    assert!(duplicated.validate().is_err());
    let mut missing_actual_file = initial.clone();
    missing_actual_file
        .files
        .retain(|file| file.path != original_js);
    assert!(missing_actual_file.validate().is_err());
    let mut duplicate_file = initial.clone();
    duplicate_file.files.push(duplicate_file.files[0].clone());
    assert!(duplicate_file.validate().is_err());
    let mut changed_source = initial.clone();
    changed_source.source.inputs_sha256 = Sha256Digest::of_bytes(b"not original inputs");
    assert!(changed_source.validate().is_err());
    let mut over_member = initial.clone();
    over_member.files[0].size = 1024 * 1024 * 1024 + 1;
    assert!(over_member.validate().is_err());
    let mut over_total = initial.clone();
    for file in over_total.files.iter_mut().take(5) {
        file.size = 1024 * 1024 * 1024;
    }
    assert!(over_total.validate().is_err());
    let mut invalid_raw = serde_json::to_value(initial).unwrap();
    invalid_raw["worker_closures"][0]["unexpected_authority"] = json!(true);
    assert!(serde_json::from_value::<NativeReleaseManifest>(invalid_raw).is_err());
}

#[test]
fn migrated_runtime_reader_is_explicit_and_old_manifest_shape_does_not_claim_it() {
    use crate::management::ReaderContract;
    let old = runtime(NativeReleaseTarget::LinuxX86_64Gnu, &[]);
    let raw = serde_json::to_vec(&old).unwrap();
    old.validate().unwrap();
    assert!(
        old.minimum_reader
            .supports_state_reader(ReaderContract::NativeManagementStateV1)
    );
    assert!(
        !old.minimum_reader
            .supports_state_reader(ReaderContract::NativeMigratedStateV1)
    );
    let mut new = old.clone();
    new.minimum_reader = NativeReleaseReader::NativeRuntimeMigratedV1;
    new.validate().unwrap();
    assert!(
        new.minimum_reader
            .supports_state_reader(ReaderContract::NativeMigratedStateV1)
    );
    assert!(
        new.minimum_reader
            .supports_state_reader(ReaderContract::NativeManagementStateV1)
    );
    assert_ne!(raw, serde_json::to_vec(&new).unwrap());
    let decoded: NativeReleaseManifest = serde_json::from_slice(&raw).unwrap();
    assert_eq!(raw, serde_json::to_vec(&decoded).unwrap());
    assert_eq!(decoded.minimum_reader, NativeReleaseReader::NativeRuntimeV1);
    let mut preview = preview();
    preview.minimum_reader = new.minimum_reader;
    assert!(preview.validate().is_err());
    assert!(
        !NativeReleaseReader::NativeReleaseV1
            .supports_state_reader(ReaderContract::NativeMigratedStateV1)
    );
    let mut unknown = serde_json::to_value(&new).unwrap();
    unknown["minimum_reader"] = "native_runtime_unknown_v1".into();
    assert!(serde_json::from_value::<NativeReleaseManifest>(unknown).is_err());
}

/// These are manifest compatibility controls, not signed-package acceptance.
#[test]
fn host_admission_report_requires_explicit_signed_reader_declaration() {
    for old in [
        NativeReleaseReader::NativeReleaseV1,
        NativeReleaseReader::NativeRuntimeV1,
        NativeReleaseReader::NativeRuntimeMigratedV1,
        NativeReleaseReader::NativeRuntimeMigratedV2,
    ] {
        assert!(!old.supports_host_admission_v2());
    }
    for target in [
        NativeReleaseTarget::LinuxX86_64Gnu,
        NativeReleaseTarget::MacosAarch64,
        NativeReleaseTarget::MacosX86_64,
        NativeReleaseTarget::WindowsX86_64Msvc,
    ] {
        let mut package = runtime(target, &[]);
        package.minimum_reader = NativeReleaseReader::NativeRuntimeMigratedV3;
        let decoded: NativeReleaseManifest =
            serde_json::from_slice(&serde_json::to_vec(&package).unwrap()).unwrap();
        decoded.validate().unwrap();
        assert!(decoded.minimum_reader.supports_host_admission_v2());
        assert!(
            decoded
                .minimum_reader
                .supports_state_reader(ReaderContract::NativeMigratedStateV2)
        );
        assert!(
            decoded
                .minimum_reader
                .supports_state_reader(ReaderContract::NativeMigratedStateV1)
        );
        assert!(
            decoded
                .minimum_reader
                .supports_state_reader(ReaderContract::NativeManagementStateV1)
        );
        let mut unsupported = serde_json::to_value(package).unwrap();
        unsupported["minimum_reader"] = "native_runtime_migrated_v4".into();
        assert!(
            serde_json::from_slice::<NativeReleaseManifest>(
                &serde_json::to_vec(&unsupported).unwrap()
            )
            .is_err()
        );
    }
}

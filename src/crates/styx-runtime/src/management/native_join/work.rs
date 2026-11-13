use super::{
    deployment::{Input, deployment, identity, text, tls},
    *,
};
use crate::{
    crypto::DevicePrivateKey,
    release::{self, VerifiedNativeRelease},
    store::{
        PrivateRoot,
        native_root::{
            self,
            host::{FreshHostFiles, NativeHostJoinFile as File, NativeHostJoinStore},
        },
    },
    tls::GatewayClientTls,
};
use std::collections::BTreeMap;
use styx_contracts::{
    management::ReaderContract,
    native_host::NativeHostJoinSeed,
    native_management::{
        NATIVE_PAIRING_LIFECYCLE_STATE_SCHEMA, NativeAutostartDesired, NativeComponentDesired,
        NativeDeploymentMode, NativeDesired, NativeManager, NativeRunDesired, NativeRuntimeFormat,
        NativeRuntimeSelection, NativeState, NativeStateKind,
    },
};
use zeroize::Zeroizing;

pub(in super::super) struct Work {
    pub(super) store: NativeHostJoinStore,
    pub(super) root: PrivateRoot,
    pub(super) state_dir: PathBuf,
    pub(super) seed: NativeHostJoinSeed,
    pub(super) seed_raw: Zeroizing<Vec<u8>>,
    pub(super) key: DevicePrivateKey,
    pub(super) tls: GatewayClientTls,
    pub(super) origin: url::Url,
    pub(super) candidate: Arc<VerifiedNativeRelease>,
    pub(super) inputs: Vec<Input>,
    pub(super) app_scope: Option<Arc<crate::app::HostScope>>,
}
impl Work {
    pub(super) fn validate(&self) -> Result<()> {
        validate_app_scope(self.app_scope.as_deref(), &self.state_dir)?;
        let (state, seed) = self.store.readstate_and_seed().map_err(|_| unknown())?;
        if !state
            .state()
            .desired
            .host
            .as_ref()
            .is_some_and(|host| host.manager == caller_manager(self.app_scope.as_deref()))
        {
            return Err(unknown());
        }
        // readstate already checks the complete C07 chain under the original
        // join-store owner. Immutable seed runtime remains the bootstrap only.
        let selected = state
            .state()
            .runtime_selection()
            .map_err(|_| unknown())?
            .ok_or_else(unknown)?;
        let update = state.state().runtime_update().map_err(|_| unknown())?;
        let bootstrap = update
            .as_ref()
            .map_or(&selected, |update| &update.bootstrap_runtime);
        // Keep a complete pinned-release check at every existing Work
        // boundary, but derive reader support from that same authenticated
        // immutable manifest. The publication getters would scan the entire
        // payload three times here; no validation is cached across calls.
        self.candidate
            .revalidate_matches_selection(&selected)
            .map_err(|_| unknown())?;
        if bootstrap != &self.seed.runtime
            || selected.publisher_spki_sha256 != self.seed.runtime.publisher_spki_sha256
            || !self
                .candidate
                .manifest()
                .minimum_reader
                .supports_state_reader(state.state().reader_contract)
            || seed != self.seed_raw.as_slice()
            || self
                .store
                .configuration_root()
                .identity()
                .map_err(|_| unknown())?
                != self.root.identity()
        {
            return Err(unknown());
        }
        for input in &self.inputs {
            input.revalidate()?;
        }
        validate_app_scope(self.app_scope.as_deref(), &self.state_dir)
    }
    pub(super) fn append(&mut self, file: File, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        self.store.append(file, bytes).map_err(|_| unknown())?;
        self.validate()
    }
    pub(super) fn report(
        &self,
        operation: &'static str,
        status: JoinStatus,
        pending: &protocol::PendingJoin,
    ) -> JoinReport {
        JoinReport {
            schema: 1,
            operation,
            status,
            state_dir: self.state_dir.clone(),
            device_id: self.seed.device_id.clone(),
            fingerprint: self.seed.fingerprint,
            request_id: Some(pending.request_id.clone()),
            comparison_code: Some(pending.comparison_code.clone()),
            expires_at: Some(pending.expires_at),
            service_started: false,
            runtime_health: "not_started",
            selected_features: SelectedFeatures {
                computer: self.seed.computer_requested,
                browser: self.seed.browser_requested,
            },
            computer_requested: self.seed.computer_requested,
            verified_runtime: self.candidate.clone(),
        }
    }
}
pub(super) async fn io<T: Send + 'static>(
    mut work: Work,
    job: impl FnOnce(&mut Work) -> Result<T> + Send + 'static,
) -> Result<(Work, T)> {
    blocking(move || match job(&mut work) {
        Ok(value) => Ok((work, value)),
        Err(error) => Err(error.keep(Retained::Work {
            _work: Box::new(work),
        })),
    })
    .await
}
fn caller_manager(scope: Option<&crate::app::HostScope>) -> NativeManager {
    if scope.is_some() {
        NativeManager::AppManaged
    } else {
        NativeManager::ForegroundCli
    }
}
fn validate_app_scope(scope: Option<&crate::app::HostScope>, path: &Path) -> Result<()> {
    if let Some(scope) = scope {
        if path != scope.state_dir() {
            return Err(bad());
        }
        scope
            .validate()
            .map_err(|_| JoinError::new("native_join_app_scope_changed", 4))?;
    }
    Ok(())
}
fn candidate_for_load(
    selected: &NativeRuntimeSelection,
    retained: Option<Arc<release::VerifiedNativeRelease>>,
) -> Result<Arc<release::VerifiedNativeRelease>> {
    let candidate = match retained {
        Some(candidate) => {
            // Create or the original App owner may pass its formal object.
            // Revalidate the retained selection and native image identities;
            // ordinary loading does not repeat install-time asset scanning.
            candidate
                .revalidate_matches_selection(selected)
                .map_err(|_| JoinError::new("native_join_candidate_untrusted", 2))?;
            candidate
        }
        None => Arc::new(
            release::load_selected(selected)
                .map_err(|_| JoinError::new("native_join_candidate_untrusted", 2))?,
        ),
    };
    Ok(candidate)
}
pub(super) fn load_with_candidate(
    store: NativeHostJoinStore,
    path: PathBuf,
    app_scope: Option<Arc<crate::app::HostScope>>,
    candidate: Option<Arc<release::VerifiedNativeRelease>>,
) -> Result<Work> {
    let loaded: Result<_> = (|| {
        validate_app_scope(app_scope.as_deref(), &path)?;
        let (state, seed) = store.readstate_and_seed().map_err(|_| unknown())?;
        if !state
            .state()
            .desired
            .host
            .as_ref()
            .is_some_and(|host| host.manager == caller_manager(app_scope.as_deref()))
        {
            return Err(bad());
        }
        let root = PrivateRoot::open(&path).map_err(|_| unknown())?;
        if store
            .configuration_root()
            .identity()
            .map_err(|_| unknown())?
            != root.identity()
        {
            return Err(unknown());
        }
        let seed_raw = Zeroizing::new(seed.to_vec());
        let seed: NativeHostJoinSeed = serde_json::from_slice(&seed_raw).map_err(|_| unknown())?;
        let deployment_input = Input::open(&path.join("deployment.json"), LIMIT)?;
        let (d, origin, browser_requested) = deployment(&deployment_input.raw)?;
        let ca = Input::open(&path.join("host-ca.pem"), 128 * 1024)?;
        let private = Input::open(&path.join("host-identity.pem"), 16 * 1024)?;
        let key = DevicePrivateKey::from_pkcs8_pem(&private.raw).map_err(|_| unknown())?;
        // The original store read above proves the complete C07 history.
        let selected = state
            .state()
            .runtime_selection()
            .map_err(|_| unknown())?
            .ok_or_else(unknown)?;
        let update = state.state().runtime_update().map_err(|_| unknown())?;
        let bootstrap = update
            .as_ref()
            .map_or(&selected, |update| &update.bootstrap_runtime);
        if update.is_some() && store.read(File::Ready).map_err(|_| unknown())?.is_none() {
            // Updating an incomplete enrollment cannot authorize replaying a
            // request/claim/confirm, including App-managed updates.
            return Err(bad());
        }
        let candidate = candidate_for_load(&selected, candidate)?;
        // The cold verifier or retained-candidate boundary above performed
        // complete original-root/publisher validation and exact selection
        // comparison. Reader support is part
        // of that same immutable authenticated manifest, not a new boundary.
        if !candidate
            .manifest()
            .minimum_reader
            .supports_state_reader(state.state().reader_contract)
        {
            return Err(bad());
        }
        if !matches!(seed.schema, 1 | 2)
            || (seed.schema == 2
                && state.state().reader_contract != ReaderContract::NativePairingLifecycleStateV1)
            || (seed.schema == 1
                && state.state().reader_contract == ReaderContract::NativePairingLifecycleStateV1
                && update.is_none())
            || seed.root_identity != identity(&root)
            || seed.scope_generation != state.state().scope_generation
            || seed.deployment_raw_sha256 != Sha256Digest::of_bytes(&deployment_input.raw)
            || seed.deployment_raw_sha256 != state.state().deployment_raw_sha256
            || seed.gateway_origin != d.gateway.url
            || seed.anchor_sha256 != d.gateway.expected_ca_sha256
            || &seed.runtime != bootstrap
            || selected.publisher_spki_sha256 != seed.runtime.publisher_spki_sha256
            || seed.label != d.host.label
            || seed.cwd != text(&d.host.cwd)?
            || seed.shell != text(&d.host.shell)?
            || seed.computer_requested != d.host.computer
            || seed.browser_requested != browser_requested
            || seed.platform != PLATFORM
            || Sha256Digest::of_bytes(key.public_key().spki_der()) != seed.fingerprint
            || crate::crypto::DevicePublicKey::from_spki_pem(seed.public_key_pem.as_bytes())
                .map_err(|_| unknown())?
                .spki_der()
                != key.public_key().spki_der()
        {
            return Err(unknown());
        }
        let client = tls(&ca.raw, seed.anchor_sha256)?;
        Ok((
            root,
            seed,
            seed_raw,
            key,
            client,
            origin,
            candidate,
            vec![deployment_input, ca, private],
        ))
    })();
    let (root, seed, seed_raw, key, tls, origin, candidate, inputs) = match loaded {
        Ok(value) => value,
        Err(error) => {
            return Err(error.keep(Retained::Store {
                _store: Box::new(store),
            }));
        }
    };
    let work = Work {
        store,
        root,
        state_dir: path,
        seed,
        seed_raw,
        key,
        tls,
        origin,
        candidate,
        inputs,
        app_scope,
    };
    if let Err(error) = work.validate() {
        return Err(error.keep(Retained::Work {
            _work: Box::new(work),
        }));
    }
    Ok(work)
}
pub(super) fn create(
    parent: &Path,
    name: &OsStr,
    deployment_file: &Path,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> Result<(Work, Zeroizing<Vec<u8>>)> {
    if !parent.is_absolute() {
        return Err(bad());
    }
    validate_app_scope(app_scope.as_deref(), &parent.join(name))?;
    let source = Input::open(deployment_file, LIMIT)?;
    let (d, _, browser_requested) = deployment(&source.raw)?;
    let selection_input = Input::open(&d.runtime_selection_file, LIMIT)?;
    let selection: NativeRuntimeSelection =
        serde_json::from_slice(&selection_input.raw).map_err(|_| bad())?;
    let candidate = release::load_selected(&selection)
        .map_err(|_| JoinError::new("native_join_candidate_untrusted", 2))?;
    if !candidate
        .manifest()
        .minimum_reader
        .supports_state_reader(ReaderContract::NativePairingLifecycleStateV1)
    {
        return Err(JoinError::new("native_join_reader_unsupported", 2));
    }
    // verify_selected already binds the exact original selection. The full
    // release is checked again below at the actual root-creation boundary.
    let ca = Input::open(&d.gateway.ca_file, 128 * 1024)?;
    let _ = tls(&ca.raw, d.gateway.expected_ca_sha256)?;
    let invitation_input = Input::open(&d.invitation_file, 4096)?;
    let invitation = std::str::from_utf8(&invitation_input.raw)
        .map_err(|_| bad())?
        .trim();
    if invitation.is_empty() {
        return Err(bad());
    }
    let generated = DevicePrivateKey::generate_rsa3072()
        .map_err(|_| JoinError::new("native_join_identity_generation_failed", 3))?;
    let mut random = [0u8; 12];
    getrandom::fill(&mut random)
        .map_err(|_| JoinError::new("native_join_entropy_unavailable", 3))?;
    let device_id =
        DeviceId::try_from(format!("styx-{}", hex::encode(random))).map_err(|_| bad())?;
    let parent_root = PrivateRoot::open(parent).map_err(|_| bad())?;
    for input in [&source, &selection_input, &ca, &invitation_input] {
        input.revalidate()?;
    }
    candidate.revalidate().map_err(|_| unknown())?;
    // Validate the original App parent again immediately before creation.
    validate_app_scope(app_scope.as_deref(), &parent.join(name))?;
    let fresh = native_root::create_fresh(&parent_root, name).map_err(JoinError::root)?;
    if let Some(scope) = &app_scope
        && scope.bind().and_then(|()| scope.validate()).is_err()
    {
        return Err(
            JoinError::new("native_join_app_scope_changed", 4).keep(Retained::Fresh {
                _root: Box::new(fresh),
            }),
        );
    }
    let metadata: Result<_> = (|| {
        let seed = NativeHostJoinSeed {
            schema: styx_contracts::native_host::NATIVE_HOST_JOIN_SEED_SCHEMA,
            root_identity: fresh.marker().root_identity.clone(),
            scope_generation: fresh.marker().scope_generation,
            deployment_raw_sha256: Sha256Digest::of_bytes(&source.raw),
            runtime: selection.clone(),
            gateway_origin: d.gateway.url.clone(),
            anchor_sha256: d.gateway.expected_ca_sha256,
            device_id,
            fingerprint: Sha256Digest::of_bytes(generated.public_key().spki_der()),
            public_key_pem: generated.public_key_pem().to_owned(),
            label: d.host.label.clone(),
            platform: PLATFORM.into(),
            cwd: text(&d.host.cwd)?,
            shell: text(&d.host.shell)?,
            computer_requested: d.host.computer,
            browser_requested,
        };
        let join = protocol::make_join(&seed, invitation, generated.private_key())
            .map_err(protocol_error)?;
        let seed_raw = Zeroizing::new(serde_json::to_vec(&seed).map_err(|_| bad())?);
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "fresh_host_seed_v1".into(),
            serde_json::value::to_raw_value(&Sha256Digest::of_bytes(&seed_raw))
                .map_err(|_| bad())?,
        );
        extensions.insert(
            "runtime_selection_v1".into(),
            serde_json::value::to_raw_value(&selection).map_err(|_| bad())?,
        );
        let state = NativeState {
            schema: NATIVE_PAIRING_LIFECYCLE_STATE_SCHEMA,
            kind: NativeStateKind::StyxDesiredState,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            reader_contract: ReaderContract::NativePairingLifecycleStateV1,
            scope_generation: seed.scope_generation,
            deployment_raw_sha256: seed.deployment_raw_sha256,
            mode: NativeDeploymentMode::JoinExisting,
            revision: 0,
            last_transaction: None,
            desired: NativeDesired {
                gateway: None,
                host: Some(NativeComponentDesired {
                    manager: caller_manager(app_scope.as_deref()),
                    run: NativeRunDesired::Stopped,
                    autostart: NativeAutostartDesired::Disabled,
                }),
            },
            migration: None,
            extensions,
        };
        Ok((seed_raw, state, join))
    })();
    let (seed_raw, state, join) = match metadata {
        Ok(value) => value,
        Err(error) => {
            return Err(error.keep(Retained::Fresh {
                _root: Box::new(fresh),
            }));
        }
    };
    let seconds = match clock_ms() {
        Ok(now) => now / 1000,
        Err(error) => {
            return Err(error.keep(Retained::Fresh {
                _root: Box::new(fresh),
            }));
        }
    };
    let material = FreshHostFiles {
        ca_certificate_pem: &ca.raw,
        private_identity_pem: generated.protected_pkcs8_pem(),
        seed_binding: &seed_raw,
    };
    let store = fresh
        .initialize_host_pending(&source.raw, &state, material, seconds)
        .map_err(JoinError::root)?;
    // Retain the exact candidate admitted before root creation. The loader
    // still derives selection from the original store/C07 chain and performs
    // a complete exact-selection revalidation before retaining it in Work.
    let mut work = load_with_candidate(
        store,
        parent.join(name),
        app_scope,
        Some(Arc::new(candidate)),
    )?;
    // Before dispatch recheck the caller's original source/CA/invitation too.
    for input in [source, selection_input, ca, invitation_input] {
        if let Err(error) = input.revalidate() {
            return Err(error.keep(Retained::Work {
                _work: Box::new(work),
            }));
        }
    }
    if let Err(error) = work.append(File::JoinDispatched, &join) {
        return Err(error.keep(Retained::Work {
            _work: Box::new(work),
        }));
    }
    Ok((work, join))
}
pub(super) fn open_with_candidate(
    path: &Path,
    app_scope: Option<Arc<crate::app::HostScope>>,
    candidate: Option<Arc<release::VerifiedNativeRelease>>,
) -> Result<Work> {
    if !path.is_absolute() {
        return Err(bad());
    }
    validate_app_scope(app_scope.as_deref(), path)?;
    let root = PrivateRoot::open(path).map_err(|_| bad())?;
    let writer = root
        .try_existing_configuration_writer()
        .map_err(|_| JoinError::new("native_join_configuration_busy", 3))?;
    let binding = native_root::reopen_native(root, writer).map_err(JoinError::root)?;
    let store = NativeHostJoinStore::from_binding(binding).map_err(JoinError::root)?;
    load_with_candidate(store, path.to_path_buf(), app_scope, candidate)
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod retained_candidate_tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
    use std::{
        fs,
        io::Write as _,
        os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    };

    // Actual private files and a synthetic signing key; no worker execution,
    // pairing, external publisher key or platform acceptance is claimed.
    #[test]
    fn retained_join_candidate_rejects_selection_other_release_and_changed_member() {
        fn directory(path: &Path) {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        fn write(path: &Path, bytes: &[u8], executable: bool) {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(if executable { 0o700 } else { 0o600 })
                .open(path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        let root =
            std::env::temp_dir().join(format!("styx-join-retained-{}", uuid::Uuid::new_v4()));
        directory(&root);
        let key = SigningKey::from_bytes(&[37u8; 32]);
        let der = key.verifying_key().to_public_key_der().unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
        );
        let publisher = root.join("publisher.pem");
        write(&publisher, pem.as_bytes(), false);
        let expected = crate::crypto::PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
            .unwrap()
            .fingerprint()
            .unwrap();
        let make = |name: &str| {
            let payload = root.join(name);
            directory(&payload);
            directory(&payload.join("bin"));
            let sources = [
                (
                    "LICENSE",
                    b"synthetic join fixture license".as_slice(),
                    false,
                ),
                (
                    "bin/styx",
                    b"\x7fELF synthetic join fixture, never executed".as_slice(),
                    true,
                ),
                (
                    "source-inputs.json",
                    b"synthetic source inputs".as_slice(),
                    false,
                ),
            ];
            let files: Vec<_> = sources
                .iter()
                .map(|(name, bytes, executable)| {
                    write(&payload.join(name), bytes, *executable);
                    styx_contracts::native_release::NativeReleaseMember {
                        path: (*name).to_owned(),
                        size: bytes.len() as u64,
                        sha256: Sha256Digest::of_bytes(bytes),
                        executable: *executable,
                    }
                })
                .collect();
            let manifest = serde_json::json!({"schema":2,"runtime_format":"native_rust_v1","component":"styx",
                "scope":"runtime_candidate","minimum_reader":"native_runtime_migrated_v3","target":"x86_64-unknown-linux-gnu",
                "version":"0.4.0-test.1","entrypoint":"bin/styx","source":{"revision":"1".repeat(40),
                "inputs_sha256":Sha256Digest::of_bytes(sources[2].1)},"contracts":{"control":1,"management_state":2},
                "files":files,"external_workers":[]});
            let raw = serde_json::to_vec(&manifest).unwrap();
            write(&payload.join("manifest.json"), &raw, false);
            write(
                &payload.join("manifest.sig"),
                &key.sign(&raw).to_bytes(),
                false,
            );
            let verified = release::verify(&payload, &publisher, &expected).unwrap();
            let selected = verified.runtime_selection().unwrap();
            (Arc::new(verified), selected)
        };
        let (original, selected) = make("original");
        let accepted = candidate_for_load(&selected, Some(original)).unwrap();
        let mut wrong = selected.clone();
        wrong.manifest_sha256 = Sha256Digest::of_bytes(b"wrong manifest");
        assert!(candidate_for_load(&wrong, Some(accepted)).is_err());
        let (other, _) = make("other");
        assert!(candidate_for_load(&selected, Some(other)).is_err());
        // Cold load reads installed metadata, not the complete payload.
        let original = candidate_for_load(&selected, None).unwrap();
        let member = root.join("original/source-inputs.json");
        let mut file = fs::OpenOptions::new().write(true).open(member).unwrap();
        file.write_all(b"changed").unwrap();
        file.sync_all().unwrap();
        drop(file);
        candidate_for_load(&selected, Some(original.clone())).unwrap();
        assert!(release::verify_selected(&selected).is_err());
        let image = root.join("original/bin/styx");
        let mut file = fs::OpenOptions::new().write(true).open(image).unwrap();
        file.write_all(b"changed").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(candidate_for_load(&selected, Some(original)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

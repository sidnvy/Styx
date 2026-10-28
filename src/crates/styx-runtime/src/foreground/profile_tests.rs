#[cfg(target_os = "linux")]
mod linux {
    use super::super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };
    struct Fixture {
        root: PathBuf,
        state: PathBuf,
        base: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_exec("enabled")
        }
        fn with_exec(exec_mode: &str) -> Self {
            let root = std::env::temp_dir().join(format!("styx-profile-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let fixture = Self {
                state: root.join("state"),
                base: root.join("host"),
                root: root.clone(),
            };
            let script = r#"const fs=require('node:fs'),path=require('node:path'),c=require('node:crypto');
const root=process.argv[1],base=path.join(root,'host'),state=path.join(root,'state'),release=path.join(base,'install/releases/fixture-1');
for(const d of [state,base,path.join(base,'device'),path.join(base,'install'),path.join(base,'install/releases'),release,path.join(release,'bin')])fs.mkdirSync(d,{mode:0o700});
const put=(p,b,x=false)=>fs.writeFileSync(p,b,{mode:x?0o700:0o600,flag:'wx'}),sha=b=>c.createHash('sha256').update(b).digest('hex');
const publisher=c.generateKeyPairSync('ed25519'),device=c.generateKeyPairSync('rsa',{modulusLength:3072});
const pub=publisher.publicKey.export({type:'spki',format:'pem'}),dp=device.publicKey.export({type:'spki',format:'pem'}),fingerprint=sha(device.publicKey.export({type:'spki',format:'der'}));
put(path.join(base,'publisher.pem'),pub);put(path.join(base,'device/identity.pem'),device.privateKey.export({type:'pkcs8',format:'pem'}));
const id='styx-1234567890abcdef12345678';put(path.join(base,'device/identity.json'),JSON.stringify({version:1,device_id:id,platform:'linux',fingerprint,public_key_pem:dp,created_at:'fixture'}));put(path.join(base,'device/host.token'),'a'.repeat(64)+'\n');
const ca=fs.readFileSync(process.argv[2]);put(path.join(base,'gateway-ca.pem'),ca);
put(path.join(base,'device/host.json'),JSON.stringify({host_id:id,gateway_ws_url:'wss://127.0.0.1:37719/',token_file:path.join(base,'device/host.token'),gateway_ca_file:path.join(base,'gateway-ca.pem'),exec:process.argv[3]==='absent'?null:{enabled:process.argv[3]==='enabled'?undefined:false,binary:'/untrusted/config-selected-codex',cwd:root,env:{CODEX_HOME:path.join(root,'codex-home')}}}));
const member=process.argv[3]==='enabled'?'bin/codex':'bin/node',binary=fs.readFileSync('/usr/bin/true');put(path.join(release,member),binary,true);
const manifest=JSON.stringify({schema:1,version:'fixture-1',platform:'linux',arch:process.arch,upstream:{fixture:true},files:[{path:member,sha256:sha(binary),size:binary.length,executable:true}]},null,2)+'\n';put(path.join(release,'manifest.json'),manifest);put(path.join(release,'manifest.sig'),c.sign(null,Buffer.from(manifest),publisher.privateKey).toString('base64url')+'\n');
put(path.join(base,'install/active.json'),JSON.stringify({schema:1,version:'fixture-1',previous:null,manifest_sha256:sha(manifest)}));
const config=JSON.stringify({schema:1,mode:'join-existing',gateway:{url:'https://127.0.0.1:37719/'},host:{baseDir:base,publisherSha256:sha(publisher.publicKey.export({type:'spki',format:'der'}))}});put(path.join(state,'deployment.json'),config);put(path.join(state,'state.json'),JSON.stringify({schema:1,mode:'join-existing',configSha256:sha(config),steps:['host.prepare','host.doctor','host.pair'].map(id=>({id,status:'succeeded'}))}));
"#;
            // A disposable test CA is not a live trust store or platform acceptance.
            let ca = root.join("fixture-ca.pem");
            let key = root.join("fixture-ca.key");
            let output = Command::new("openssl")
                .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
                .arg(&key)
                .arg("-out")
                .arg(&ca)
                .args(["-days", "1", "-subj", "/CN=Styx isolated profile fixture"])
                .output()
                .unwrap();
            assert!(output.status.success(), "owned openssl fixture failed");
            fs::set_permissions(&ca, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            let output = Command::new("node")
                .arg("-e")
                .arg(script)
                .arg(&root)
                .arg(&ca)
                .arg(exec_mode)
                .output()
                .unwrap();
            assert!(output.status.success(), "owned Node signed fixture failed");
            fixture
        }
        fn release(&self) -> PathBuf {
            self.base.join("install/releases/fixture-1")
        }
    }
    /// Signed closure still validates without a Codex member; these fixtures
    /// exercise configuration only and never start the dummy signed worker.
    #[test]
    fn ordinary_profiles_never_alias_a_retired_credential_locator() {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        let legacy = load_legacy(&fixture.state).unwrap();
        let paired = load_paired(&fixture.state).unwrap();
        let original = fixture.base.join("device/host.token");
        let retired = fixture
            .base
            .join("device/.styx-retired-host-token-profile-test");
        let before = fs::metadata(&original).unwrap();
        let raw = zeroize::Zeroizing::new(fs::read(&original).unwrap());
        let host_json = fs::read(fixture.base.join("device/host.json")).unwrap();
        let active = fs::read(fixture.base.join("install/active.json")).unwrap();
        // This owned filesystem negative is deliberately NOT a retirement proof:
        // no writer/journal/settlement attestation or migration reader is minted.
        fs::rename(&original, &retired).unwrap();
        let after = fs::metadata(&retired).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(before.mode(), after.mode());
        assert!(fs::read(&retired).unwrap().as_slice() == raw.as_slice());
        assert!(!original.exists());
        assert!(load_legacy(&fixture.state).is_err());
        assert!(load_paired(&fixture.state).is_err());
        assert!(legacy.revalidate().is_err());
        assert!(paired.revalidate().is_err());
        assert!(fs::read(fixture.base.join("device/host.json")).unwrap() == host_json);
        assert!(fs::read(fixture.base.join("install/active.json")).unwrap() == active);
        assert!(
            !original.exists(),
            "reader must never restore the old locator"
        );
    }

    #[test]
    fn paired_disabled_or_absent_exec_keeps_protected_worker_inputs() {
        for mode in ["disabled", "absent"] {
            let f = Fixture::with_exec(mode);
            let raw = fs::read(f.base.join("device/host.json")).unwrap();
            let paired = load_paired(&f.state).unwrap();
            assert!(!paired.executor_enabled());
            assert!(matches!(
                paired.executor_config(),
                Err(ProfileError::Unsupported)
            ));
            assert!(matches!(
                load_legacy(&f.state),
                Err(ProfileError::Unsupported)
            ));
            assert_eq!(
                paired.cwd,
                if mode == "disabled" {
                    f.root.clone()
                } else {
                    PathBuf::new()
                }
            );
            paired.revalidate().unwrap();
            assert_eq!(fs::read(f.base.join("device/host.json")).unwrap(), raw);
            fs::write(f.release().join("bin/node"), b"tampered worker").unwrap();
            assert!(matches!(paired.revalidate(), Err(ProfileError::Changed)));
            assert!(matches!(
                load_paired(&f.state),
                Err(ProfileError::UntrustedRelease)
            ));
        }
    }
    #[test]
    fn signed_profile_binding_preservation_and_provenance_counterexamples() {
        let f = Fixture::new();
        let host = f.base.join("device/host.json");
        let before = Sha256Digest::of_bytes(&fs::read(&host).unwrap());
        let loaded = load_legacy(&f.state).unwrap();
        assert_eq!(loaded.device_id().as_str(), "styx-1234567890abcdef12345678");
        assert_eq!(
            loaded.diagnostics().endpoint.as_str(),
            "wss://127.0.0.1:37719/styx/hosts/styx-1234567890abcdef12345678/exec"
        );
        let config = loaded.executor_config().unwrap();
        assert!(config.binary.to_string_lossy().starts_with("/proc/"));
        assert_ne!(
            config.binary,
            PathBuf::from("/untrusted/config-selected-codex")
        );
        assert_eq!(config.environment.len(), 1);
        assert_eq!(
            config.environment.get("CODEX_HOME"),
            Some(&f.root.join("codex-home").to_string_lossy().into_owned())
        );
        assert_eq!(Sha256Digest::of_bytes(&fs::read(&host).unwrap()), before);
        let active = f.base.join("install/active.json");
        let original = fs::read(&active).unwrap();
        fs::write(&active, b"{}").unwrap();
        assert!(matches!(loaded.revalidate(), Err(ProfileError::Changed)));
        fs::write(&active, original).unwrap();
        let extra = f.release().join("unsigned-extra");
        fs::write(&extra, b"extra").unwrap();
        fs::set_permissions(&extra, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_legacy(&f.state),
            Err(ProfileError::UntrustedRelease)
        ));
        fs::remove_file(extra).unwrap();
        let binary = f.release().join("bin/codex");
        fs::write(&binary, b"replaced executable").unwrap();
        assert!(matches!(
            load_legacy(&f.state),
            Err(ProfileError::UntrustedRelease)
        ));
    }
    /// Real disposable RSA/Ed25519/TLS fixture; only protected loading is
    /// exercised. No native executor, Gateway request or account migration runs.
    #[test]
    fn paired_route_retains_original_trust_and_uses_ca_namespace() {
        let f = Fixture::new();
        let protected = [
            f.state.join("deployment.json"),
            f.state.join("state.json"),
            f.base.join("publisher.pem"),
            f.base.join("device/identity.json"),
            f.base.join("device/identity.pem"),
            f.base.join("device/host.json"),
            f.base.join("device/host.token"),
            f.base.join("gateway-ca.pem"),
            f.base.join("install/active.json"),
            f.release().join("manifest.json"),
            f.release().join("manifest.sig"),
            f.release().join("bin/codex"),
        ];
        let originals: Vec<_> = protected
            .iter()
            .map(|path| Sha256Digest::of_bytes(&fs::read(path).unwrap()))
            .collect();
        let legacy = load_legacy(&f.state).unwrap();
        let paired = load_paired(&f.state).unwrap();
        assert_eq!(legacy.diagnostics().wire_mode, "explicit_legacy_gateway");
        assert_eq!(paired.diagnostics().wire_mode, "paired_v3");
        assert_eq!(
            paired.diagnostics().runtime_format,
            "legacy_js_v1_executor_only"
        );
        assert_eq!(
            legacy.endpoint().as_str(),
            "wss://127.0.0.1:37719/styx/hosts/styx-1234567890abcdef12345678/exec"
        );
        assert_eq!(
            paired.endpoint().as_str(),
            "wss://127.0.0.1:37719/styx/host/v3/styx-1234567890abcdef12345678/exec"
        );
        let ca = fs::read(f.base.join("gateway-ca.pem")).unwrap();
        let ca_der = rustls_pemfile::certs(&mut Cursor::new(&ca))
            .next()
            .unwrap()
            .unwrap();
        let expected = GatewayId::try_from(format!(
            "paired.{}",
            Sha256Digest::of_bytes(&ca_der).to_hex()
        ))
        .unwrap();
        assert_eq!(paired.paired_gateway_namespace(), expected);
        assert_eq!(legacy.paired_gateway_namespace(), expected);
        assert_eq!(paired.device_id(), legacy.device_id());
        assert_eq!(
            paired.diagnostics().manifest_sha256,
            legacy.diagnostics().manifest_sha256
        );
        assert_eq!(
            paired.executor_config().unwrap().environment,
            legacy.executor_config().unwrap().environment
        );
        paired.revalidate().unwrap();
        for (path, original) in protected.iter().zip(&originals) {
            assert_eq!(Sha256Digest::of_bytes(&fs::read(path).unwrap()), *original);
        }
        // An origin change still invalidates the captured profile, but loading
        // that same CA at another address must retain its paired namespace.
        let config_file = f.state.join("deployment.json");
        let state_file = f.state.join("state.json");
        let host_file = f.base.join("device/host.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_file).unwrap()).unwrap();
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
        let mut host: serde_json::Value =
            serde_json::from_slice(&fs::read(&host_file).unwrap()).unwrap();
        config["gateway"]["url"] = serde_json::json!("https://LOCALHOST:443/");
        host["gateway_ws_url"] = serde_json::json!("wss://localhost/");
        let raw_config = serde_json::to_vec(&config).unwrap();
        state["configSha256"] = serde_json::json!(Sha256Digest::of_bytes(&raw_config).to_hex());
        fs::write(&config_file, raw_config).unwrap();
        fs::write(&state_file, serde_json::to_vec(&state).unwrap()).unwrap();
        fs::write(&host_file, serde_json::to_vec(&host).unwrap()).unwrap();
        assert!(matches!(paired.revalidate(), Err(ProfileError::Changed)));
        assert!(matches!(legacy.revalidate(), Err(ProfileError::Changed)));
        let normalized = load_paired(&f.state).unwrap();
        assert_eq!(
            normalized.endpoint().as_str(),
            "wss://localhost/styx/host/v3/styx-1234567890abcdef12345678/exec"
        );
        assert_eq!(normalized.paired_gateway_namespace(), expected);
        host["gateway_ws_url"] = serde_json::json!("wss://localhost:444/");
        fs::write(&host_file, serde_json::to_vec(&host).unwrap()).unwrap();
        assert!(matches!(load_paired(&f.state), Err(ProfileError::Invalid)));
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        host["gateway_ws_url"] = serde_json::json!("wss://localhost/");
        host["host_id"] = serde_json::json!("styx-wrong-device");
        fs::write(&host_file, serde_json::to_vec(&host).unwrap()).unwrap();
        assert!(matches!(load_paired(&f.state), Err(ProfileError::Invalid)));
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        host["host_id"] = serde_json::json!("styx-1234567890abcdef12345678");
        fs::write(&host_file, serde_json::to_vec(&host).unwrap()).unwrap();
        let identity_file = f.base.join("device/identity.json");
        let mut identity: serde_json::Value =
            serde_json::from_slice(&fs::read(&identity_file).unwrap()).unwrap();
        identity["fingerprint"] = serde_json::json!("0".repeat(64));
        fs::write(identity_file, serde_json::to_vec(&identity).unwrap()).unwrap();
        assert!(matches!(load_paired(&f.state), Err(ProfileError::Invalid)));
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
    }
    #[test]
    fn paired_gateway_namespace_matches_fresh_profiles_for_loopback_and_private_origins() {
        let f = Fixture::new();
        let ca = fs::read(f.base.join("gateway-ca.pem")).unwrap();
        let der = rustls_pemfile::certs(&mut Cursor::new(&ca))
            .next()
            .unwrap()
            .unwrap();
        let ca_hash = Sha256Digest::of_bytes(&der);
        let gateway =
            crate::tls::paired_gateway_namespace(&TrustAnchorPin::from_certificate_der(&der));
        let config_file = f.state.join("deployment.json");
        let state_file = f.state.join("state.json");
        let host_file = f.base.join("device/host.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_file).unwrap()).unwrap();
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
        let mut host: serde_json::Value =
            serde_json::from_slice(&fs::read(&host_file).unwrap()).unwrap();
        for origin in [
            "https://127.0.0.1:37719",
            "https://10.0.2.19:37719",
            "https://10.118.53.220:37719",
        ] {
            config["gateway"]["url"] = serde_json::json!(format!("{origin}/"));
            host["gateway_ws_url"] =
                serde_json::json!(format!("{}/", origin.replacen("https:", "wss:", 1)));
            let raw = serde_json::to_vec(&config).unwrap();
            state["configSha256"] = serde_json::json!(Sha256Digest::of_bytes(&raw).to_hex());
            fs::write(&config_file, raw).unwrap();
            fs::write(&state_file, serde_json::to_vec(&state).unwrap()).unwrap();
            fs::write(&host_file, serde_json::to_vec(&host).unwrap()).unwrap();
            let paired = load_paired(&f.state).unwrap();
            let legacy = load_legacy(&f.state).unwrap();
            let (endpoint, fresh_namespace, _) =
                fresh_connection_profile(origin, paired.device_id(), ca_hash, &ca).unwrap();
            assert_eq!(paired.endpoint().as_str(), endpoint.as_str());
            assert_eq!(paired.paired_gateway_namespace(), gateway);
            assert_eq!(legacy.paired_gateway_namespace(), gateway);
            assert_eq!(fresh_namespace, gateway);
            paired.revalidate().unwrap();
        }
        // No primary Gateway identity can be selected from a multi-CA trust set.
        // Legacy-v2 still loads exactly that trust set without using paired-v3.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let other = crate::tls::generate_gateway_ca(now, now - 60, now + 86400).unwrap();
        for bundle in [
            [ca.as_slice(), other.certificate_pem.as_slice()].concat(),
            [other.certificate_pem.as_slice(), ca.as_slice()].concat(),
        ] {
            fs::write(f.base.join("gateway-ca.pem"), bundle).unwrap();
            assert!(matches!(
                load_paired(&f.state),
                Err(ProfileError::Unsupported)
            ));
            assert!(load_legacy(&f.state).is_ok());
        }
    }

    #[test]
    fn state_transaction_and_publisher_pins_remain_authoritative() {
        let f = Fixture::new();
        let statefile = f.state.join("state.json");
        let original = fs::read(&statefile).unwrap();
        let mut state: serde_json::Value = serde_json::from_slice(&original).unwrap();
        state["activeStep"] = serde_json::json!("host.claim");
        fs::write(&statefile, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        state["activeStep"] = serde_json::Value::Null;
        state["steps"][0]["status"] = serde_json::json!("uncertain");
        fs::write(&statefile, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        fs::write(&statefile, &original).unwrap();
        let configfile = f.state.join("deployment.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&configfile).unwrap()).unwrap();
        config["host"]["publisherSha256"] = serde_json::json!("0".repeat(64));
        let raw = serde_json::to_vec(&config).unwrap();
        fs::write(&configfile, &raw).unwrap();
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        let mut state: serde_json::Value = serde_json::from_slice(&original).unwrap();
        state["configSha256"] = serde_json::json!(Sha256Digest::of_bytes(&raw).to_hex());
        fs::write(&statefile, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(matches!(
            load_legacy(&f.state),
            Err(ProfileError::UntrustedRelease)
        ));
    }
    #[test]
    fn identity_publisher_private_paths_and_tls_cannot_be_substituted() {
        let f = Fixture::new();
        let profile = f.base.join("device/host.json");
        let original = fs::read(&profile).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["gateway_ws_url"] = serde_json::json!("ws://127.0.0.1:37719/");
        fs::write(&profile, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            load_legacy(&f.state),
            Err(ProfileError::Unsupported)
        ));
        value["gateway_ws_url"] = serde_json::json!("wss://127.0.0.1:37720/");
        fs::write(&profile, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        fs::write(&profile, &original).unwrap();
        let mut unsupported: serde_json::Value = serde_json::from_slice(&original).unwrap();
        unsupported["exec"]["env"]["LD_PRELOAD"] = serde_json::json!("/tmp/unsigned.so");
        fs::write(&profile, serde_json::to_vec(&unsupported).unwrap()).unwrap();
        assert!(matches!(
            load_legacy(&f.state),
            Err(ProfileError::UnsupportedExecutorEnvironment)
        ));
        fs::write(&profile, &original).unwrap();
        let identity = f.base.join("device/identity.json");
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(&identity).unwrap()).unwrap();
        let original_identity = v.clone();
        v["platform"] = serde_json::json!("darwin");
        fs::write(&identity, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        v = original_identity;
        v["fingerprint"] = serde_json::json!("0".repeat(64));
        fs::write(&identity, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(load_legacy(&f.state), Err(ProfileError::Invalid)));
        let f = Fixture::new();
        let p = f.base.join("publisher.pem");
        let saved = f.base.join("publisher-original.pem");
        fs::rename(&p, &saved).unwrap();
        symlink(&saved, &p).unwrap();
        assert!(matches!(
            load_legacy(&f.state),
            Err(ProfileError::ProtectedRead)
        ));
        let f = Fixture::new();
        let p = f.state.join("deployment.json");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_legacy(&f.state),
            Err(ProfileError::ProtectedRead)
        ));
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn unsupported_platform_does_not_read_or_fall_back() {
    assert!(matches!(
        super::load_legacy(std::path::Path::new("/nonexistent")),
        Err(super::ProfileError::Unsupported)
    ));
    assert!(matches!(
        super::load_paired(std::path::Path::new("/nonexistent")),
        Err(super::ProfileError::Unsupported)
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_only_admits_explicit_paired_profile_loading() {
    assert!(matches!(
        super::load_legacy(std::path::Path::new("/nonexistent")),
        Err(super::ProfileError::Unsupported)
    ));
    assert!(matches!(
        super::load_paired(std::path::Path::new("/nonexistent")),
        Err(super::ProfileError::ProtectedRead)
    ));
}

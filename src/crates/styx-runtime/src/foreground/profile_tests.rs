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
put(path.join(base,'device/host.json'),JSON.stringify({host_id:id,gateway_ws_url:'wss://127.0.0.1:37719/',token_file:path.join(base,'device/host.token'),gateway_ca_file:path.join(base,'gateway-ca.pem'),exec:{binary:'/untrusted/config-selected-codex',cwd:root,env:{CODEX_HOME:path.join(root,'codex-home')}}}));
const binary=fs.readFileSync('/usr/bin/true');put(path.join(release,'bin/codex'),binary,true);
const manifest=JSON.stringify({schema:1,version:'fixture-1',platform:'linux',arch:process.arch,upstream:{fixture:true},files:[{path:'bin/codex',sha256:sha(binary),size:binary.length,executable:true}]},null,2)+'\n';put(path.join(release,'manifest.json'),manifest);put(path.join(release,'manifest.sig'),c.sign(null,Buffer.from(manifest),publisher.privateKey).toString('base64url')+'\n');
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
                .output()
                .unwrap();
            assert!(output.status.success(), "owned Node signed fixture failed");
            fixture
        }
        fn release(&self) -> PathBuf {
            self.base.join("install/releases/fixture-1")
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
#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_does_not_read_or_fall_back() {
    assert!(matches!(
        super::load_legacy(std::path::Path::new("/nonexistent")),
        Err(super::ProfileError::Unsupported)
    ));
}

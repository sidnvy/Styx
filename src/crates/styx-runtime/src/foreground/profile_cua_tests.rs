//! Original signature/inventory + explicit protected selection integration.
//! Disposable test publisher and /usr/bin/true payloads: no Cua/native readiness.
use super::*;
use crate::crypto::PublisherSigningKey;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};
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
        let root = std::env::temp_dir().join(format!("styx-profile-cua-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            state: root.join("state"),
            base: root.join("host"),
            root,
        };
        let ca = fixture.root.join("fixture-ca.pem");
        let key = fixture.root.join("fixture-ca.key");
        let output = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&ca)
            .args([
                "-days",
                "1",
                "-subj",
                "/CN=Styx isolated Cua profile fixture",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "owned fixture CA failed");
        for path in [&ca, &key] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let script = r#"const fs=require('node:fs'),path=require('node:path'),c=require('node:crypto');
const root=process.argv[1],base=path.join(root,'host'),state=path.join(root,'state'),release=path.join(base,'install/releases/fixture-cua');
for(const d of [state,base,path.join(base,'device'),path.join(base,'install'),path.join(base,'install/releases'),release,path.join(release,'bin')])fs.mkdirSync(d,{mode:0o700});
const put=(p,b,x=false)=>fs.writeFileSync(p,b,{mode:x?0o700:0o600,flag:'wx'}),sha=b=>c.createHash('sha256').update(b).digest('hex');
const publisher=c.generateKeyPairSync('ed25519'),device=c.generateKeyPairSync('rsa',{modulusLength:3072});
const pub=publisher.publicKey.export({type:'spki',format:'pem'}),dp=device.publicKey.export({type:'spki',format:'pem'}),fingerprint=sha(device.publicKey.export({type:'spki',format:'der'}));
put(path.join(base,'publisher.pem'),pub);put(path.join(root,'owned-fixture-publisher.pem'),publisher.privateKey.export({type:'pkcs8',format:'pem'}));
put(path.join(base,'device/identity.pem'),device.privateKey.export({type:'pkcs8',format:'pem'}));const id='styx-1234567890abcdef12345678';put(path.join(base,'device/identity.json'),JSON.stringify({version:1,device_id:id,platform:'linux',fingerprint,public_key_pem:dp}));put(path.join(base,'device/host.token'),'a'.repeat(64)+'\n');
put(path.join(base,'gateway-ca.pem'),fs.readFileSync(process.argv[2]));
put(path.join(base,'device/host.json'),JSON.stringify({host_id:id,gateway_ws_url:'wss://127.0.0.1:37719/',token_file:path.join(base,'device/host.token'),gateway_ca_file:path.join(base,'gateway-ca.pem'),exec:{binary:'/ignored-exec',cwd:root},computer:{enabled:true,binary:'/ignored-mutable-cua',connections:1,env:{CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}}}));
const config=JSON.stringify({schema:1,mode:'join-existing',gateway:{url:'https://127.0.0.1:37719/'},host:{baseDir:base,publisherSha256:sha(publisher.publicKey.export({type:'spki',format:'der'})),computer:true}});put(path.join(state,'deployment.json'),config);put(path.join(state,'state.json'),JSON.stringify({schema:1,mode:'join-existing',configSha256:sha(config),steps:['host.prepare','host.doctor','host.pair'].map(id=>({id,status:'succeeded'}))}));
for(const name of ['codex','cua-driver'])put(path.join(release,'bin',name),fs.readFileSync('/usr/bin/true'),true);
"#;
        let output = Command::new("node")
            .arg("-e")
            .arg(script)
            .arg(&fixture.root)
            .arg(ca)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "owned signed profile fixture failed"
        );
        fixture.sign_release("cua-driver 0.36.0", Some(true));
        fixture
    }
    fn release(&self) -> PathBuf {
        self.base.join("install/releases/fixture-cua")
    }
    fn write_json(&self, path: &Path, value: &serde_json::Value) {
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn sign_release(&self, version: &str, cua_executable: Option<bool>) {
        let mut files = Vec::new();
        for (name, executable) in
            std::iter::once(("codex", true)).chain(cua_executable.map(|x| ("cua-driver", x)))
        {
            let file = self.release().join("bin").join(name);
            let bytes = fs::read(&file).unwrap();
            fs::set_permissions(
                file,
                fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }),
            )
            .unwrap();
            files.push(serde_json::json!({"path":format!("bin/{name}"),"size":bytes.len(),"sha256":Sha256Digest::of_bytes(&bytes).to_hex(),"executable":executable}));
        }
        let manifest = serde_json::json!({"schema":1,"version":"fixture-cua","platform":"linux","arch":match std::env::consts::ARCH{"x86_64"=>"x64","aarch64"=>"arm64",_=>panic!("fixture architecture unsupported")},"upstream":{"cua":version},"files":files});
        let raw = serde_json::to_vec(&manifest).unwrap();
        let private = zeroize::Zeroizing::new(
            fs::read(self.root.join("owned-fixture-publisher.pem")).unwrap(),
        );
        let signer = PublisherSigningKey::from_pkcs8_pem(&private).unwrap();
        let signature = URL_SAFE_NO_PAD
            .encode(signer.sign_manifest(RawReleaseManifest::from_original_bytes(&raw)));
        fs::write(self.release().join("manifest.json"), &raw).unwrap();
        fs::write(self.release().join("manifest.sig"), signature).unwrap();
        for name in ["manifest.json", "manifest.sig"] {
            fs::set_permissions(self.release().join(name), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        self.write_json(&self.base.join("install/active.json"),&serde_json::json!({"schema":1,"version":"fixture-cua","previous":null,"manifest_sha256":Sha256Digest::of_bytes(&raw).to_hex()}));
    }
    fn selection(&self, deployment: serde_json::Value, host: serde_json::Value) {
        let path = self.state.join("deployment.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        config["host"]["computer"] = deployment;
        self.write_json(&path, &config);
        let path = self.state.join("state.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state["configSha256"] = serde_json::json!(
            Sha256Digest::of_bytes(&fs::read(self.state.join("deployment.json")).unwrap()).to_hex()
        );
        self.write_json(&path, &state);
        let path = self.base.join("device/host.json");
        let mut profile: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        profile["computer"] = host;
        self.write_json(&path, &profile);
    }
}
#[test]
fn original_signed_cua_pin_requires_both_selections_and_exact_member_provenance() {
    let fixture = Fixture::new();
    let protected = [
        fixture.state.join("deployment.json"),
        fixture.state.join("state.json"),
        fixture.base.join("device/host.json"),
        fixture.base.join("publisher.pem"),
        fixture.base.join("install/active.json"),
        fixture.release().join("manifest.json"),
        fixture.release().join("manifest.sig"),
        fixture.release().join("bin/cua-driver"),
    ];
    let before: Vec<_> = protected
        .iter()
        .map(|p| Sha256Digest::of_bytes(&fs::read(p).unwrap()))
        .collect();
    let loaded = load_paired(&fixture.state).unwrap();
    let pin = loaded.pin_cua_driver().unwrap().unwrap();
    let launch = pin.launch_path().unwrap();
    assert!(launch.to_string_lossy().starts_with("/proc/"));
    assert_ne!(launch, PathBuf::from("/ignored-mutable-cua"));
    pin.revalidate().unwrap();
    loaded.revalidate().unwrap();
    for (path, hash) in protected.iter().zip(before) {
        assert_eq!(Sha256Digest::of_bytes(&fs::read(path).unwrap()), hash);
    }
    let enabled =
        serde_json::json!({"enabled":true,"binary":"/ignored-mutable-cua","connections":1});
    fixture.selection(
        serde_json::json!(true),
        serde_json::json!({"enabled":false}),
    );
    assert!(matches!(
        loaded.pin_cua_driver(),
        Err(ProfileError::Changed)
    ));
    let disabled = load_paired(&fixture.state).unwrap();
    assert!(disabled.pin_cua_driver().unwrap().is_none());
    assert!(disabled.executor_config().is_ok());
    fixture.selection(serde_json::json!(false), enabled.clone());
    assert!(
        load_paired(&fixture.state)
            .unwrap()
            .pin_cua_driver()
            .unwrap()
            .is_none()
    );
    for host in [
        serde_json::json!({"enabled":true,"socket":"/tmp/not-owned"}),
        serde_json::json!({"enabled":true,"env":{"LD_PRELOAD":"/not-authorized"}}),
        serde_json::json!({"enabled":true,"connections":2}),
        serde_json::json!({"enabled":true,"futureMode":true}),
    ] {
        fixture.selection(serde_json::json!(true), host);
        let profile = load_paired(&fixture.state).unwrap();
        assert!(profile.executor_config().is_ok());
        assert!(matches!(
            profile.pin_cua_driver(),
            Err(ProfileError::Unsupported)
        ));
    }
    fixture.selection(serde_json::json!(true), enabled);
    fixture.sign_release("cua-driver 0.35.0", Some(true));
    let wrong_version = load_paired(&fixture.state).unwrap();
    assert!(wrong_version.executor_config().is_ok());
    assert!(matches!(
        wrong_version.pin_cua_driver(),
        Err(ProfileError::UntrustedRelease)
    ));
    fixture.sign_release("cua-driver 0.36.0", Some(false));
    assert!(matches!(
        load_paired(&fixture.state).unwrap().pin_cua_driver(),
        Err(ProfileError::UntrustedRelease)
    ));
    fs::remove_file(fixture.release().join("bin/cua-driver")).unwrap();
    fixture.sign_release("cua-driver 0.36.0", None);
    assert!(matches!(
        load_paired(&fixture.state).unwrap().pin_cua_driver(),
        Err(ProfileError::UntrustedRelease)
    ));
    fs::copy("/usr/bin/true", fixture.release().join("bin/cua-driver")).unwrap();
    fixture.sign_release("cua-driver 0.36.0", Some(true));
    let original = load_paired(&fixture.state).unwrap();
    let original_pin = original.pin_cua_driver().unwrap().unwrap();
    fs::write(
        fixture.release().join("bin/cua-driver"),
        b"tampered fixture image",
    )
    .unwrap();
    assert!(original_pin.revalidate().is_err());
    assert!(matches!(
        original.pin_cua_driver(),
        Err(ProfileError::Changed)
    ));
    assert!(matches!(
        load_paired(&fixture.state),
        Err(ProfileError::UntrustedRelease)
    ));
}

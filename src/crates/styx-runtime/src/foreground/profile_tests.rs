#[cfg(target_os = "linux")]
mod linux {
    use super::super::*;
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
    }
    #[test]
    fn legacy_signed_profile_is_not_a_native_runtime_fallback() {
        let fixture = Fixture::new();
        let state = fs::read(fixture.state.join("state.json")).unwrap();
        let identity = fs::read(fixture.base.join("device/identity.json")).unwrap();
        let token = fs::read(fixture.base.join("device/host.token")).unwrap();
        assert!(load_paired(&fixture.state).is_err());
        assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), state);
        assert_eq!(
            fs::read(fixture.base.join("device/identity.json")).unwrap(),
            identity
        );
        assert_eq!(
            fs::read(fixture.base.join("device/host.token")).unwrap(),
            token
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn computer_configuration_does_not_adopt_arbitrary_worker_connections() {
    use serde_json::json;
    assert!(!super::computer_selected(None, None).unwrap());
    assert!(
        !super::computer_selected(Some(&json!(false)), Some(&json!({"enabled":true}))).unwrap()
    );
    assert!(
        super::computer_selected(
            Some(&json!(true)),
            Some(&json!({"enabled":true,"connections":1}))
        )
        .unwrap()
    );
    assert!(
        super::computer_selected(
            Some(&json!(true)),
            Some(&json!({"enabled":true,"connections":2}))
        )
        .is_err()
    );
    assert!(
        super::computer_selected(
            Some(&json!(true)),
            Some(&json!({"enabled":true,"socket":"/other-worker"}))
        )
        .is_err()
    );
}

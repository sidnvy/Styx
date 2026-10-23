//! Anonymous owned Node22 keys generate real legacy wire proofs. No private
//! PEM, token or real identity leaves the child or is written to a fixture file.
use super::*;
use std::process::Command;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedJoin {
    payload: JoinPayload,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedCapability {
    payload: CapabilityPayload,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    node: String,
    joins: Vec<SignedJoin>,
    capability_v1: SignedCapability,
    capability_v2: SignedCapability,
    other_public: String,
    unsupported_public: String,
    wrong_join_signature: String,
    wrong_salt_signature: String,
}
const NODE: &str = r#"
import {generateKeyPairSync, sign, createHash, constants} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const {joinPayload,capabilityPayload}=await import(pathToFileURL(process.env.STYX_TEST_PROFILE_PROTOCOL).href);
const make=bits=>generateKeyPairSync('rsa',{modulusLength:bits});
const a=make(3072),b=make(3072),small=make(2048);
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const publicPem=pem(a);
const base={invitation:'owned_invitation_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',device_id:'styx-0123456789abcdef01234567',label:'设备 Alpha １２３',platform:'linux',cwd:'/tmp/owned',shell:'/bin/SH',computer_requested:true,public_key_pem:publicPem,browser_requested:false};
const signBytes=(bytes,key=a.privateKey,saltLength=32)=>sign('sha256',Buffer.from(bytes),{key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength}).toString('base64url');
const absent={...base};delete absent.browser_requested;
const joins=[base,absent,{...base,platform:'win32',cwd:'C:\\工作',shell:'C:\\Windows\\PowerShell.EXE'},{...base,platform:'win32',cwd:'\\工作',shell:'\\Program Files\\pwsh.EXE'},{...base,platform:'darwin',cwd:'/Users/owned',shell:'/bin/ZSH'},{...base,cwd:'/'+'😀'.repeat(255)}].map(payload=>({payload,signature:signBytes(joinPayload(payload))}));
const fingerprint=createHash('sha256').update(a.publicKey.export({type:'spki',format:'der'})).digest('hex');
const c1={device_id:base.device_id,fingerprint,generation:'paired-original-owned',enable_computer:true};
const c2={device_id:base.device_id,fingerprint,generation:'capability-owned-next',enable_computer:false,enable_browser:true};
console.log(JSON.stringify({node:process.version,joins,capability_v1:{payload:c1,signature:signBytes(capabilityPayload(c1))},capability_v2:{payload:c2,signature:signBytes(capabilityPayload(c2))},other_public:pem(b),unsupported_public:pem(small),wrong_join_signature:signBytes(joinPayload(base),b.privateKey),wrong_salt_signature:signBytes(joinPayload(base),a.privateKey,20)}));
"#;

/// One new focused crypto/profile batch, not the old complete interop batch.
#[test]
#[ignore = "requires STYX_TEST_NODE22 fixed Node22; owned real RSA/PSS typed-profile batch"]
fn actual_node22_profile_join_and_capability_proofs() {
    let node = std::env::var("STYX_TEST_NODE22").expect("set explicit fixed Node22 path");
    let protocol = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../shared/enrollment-protocol.mjs");
    let output = Command::new(node)
        .args(["--input-type=module", "-e", NODE])
        .env("STYX_TEST_PROFILE_PROTOCOL", protocol)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "owned public-vector Node fixture failed"
    );
    assert!(output.stdout.len() <= 128 * 1024);
    let fixture: Fixture = serde_json::from_slice(&output.stdout).unwrap();
    assert!(fixture.node.starts_with("v22."));
    assert_eq!(fixture.joins.len(), 6);
    for vector in &fixture.joins {
        let verified = verify_join(&vector.payload, &vector.signature).unwrap();
        assert_eq!(verified.profile().device_id, vector.payload.device_id);
        assert_eq!(verified.profile().platform, vector.payload.platform);
        assert_eq!(verified.profile().cwd, vector.payload.cwd);
        assert_eq!(verified.profile().schema, 1);
        assert_eq!(
            verified.fingerprint(),
            fixture.capability_v1.payload.fingerprint
        );
        assert_eq!(
            fingerprint(verified.public_key()).unwrap(),
            verified.fingerprint()
        );
        let stored = VerifiedProfile::from_stored(verified.raw_profile_bytes()).unwrap();
        assert_eq!(stored.raw_profile_bytes(), verified.raw_profile_bytes());
        assert_eq!(stored.fingerprint(), verified.fingerprint());
        let raw = std::str::from_utf8(verified.raw_profile_bytes()).unwrap();
        assert!(!raw.contains(&vector.payload.invitation));
        assert!(!raw.contains("\"invitation\""));
        assert!(!raw.contains("\"claim\""));
        assert!(!raw.contains("\"token\""));
        assert!(!raw.contains("\"signature\""));
    }
    let join = &fixture.joins[0];
    let verified = verify_join(&join.payload, &join.signature).unwrap();
    for capability in [&fixture.capability_v1, &fixture.capability_v2] {
        verified
            .verify_capability(
                &capability.payload,
                &join.payload.public_key_pem,
                &capability.signature,
            )
            .unwrap();
        let crlf = join.payload.public_key_pem.replace('\n', "\r\n");
        verified
            .verify_capability(&capability.payload, &crlf, &capability.signature)
            .unwrap();
        assert_eq!(
            verified.verify_capability(
                &capability.payload,
                &fixture.other_public,
                &capability.signature
            ),
            Err(ProfileError::CapabilityKey)
        );
    }
    let mut changed = fixture.capability_v1.payload.clone();
    changed.enable_computer = Some(false);
    assert_eq!(
        verified.verify_capability(
            &changed,
            &join.payload.public_key_pem,
            &fixture.capability_v1.signature
        ),
        Err(ProfileError::Proof)
    );
    changed.device_id = DeviceId::try_from("styx-1123456789abcdef01234567").unwrap();
    assert_eq!(
        verified.verify_capability(
            &changed,
            &join.payload.public_key_pem,
            &fixture.capability_v1.signature
        ),
        Err(ProfileError::CapabilityIdentity)
    );
    assert_eq!(
        verify_join(&join.payload, &fixture.wrong_join_signature).unwrap_err(),
        ProfileError::Proof
    );
    assert_eq!(
        verify_join(&join.payload, &fixture.wrong_salt_signature).unwrap_err(),
        ProfileError::Proof
    );
    assert_eq!(
        verify_join(&join.payload, &format!("{}=", join.signature)).unwrap_err(),
        ProfileError::Signature
    );
    let mut changed = join.payload.clone();
    changed.label = "Valid but changed label".into();
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Proof
    );
    changed = join.payload.clone();
    changed.browser_requested = None;
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Proof,
        "absent browser flag differs from explicitly false"
    );
    changed = join.payload.clone();
    changed.invitation = "short".into();
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Invitation
    );
    changed = join.payload.clone();
    changed.device_id = DeviceId::try_from("generic-id").unwrap();
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::DeviceId
    );
    for label in ["bad\nlabel", "emoji😀", "trailing newline\n"] {
        changed = join.payload.clone();
        changed.label = label.into();
        assert_eq!(
            verify_join(&changed, &join.signature).unwrap_err(),
            ProfileError::Label
        );
    }
    changed = join.payload.clone();
    changed.label = "a".repeat(73);
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Label
    );
    changed = join.payload.clone();
    changed.platform = "freebsd".into();
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Platform
    );
    changed = join.payload.clone();
    changed.cwd = "relative/path".into();
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Cwd
    );
    changed = join.payload.clone();
    changed.cwd = format!("/{}", "😀".repeat(256));
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Cwd,
        "UTF16 units, not code-point count"
    );
    changed = fixture.joins[2].payload.clone();
    changed.cwd = "C:relative".into();
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::Cwd
    );
    for shell in ["/bin/fish", "/bin/ſh", "relative/sh"] {
        changed = join.payload.clone();
        changed.shell = shell.into();
        assert_eq!(
            verify_join(&changed, &join.signature).unwrap_err(),
            ProfileError::Shell
        );
    }
    changed = join.payload.clone();
    changed.public_key_pem = fixture.unsupported_public;
    assert_eq!(
        verify_join(&changed, &join.signature).unwrap_err(),
        ProfileError::PublicKey,
        "actual RSA2048 identity is unsupported"
    );
    let mut stored = verified.profile().clone();
    stored.fingerprint = Sha256Digest::of_bytes(b"wrong SPKI");
    assert_eq!(
        VerifiedProfile::from_stored(&serde_json::to_vec(&stored).unwrap()).unwrap_err(),
        ProfileError::Fingerprint
    );
    stored = verified.profile().clone();
    stored.public_key_pem = fixture.other_public;
    assert_eq!(
        VerifiedProfile::from_stored(&serde_json::to_vec(&stored).unwrap()).unwrap_err(),
        ProfileError::Fingerprint
    );
    stored = verified.profile().clone();
    stored.schema = 2;
    assert_eq!(
        VerifiedProfile::from_stored(&serde_json::to_vec(&stored).unwrap()).unwrap_err(),
        ProfileError::Schema
    );
    #[derive(Serialize)]
    struct Unexpected<'a> {
        #[serde(flatten)]
        profile: &'a StoredProfile,
        invitation: &'static str,
    }
    let unexpected = serde_json::to_vec(&Unexpected {
        profile: verified.profile(),
        invitation: "must not be persisted",
    })
    .unwrap();
    assert_eq!(
        VerifiedProfile::from_stored(&unexpected).unwrap_err(),
        ProfileError::Schema
    );
    assert_eq!(
        VerifiedProfile::from_stored(&vec![b' '; MAX_BODY + 1]).unwrap_err(),
        ProfileError::Size
    );
    println!(
        "PROFILE_PROOF_OBSERVATION {}",
        serde_json::json!({"node":fixture.node,"validSignedJoinVectors":6,"legacyBrowserAbsentDistinctFromFalse":true,"originalFingerprint":verified.fingerprint(),"exactCapabilityV1V2Verified":true,"wrongSPKIAndSaltRefused":true,"typedProfileRestoredWithoutSecretFields":true,"privateKeysLeftChild":false,"liveIdentityOrNetworkReadyClaim":false})
    );
}

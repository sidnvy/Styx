//! Ordinary fresh native Host reader. Snapshot owns protected local bindings;
//! C08 owns signed workers; neither local DATA nor this adapter grants tools.
use super::*;
use crate::store::native_host_snapshot::NativeHostSnapshot;
#[cfg(target_os = "linux")]
use serde_json::Value;

#[derive(Deserialize)]
struct FreshDeployment {
    schema: u16,
    mode: String,
    #[cfg(target_os = "linux")]
    host: FreshHost,
    #[cfg(target_os = "windows")]
    #[serde(rename = "host")]
    _host: FreshHost,
}
#[derive(Deserialize)]
struct FreshHost {
    #[cfg(target_os = "linux")]
    computer: Option<Value>,
    #[cfg(target_os = "linux")]
    browser: Option<Value>,
}

pub(super) fn load(state_dir: &Path) -> Result<LoadedLegacyProfile, ProfileError> {
    absolute(state_dir)?;
    let snapshot =
        Arc::new(NativeHostSnapshot::open(state_dir).map_err(|_| ProfileError::Changed)?);
    snapshot.revalidate().map_err(|_| ProfileError::Changed)?;
    let seed = snapshot.seed();
    let ready = snapshot.ready();
    if seed.schema != 1
        || ready.schema != 1
        || seed.platform
            != if cfg!(target_os = "windows") {
                "win32"
            } else {
                "linux"
            }
        || seed.device_id != ready.device_id
        || seed.fingerprint != ready.fingerprint
        || snapshot.state_dir() != state_dir
    {
        return Err(ProfileError::Invalid);
    }
    let private = DevicePrivateKey::from_pkcs8_pem(snapshot.private_identity_pem())
        .map_err(|_| ProfileError::Invalid)?;
    let public = DevicePublicKey::from_spki_pem(seed.public_key_pem.as_bytes())
        .map_err(|_| ProfileError::Invalid)?;
    if private.public_key().spki_der() != public.spki_der()
        || public.fingerprint().as_hex() != seed.fingerprint.to_hex()
    {
        return Err(ProfileError::Invalid);
    }
    let gateway = origin(&seed.gateway_origin, "https")?;
    let normalized_origin = gateway.origin().ascii_serialization();
    if normalized_origin != seed.gateway_origin {
        return Err(ProfileError::Invalid);
    }
    let mut endpoint = gateway;
    endpoint
        .set_scheme("wss")
        .map_err(|_| ProfileError::Invalid)?;
    endpoint.set_path(&format!("/styx/host/v3/{}/exec", seed.device_id.as_str()));
    let endpoint_text = endpoint.to_string();
    let endpoint = LinkEndpoint::parse(endpoint.as_str()).map_err(|_| ProfileError::Invalid)?;
    let paired_namespace = GatewayId::try_from(format!(
        "paired.{}",
        Sha256Digest::of_bytes(normalized_origin.as_bytes()).to_hex()
    ))
    .map_err(|_| ProfileError::Invalid)?;
    let ca = snapshot.ca_pem();
    let certs = rustls_pemfile::certs(&mut Cursor::new(ca))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProfileError::Invalid)?;
    if certs.len() != 1
        || TrustAnchorPin::from_certificate_der(&certs[0]).as_hex() != seed.anchor_sha256.to_hex()
    {
        return Err(ProfileError::Invalid);
    }
    let tls = GatewayClientTls::from_pinned_ca_bundle(
        ca,
        &[TrustAnchorPin::from_certificate_der(&certs[0])],
        None,
    )
    .map_err(|_| ProfileError::Invalid)?;
    let token = std::str::from_utf8(snapshot.credential()).map_err(|_| ProfileError::Invalid)?;
    if !(32..=4096).contains(&token.len())
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(ProfileError::Invalid);
    }
    let bearer =
        SecretBearer::from_protected_reader(token.to_owned()).map_err(|_| ProfileError::Invalid)?;
    let expected = PublisherFingerprint::parse(&seed.runtime.publisher_spki_sha256.to_hex())
        .map_err(|_| ProfileError::UntrustedRelease)?;
    let inventory = release::ProfileRelease::from_native_selection(&seed.runtime, &expected)?;
    let executor = if inventory.has_worker(NativeExternalWorker::CodexExec) {
        Some(Arc::new(
            inventory.pin_worker(NativeExternalWorker::CodexExec)?,
        ))
    } else {
        None
    };
    let cwd = PathBuf::from(&seed.cwd);
    let shell = Path::new(&seed.shell);
    absolute(&cwd)?;
    absolute(shell)?;
    if seed.cwd.len() > 4096
        || seed.shell.len() > 4096
        || seed.cwd.contains('\0')
        || seed.shell.contains('\0')
    {
        return Err(ProfileError::Invalid);
    }
    let mut capture = Capture {
        observed: vec![],
        public: vec![],
    };
    let deployment_raw = capture.read(state_dir, "deployment.json", JSON_LIMIT)?;
    if Sha256Digest::of_bytes(&deployment_raw) != seed.deployment_raw_sha256 {
        return Err(ProfileError::Changed);
    }
    let deployment: FreshDeployment = decode(&deployment_raw)?;
    if deployment.schema != 1 || deployment.mode != "join-existing" {
        return Err(ProfileError::Invalid);
    }
    // Only Linux implements these native Browser/Computer factories. Remote
    // approvals are not local feature configuration or Windows desktop authority.
    #[cfg(target_os = "linux")]
    let computer = seed.computer_requested && deployment.host.computer == Some(Value::Bool(true));
    #[cfg(target_os = "linux")]
    let deployment_computer = Some(Value::Bool(computer));
    #[cfg(target_os = "linux")]
    let host_computer = Some(serde_json::json!({
        "enabled":computer,"connections":1,"env":{"CUA_DRIVER_RS_ENABLE_WAYLAND":"1"}
    }));
    #[cfg(target_os = "linux")]
    let deployment_browser = if seed.browser_requested {
        deployment.host.browser
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let host_browser = deployment_browser.clone().map(|mut value| {
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "profileRoot".into(),
                Value::String(state_dir.join("browser").to_string_lossy().into_owned()),
            );
        }
        value
    });
    #[cfg(target_os = "linux")]
    let release_root = inventory.browser_release_root();
    #[cfg(target_os = "linux")]
    let browser_node_version = inventory.browser_node_version();
    #[cfg(target_os = "linux")]
    let cua_version = inventory.cua_version();
    #[cfg(target_os = "windows")]
    let environment = super::super::windows_env::executor_environment(&BTreeMap::new(), state_dir)?;
    #[cfg(not(target_os = "windows"))]
    let environment = BTreeMap::new();
    let signed_version = inventory.version().to_owned();
    let loaded = LoadedLegacyProfile {
        host_base_dir: state_dir.to_path_buf(),
        device: seed.device_id.clone(),
        endpoint,
        paired_namespace,
        tls,
        bearer,
        executor,
        inventory,
        #[cfg(target_os = "linux")]
        release_root,
        #[cfg(target_os = "linux")]
        browser_node_version,
        #[cfg(target_os = "linux")]
        cua_version,
        #[cfg(target_os = "linux")]
        deployment_computer,
        #[cfg(target_os = "linux")]
        host_computer,
        #[cfg(target_os = "linux")]
        deployment_browser,
        #[cfg(target_os = "linux")]
        host_browser,
        cwd,
        environment,
        #[cfg(target_os = "windows")]
        runtime_temp: std::sync::OnceLock::new(),
        rpc_timeout: Duration::from_millis(35000),
        observed: capture.observed,
        diagnostics: ProfileDiagnostics {
            schema: 1,
            device_id: seed.device_id.clone(),
            endpoint: endpoint_text,
            runtime_format: "native_rust_v1_fresh_host_profile",
            wire_mode: "paired_v3",
            version: signed_version,
            publisher_sha256: expected.as_hex().to_owned(),
            manifest_sha256: seed.runtime.manifest_sha256,
            preservation: capture.public,
            tool_health: "NOT RUN",
            account_acceptance: "NOT RUN",
        },
        source: ProfileSource::Fresh(snapshot),
    };
    loaded.revalidate()?;
    Ok(loaded)
}

//! Manage the same private settings consumed by the Gateway on startup.
pub use crate::gateway::auth::public_mcp::{PublicMcpAuthentication, PublicMcpConfig};
use crate::{
    gateway::auth::public_mcp::{CONFIG_FILE, PublicMcp, read_config, read_secret},
    store::PrivateRoot,
};
use serde_json::Value;
use std::{ffi::OsStr, path::Path};
use zeroize::Zeroizing;

pub fn status(state: &Path) -> Result<Option<Value>, &'static str> {
    Ok(PublicMcp::load(state)
        .map_err(|_| "gateway_public_mcp_configuration_invalid")?
        .map(|public| public.client_connection()))
}

pub(crate) fn configuration_for_owner(
    state: &Path,
) -> Result<Option<PublicMcpConfig>, &'static str> {
    let invalid = "gateway_public_mcp_configuration_invalid";
    let root = PrivateRoot::open(state).map_err(|_| invalid)?;
    Ok(read_config(&root).map_err(|_| invalid)?.map(|mut config| {
        config.secret_file = None;
        config
    }))
}

pub fn read_input_secret(path: &Path) -> Result<Zeroizing<String>, &'static str> {
    let bytes = Zeroizing::new(
        super::setup::read_private(path, 4096).map_err(|_| "gateway_public_mcp_secret_invalid")?,
    );
    let text = std::str::from_utf8(&bytes).map_err(|_| "gateway_public_mcp_secret_invalid")?;
    Ok(Zeroizing::new(
        text.trim_end_matches(['\r', '\n']).to_owned(),
    ))
}

pub(crate) fn validate(
    config: &PublicMcpConfig,
    secret: Option<&str>,
) -> Result<PublicMcp, &'static str> {
    let invalid = "gateway_public_mcp_configuration_invalid";
    if config.secret_file.is_some()
        || serde_json::to_vec(config).map_err(|_| invalid)?.len()
            > styx_contracts::CONTROL_FRAME_BYTES - 128
        || matches!(config.authentication, PublicMcpAuthentication::Bearer) && secret.is_some()
        || secret.is_some_and(|text| text.len() > 4096)
    {
        return Err(invalid);
    }
    PublicMcp::new(config.clone(), || {
        secret
            .map(|text| Zeroizing::new(text.to_owned()))
            .ok_or(crate::gateway::auth::GatewayAuthError::InvalidConfiguration)
    })
    .map_err(|_| invalid)
}

pub fn validate_input(config: &PublicMcpConfig, secret: Option<&str>) -> Result<(), &'static str> {
    validate(config, secret).map(|_| ())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicMcpProbe {
    pub http_status: u16,
    pub bearer_challenge: bool,
    pub resource_metadata_challenge: bool,
}

pub async fn probe(url: &str) -> Result<PublicMcpProbe, &'static str> {
    let unreachable = "gateway_public_mcp_unreachable";
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| unreachable)?;
    let response = client.get(url).send().await.map_err(|_| unreachable)?;
    let challenges = response.headers().get_all(http::header::WWW_AUTHENTICATE);
    let mut bearer_challenge = false;
    let mut resource_metadata_challenge = false;
    for challenge in challenges.iter().filter_map(|value| value.to_str().ok()) {
        if challenge
            .split_whitespace()
            .next()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer"))
        {
            bearer_challenge = true;
            resource_metadata_challenge |= challenge.contains("resource_metadata=");
        }
    }
    Ok(PublicMcpProbe {
        http_status: response.status().as_u16(),
        bearer_challenge,
        resource_metadata_challenge,
    })
}

/// Write while the Gateway is stopped. New credentials are published before
/// replacing the settings that select them, under the same execution lease.
pub fn configure(
    state: &Path,
    mut config: PublicMcpConfig,
    secret: Option<&str>,
) -> Result<Value, &'static str> {
    let public = validate(&config, secret)?;
    let root =
        PrivateRoot::open(state).map_err(|_| "gateway_public_mcp_protected_state_required")?;
    let _lease = root
        .try_execution_lease()
        .map_err(|_| "gateway_public_mcp_stop_required")?;
    let deployment = root
        .read_raw("deployment.json", styx_contracts::CONTROL_FRAME_BYTES)
        .map_err(|_| "gateway_public_mcp_protected_state_required")?;
    let deployment: Value = serde_json::from_slice(deployment.bytes())
        .map_err(|_| "gateway_public_mcp_protected_state_required")?;
    let local = deployment["gateway"]["url"]
        .as_str()
        .and_then(|url| url.strip_prefix("https://"))
        .ok_or("gateway_public_mcp_protected_state_required")?;
    if local == public.authority() {
        return Err("gateway_public_mcp_separate_authority_required");
    }

    let old = read_config(&root).map_err(|_| "gateway_public_mcp_configuration_invalid")?;
    if let Some(previous) = &old {
        let mut previous_config = previous.clone();
        previous_config.secret_file = None;
        let same_secret = match secret {
            Some(secret) => read_secret(&root, previous.secret_file.as_deref())
                .is_ok_and(|stored| stored.as_str() == secret),
            None => true,
        };
        if previous_config == config && same_secret {
            return Ok(public.client_connection());
        }
    }

    if let Some(secret) = secret {
        let file = format!("mcp-oauth-key-{}", uuid::Uuid::new_v4().simple());
        root.create_setup_export(OsStr::new(&file), secret.as_bytes())
            .map_err(|_| "gateway_public_mcp_write_unknown")?;
        config.secret_file = Some(file);
    }
    let json =
        serde_json::to_vec(&config).map_err(|_| "gateway_public_mcp_configuration_invalid")?;
    super::setup::replace_private_file(state, &root, CONFIG_FILE, &json)
        .map_err(|_| "gateway_public_mcp_write_unknown")?;
    if let Some(previous_secret) = old.and_then(|old| old.secret_file)
        && previous_secret.starts_with("mcp-oauth-key-")
        && uuid::Uuid::parse_str(&previous_secret["mcp-oauth-key-".len()..]).is_ok()
    {
        std::fs::remove_file(state.join(previous_secret))
            .map_err(|_| "gateway_public_mcp_old_secret_cleanup_unconfirmed")?;
    }
    Ok(public.client_connection())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn public_configuration_respects_execution_lease_and_rotates_credential_after_commit() {
        let state = tempfile::tempdir().unwrap();
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(state.path()).unwrap();
        root.create_setup_export(
            OsStr::new("deployment.json"),
            br#"{"gateway":{"url":"https://127.0.0.1:22022"}}"#,
        )
        .unwrap();
        let config = PublicMcpConfig::new(
            "https://styx.unit.test/mcp".into(),
            PublicMcpAuthentication::OAuthIntrospection {
                issuer: "https://issuer.unit.test".into(),
                introspection_url: "https://issuer.unit.test/introspect".into(),
                client_id: "styx-test".into(),
                allowed_subjects: ["operator".to_owned()].into_iter().collect(),
            },
        );
        let lock = root.try_execution_lease().unwrap();
        assert_eq!(
            configure(state.path(), config.clone(), Some("first")),
            Err("gateway_public_mcp_stop_required")
        );
        assert!(status(state.path()).unwrap().is_none());
        drop(lock);

        let connection = configure(state.path(), config.clone(), Some("first")).unwrap();
        assert_eq!(status(state.path()).unwrap().unwrap(), connection);
        assert_eq!(connection["authentication"], "oauth");
        let first = read_config(&root).unwrap().unwrap().secret_file.unwrap();
        configure(state.path(), config.clone(), Some("first")).unwrap();
        assert_eq!(
            read_config(&root).unwrap().unwrap().secret_file.as_deref(),
            Some(first.as_str())
        );
        configure(state.path(), config, Some("second")).unwrap();
        let second = read_config(&root).unwrap().unwrap().secret_file.unwrap();
        assert_ne!(first, second);
        assert!(root.ensure_absent(first).is_ok());
        assert_eq!(
            read_secret(&root, Some(&second)).unwrap().as_str(),
            "second"
        );
        assert!(
            !serde_json::to_string(&status(state.path()).unwrap())
                .unwrap()
                .contains("second")
        );
    }
}

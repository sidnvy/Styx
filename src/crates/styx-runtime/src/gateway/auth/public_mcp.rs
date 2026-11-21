//! Explicit external MCP authority. Identity comes from the configured
//! authorization server over HTTPS, never from proxy or client identity claims.
use super::GatewayAuthError;
use crate::store::PrivateRoot;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use styx_contracts::identity::Sha256Digest;
use url::{Position, Url};
use zeroize::Zeroizing;

pub(crate) const CONFIG_FILE: &str = "public-mcp.json";
pub(crate) const SECRET_FILE: &str = "mcp-oauth-client-secret";
pub(crate) const RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicMcpConfig {
    pub url: String,
    #[serde(default)]
    pub allowed_origins: BTreeSet<String>,
    pub authentication: PublicMcpAuthentication,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret_file: Option<String>,
}

impl PublicMcpConfig {
    pub fn new(url: String, authentication: PublicMcpAuthentication) -> Self {
        Self {
            url,
            allowed_origins: BTreeSet::new(),
            authentication,
            secret_file: None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicMcpAuthentication {
    Bearer,
    #[serde(rename = "oauth_introspection")]
    OAuthIntrospection {
        issuer: String,
        introspection_url: String,
        client_id: String,
        allowed_subjects: BTreeSet<String>,
    },
}

pub(crate) struct PublicMcp {
    resource: Url,
    authority: String,
    allowed_origins: BTreeSet<String>,
    oauth: Option<OAuthIntrospection>,
}

impl PublicMcp {
    pub(crate) fn load(state: &Path) -> Result<Option<Self>, GatewayAuthError> {
        let invalid = GatewayAuthError::InvalidConfiguration;
        let root = PrivateRoot::open(state).map_err(|_| invalid)?;
        let Some(config) = read_config(&root)? else {
            return Ok(None);
        };
        let file = config.secret_file.clone();
        Self::new(config, || read_secret(&root, file.as_deref())).map(Some)
    }

    pub(crate) fn new(
        config: PublicMcpConfig,
        read_secret: impl FnOnce() -> Result<Zeroizing<String>, GatewayAuthError>,
    ) -> Result<Self, GatewayAuthError> {
        let invalid = GatewayAuthError::InvalidConfiguration;
        let resource = https_url(&config.url)?;
        if resource.path() != "/mcp" || resource.as_str() != config.url {
            return Err(invalid);
        }
        for origin in &config.allowed_origins {
            if https_url(origin)?.origin().ascii_serialization() != *origin {
                return Err(invalid);
            }
        }
        let oauth = match config.authentication {
            PublicMcpAuthentication::Bearer => None,
            PublicMcpAuthentication::OAuthIntrospection {
                issuer,
                introspection_url,
                client_id,
                allowed_subjects,
            } => {
                https_url(&issuer)?;
                let endpoint = https_url(&introspection_url)?;
                let secret = read_secret()?;
                if !nonempty(&client_id)
                    || !nonempty(&secret)
                    || allowed_subjects.is_empty()
                    || !allowed_subjects.iter().all(|subject| nonempty(subject))
                {
                    return Err(invalid);
                }
                let metadata_url = resource.join(RESOURCE_METADATA_PATH).map_err(|_| invalid)?;
                let challenge =
                    HeaderValue::from_str(&format!(r#"Bearer resource_metadata="{metadata_url}""#))
                        .map_err(|_| invalid)?;
                let metadata = serde_json::to_vec(&serde_json::json!({
                    "resource": resource.as_str(),
                    "authorization_servers": [issuer],
                    "bearer_methods_supported": ["header"]
                }))
                .map_err(|_| invalid)?;
                let client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|_| invalid)?;
                Some(OAuthIntrospection {
                    resource: config.url,
                    issuer,
                    endpoint,
                    client,
                    client_id: form_component(&client_id),
                    secret: Zeroizing::new(form_component(&secret)),
                    allowed_subjects,
                    challenge,
                    metadata,
                })
            }
        };
        Ok(Self {
            authority: resource[Position::BeforeHost..Position::AfterPort].to_owned(),
            resource,
            allowed_origins: config.allowed_origins,
            oauth,
        })
    }

    pub(crate) fn client_connection(&self) -> serde_json::Value {
        serde_json::json!({
            "url": self.resource.as_str(),
            "authentication": if self.oauth.is_some() { "oauth" } else { "bearer" }
        })
    }

    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    pub(super) fn allowed_origins(&self) -> &BTreeSet<String> {
        &self.allowed_origins
    }

    pub(in crate::gateway) fn oauth(&self) -> Option<&OAuthIntrospection> {
        self.oauth.as_ref()
    }
}

pub(crate) fn read_config(root: &PrivateRoot) -> Result<Option<PublicMcpConfig>, GatewayAuthError> {
    if root.ensure_absent(CONFIG_FILE).is_ok() {
        return Ok(None);
    }
    let invalid = GatewayAuthError::InvalidConfiguration;
    let raw = root
        .read_raw(CONFIG_FILE, styx_contracts::CONTROL_FRAME_BYTES)
        .map_err(|_| invalid)?;
    serde_json::from_slice(raw.bytes())
        .map(Some)
        .map_err(|_| invalid)
}

pub(crate) fn read_secret(
    root: &PrivateRoot,
    generation: Option<&str>,
) -> Result<Zeroizing<String>, GatewayAuthError> {
    let invalid = GatewayAuthError::InvalidConfiguration;
    let file = generation.unwrap_or(SECRET_FILE);
    if file != SECRET_FILE
        && !file.strip_prefix("mcp-oauth-key-").is_some_and(|suffix| {
            suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        })
    {
        return Err(invalid);
    }
    let raw = root.read_raw(file, 4096).map_err(|_| invalid)?;
    let value = std::str::from_utf8(raw.bytes()).map_err(|_| invalid)?;
    Ok(Zeroizing::new(value.to_owned()))
}

pub(in crate::gateway) struct OAuthIntrospection {
    resource: String,
    issuer: String,
    endpoint: Url,
    client: reqwest::Client,
    client_id: String,
    secret: Zeroizing<String>,
    allowed_subjects: BTreeSet<String>,
    pub(in crate::gateway) challenge: HeaderValue,
    pub(in crate::gateway) metadata: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Deserialize)]
struct TokenStatus {
    active: bool,
    exp: Option<u64>,
    nbf: Option<u64>,
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    token_type: Option<String>,
}

impl OAuthIntrospection {
    pub(super) async fn authenticate(&self, token: &str) -> Result<Sha256Digest, GatewayAuthError> {
        if token.is_empty()
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return Err(GatewayAuthError::Unauthenticated);
        }
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("token_type_hint", "access_token")
            .finish();
        let unavailable = GatewayAuthError::AuthorizationUnavailable;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .basic_auth(&self.client_id, Some(self.secret.as_str()))
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form)
            .send()
            .await
            .map_err(|_| unavailable)?
            .error_for_status()
            .map_err(|_| unavailable)?;
        if !response.status().is_success() {
            return Err(unavailable);
        }
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable)? {
            if data.len() + chunk.len() > styx_contracts::CONTROL_FRAME_BYTES {
                return Err(unavailable);
            }
            data.extend_from_slice(&chunk);
        }
        let status = serde_json::from_slice(&data).map_err(|_| unavailable)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unavailable)?
            .as_secs();
        self.principal(status, now)
    }

    fn principal(&self, status: TokenStatus, now: u64) -> Result<Sha256Digest, GatewayAuthError> {
        let unauthenticated = GatewayAuthError::Unauthenticated;
        let accepts_resource = match status.aud {
            Some(Audience::Single(aud)) => aud == self.resource,
            Some(Audience::Multiple(aud)) => aud.contains(&self.resource),
            None => false,
        };
        if !status.active
            || !status.exp.is_some_and(|exp| exp > now)
            || status.nbf.is_some_and(|nbf| nbf > now)
            || status.iss.as_deref() != Some(self.issuer.as_str())
            || !status
                .token_type
                .is_some_and(|kind| kind.eq_ignore_ascii_case("Bearer"))
            || !accepts_resource
        {
            return Err(unauthenticated);
        }
        let subject = status.sub.filter(|s| nonempty(s)).ok_or(unauthenticated)?;
        if !self.allowed_subjects.contains(&subject) {
            return Err(GatewayAuthError::Forbidden);
        }
        let identity = serde_json::to_vec(&["oauth", &self.issuer, &subject])
            .expect("serialize fixed principal fields");
        Ok(Sha256Digest::of_bytes(&identity))
    }
}

fn nonempty(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn https_url(value: &str) -> Result<Url, GatewayAuthError> {
    let invalid = GatewayAuthError::InvalidConfiguration;
    let url = Url::parse(value).map_err(|_| invalid)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid);
    }
    Ok(url)
}

fn form_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn configured_oauth() -> PublicMcp {
        PublicMcp::new(
            serde_json::from_value(json!({
                "url": "https://mcp.example/mcp",
                "authentication": {
                    "type": "oauth_introspection",
                    "issuer": "https://issuer.example",
                    "introspection_url": "https://issuer.example/introspect",
                    "client_id": "styx-mcp",
                    "allowed_subjects": ["operator"]
                }
            }))
            .unwrap(),
            || Ok(Zeroizing::new("fixture-secret".into())),
        )
        .unwrap()
    }

    #[test]
    fn oauth_introspection_binds_active_token_to_resource_issuer_and_admitted_subject() {
        let public = configured_oauth();
        let oauth = public.oauth().unwrap();
        let valid = json!({
            "active": true, "sub": "operator", "iss": "https://issuer.example",
            "aud": "https://mcp.example/mcp", "token_type": "Bearer",
            "exp": 200, "nbf": 100,
        });
        let at = |value| oauth.principal(serde_json::from_value(value).unwrap(), 100);
        let first = at(valid.clone()).unwrap();
        let mut refreshed = valid.clone();
        refreshed["exp"] = json!(300);
        refreshed["aud"] = json!(["https://another.example/mcp", "https://mcp.example/mcp"]);
        assert_eq!(at(refreshed).unwrap(), first);

        for (claim, value) in [
            ("active", json!(false)),
            ("sub", json!(null)),
            ("iss", json!("https://other-issuer.example")),
            ("aud", json!("https://other-resource.example/mcp")),
            ("exp", json!(100)),
            ("exp", json!(null)),
            ("nbf", json!(101)),
            ("token_type", json!("Refresh")),
        ] {
            let mut rejected = valid.clone();
            rejected[claim] = value;
            assert_eq!(
                at(rejected),
                Err(GatewayAuthError::Unauthenticated),
                "{claim}"
            );
        }

        let mut outside_deployment = valid;
        outside_deployment["sub"] = json!("other-operator");
        assert_eq!(at(outside_deployment), Err(GatewayAuthError::Forbidden));
    }

    #[test]
    fn oauth_resource_metadata_and_challenge_share_the_canonical_https_url() {
        let public = configured_oauth();
        let oauth = public.oauth().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&oauth.metadata).unwrap(),
            json!({
                "resource": "https://mcp.example/mcp",
                "authorization_servers": ["https://issuer.example"],
                "bearer_methods_supported": ["header"]
            })
        );
        assert_eq!(
            oauth.challenge.to_str().unwrap(),
            r#"Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp""#
        );
    }
}

use super::*;
use crate::{
    store::{FileObservation, PrivateRoot, RootIdentity},
    tls::{GatewayClientTls, TrustAnchorPin},
};
use serde::Deserialize;
use serde_json::value::RawValue;
use styx_contracts::native_management::NativeRootIdentity;
use zeroize::Zeroizing;

// A protected input retains raw custody and its descriptor-relative identity.
// PrivateRoot's transient read buffer follows the existing store lifecycle;
// retained copies here are zeroizing and never formatted or serialized.
pub(super) struct Input {
    root: PrivateRoot,
    relative: PathBuf,
    observation: FileObservation,
    pub(super) raw: Zeroizing<Vec<u8>>,
}
impl Input {
    pub(super) fn open(path: &Path, limit: usize) -> Result<Self> {
        if !path.is_absolute() {
            return Err(bad());
        }
        let root = PrivateRoot::open(path.parent().ok_or_else(bad)?).map_err(|_| bad())?;
        let file = root
            .read_raw(path.file_name().ok_or_else(bad)?, limit)
            .map_err(|_| bad())?;
        Ok(Self {
            relative: file.relative_path().to_path_buf(),
            observation: file.observation().clone(),
            raw: Zeroizing::new(file.bytes().to_vec()),
            root,
        })
    }
    pub(super) fn revalidate(&self) -> Result<()> {
        let after = self
            .root
            .read_raw(&self.relative, LIMIT)
            .map_err(|_| unknown())?;
        if after.observation() != &self.observation || after.bytes() != self.raw.as_slice() {
            return Err(unknown());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Deployment {
    schema: u16,
    mode: String,
    pub(super) gateway: Gateway,
    pub(super) host: Host,
    pub(super) runtime_selection_file: PathBuf,
    pub(super) invitation_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Gateway {
    pub(super) url: String,
    pub(super) ca_file: PathBuf,
    pub(super) expected_ca_sha256: Sha256Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Host {
    pub(super) label: String,
    pub(super) cwd: PathBuf,
    pub(super) shell: PathBuf,
    #[serde(default)]
    pub(super) computer: bool,
    browser: Option<Box<RawValue>>,
}
// Same closed selection spellings as the existing protected Browser loader;
// these are requested DATA, never permission or executable authority here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BrowserSelection {
    enabled: bool,
    #[serde(rename = "headless")]
    _headless: Option<bool>,
    #[serde(rename = "persistLogin")]
    _persist_login: Option<bool>,
    #[serde(rename = "executablePath")]
    _executable_path: Option<PathBuf>,
    #[serde(rename = "channel")]
    _channel: Option<String>,
    #[serde(rename = "profileRoot")]
    _profile_root: Option<PathBuf>,
}
pub(super) fn deployment(raw: &[u8]) -> Result<(Deployment, url::Url, bool)> {
    let d: Deployment =
        serde_json::from_slice(raw).map_err(|e| invalid("deployment", e.to_string()))?;
    if d.schema != 1 {
        return Err(invalid("schema", "must be 1"));
    }
    if d.mode != "join-existing" {
        return Err(invalid("mode", "must be \"join-existing\""));
    }
    let origin =
        url::Url::parse(&d.gateway.url).map_err(|e| invalid("gateway.url", e.to_string()))?;
    if origin.scheme() != "https"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || d.gateway.url != origin.origin().ascii_serialization()
    {
        return Err(invalid(
            "gateway.url",
            format!(
                "must be the bare https origin with no path or trailing slash, e.g. {}",
                origin.origin().ascii_serialization()
            ),
        ));
    }
    for (field, path) in [
        ("host.cwd", &d.host.cwd),
        ("host.shell", &d.host.shell),
        ("gateway.caFile", &d.gateway.ca_file),
        ("runtimeSelectionFile", &d.runtime_selection_file),
        ("invitationFile", &d.invitation_file),
    ] {
        if !path.is_absolute() {
            return Err(invalid(field, "must be an absolute path"));
        }
    }
    let requested = d
        .host
        .browser
        .as_ref()
        .map(|b| serde_json::from_str::<BrowserSelection>(b.get()))
        .transpose()
        .map_err(|e| invalid("host.browser", e.to_string()))?
        .is_some_and(|b| b.enabled);
    Ok((d, origin, requested))
}
pub(super) fn tls(ca: &[u8], expected: Sha256Digest) -> Result<GatewayClientTls> {
    let pin = TrustAnchorPin::parse_hex(&expected.to_hex()).map_err(|_| bad())?;
    GatewayClientTls::from_pinned_ca_pem(ca, pin, None)
        .map_err(|_| JoinError::new("native_join_ca_rejected", 2))
}
pub(super) fn text(path: &Path) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(bad)
}
pub(super) fn identity(root: &PrivateRoot) -> NativeRootIdentity {
    match root.identity() {
        RootIdentity::Linux { device, inode, uid } => {
            NativeRootIdentity::Linux { device, inode, uid }
        }
        #[cfg(target_os = "macos")]
        RootIdentity::Macos { device, inode, uid } => {
            NativeRootIdentity::Macos { device, inode, uid }
        }
        #[cfg(target_os = "windows")]
        RootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        } => NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        },
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod deployment_field_tests {
    use super::*;

    fn refused(value: serde_json::Value) -> (&'static str, String) {
        let error = deployment(value.to_string().as_bytes()).err().unwrap();
        assert_eq!(error.code(), "native_join_invalid_input");
        let (field, reason) = error.detail().unwrap();
        (field, reason.to_owned())
    }

    #[test]
    fn join_deployment_refusals_name_the_field() {
        let valid = serde_json::json!({
            "schema": 1, "mode": "join-existing",
            "gateway": {"url": "https://127.0.0.1:8443", "caFile": "/p/ca.pem",
                "expectedCaSha256": "00".repeat(32)},
            "host": {"label": "l", "cwd": "/p/cwd", "shell": "/bin/bash",
                "browser": {"enabled": true, "headless": true, "persistLogin": false}},
            "runtimeSelectionFile": "/p/sel.json", "invitationFile": "/p/inv.txt"
        });
        assert!(deployment(valid.to_string().as_bytes()).is_ok());
        for origin in ["https://192.168.1.2:8443", "https://100.64.1.2:8443"] {
            let mut remote = valid.clone();
            remote["gateway"]["url"] = origin.into();
            assert!(deployment(remote.to_string().as_bytes()).is_ok());
        }

        let mut slash = valid.clone();
        slash["gateway"]["url"] = "https://127.0.0.1:8443/".into();
        let (field, reason) = refused(slash);
        assert_eq!(field, "gateway.url");
        assert!(reason.contains("https://127.0.0.1:8443"), "{reason}");

        let mut misspelt = valid.clone();
        misspelt["host"]["browser"]["executable"] = "/usr/bin/chrome".into();
        let (field, reason) = refused(misspelt);
        assert_eq!(field, "host.browser");
        assert!(reason.contains("executable"), "{reason}");

        let mut relative = valid;
        relative["host"]["cwd"] = "work".into();
        assert_eq!(refused(relative).0, "host.cwd");
    }
}

//! Installed legacy signed Gateway inputs, not a service/settlement authority.
//! Source contracts 2/3/4 only. Unversioned and source-checkout runners remain
//! explicit compatibility gaps; no JavaScript is executed to obtain authority.
use super::*;
use crate::{
    crypto::{PublisherFingerprint, PublisherVerifyingKey, RawReleaseManifest},
    store::{PayloadInventory, PayloadLimits, RawFile},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const ENTRY: &str = "app/onboarding/gateway-signed-runner.mjs";
// Original frozen onboarding/gateway-release-contract.mjs sourceContract 2.
const V2: &[&str] = &[
    "gateway/index.mjs",
    "gateway/runtime.mjs",
    "gateway/registry.mjs",
    "gateway/mcp.mjs",
    "gateway/conversation-owners.mjs",
    "gateway/device-ingress.mjs",
    "gateway/cua.mjs",
    "gateway/browser.mjs",
    "gateway/outbound.mjs",
    "gateway/http.mjs",
    "gateway/enrollment.mjs",
    "gateway/cua-portable-0.36.0.json",
    "gateway/cas/mcp.mjs",
    "gateway/cas/controller.html",
    "packages/styx-browser-provider/contract.mjs",
    "packages/styx-browser-provider/playwright-contract-0.0.83.json",
    "packages/styx-exec-adapter/rpc.mjs",
    "packages/styx-exec-adapter/errors.mjs",
    "packages/styx-exec-adapter/adapter.mjs",
    "packages/styx-exec-adapter/schema.mjs",
    "packages/styx-gui-broker/mcp.mjs",
    "shared/private-file.mjs",
    "shared/enrollment-protocol.mjs",
    "host/private-storage.mjs",
    "shared/onboarding-evidence.mjs",
    "shared/deployment-scope.mjs",
    "onboarding/deployment-config.mjs",
    "onboarding/device-ingress-config.mjs",
    "onboarding/gateway-runtime-start-guard.mjs",
    "onboarding/gateway-deployment-reader.mjs",
    "onboarding/gateway-signed-runner.mjs",
    "onboarding/tunnel-context.mjs",
];
const V3: &str = "onboarding/host-payload-start-guard.mjs";
const V4: &str = "shared/work-admission.mjs";
const SUPPORT: &[&str] = &[
    "app/package.json",
    "app/package-lock.json",
    "licenses/node-LICENSE",
    "licenses/styx-LICENSE",
    "provenance/gateway-build.json",
];

#[derive(Deserialize)]
struct Deployment {
    schema: u32,
    mode: String,
    gateway: Gateway,
}
#[derive(Deserialize)]
struct Gateway {
    runtime: Option<Runtime>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Runtime {
    base_dir: PathBuf,
    publisher_sha256: String,
    // Original protected configuration fields, never selected as installed IO.
    bundle: PathBuf,
    publisher_key_file: PathBuf,
}
#[derive(Deserialize)]
struct Active {
    schema: u32,
    version: String,
    manifest_sha256: Sha256Digest,
}
#[derive(Deserialize)]
struct Manifest {
    schema: u32,
    component: Option<String>,
    #[serde(rename = "sourceContract")]
    source_contract: Option<u32>,
    entrypoint: Option<String>,
    version: String,
    platform: String,
    arch: String,
    files: Vec<Member>,
}
struct StableNode {
    file: File,
    path: PathBuf,
    original: Stat,
}
/// Constructed only from the original Host proof's protected configuration root,
/// independently verifying the Gateway's own signed application and pin. No
/// Clone/Debug/Deserialize; this object does not authorize stopping any process.
pub(super) struct VerifiedGatewayInputs {
    pub(super) unit_name: String,
    pub(super) unit_file: PathBuf,
    pub(super) unit_bytes: Vec<u8>,
    pub(super) node_sha: Sha256Digest,
    pub(super) expected_argv: Vec<String>,
    pub(super) publisher_sha256: String,
    pub(super) working_directory: String,
    configuration: PrivateRoot,
    configuration_identity: RootIdentity,
    deployment: RawFile,
    base: PrivateRoot,
    base_identity: RootIdentity,
    protected: Vec<RawFile>,
    inventory: PayloadInventory,
    node: StableNode,
    unit_fd: File,
    unit_stat: Stat,
}

fn path_text(path: &Path) -> LegacyResult<&str> {
    let text = path.to_str().ok_or(LegacyError::Unsupported)?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || text.contains("//")
        || (text.len() > 1 && text.ends_with('/'))
    {
        return Err(LegacyError::Unsupported);
    }
    Ok(text)
}
fn quote(path: &Path) -> LegacyResult<String> {
    Ok(format!(
        "\"{}\"",
        path_text(path)?
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || (i > 0 && b"._-".contains(&b)))
}
fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 4096
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
fn application_file(value: &str) -> bool {
    if SUPPORT.contains(&value)
        || V2.iter().any(|p| value.strip_prefix("app/") == Some(*p))
        || value.strip_prefix("app/") == Some(V3)
        || value.strip_prefix("app/") == Some(V4)
    {
        return true;
    }
    let Some(dependency) = value.strip_prefix("app/node_modules/") else {
        return false;
    };
    let parts: Vec<_> = dependency.split('/').collect();
    let mut i = 0;
    loop {
        let Some(package) = parts.get(i) else {
            return false;
        };
        let package_part = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        if let Some(scope) = package.strip_prefix('@') {
            if !package_part(scope) || parts.get(i + 1).is_none_or(|p| !package_part(p)) {
                return false;
            }
            i += 2;
        } else if !package_part(package) {
            return false;
        } else {
            i += 1;
        }
        if parts.get(i) != Some(&"node_modules") {
            break;
        }
        i += 1;
    }
    let tail = &parts[i..];
    if tail.is_empty()
        || tail.iter().any(|p| {
            [
                "node_modules",
                ".git",
                ".bin",
                ".cache",
                ".runtime",
                ".local",
                "profiles",
                "sessions",
                "credentials",
                "__pycache__",
            ]
            .contains(p)
                || p.starts_with(".env")
                || p.ends_with(".log")
                || p.ends_with(".tmp")
        })
    {
        return false;
    }
    let Some(file) = tail.last() else {
        return false;
    };
    let lower = file.to_ascii_lowercase();
    ["js", "cjs", "mjs", "json"]
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
        || ["license", "licence", "copying", "notice"]
            .iter()
            .any(|name| {
                lower == *name
                    || lower.strip_prefix(name).is_some_and(|suffix| {
                        suffix.starts_with('.')
                            && suffix.len() > 1
                            && suffix
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    })
            })
}
fn unit(state: &Path, node: &Path, runner: &Path) -> LegacyResult<(String, Vec<u8>)> {
    let identity = Sha256Digest::of_bytes(path_text(state)?.as_bytes()).to_hex();
    let name = format!("styx-gateway-{}.service", &identity[..12]);
    let raw = format!(
        "# Styx owned Gateway {identity}\n[Unit]\nDescription=Styx private Gateway\nAfter=network.target\n[Service]\nType=simple\nExecStart={} {} {}\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=15\nUMask=0077\nNoNewPrivileges=true\n[Install]\nWantedBy=default.target\n",
        quote(node)?,
        quote(runner)?,
        quote(state)?
    );
    Ok((name, raw.into_bytes()))
}
impl VerifiedGatewayInputs {
    pub(super) fn derive(host: &VerifiedLegacyServiceInputs) -> LegacyResult<Self> {
        // Do not call host.revalidate(): the original Host token may already be
        // legally retired. The parent retains its maintenance/settlement proof.
        let state = &host.profile.path;
        path_text(state)?;
        let configuration = PrivateRoot::open(state).map_err(unavailable)?;
        let configuration_identity = configuration.identity();
        if configuration_identity != host.profile.root.identity() {
            return Err(LegacyError::Conflict);
        }
        let deployment = configuration
            .read_raw("deployment.json", MANIFEST_CAP)
            .map_err(unavailable)?;
        let preserved = host
            .profile
            ._loaded
            .diagnostics()
            .preservation
            .iter()
            .find(|p| p.path == state.join("deployment.json"))
            .ok_or(LegacyError::Conflict)?;
        if preserved.bytes != deployment.bytes().len() as u64
            || preserved.sha256 != Sha256Digest::of_bytes(deployment.bytes())
        {
            return Err(LegacyError::Conflict);
        }
        let original = host
            .profile
            .root
            .read_raw("deployment.json", MANIFEST_CAP)
            .map_err(conflict)?;
        if original.observation() != deployment.observation()
            || original.bytes() != deployment.bytes()
        {
            return Err(LegacyError::Conflict);
        }
        let config: Deployment = serde_json::from_slice(deployment.bytes()).map_err(conflict)?;
        if config.schema != 1 || config.mode != "create-local" {
            return Err(LegacyError::Unsupported);
        }
        let runtime = config.gateway.runtime.ok_or(LegacyError::Unsupported)?;
        for p in [
            &runtime.base_dir,
            &runtime.bundle,
            &runtime.publisher_key_file,
        ] {
            path_text(p)?;
        }
        let expected = PublisherFingerprint::parse(&runtime.publisher_sha256).map_err(conflict)?;
        let base = PrivateRoot::open(&runtime.base_dir).map_err(unavailable)?;
        let base_identity = base.identity();
        let publisher_raw = base.read_raw("publisher.pem", 2400).map_err(unavailable)?;
        let publisher =
            PublisherVerifyingKey::from_spki_pem(publisher_raw.bytes()).map_err(conflict)?;
        if publisher.fingerprint().map_err(conflict)? != expected {
            return Err(LegacyError::Conflict);
        }
        let active_raw = base
            .read_raw("install/active.json", UNIT_CAP)
            .map_err(unavailable)?;
        let active: Active = serde_json::from_slice(active_raw.bytes()).map_err(conflict)?;
        if active.schema != 1 || !version(&active.version) {
            return Err(LegacyError::Unsupported);
        }
        let release_rel = PathBuf::from(format!("install/releases/{}", active.version));
        let release_path = runtime.base_dir.join(&release_rel);
        let release = PrivateRoot::open(&release_path).map_err(unavailable)?;
        let manifest_raw = base
            .read_raw(release_rel.join("manifest.json"), MANIFEST_CAP)
            .map_err(unavailable)?;
        let signature_raw = base
            .read_raw(release_rel.join("manifest.sig"), 256)
            .map_err(unavailable)?;
        if Sha256Digest::of_bytes(manifest_raw.bytes()) != active.manifest_sha256 {
            return Err(LegacyError::Conflict);
        }
        let signature = std::str::from_utf8(signature_raw.bytes())
            .map_err(conflict)?
            .trim();
        if signature.len() != 86
            || !signature
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(LegacyError::Conflict);
        }
        let decoded = URL_SAFE_NO_PAD.decode(signature).map_err(conflict)?;
        publisher
            .verify_manifest(
                &expected,
                RawReleaseManifest::from_original_bytes(manifest_raw.bytes()),
                &decoded,
            )
            .map_err(conflict)?;
        let manifest: Manifest = serde_json::from_slice(manifest_raw.bytes()).map_err(conflict)?;
        let source = manifest.source_contract.ok_or(LegacyError::Unsupported)?;
        let arch = if cfg!(target_arch = "x86_64") {
            "x64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            return Err(LegacyError::Unsupported);
        };
        if manifest.schema != 1
            || manifest.component.as_deref() != Some("gateway-application")
            || ![2, 3, 4].contains(&source)
            || manifest.entrypoint.as_deref() != Some(ENTRY)
            || manifest.version != active.version
            || manifest.platform != "linux"
            || manifest.arch != arch
            || manifest.files.is_empty()
            || manifest.files.len() > 4096
        {
            return Err(LegacyError::Unsupported);
        }
        let mut expected_members = BTreeMap::new();
        for member in manifest.files {
            if !relative(&member.path)
                || member.size > IMAGE_CAP
                || (member.path != "bin/node"
                    && (!application_file(&member.path) || member.executable))
                || (member.path == "bin/node" && (!member.executable || member.size == 0))
                || expected_members
                    .insert(
                        PathBuf::from(&member.path),
                        (member.size, member.sha256, member.executable),
                    )
                    .is_some()
            {
                return Err(LegacyError::Conflict);
            }
        }
        let node_member = *expected_members
            .get(Path::new("bin/node"))
            .ok_or(LegacyError::Unsupported)?;
        for name in V2
            .iter()
            .map(|p| format!("app/{p}"))
            .chain(SUPPORT.iter().map(|p| (*p).to_owned()))
            .chain((source >= 3).then_some(format!("app/{V3}")))
            .chain((source >= 4).then_some(format!("app/{V4}")))
        {
            if !expected_members.contains_key(Path::new(&name)) {
                return Err(LegacyError::Conflict);
            }
        }
        for (name, raw) in [
            ("manifest.json", &manifest_raw),
            ("manifest.sig", &signature_raw),
        ] {
            expected_members.insert(
                PathBuf::from(name),
                (
                    raw.bytes().len() as u64,
                    Sha256Digest::of_bytes(raw.bytes()),
                    false,
                ),
            );
        }
        let inventory = release
            .payload_inventory(PayloadLimits::default())
            .map_err(conflict)?;
        if inventory.members().len() != expected_members.len()
            || inventory
                .members()
                .iter()
                .any(|m| expected_members.get(&m.path) != Some(&(m.bytes, m.sha256, m.executable)))
        {
            return Err(LegacyError::Conflict);
        }
        let node_path = runtime.base_dir.join("install/node");
        let mut node_file = open_checked(&node_path, false)?;
        let node_stat = stat(&node_file)?;
        if node_stat.len != node_member.0 || image_sha(&mut node_file)? != node_member.1 {
            return Err(LegacyError::Conflict);
        }
        let mut protected = vec![publisher_raw, active_raw, manifest_raw, signature_raw];
        // The runner imports these stable installation shims, explicitly exempt
        // from the old Gateway source scanner. Their authority is the original
        // Host signed-shim proof, not a claim they are Gateway manifest members.
        for name in ["install/installer.mjs", "install/private-storage.mjs"] {
            let signed = host
                .frozen
                .iter()
                .find(|f| f.relative == Path::new(name))
                .ok_or(LegacyError::Unsupported)?;
            let raw = base.read_raw(name, signed.length).map_err(unavailable)?;
            if raw.bytes().len() != signed.length
                || Sha256Digest::of_bytes(raw.bytes()) != signed.hash
            {
                return Err(LegacyError::Conflict);
            }
            protected.push(raw);
        }
        let runner = release_path.join(ENTRY);
        let (unit_name, unit_bytes) = unit(state, &node_path, &runner)?;
        let home = User::from_uid(Uid::current())
            .map_err(unavailable)?
            .ok_or(LegacyError::Unavailable)?
            .dir;
        // systemd's user manager fills an omitted WorkingDirectory with the
        // owning user's home and missing-ok=true. The official DBus getter
        // encodes that flag as `!`; the original unit itself stays unchanged.
        let working_directory = format!("!{}", path_text(&home)?);
        let unit_file = home.join(".config/systemd/user").join(&unit_name);
        let mut unit_fd = open_checked(&unit_file, false)?;
        let unit_stat = stat(&unit_fd)?;
        if read_file(&mut unit_fd, UNIT_CAP as u64)? != unit_bytes {
            return Err(LegacyError::Conflict);
        }
        let value = Self {
            unit_name,
            unit_file,
            unit_bytes,
            node_sha: node_member.1,
            expected_argv: vec![
                path_text(&node_path)?.to_owned(),
                path_text(&runner)?.to_owned(),
                path_text(state)?.to_owned(),
            ],
            publisher_sha256: runtime.publisher_sha256,
            working_directory,
            configuration,
            configuration_identity,
            deployment,
            base,
            base_identity,
            protected,
            inventory,
            node: StableNode {
                file: node_file,
                path: node_path,
                original: node_stat,
            },
            unit_fd,
            unit_stat,
        };
        value.revalidate()?;
        Ok(value)
    }
    pub(super) fn revalidate(&self) -> LegacyResult<()> {
        if self.configuration.identity() != self.configuration_identity
            || self.base.identity() != self.base_identity
        {
            return Err(LegacyError::Conflict);
        }
        let now = self
            .configuration
            .read_raw("deployment.json", MANIFEST_CAP)
            .map_err(conflict)?;
        if now.observation() != self.deployment.observation()
            || now.bytes() != self.deployment.bytes()
        {
            return Err(LegacyError::Conflict);
        }
        for old in &self.protected {
            let now = self
                .base
                .read_raw(old.relative_path(), old.bytes().len())
                .map_err(conflict)?;
            if now.observation() != old.observation() || now.bytes() != old.bytes() {
                return Err(LegacyError::Conflict);
            }
        }
        self.inventory.revalidate().map_err(conflict)?;
        if stat(&self.node.file)? != self.node.original || stat(&self.unit_fd)? != self.unit_stat {
            return Err(LegacyError::Conflict);
        }
        let mut node = open_checked(&self.node.path, false)?;
        if stat(&node)? != self.node.original || image_sha(&mut node)? != self.node_sha {
            return Err(LegacyError::Conflict);
        }
        let mut unit = open_checked(&self.unit_file, false)?;
        if stat(&unit)? != self.unit_stat
            || read_file(&mut unit, UNIT_CAP as u64)? != self.unit_bytes
        {
            return Err(LegacyError::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "legacy_gateway_tests.rs"]
mod tests;

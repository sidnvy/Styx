//! Protected Windows staging of this Rust image's fixed Browser adapter.
//! No symlink/junction privilege or alternate dependency loader is required.
use super::{BrowserError, Result};
use crate::store::{PrivateRoot, RawFile};
use std::{
    fs::File,
    path::{Component, Path, PathBuf, Prefix},
};
const WORKER: &str = include_str!("../../../../../providers/browser-worker/worker.mjs");
const CONFIG: &[u8] = include_bytes!("../../../../../providers/browser-worker/config.mjs");
const LIMIT: usize = 1024 * 1024;
// Exact package exports in the original verified versioned closure. Changing a
// dependency version requires changing/validating this bounded table, not asking
// Node to resolve arbitrary environment-provided modules.
const IMPORTS: [(&str, &str); 7] = [
    ("@playwright/mcp", "@playwright/mcp/index.js"),
    ("playwright", "playwright/index.mjs"),
    (
        "@modelcontextprotocol/sdk/client/index.js",
        "@modelcontextprotocol/sdk/dist/esm/client/index.js",
    ),
    (
        "@modelcontextprotocol/sdk/server/index.js",
        "@modelcontextprotocol/sdk/dist/esm/server/index.js",
    ),
    (
        "@modelcontextprotocol/sdk/server/stdio.js",
        "@modelcontextprotocol/sdk/dist/esm/server/stdio.js",
    ),
    (
        "@modelcontextprotocol/sdk/inMemory.js",
        "@modelcontextprotocol/sdk/dist/esm/inMemory.js",
    ),
    (
        "@modelcontextprotocol/sdk/types.js",
        "@modelcontextprotocol/sdk/dist/esm/types.js",
    ),
];

pub(crate) fn canonical_path(path: &Path) -> Result<PathBuf> {
    let mut parts = path.components();
    if !matches!(parts.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        || !matches!(parts.next(), Some(Component::RootDir))
    {
        return Err(BrowserError::PermissionDenied);
    }
    let raw = path.to_str().ok_or(BrowserError::PermissionDenied)?;
    if raw.len() > 4096
        || raw.contains(['\0', '\r', '\n'])
        || raw.split(['\\', '/']).any(|p| p == "." || p == "..")
    {
        return Err(BrowserError::PermissionDenied);
    }
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(BrowserError::PermissionDenied);
        };
        let name = name.to_str().ok_or(BrowserError::PermissionDenied)?;
        if name.contains([':', '<', '>', '"', '|', '?', '*']) || name.ends_with(['.', ' ']) {
            return Err(BrowserError::PermissionDenied);
        }
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| BrowserError::PermissionDenied)?;
    let text = canonical.to_str().ok_or(BrowserError::PermissionDenied)?;
    let plain = text
        .strip_prefix(r"\\?\")
        .ok_or(BrowserError::PermissionDenied)?;
    let result = PathBuf::from(plain);
    if result != path {
        return Err(BrowserError::PermissionDenied);
    }
    Ok(result)
}

pub(crate) struct PrivateDirectory {
    path: PathBuf,
    root: PrivateRoot,
    parent: PrivateRoot,
}
impl PrivateDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.parent
            .revalidate_runtime_directory()
            .map_err(|_| BrowserError::PermissionDenied)?;
        self.root
            .revalidate_runtime_directory()
            .map_err(|_| BrowserError::PermissionDenied)
    }
}
pub(crate) fn fresh_private_directory(parent: &Path) -> Result<PrivateDirectory> {
    canonical_path(parent)?;
    let parent_root = PrivateRoot::open(parent).map_err(|_| BrowserError::PermissionDenied)?;
    let name = format!("styx-browser-{}", uuid::Uuid::new_v4().simple());
    parent_root
        .ensure_absent(&name)
        .map_err(|_| BrowserError::PermissionDenied)?;
    let root = parent_root
        .create_runtime_child(&name)
        .map_err(|_| BrowserError::SpawnFailed)?;
    let result = PrivateDirectory {
        path: parent.join(name),
        root,
        parent: parent_root,
    };
    result.revalidate()?;
    Ok(result)
}

pub(crate) struct PreparedBrowserAssets {
    stage: PrivateDirectory,
    dependency: PrivateRoot,
    dependency_path: PathBuf,
    worker: RawFile,
    config: RawFile,
    _pins: Vec<File>,
    entry: PathBuf,
}
fn worker_bytes(dependency: &PrivateRoot, dependency_path: &Path) -> Result<Vec<u8>> {
    let mut worker = WORKER.to_owned();
    for (specifier, member) in IMPORTS {
        // The root's native reader rejects reparses, aliases, weak ACLs and
        // streams. The retained parent bootstrap verifies the entire signature.
        dependency
            .read_raw(member, LIMIT)
            .map_err(|_| BrowserError::PermissionDenied)?;
        let path = dependency_path.join(member);
        canonical_path(&path)?;
        let url = url::Url::from_file_path(&path).map_err(|_| BrowserError::PermissionDenied)?;
        if url.scheme() != "file" || url.query().is_some() || url.fragment().is_some() {
            return Err(BrowserError::PermissionDenied);
        }
        let from = format!("from '{specifier}'");
        if worker.matches(&from).count() != 1 {
            return Err(BrowserError::ProtocolMismatch);
        }
        let quoted =
            serde_json::to_string(url.as_str()).map_err(|_| BrowserError::InvalidRequest)?;
        worker = worker.replacen(&from, &format!("from {quoted}"), 1);
    }
    Ok(worker.into_bytes())
}
impl PreparedBrowserAssets {
    pub(crate) fn entry_path(&self) -> &Path {
        &self.entry
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.stage.revalidate()?;
        self.dependency
            .revalidate_runtime_directory()
            .map_err(|_| BrowserError::PermissionDenied)?;
        let expected = worker_bytes(&self.dependency, &self.dependency_path)?;
        for (original, bytes) in [(&self.worker, expected.as_slice()), (&self.config, CONFIG)] {
            let current = self
                .stage
                .root
                .read_raw(original.relative_path(), LIMIT)
                .map_err(|_| BrowserError::PermissionDenied)?;
            if current.observation() != original.observation() || current.bytes() != bytes {
                return Err(BrowserError::PermissionDenied);
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for entry in
            std::fs::read_dir(self.stage.path()).map_err(|_| BrowserError::PermissionDenied)?
        {
            if names.len() >= 2 {
                return Err(BrowserError::PermissionDenied);
            }
            names.insert(
                entry
                    .map_err(|_| BrowserError::PermissionDenied)?
                    .file_name(),
            );
        }
        if names != std::collections::BTreeSet::from(["worker.mjs".into(), "config.mjs".into()]) {
            return Err(BrowserError::PermissionDenied);
        }
        self.stage.revalidate()
    }
}
pub(crate) fn prepare(parent: &Path, dependency_path: &Path) -> Result<PreparedBrowserAssets> {
    canonical_path(dependency_path)?;
    let dependency =
        PrivateRoot::open(dependency_path).map_err(|_| BrowserError::PermissionDenied)?;
    let bytes = worker_bytes(&dependency, dependency_path)?;
    let stage = fresh_private_directory(parent)?;
    let (worker, worker_pin) = stage
        .root
        .create_runtime_asset("worker.mjs", &bytes)
        .map_err(|_| BrowserError::SpawnFailed)?;
    let (config, config_pin) = stage
        .root
        .create_runtime_asset("config.mjs", CONFIG)
        .map_err(|_| BrowserError::SpawnFailed)?;
    let entry = stage.path().join("worker.mjs");
    let result = PreparedBrowserAssets {
        stage,
        dependency,
        dependency_path: dependency_path.into(),
        worker,
        config,
        _pins: vec![worker_pin, config_pin],
        entry,
    };
    result.revalidate()?;
    Ok(result)
}

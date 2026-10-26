//! C08 native release metadata. Parsing data never grants publisher trust,
//! executable admission, installation, profile migration or platform permissions.
use crate::{
    identity::Sha256Digest, management::ReaderContract, native_management::NativeRuntimeFormat,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub const NATIVE_RELEASE_SCHEMA: u16 = 2;
pub const NATIVE_RELEASE_MANIFEST_BYTES: usize = 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReleaseComponent {
    Styx,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReleaseScope {
    ConfigurationPreview,
    RuntimeCandidate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReleaseReader {
    NativeReleaseV1,
    NativeRuntimeV1,
    /// Original-identity cutover reader barrier; old runtimes reject this variant.
    NativeRuntimeMigratedV1,
    /// Typed Host-only/local-Gateway migration reader; earlier readers reject it.
    NativeRuntimeMigratedV2,
    /// Host admission v2 and durable migration-plan journal support.
    NativeRuntimeMigratedV3,
    /// Fresh-root committed runtime update and compatible forward rollback.
    NativeRuntimeSelectedV1,
}
impl NativeReleaseReader {
    /// Signed feature declaration, not evidence of successful migration.
    pub fn supports_host_admission_v2(self) -> bool {
        matches!(
            self,
            Self::NativeRuntimeMigratedV3 | Self::NativeRuntimeSelectedV1
        )
    }

    /// Signed reader declaration only; no runtime health or activation authority.
    pub fn supports_state_reader(self, reader: ReaderContract) -> bool {
        matches!(
            (self, reader),
            (
                Self::NativeRuntimeV1
                    | Self::NativeRuntimeMigratedV1
                    | Self::NativeRuntimeMigratedV2
                    | Self::NativeRuntimeMigratedV3
                    | Self::NativeRuntimeSelectedV1,
                ReaderContract::NativeManagementStateV1
            ) | (
                Self::NativeRuntimeMigratedV1
                    | Self::NativeRuntimeMigratedV2
                    | Self::NativeRuntimeMigratedV3
                    | Self::NativeRuntimeSelectedV1,
                ReaderContract::NativeMigratedStateV1
            ) | (
                Self::NativeRuntimeMigratedV2
                    | Self::NativeRuntimeMigratedV3
                    | Self::NativeRuntimeSelectedV1,
                ReaderContract::NativeMigratedStateV2
            ) | (
                Self::NativeRuntimeSelectedV1,
                ReaderContract::NativeRuntimeSelectedStateV1
            )
        )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeReleaseTarget {
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    LinuxX86_64Gnu,
    #[serde(rename = "aarch64-apple-darwin")]
    MacosAarch64,
    #[serde(rename = "x86_64-apple-darwin")]
    MacosX86_64,
    #[serde(rename = "x86_64-pc-windows-msvc")]
    WindowsX86_64Msvc,
}
impl NativeReleaseTarget {
    pub fn entrypoint(self) -> &'static str {
        match self {
            Self::WindowsX86_64Msvc => "bin/styx.exe",
            _ => "bin/styx",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleaseSource {
    pub revision: String,
    pub inputs_sha256: Sha256Digest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleaseContracts {
    pub control: u16,
    pub management_state: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleaseMember {
    pub path: String,
    pub size: u64,
    pub sha256: Sha256Digest,
    pub executable: bool,
}
/// Closed native executor kinds; declarations do not grant runtime readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeExternalWorker {
    CodexExec,
    BrowserNode22,
    CuaNative,
}
impl NativeExternalWorker {
    pub fn prefix(self) -> &'static str {
        match self {
            Self::CodexExec => "workers/codex-exec",
            Self::BrowserNode22 => "workers/browser-node22",
            Self::CuaNative => "workers/cua-native",
        }
    }
    pub fn entrypoint(self, target: NativeReleaseTarget) -> String {
        let binary = match self {
            Self::CodexExec => "codex",
            Self::BrowserNode22 => "node",
            Self::CuaNative => "cua-driver",
        };
        let suffix = if target == NativeReleaseTarget::WindowsX86_64Msvc {
            ".exe"
        } else {
            ""
        };
        format!("{}/bin/{binary}{suffix}", self.prefix())
    }
}
/// Package-relative exact membership of one independently sourced native worker.
/// Path presence is not proof of license contents, source provenance or publisher
/// approval. The signed-artifact builder/verifier owns those byte-level checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClosure {
    pub kind: NativeExternalWorker,
    pub version: String,
    pub source_manifest_sha256: Sha256Digest,
    pub source_publisher_spki_sha256: Sha256Digest,
    pub entrypoint: String,
    pub members: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleaseManifest {
    pub schema: u16,
    pub runtime_format: NativeRuntimeFormat,
    pub component: NativeReleaseComponent,
    pub scope: NativeReleaseScope,
    pub minimum_reader: NativeReleaseReader,
    pub target: NativeReleaseTarget,
    pub version: String,
    pub entrypoint: String,
    pub source: NativeReleaseSource,
    pub contracts: NativeReleaseContracts,
    pub files: Vec<NativeReleaseMember>,
    pub external_workers: Vec<NativeExternalWorker>,
    // Omitted for the original preview, retaining its exact serialized shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_closures: Vec<NativeWorkerClosure>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("native_release_manifest_invalid")]
pub struct NativeReleaseManifestError;
fn relative_member(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && path
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}
impl NativeReleaseManifest {
    pub fn validate(&self) -> Result<(), NativeReleaseManifestError> {
        match self.scope {
            NativeReleaseScope::ConfigurationPreview => self.validate_preview(),
            NativeReleaseScope::RuntimeCandidate => self.validate_runtime(),
        }
    }
    // Keep the original three-member preview validation and reader boundary.
    fn validate_preview(&self) -> Result<(), NativeReleaseManifestError> {
        let invalid = NativeReleaseManifestError;
        if self.schema != NATIVE_RELEASE_SCHEMA
            || self.version.is_empty()
            || self.version.len() > 128
            || !self
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.source.revision.len() != 40
            || !self
                .source
                .revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.entrypoint != self.target.entrypoint()
            || self.contracts.control != 1
            || self.contracts.management_state != 2
            || self.files.len() != 3
            || !self.external_workers.is_empty()
            || !self.worker_closures.is_empty()
            || self.minimum_reader != NativeReleaseReader::NativeReleaseV1
        {
            return Err(invalid);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for member in &self.files {
            if !relative_member(&member.path)
                || ![self.entrypoint.as_str(), "LICENSE", "source-inputs.json"]
                    .contains(&member.path.as_str())
                || !seen.insert(&member.path)
                || member.size > 1024 * 1024 * 1024
            {
                return Err(invalid);
            }
            total = total.checked_add(member.size).ok_or(invalid)?;
            if total > 4 * 1024 * 1024 * 1024 {
                return Err(invalid);
            }
        }
        if !self
            .files
            .iter()
            .any(|m| m.path == "LICENSE" && !m.executable && m.size > 0)
            || !self
                .files
                .iter()
                .any(|m| m.path == self.entrypoint && m.executable && m.size > 0)
            || !self.files.iter().any(|m| {
                m.path == "source-inputs.json"
                    && !m.executable
                    && m.size > 0
                    && m.sha256 == self.source.inputs_sha256
            })
        {
            return Err(invalid);
        }
        Ok(())
    }
}

/// 4096 signed members plus manifest/signature fit existing PayloadLimits (4098).
pub const NATIVE_RUNTIME_RELEASE_FILES: usize = 4096;
fn worker_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
}
fn npm_member(path: &str) -> bool {
    if path.is_empty() || path.len() > 512 {
        return false;
    }
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || matches!(*part, "." | "..") {
            return false;
        }
        if let Some(scope) = part.strip_prefix('@') {
            if scope.is_empty()
                || index == 0
                || parts[index - 1] != "node_modules"
                || index + 1 == parts.len()
                || parts[index + 1].starts_with('@')
                || !scope
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return false;
            }
        } else if !part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return false;
        }
    }
    true
}
fn required_worker_members(kind: NativeExternalWorker, target: NativeReleaseTarget) -> Vec<String> {
    let prefix = kind.prefix();
    let mut required = vec![kind.entrypoint(target)];
    match kind {
        NativeExternalWorker::CodexExec => {
            required.push(format!("{prefix}/licenses/codex-LICENSE"));
            required.push(format!("{prefix}/licenses/codex-NOTICE"));
        }
        NativeExternalWorker::BrowserNode22 => {
            required.push(format!("{prefix}/licenses/node-LICENSE"));
            required.push(format!("{prefix}/provenance/node.json"));
            for package in [
                "@playwright/mcp",
                "playwright",
                "playwright-core",
                "@modelcontextprotocol/sdk",
            ] {
                for name in ["package.json", "LICENSE"] {
                    required.push(format!(
                        "{prefix}/packages/styx-browser-provider/node_modules/{package}/{name}"
                    ));
                }
            }
        }
        NativeExternalWorker::CuaNative => required.push(format!("{prefix}/licenses/cua-LICENSE")),
    }
    required
}
impl NativeReleaseManifest {
    fn validate_runtime(&self) -> Result<(), NativeReleaseManifestError> {
        let invalid = NativeReleaseManifestError;
        if self.schema != NATIVE_RELEASE_SCHEMA
            || !matches!(
                self.minimum_reader,
                NativeReleaseReader::NativeRuntimeV1
                    | NativeReleaseReader::NativeRuntimeMigratedV1
                    | NativeReleaseReader::NativeRuntimeMigratedV2
                    | NativeReleaseReader::NativeRuntimeMigratedV3
                    | NativeReleaseReader::NativeRuntimeSelectedV1
            )
            || !worker_version(&self.version)
            || self.version.contains('+')
            || self.source.revision.len() != 40
            || !self
                .source
                .revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.entrypoint != self.target.entrypoint()
            || self.contracts.control != 1
            || self.contracts.management_state
                != if self.minimum_reader == NativeReleaseReader::NativeRuntimeSelectedV1 {
                    3
                } else {
                    2
                }
            || self.files.len() < 3
            || self.files.len() > NATIVE_RUNTIME_RELEASE_FILES
            || self.external_workers.len() > 3
            || self.worker_closures.len() > 3
        {
            return Err(invalid);
        }
        let kinds: BTreeSet<_> = self.external_workers.iter().copied().collect();
        if kinds.len() != self.external_workers.len() || kinds.len() != self.worker_closures.len() {
            return Err(invalid);
        }
        let mut allocated = BTreeSet::new();
        let mut closure_kinds = BTreeSet::new();
        let mut executable = BTreeSet::from([self.entrypoint.clone()]);
        let mut required = BTreeSet::from([
            self.entrypoint.clone(),
            "LICENSE".to_owned(),
            "source-inputs.json".to_owned(),
        ]);
        for closure in &self.worker_closures {
            if !kinds.contains(&closure.kind)
                || !closure_kinds.insert(closure.kind)
                || !worker_version(&closure.version)
                || closure.entrypoint != closure.kind.entrypoint(self.target)
                || closure.members.is_empty()
                || closure.members.len() > NATIVE_RUNTIME_RELEASE_FILES
                || (closure.kind == NativeExternalWorker::CuaNative
                    && matches!(
                        self.target,
                        NativeReleaseTarget::MacosAarch64 | NativeReleaseTarget::MacosX86_64
                    ))
            {
                return Err(invalid);
            }
            let mandatory = required_worker_members(closure.kind, self.target);
            let dependency_prefix = format!(
                "{}/packages/styx-browser-provider/node_modules/",
                closure.kind.prefix()
            );
            let mut own_members = BTreeSet::new();
            for path in &closure.members {
                let fixed = mandatory.contains(path);
                let dependency = closure.kind == NativeExternalWorker::BrowserNode22
                    && path
                        .strip_prefix(&dependency_prefix)
                        .is_some_and(|rest| !rest.is_empty())
                    && npm_member(path);
                if !(dependency || fixed && relative_member(path))
                    || !own_members.insert(path.as_str())
                    || !allocated.insert(path.as_str())
                {
                    return Err(invalid);
                }
            }
            if mandatory
                .iter()
                .any(|path| !own_members.contains(path.as_str()))
            {
                return Err(invalid);
            }
            executable.insert(closure.entrypoint.clone());
            required.extend(mandatory);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for member in &self.files {
            let base = [self.entrypoint.as_str(), "LICENSE", "source-inputs.json"]
                .contains(&member.path.as_str());
            if (!base && !allocated.contains(member.path.as_str()))
                || !seen.insert(member.path.as_str())
                || member.size > 1024 * 1024 * 1024
                || member.executable != executable.contains(&member.path)
                || (required.contains(&member.path) && member.size == 0)
            {
                return Err(invalid);
            }
            total = total.checked_add(member.size).ok_or(invalid)?;
            if total > 4 * 1024 * 1024 * 1024 {
                return Err(invalid);
            }
        }
        if required.iter().any(|path| !seen.contains(path.as_str()))
            || allocated.iter().any(|path| !seen.contains(*path))
            || !self.files.iter().any(|member| {
                member.path == "source-inputs.json" && member.sha256 == self.source.inputs_sha256
            })
        {
            return Err(invalid);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "native_release_tests.rs"]
mod tests;

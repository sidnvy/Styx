//! C08 native release metadata. Parsing data never grants publisher trust,
//! executable admission, installation, profile migration or platform permissions.
use crate::{identity::Sha256Digest, native_management::NativeRuntimeFormat};
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
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReleaseReader {
    NativeReleaseV1,
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
/// Reserved closed kinds; this configuration-only preview accepts no workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeExternalWorker {
    CodexExec,
    BrowserNode22,
    CuaNative,
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

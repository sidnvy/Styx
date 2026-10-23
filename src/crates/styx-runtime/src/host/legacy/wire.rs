//! The existing Codex Exec-shaped legacy wire. No owner/operation authority is
//! inferred from request IDs, process UUIDs or any other network DTO.
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

pub(super) const MAX_FRAME: usize = 2 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum Id {
    Number(u64),
    Text(String),
}
impl Id {
    fn valid(&self) -> bool {
        match self {
            Self::Number(n) => *n <= MAX_SAFE_INTEGER,
            Self::Text(s) => !s.is_empty() && s.len() <= 128 && !s.contains('\0'),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub id: Option<Id>,
    pub method: String,
    pub params: Box<RawValue>,
    pub jsonrpc: Option<String>,
}
impl Request {
    pub fn parse(frame: &str) -> Result<Self, ()> {
        if frame.len() > MAX_FRAME {
            return Err(());
        }
        let request: Self = serde_json::from_str(frame).map_err(|_| ())?;
        if request.method.is_empty()
            || request.method.len() > 128
            || request.method.contains('\0')
            || request.id.as_ref().is_some_and(|id| !id.valid())
            || request.jsonrpc.as_deref().is_some_and(|v| v != "2.0")
        {
            return Err(());
        }
        let parameter_limit = match request.method.as_str() {
            "process/start" | "process/write" => 128 * 1024,
            "initialize" | "process/read" | "process/terminate" => 16 * 1024,
            "initialized" => 4096,
            _ => 128 * 1024,
        };
        if request.params.get().len() > parameter_limit {
            return Err(());
        }
        Ok(request)
    }
    pub fn typed<T: serde::de::DeserializeOwned>(&self) -> Result<T, ()> {
        serde_json::from_str(self.params.get()).map_err(|_| ())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Initialize {
    pub client_name: String,
    pub resume_session_id: Option<String>,
}
impl Initialize {
    pub fn valid(&self) -> bool {
        !self.client_name.is_empty()
            && self.client_name.len() <= 512
            && !self.client_name.contains('\0')
            && self
                .resume_session_id
                .as_ref()
                .is_none_or(|v| !v.is_empty() && v.len() <= 512 && !v.contains('\0'))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Initialized {}

pub(super) use crate::providers::codex::{LegacyStartProcess as Start, LegacyWrite as Write};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Read {
    pub process_id: String,
    pub after_seq: Option<u64>,
    pub max_bytes: usize,
    pub wait_ms: u64,
}
impl Read {
    pub fn valid(&self) -> bool {
        canonical_uuid(&self.process_id)
            && self.after_seq.is_none_or(|n| n <= MAX_SAFE_INTEGER)
            && (1..=65536).contains(&self.max_bytes)
            && self.wait_ms <= 1000
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Terminate {
    pub process_id: String,
}
impl Terminate {
    pub fn valid(&self) -> bool {
        canonical_uuid(&self.process_id)
    }
}
pub(super) fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
#[derive(Serialize)]
pub(super) struct Response {
    pub id: Id,
    #[serde(flatten)]
    pub outcome: Outcome,
}
#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum Outcome {
    Result { result: serde_json::Value },
    Error { error: RpcError },
}
#[derive(Serialize)]
pub(super) struct RpcError {
    pub code: i32,
    pub message: String,
}
impl Response {
    pub fn result(id: Id, result: serde_json::Value) -> Self {
        Self {
            id,
            outcome: Outcome::Result { result },
        }
    }
    pub fn error(id: Id, code: i32, message: impl Into<String>) -> Self {
        Self {
            id,
            outcome: Outcome::Error {
                error: RpcError {
                    code,
                    message: message.into(),
                },
            },
        }
    }
}

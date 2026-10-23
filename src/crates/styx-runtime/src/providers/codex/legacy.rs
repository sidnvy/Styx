//! Explicit legacy native IDs, always consumed through Core DispatchPermit.
//! This is not a generic RPC passthrough or a source of owner authority.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use styx_contracts::capability::CapabilityId;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyEnvPolicy {
    pub inherit: String,
    pub ignore_default_excludes: bool,
    pub exclude: Vec<String>,
    pub set: BTreeMap<String, String>,
    pub include_only: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyStartProcess {
    pub process_id: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub env_policy: LegacyEnvPolicy,
    pub tty: bool,
    pub pipe_stdin: bool,
    pub arg0: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<Box<RawValue>>,
}
impl LegacyStartProcess {
    pub fn valid(&self) -> bool {
        canonical_uuid(&self.process_id)
            && !self.argv.is_empty()
            && self.argv.len() <= 4096
            && self.argv.iter().all(|v| !v.contains('\0'))
            && self.argv.iter().map(String::len).sum::<usize>() <= 65536
            && !self.cwd.is_empty()
            && self.cwd.len() <= 16384
            && !self.cwd.contains('\0')
            && self.arg0.is_none()
            && self.pipe_stdin != self.tty
            && matches!(self.env_policy.inherit.as_str(), "all" | "none")
            && self.env.len() <= 4096
            && self.env_policy.set.len() <= 4096
            && self
                .env
                .iter()
                .chain(self.env_policy.set.iter())
                .all(|(k, v)| !k.is_empty() && !k.contains(['\0', '=']) && !v.contains('\0'))
            && self
                .env
                .iter()
                .chain(self.env_policy.set.iter())
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                <= 65536
            && self.env_policy.exclude.len() <= 4096
            && self.env_policy.include_only.len() <= 4096
            && self
                .env_policy
                .exclude
                .iter()
                .chain(self.env_policy.include_only.iter())
                .all(|s| s.len() <= 512 && !s.contains('\0'))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyWrite {
    pub process_id: String,
    pub write_id: String,
    pub chunk: String,
}
impl LegacyWrite {
    pub fn valid(&self) -> bool {
        canonical_uuid(&self.process_id)
            && canonical_uuid(&self.write_id)
            && self.chunk.len() <= 4 * 65536usize.div_ceil(3)
            && STANDARD.decode(&self.chunk).is_ok_and(|b| {
                !b.is_empty() && b.len() <= 65536 && STANDARD.encode(b) == self.chunk
            })
    }
}

pub(crate) fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LegacyAction {
    Write {
        process_id: String,
        write_id: String,
        chunk: String,
    },
    Terminate {
        process_id: String,
    },
}
impl LegacyAction {
    pub fn to_operation_payload(&self) -> Result<Vec<u8>, ExecError> {
        if !self.valid() {
            return Err(ExecError::InvalidRequest);
        }
        serde_json::to_vec(self).map_err(|_| ExecError::InvalidRequest)
    }
    fn valid(&self) -> bool {
        match self {
            Self::Write {
                process_id,
                write_id,
                chunk,
            } => LegacyWrite {
                process_id: process_id.clone(),
                write_id: write_id.clone(),
                chunk: chunk.clone(),
            }
            .valid(),
            Self::Terminate { process_id } => canonical_uuid(process_id),
        }
    }
    pub fn process_id(&self) -> &str {
        match self {
            Self::Write { process_id, .. } | Self::Terminate { process_id } => process_id,
        }
    }
}
impl LegacyStartProcess {
    pub fn to_operation_payload(&self) -> Result<Vec<u8>, ExecError> {
        if !self.valid() {
            return Err(ExecError::InvalidRequest);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ExecError::InvalidRequest)?;
        if bytes.len() > 131072 {
            return Err(ExecError::InvalidRequest);
        }
        Ok(bytes)
    }
}
pub struct LegacyStartReceipt {
    pub start: StartReceipt,
    pub raw_result: Option<Value>,
}
pub struct LegacyActionReceipt {
    pub action: ActionReceipt,
    pub raw_result: Option<Value>,
}
impl CodexStdio {
    pub(crate) fn initialization(&self) -> &Value {
        &self.initialization
    }
    pub(crate) fn legacy_terminal(&self) -> tokio::sync::broadcast::Receiver<rpc::TerminalEvent> {
        self.rpc.subscribe_terminal()
    }
    pub(crate) async fn start_legacy(
        &self,
        permit: DispatchPermit,
    ) -> Result<LegacyStartReceipt, StartFailure> {
        let operation = permit.id().clone();
        let refuse = |error| StartFailure {
            operation: operation.clone(),
            evidence: DispatchEvidence::NotDispatched,
            error,
        };
        if permit.target().is_some()
            || permit.context().capability != CapabilityId::ExecRun
            || permit.payload().len() > 131072
        {
            return Err(refuse(ExecError::InvalidRequest));
        }
        let spec: LegacyStartProcess = serde_json::from_slice(permit.payload())
            .map_err(|_| refuse(ExecError::InvalidRequest))?;
        if !spec.valid() {
            return Err(refuse(ExecError::InvalidRequest));
        }
        let raw = serde_json::from_slice::<Value>(permit.payload())
            .map_err(|_| refuse(ExecError::InvalidRequest))?;
        let handle = ProcessHandle {
            process_id: spec.process_id,
            operation: operation.clone(),
        };
        {
            let mut operations = self.operations.lock().expect("operation mutex");
            if operations.contains_key(&operation) {
                return Err(StartFailure {
                    operation,
                    evidence: DispatchEvidence::Unknown,
                    error: ExecError::AlreadyDispatched,
                });
            }
            if operations.len() >= self.limit {
                return Err(refuse(ExecError::Capacity));
            }
            let mut records = self.records.lock().expect("records mutex");
            if records.contains_key(&handle.process_id) {
                return Err(refuse(ExecError::InvalidRequest));
            }
            operations.insert(operation.clone(), handle.clone());
            records.insert(
                handle.process_id.clone(),
                Arc::new(Resource {
                    start_digest: Sha256Digest::of_bytes(permit.payload()),
                    owner: permit.owner().clone(),
                    handle: handle.clone(),
                    state: Arc::new(tokio::sync::Mutex::new(Record {
                        retired: false,
                        read_mode: None,
                        cursor: None,
                        gaps: 0,
                        decoder: OutputDecoder::default(),
                        drained: false,
                        input_unknown: None,
                        last_exit: None,
                    })),
                }),
            );
        }
        if let Err(error) = self.rpc.register(&handle.process_id) {
            self.discard_unstarted(&handle);
            return Err(refuse(error));
        }
        match self.rpc.request("process/start", raw).await {
            Ok(value)
                if value.get("processId").and_then(Value::as_str)
                    == Some(handle.process_id.as_str()) =>
            {
                Ok(LegacyStartReceipt {
                    start: StartReceipt {
                        handle,
                        dispatch: DispatchEvidence::Started,
                        cause: None,
                    },
                    raw_result: Some(value),
                })
            }
            Err(error @ (ExecError::NotSent | ExecError::Capacity | ExecError::InvalidRequest)) => {
                self.discard_unstarted(&handle);
                Err(refuse(error))
            }
            result => Ok(LegacyStartReceipt {
                start: StartReceipt {
                    handle,
                    dispatch: DispatchEvidence::Unknown,
                    cause: Some(result.err().unwrap_or(ExecError::InvalidFrame)),
                },
                raw_result: None,
            }),
        }
    }
}

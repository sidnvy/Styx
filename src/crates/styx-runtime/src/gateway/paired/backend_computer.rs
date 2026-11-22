//! Stateless Desktop routing only. Host owns per-owner native CUA sessions,
//! resource lifecycle, and once-only dispatch; Gateway routes and authenticates.
use super::*;
use crate::providers::cua::CuaAction;
use serde_json::value::RawValue;
use styx_contracts::error::{ErrorCategory, ExecutionCertainty};

const MAX_COMPUTER_RESULT_BYTES: usize = styx_contracts::DESKTOP_BROWSER_FRAME_BYTES;

pub(super) fn is_public_computer_tool(name: &str) -> bool {
    matches!(name, "desktop_list_tools" | "desktop_call")
}

struct ComputerRequest {
    environment_id: Option<String>,
    action: CuaAction,
}
impl ComputerRequest {
    fn parse(name: &str, args: Option<Map<String, Value>>) -> Result<Self, &'static str> {
        let mut args = args.unwrap_or_default();
        let environment_id = match args.remove("environment_id") {
            None => None,
            Some(Value::String(id)) if !id.is_empty() && id.len() <= 128 => Some(id),
            _ => return Err("invalid_arguments"),
        };
        let action = match name {
            "desktop_list_tools" => {
                let names = match args.remove("names") {
                    None => None,
                    Some(Value::Array(items)) => {
                        let mut out = Vec::with_capacity(items.len());
                        for item in items {
                            match item {
                                Value::String(s) if !s.is_empty() && s.len() <= 128 => out.push(s),
                                _ => return Err("invalid_arguments"),
                            }
                        }
                        Some(out)
                    }
                    _ => return Err("invalid_arguments"),
                };
                if !args.is_empty() {
                    return Err("invalid_arguments");
                }
                CuaAction::list_tools(names).map_err(|_| "invalid_arguments")?
            }
            "desktop_call" => {
                let tool = match args.remove("tool") {
                    Some(Value::String(t)) if !t.is_empty() && t.len() <= 128 => t,
                    _ => return Err("invalid_arguments"),
                };
                let arguments = match args.remove("arguments") {
                    None => Map::new(),
                    Some(Value::Object(map)) => map,
                    _ => return Err("invalid_arguments"),
                };
                if !args.is_empty() {
                    return Err("invalid_arguments");
                }
                CuaAction::call_tool(tool, arguments).map_err(|_| "invalid_arguments")?
            }
            _ => return Err("invalid_arguments"),
        };
        action
            .to_operation_payload()
            .map_err(|_| "invalid_arguments")?;
        Ok(Self {
            environment_id,
            action,
        })
    }
}

fn computer_error(category: ErrorCategory, certainty: ExecutionCertainty) -> CallToolResult {
    let uncertain = certainty != ExecutionCertainty::NotDispatched;
    let code = if category == ErrorCategory::Busy && !uncertain {
        "capacity_busy"
    } else if uncertain {
        "outcome_unknown"
    } else {
        "computer_not_dispatched"
    };
    CallToolResult::error(vec![ContentBlock::text(
        json!({
            "error": code,
            "category": category,
            "execution_certainty": certainty,
            "uncertain": uncertain,
            "retryable": category == ErrorCategory::Busy && !uncertain,
        })
        .to_string(),
    )])
}

fn bounded_result(value: CallToolResult) -> Result<CallToolResult, &'static str> {
    struct Bound(usize);
    impl std::io::Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_COMPUTER_RESULT_BYTES)
                .ok_or_else(|| std::io::Error::other("computer result bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Bound(0), &value).map_err(|_| "outcome_unknown")?;
    Ok(value)
}

impl PairedGatewayBackend {
    pub(super) async fn computer_call(
        &self,
        owner: &VerifiedGatewayOwner,
        name: &str,
        args: Option<Map<String, Value>>,
    ) -> CallToolResult {
        let request = match ComputerRequest::parse(name, args) {
            Ok(v) => v,
            Err(e) => return failure(e, None, false),
        };
        let raw = match serde_json::to_string(&request.action)
            .ok()
            .and_then(|s| RawValue::from_string(s).ok())
        {
            Some(v) => v,
            None => return failure("invalid_arguments", None, false),
        };
        let device = match self.resolve_device(request.environment_id.as_deref()).await {
            Ok(device) => device,
            Err(error) => return failure(error, None, false),
        };
        if let Err(error) = self.refresh_host_capabilities(&device).await {
            return failure(error, None, false);
        }
        let binding = match self.relay.bind_computer(owner, &device).await {
            Ok(binding) => binding,
            Err(error) => return failure(error.code(), None, false),
        };
        if !binding.defaults().computer_approved || binding.closed() {
            return failure("permission_denied", None, false);
        }
        match self
            .relay
            .call(
                &binding,
                Call::DesktopSession {
                    owner: binding.owner_ref(),
                    grant_revision: binding.grant_revision(),
                    timeout_ms: None,
                    action: raw,
                },
            )
            .await
        {
            Ok(Reply::DesktopSession { result }) => match bounded_result(result) {
                Ok(result) => result,
                Err(code) => failure(code, None, true),
            },
            Ok(Reply::Error {
                category,
                certainty,
                ..
            }) => computer_error(category, certainty),
            Err(error) => failure(
                error.code(),
                None,
                !matches!(
                    error,
                    super::super::RelayError::Busy | super::super::RelayError::NotSent
                ),
            ),
            _ => failure("outcome_unknown", None, true),
        }
    }
}

#[cfg(test)]
#[path = "backend_computer_tests.rs"]
mod tests;

#[cfg(test)]
mod native_desktop_regressions {
    use super::*;

    #[test]
    fn desktop_list_tools_and_desktop_call_strip_environment_id_and_forward_verbatim() {
        let list = ComputerRequest::parse(
            "desktop_list_tools",
            Some(
                json!({"environment_id": "env-1", "names": ["list_windows", "set_value"]})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .unwrap();
        assert_eq!(list.environment_id.as_deref(), Some("env-1"));
        assert_eq!(
            list.action,
            CuaAction::ListTools {
                names: Some(vec!["list_windows".into(), "set_value".into()]),
            }
        );

        let call = ComputerRequest::parse(
            "desktop_call",
            Some(
                json!({
                    "environment_id": "env-2",
                    "tool": "run_steps",
                    "arguments": {
                        "steps": [{"tool": "click", "arguments": {"element_token": "s1:1"}}],
                        "nested": {"a": [1, true, "ok"]}
                    }
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .unwrap();
        assert_eq!(call.environment_id.as_deref(), Some("env-2"));
        match call.action {
            CuaAction::CallTool { name, arguments } => {
                assert_eq!(name, "run_steps");
                assert!(!arguments.contains_key("environment_id"));
                assert_eq!(arguments["nested"]["a"][2], "ok");
            }
            _ => panic!("expected CallTool"),
        }
    }
}

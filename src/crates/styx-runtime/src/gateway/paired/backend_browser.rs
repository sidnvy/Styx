//! Browser routing only. Host owns contexts, current operators and continuation.
use super::*;
use crate::host::protocol::wire::BrowserSessionCommand;
use crate::providers::browser_contract::BrowserAction;
pub(super) fn is_public_browser_tool(name: &str) -> bool {
    name.starts_with("browser_") && PUBLIC.iter().any(|tool| tool.name == name)
}
impl PairedGatewayBackend {
    pub(super) async fn browser_call(
        &self,
        owner: &VerifiedGatewayOwner,
        name: &str,
        args: Option<Map<String, Value>>,
    ) -> CallToolResult {
        let mut args = args.unwrap_or_default();
        let environment = match args.remove("environment_id") {
            None => None,
            Some(Value::String(id)) if !id.is_empty() && id.len() <= 128 => Some(id),
            _ => return failure("invalid_arguments", None, false),
        };
        let session = match args.remove("browser_session_id") {
            None => None,
            Some(Value::String(id)) if !id.is_empty() && id.len() <= 128 => Some(id),
            _ => return failure("invalid_arguments", None, false),
        };
        let command = match name {
            "list_browser_sessions" if args.is_empty() && session.is_none() => {
                BrowserSessionCommand::List
            }
            "take_over_browser_session" if args.is_empty() && session.is_some() => {
                BrowserSessionCommand::TakeOver {
                    session_id: session.expect("checked ID"),
                }
            }
            name if is_public_browser_tool(name) => {
                if (BrowserAction::Tool {
                    name: name.into(),
                    arguments: args.clone(),
                })
                .to_operation_payload()
                .is_err()
                {
                    return failure("invalid_arguments", None, false);
                }
                BrowserSessionCommand::Action {
                    session_id: session,
                    name: name.into(),
                    arguments: args,
                }
            }
            _ => return failure("invalid_arguments", None, false),
        };
        let device = match self.resolve_device(environment.as_deref()).await {
            Ok(d) => d,
            Err(e) => return failure(e, None, false),
        };
        if let Err(e) = self.refresh_host_capabilities(&device).await {
            return failure(e, None, false);
        }
        let binding = match self.relay.bind_browser(owner, &device).await {
            Ok(b) => b,
            Err(e) => {
                return failure(
                    e.code(),
                    None,
                    !matches!(
                        e,
                        super::super::RelayError::Busy | super::super::RelayError::NotSent
                    ),
                );
            }
        };
        match self
            .relay
            .call(
                &binding,
                Call::BrowserSession {
                    owner: binding.owner_ref(),
                    grant_revision: binding.grant_revision(),
                    command,
                },
            )
            .await
        {
            Ok(Reply::BrowserSession { mut result }) => {
                let metadata = result.structured_content.get_or_insert_with(|| json!({}));
                if metadata.is_object() {
                    metadata["environment_id"] = json!(device);
                }
                result
            }
            Ok(Reply::Error {
                category,
                certainty,
                ..
            }) => failure(
                &serde_json::to_value(category)
                    .expect("fixed error")
                    .as_str()
                    .unwrap_or("result_unknown")
                    .to_ascii_lowercase(),
                None,
                certainty != styx_contracts::error::ExecutionCertainty::NotDispatched,
            ),
            Err(e) => failure(
                e.code(),
                None,
                !matches!(
                    e,
                    super::super::RelayError::Busy | super::super::RelayError::NotSent
                ),
            ),
            _ => failure("outcome_unknown", None, true),
        }
    }
}
#[cfg(test)]
#[path = "backend_browser_tests.rs"]
mod tests;

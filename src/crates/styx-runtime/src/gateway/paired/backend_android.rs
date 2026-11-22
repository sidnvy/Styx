//! Android tool routing. The paired Host owns permission, observations and operations.
use super::*;
use crate::host::protocol::wire::AndroidCommand;

pub(super) fn is_public_android_tool(name: &str) -> bool {
    matches!(
        name,
        "android_list_displays" | "android_observe" | "android_act" | "android_run_steps"
    )
}

impl PairedGatewayBackend {
    pub(super) async fn android_call(
        &self,
        owner: &VerifiedGatewayOwner,
        name: &str,
        args: Option<Map<String, Value>>,
    ) -> CallToolResult {
        let mut arguments = args.unwrap_or_default();
        let environment = match arguments.remove("environment_id") {
            None => None,
            Some(Value::String(id)) if !id.is_empty() && id.len() <= 128 => Some(id),
            _ => return failure("invalid_arguments", None, false),
        };
        let command = AndroidCommand {
            name: name.to_owned(),
            arguments,
        };
        if command.validate().is_err() {
            return failure("invalid_arguments", None, false);
        }
        let device = match self.resolve_device(environment.as_deref()).await {
            Ok(device) => device,
            Err(error) => return failure(error, None, false),
        };
        let binding = match self.relay.bind_android(owner, &device).await {
            Ok(binding) => binding,
            Err(error) => return failure(error.code(), None, false),
        };
        match self
            .relay
            .call(
                &binding,
                Call::Android {
                    owner: binding.owner_ref(),
                    grant_revision: binding.grant_revision(),
                    command,
                },
            )
            .await
        {
            Ok(Reply::Android { result }) => android_result(result, &device),
            Ok(Reply::Error {
                category,
                certainty,
                ..
            }) => failure(
                &serde_json::to_value(category)
                    .expect("fixed error category")
                    .as_str()
                    .unwrap_or("result_unknown")
                    .to_ascii_lowercase(),
                None,
                certainty != styx_contracts::error::ExecutionCertainty::NotDispatched,
            ),
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

fn android_result(mut value: Value, device: &DeviceId) -> CallToolResult {
    let Some(ok) = value.get("ok").and_then(Value::as_bool) else {
        return failure("outcome_unknown", None, true);
    };
    value["environment_id"] = json!(device);
    let image = value
        .get_mut("screenshot")
        .and_then(Value::as_object_mut)
        .and_then(|screenshot| {
            let data = screenshot.remove("data")?.as_str()?.to_owned();
            let mime_type = screenshot.get("mime_type")?.as_str()?.to_owned();
            Some(ContentBlock::image(data, mime_type))
        });
    // The image is MCP image content only; metadata/text retain no base64 copy.
    let mut result = CallToolResult::structured(value);
    result.is_error = Some(!ok);
    if let Some(image) = image {
        result.content.push(image);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_screenshot_is_mcp_image_without_base64_in_text_or_metadata() {
        let device = DeviceId::try_from("styx-android-image-test").unwrap();
        let result = android_result(
            json!({
                "ok": true,
                "observation_id": "observation-1",
                "screenshot": {
                    "mime_type": "image/jpeg",
                    "data": "c2NyZWVu",
                    "width": 720,
                    "height": 1280
                }
            }),
            &device,
        );
        let serialized = serde_json::to_value(&result).unwrap();
        assert_eq!(serialized["content"][1]["type"], "image");
        assert_eq!(serialized["content"][1]["data"], "c2NyZWVu");
        assert_eq!(serialized["content"][1]["mimeType"], "image/jpeg");
        assert!(
            !serialized["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("c2NyZWVu")
        );
        assert!(
            serialized["structuredContent"]["screenshot"]
                .get("data")
                .is_none()
        );
        assert_eq!(
            serialized["structuredContent"]["environment_id"],
            device.as_str()
        );
        assert_eq!(serialized["structuredContent"]["screenshot"]["width"], 720);
        assert_eq!(result.is_error, Some(false));
    }

    #[test]
    fn android_permission_refusal_keeps_host_uncertainty_and_device() {
        let device = DeviceId::try_from("styx-android-permission-test").unwrap();
        let result = android_result(
            json!({
                "ok": false,
                "error": {"code": "permission_required", "uncertain": false}
            }),
            &device,
        );
        assert_eq!(result.is_error, Some(true));
        let value = result.structured_content.unwrap();
        assert_eq!(value["error"]["code"], "permission_required");
        assert_eq!(value["error"]["uncertain"], false);
        assert_eq!(value["environment_id"], device.as_str());
    }
}

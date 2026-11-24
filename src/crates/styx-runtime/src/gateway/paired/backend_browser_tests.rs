use super::*;
#[test]
fn browser_schemas_preserve_pinned_upstream_tools_and_only_add_routing_fields() {
    let native: Value = serde_json::from_str(include_str!(
        "../../../../../packages/styx-browser-provider/playwright-contract-0.0.83.json"
    ))
    .unwrap();
    let public: Vec<_> = PUBLIC
        .iter()
        .filter(|tool| is_public_browser_tool(tool.name.as_ref()))
        .collect();
    assert_eq!(public.len(), native["tools"].as_array().unwrap().len());
    for tool in native["tools"].as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        let actual = public.iter().find(|t| t.name == name).unwrap();
        let mut schema = serde_json::to_value(actual).unwrap()["inputSchema"].clone();
        for field in ["environment_id", "browser_session_id"] {
            assert!(
                schema["properties"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field)
                    .is_some()
            );
        }
        assert_eq!(schema, tool["inputSchema"], "upstream schema drift: {name}");
    }
    assert!(PUBLIC.iter().any(|t| t.name == "list_browser_sessions"));
    assert!(PUBLIC.iter().any(|t| t.name == "take_over_browser_session"));
}

#[test]
fn public_browser_tools_mark_destructive_hint_false() {
    let browser_tools: Vec<_> = PUBLIC
        .iter()
        .filter(|tool| is_public_browser_tool(tool.name.as_ref()))
        .collect();
    assert_eq!(browser_tools.len(), 24);
    for tool in browser_tools {
        assert_eq!(
            tool.annotations.as_ref().and_then(|a| a.destructive_hint),
            Some(false),
            "browser tool {} must keep destructiveHint=false",
            tool.name
        );
    }
}

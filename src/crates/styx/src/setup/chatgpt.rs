use super::{Answers, Failure, Plugin, Result, Session, admin, inputs, plugin_package, prompt};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) const CHATGPT_ICON: &[u8] =
    include_bytes!("../../../../assets/brand/styx-custom-mcp-icon.png");

pub(super) fn prepare_chatgpt_icon(root: &Path) -> Result<PathBuf> {
    let directory = root.join("chatgpt");
    inputs::private_directory(&directory)
        .map_err(|_| Failure::new("setup_chatgpt_icon_directory_unavailable"))?;
    let path = directory.join("styx-icon.png");
    // A repeat setup may reuse the exact public asset, but never overwrite a
    // user file or follow a symlink. No runtime settings enter this directory.
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let existing = inputs::read_private(&path, 10_000)
                .map_err(|_| Failure::new("setup_chatgpt_icon_conflict"))?;
            if existing != CHATGPT_ICON {
                return Err("setup_chatgpt_icon_conflict".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            inputs::write_new(&path, CHATGPT_ICON)
                .map_err(|_| Failure::new("setup_chatgpt_icon_write_failed"))?;
        }
        Err(_) => return Err("setup_chatgpt_icon_unavailable".into()),
    }
    Ok(path)
}

pub(super) async fn export_legacy_plugin(session: &mut Session, gateway: &Path) -> Result<()> {
    // Existing ZIP choices and stale archive bytes must not block Custom MCP.
    // Only explicitly approved automated exports retain the old ZIP contract.
    if !session.automated || !session.answers.approve.contains("plugin") {
        return Ok(());
    }
    if session.input("plugin-intent.json").exists() {
        let raw = inputs::read_private(&session.input("plugin-intent.json"), 512 * 1024)
            .map_err(|_| Failure::new("setup_plugin_intent_unavailable"))?;
        let plugin: Plugin = serde_json::from_slice(&raw)
            .map_err(|_| Failure::new("setup_plugin_intent_invalid"))?;
        if session
            .answers
            .plugin
            .as_ref()
            .is_some_and(|p| p != &plugin)
        {
            return Err("setup_existing_plugin_differs".into());
        }
        session.answers.plugin = Some(plugin);
    }
    let plugin = session
        .answers
        .plugin
        .as_ref()
        .ok_or_else(|| Failure::new("setup_plugin_choices_required"))?;
    let profile = plugin
        .profile
        .clone()
        .unwrap_or_else(|| {
            styx_runtime::management::plugin_presentation::Profile::initial(&plugin.display_name)
        })
        .normalized()?;
    let profile_directory = gateway.join("plugin-presentation");
    let saved = styx_runtime::management::plugin_presentation::load(&profile_directory)?;
    if saved.as_ref().is_some_and(|s| s.profile != profile) {
        return Err("setup_existing_plugin_differs".into());
    }
    if !session.completed("plugin") {
        session.consent("plugin", "Check the hub connection and create the ChatGPT plugin folder and ZIP. No secret is included and nothing is uploaded.")?;
        let discovery = admin::observe(gateway).await.map_err(Failure::admin)?;
        if !session.input("plugin-intent.json").exists() {
            session.json_new("plugin-intent.json", plugin)?;
        }
        if saved.is_none() {
            styx_runtime::management::plugin_presentation::save(
                &profile_directory,
                0,
                profile.clone(),
            )?;
        }
        session.begin("plugin")?;
        plugin_package::write_profile(
            &plugin.output,
            &profile,
            &session
                .answers
                .tunnel
                .as_ref()
                .ok_or_else(|| Failure::new("setup_tunnel_missing"))?
                .id,
            &discovery,
        )?;
        session.done("plugin")?;
    } else {
        let discovery = admin::observe(gateway).await.map_err(Failure::admin)?;
        plugin_package::verify_profile(
            &plugin.output,
            &profile,
            &session
                .answers
                .tunnel
                .as_ref()
                .ok_or_else(|| Failure::new("setup_tunnel_missing"))?
                .id,
            &discovery,
        )?;
        session.skip("Plugin export");
    }

    Ok(())
}

pub(super) async fn connect_chatgpt(session: &mut Session, gateway: &Path) -> Result<()> {
    prompt::section("Connect ChatGPT");
    let waiting = prompt::waiting("Waiting for the ChatGPT tunnel to be ready…");
    let until = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let status = serde_json::to_value(
            styx_runtime::foreground::tunnel::status(gateway)
                .await
                .map_err(|e| Failure::new(e.code()))?,
        )
        .map_err(|_| Failure::new("setup_tunnel_status_failed"))?;
        if status["available"] != true {
            return Err("setup_tunnel_client_missing".into());
        }
        if status["transport"] == "ready" {
            waiting.finish("ChatGPT tunnel is ready");
            break;
        }
        if tokio::time::Instant::now() >= until {
            return Err("setup_tunnel_not_ready_check_status".into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    export_legacy_plugin(session, gateway).await?;
    let icon = prepare_chatgpt_icon(&session.root)?;
    let tunnel = &session
        .answers
        .tunnel
        .as_ref()
        .ok_or_else(|| Failure::new("setup_tunnel_missing"))?
        .id;
    let name = session
        .answers
        .plugin
        .as_ref()
        .map(|p| p.display_name.clone())
        .unwrap_or_else(|| format!("Styx ({})", session.answers.label));
    // Capture before presenting the instructions so a quick Connect is observed.
    let baseline = styx_runtime::foreground::tunnel::request_observation(gateway)
        .map_err(|e| Failure::new(e.code()))?["requests"]
        .as_u64()
        .unwrap_or(0);
    println!(
        "\nConnect Styx in ChatGPT:\n1. Open https://chatgpt.com/plugins in the intended account/workspace. If this hub already has a working Custom MCP connection, reuse it. Do not delete an existing plugin.\n2. For a new connection choose Add > Add custom MCP server. Name: {name}. Use a distinct name if another Styx exists.\n3. Choose icon: {} (PNG, under 10 KB). Connection: Tunnel. Tunnel ID: {tunnel}\n4. Authentication: No authentication. Keep the tunnel runtime API key only in Styx; the tunnel client supplies Gateway authentication.\n5. Review the notice, choose Create as a plugin, then Connect. Refresh its installed detail page and check that the Styx logo remains.\n6. Choose Try in chat, or start a new chat with this connection selected. Send: List my Styx computers\nCustom MCP connects the tools; it does not install the ZIP's bundled skills.\nIf Add custom MCP server is unavailable, check Developer mode and account/workspace permissions.\nLocal setup and tunnel readiness do not prove a successful ChatGPT tool call.",
        icon.display()
    );
    let wait = if session.automated {
        session.answers.plugin.as_ref().is_some_and(|p| p.wait)
    } else {
        prompt::confirm("Wait for the first request from ChatGPT? Ctrl-C stops waiting")?
    };
    if wait {
        // The transport observation is supplied only by the Gateway-owned tunnel
        // ingress, never inferred from local discovery or user confirmation.
        loop {
            let observation = styx_runtime::foreground::tunnel::request_observation(gateway)
                .map_err(|e| Failure::new(e.code()))?;
            if observation["requests"].as_u64().unwrap_or(0) > baseline {
                println!(
                    "The hub received a request through the tunnel. Confirm that the computer list appears in your ChatGPT chat; connection discovery alone is not a successful tool test."
                );
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

pub(super) async fn require_tunnel_client(answers: &Answers, root: &Path) -> Result<()> {
    if !answers.role.owns_gateway() || answers.tunnel.is_none() {
        return Ok(());
    }
    let available = if root.join("gateway").exists() {
        let status = styx_runtime::foreground::tunnel::status(&root.join("gateway"))
            .await
            .map_err(|e| Failure::new(e.code()))?;
        serde_json::to_value(status).map_err(|_| Failure::new("setup_tunnel_status_failed"))?["available"]
            == true
    } else {
        let selection = styx_runtime::release::installed_selection(
            &answers.payload.payload_dir,
            &answers.payload.publisher_file,
            &answers.payload.expected_publisher,
        )
        .await
        .map_err(|e| Failure::new(e.code()))?;
        let release =
            styx_runtime::release::load_selected(&selection).map_err(|e| Failure::new(e.code()))?;
        release.manifest().worker_closures.iter().any(|worker| {
            worker.kind == styx_contracts::native_release::NativeExternalWorker::TunnelClient
        })
    };
    if !available {
        return Err("setup_tunnel_client_missing".into());
    }
    Ok(())
}

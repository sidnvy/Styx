//! Local hub-owner editing and export. No pairing, tunnel or account mutation.
use super::{
    PluginCommand,
    setup::{self, Failure},
    setup_prompt as prompt,
};
use std::path::PathBuf;
use styx_runtime::management::{
    native_gateway_admin as admin, plugin_package,
    plugin_presentation::{self as presentation, Icon, Profile},
    setup as inputs,
};

pub(super) fn preview(profile: &Profile) -> Result<(), Failure> {
    let profile = profile.clone().normalized()?;
    println!(
        "\nPlugin identity: {}\nDisplay name: {}\nShort description: {}\nDescription:\n{}\nIcon: {} (used for both large and small icons)\nIcon SHA256: {}",
        profile.id,
        profile.presentation.display_name,
        profile.presentation.short_description,
        profile.presentation.long_description,
        if profile.presentation.icon.is_some() {
            "custom PNG"
        } else {
            "Styx logo"
        },
        styx_contracts::identity::Sha256Digest::of_bytes(&profile.presentation.icon_bytes()?)
            .to_hex()
    );
    Ok(())
}
pub(super) fn questions(
    previous: Option<&Profile>,
    suggested_name: &str,
) -> Result<Profile, Failure> {
    let mut profile = previous
        .cloned()
        .unwrap_or_else(|| Profile::initial(suggested_name));
    profile.presentation.display_name = prompt::line(
        "Plugin display name",
        Some(&profile.presentation.display_name),
    )?;
    profile.presentation.short_description = prompt::line(
        "Short description (up to 30 characters)",
        Some(&profile.presentation.short_description),
    )?;
    // A single-line replacement preserves a saved multiline description on Enter.
    println!(
        "Current description:\n{}",
        profile.presentation.long_description
    );
    let description = prompt::line(
        "New description (Enter keeps the current description)",
        None,
    )?;
    if !description.is_empty() {
        profile.presentation.long_description = description;
    }
    let icon = prompt::line(
        "PNG icon path, 'default' for Styx logo, or Enter to keep current icon",
        None,
    )?;
    if icon == "default" {
        profile.presentation.icon = None;
    } else if !icon.is_empty() {
        profile.presentation.icon = Some(Icon::from_file(std::path::Path::new(&icon))?);
    }
    if previous.is_none() {
        profile.id = plugin_package::plugin_name(&profile.presentation.display_name);
        profile.id = prompt::line(
            "Plugin identity (kept when the display name changes)",
            Some(&profile.id),
        )?;
    }
    profile.normalized().map_err(Failure::new)
}
fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub(super) fn preview_file(path: &std::path::Path, profile: &Profile) -> Result<(), Failure> {
    let profile = profile.clone().normalized()?;
    let icon = Icon::from_bytes(&profile.presentation.icon_bytes()?)?;
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Styx plugin preview</title><style>body{{font:16px system-ui;max-width:640px;margin:48px auto;padding:24px}}img{{object-fit:contain;vertical-align:middle;margin-right:16px}}pre{{white-space:pre-wrap;font:inherit}}small{{color:#555}}</style><h1>{}</h1><p><img width=128 height=128 src=\"data:image/png;base64,{}\" alt=\"Large plugin icon\"><img width=24 height=24 src=\"data:image/png;base64,{}\" alt=\"Small plugin icon\"></p><h2>{}</h2><pre>{}</pre><small>Plugin identity: {}. Preview only; nothing has been installed.</small>",
        html(&profile.presentation.display_name),
        icon.data_base64,
        icon.data_base64,
        html(&profile.presentation.short_description),
        html(&profile.presentation.long_description),
        html(&profile.id)
    );
    inputs::write_new(path, body.as_bytes())
        .map_err(|_| Failure::new("plugin_preview_requires_new_private_file"))?;
    println!("Preview: {}", path.display());
    Ok(())
}
pub(super) async fn run(
    root: Option<PathBuf>,
    gateway_state: Option<PathBuf>,
    command: PluginCommand,
) -> Result<(), Failure> {
    let gateway = match gateway_state {
        Some(p) => p,
        None => root
            .map(Ok)
            .unwrap_or_else(setup::root_default)?
            .join("gateway"),
    };
    // Admission uses the existing owner-only native Gateway admin client.
    // No fresh hub, pairing or tunnel is created to edit presentation.
    let discovery = admin::observe(&gateway).await.map_err(Failure::admin)?;
    let directory = gateway.join("plugin-presentation");
    let saved = presentation::load(&directory)?;
    match command {
        PluginCommand::Show => {
            if let Some(saved) = saved {
                preview(&saved.profile)?;
                println!("Saved revision: {}", saved.revision);
            } else {
                preview(&Profile::initial("Styx"))?;
                println!("Default draft; no profile saved. Use styx plugin configure.");
            }
        }
        PluginCommand::Configure {
            display_name,
            short_description,
            long_description,
            icon_file,
            default_icon,
            plugin_id,
            preview_file: preview_path,
            yes,
        } => {
            let mut profile = saved
                .as_ref()
                .map(|s| s.profile.clone())
                .unwrap_or_else(|| Profile::initial("Styx"));
            let supplied = display_name.is_some()
                || short_description.is_some()
                || long_description.is_some()
                || icon_file.is_some()
                || default_icon
                || plugin_id.is_some();
            if !supplied && prompt::terminal() {
                profile = questions(saved.as_ref().map(|s| &s.profile), "Styx")?;
            }
            if let Some(name) = display_name {
                profile.presentation.display_name = name;
            }
            if let Some(value) = short_description {
                profile.presentation.short_description = value;
            }
            if let Some(value) = long_description {
                profile.presentation.long_description = value;
            }
            if let Some(path) = icon_file {
                profile.presentation.icon = Some(Icon::from_file(&path)?);
            }
            if default_icon {
                profile.presentation.icon = None;
            }
            if let Some(id) = plugin_id {
                if saved.as_ref().is_some_and(|s| s.profile.id != id) {
                    return Err(Failure::new("plugin_identity_is_immutable"));
                }
                profile.id = id;
            }
            let profile = profile.normalized()?;
            preview(&profile)?;
            if let Some(path) = preview_path {
                preview_file(&path, &profile)?;
            }
            if !yes
                && (!prompt::terminal()
                    || !prompt::confirm("Save these plugin details? Nothing is uploaded.")?)
            {
                return Err(Failure::new("plugin_save_not_confirmed"));
            }
            let revision = saved.as_ref().map_or(0, |s| s.revision);
            if saved.as_ref().is_some_and(|s| s.profile == profile) {
                println!("Plugin details are unchanged.");
            } else {
                let saved = presentation::save(&directory, revision, profile)?;
                println!(
                    "Saved plugin revision {}. Export a new ZIP and update the existing plugin in ChatGPT.",
                    saved.revision
                );
            }
        }
        PluginCommand::Export {
            output,
            preview_file: preview_path,
            yes,
        } => {
            let saved = saved.ok_or_else(|| Failure::new("plugin_configure_required"))?;
            preview(&saved.profile)?;
            if let Some(path) = preview_path {
                preview_file(&path, &saved.profile)?;
            }
            if !yes
                && (!prompt::terminal()
                    || !prompt::confirm(
                        "Export this plugin to a new directory and ZIP? Nothing is uploaded.",
                    )?)
            {
                return Err(Failure::new("plugin_export_not_confirmed"));
            }
            let tunnel = discovery["tunnel_id"]
                .as_str()
                .ok_or_else(|| Failure::new("plugin_tunnel_not_configured"))?;
            plugin_package::write_profile(&output, &saved.profile, tunnel, &discovery)?;
            println!(
                "ZIP: {}\nUpdate the existing plugin with this identity in ChatGPT. Export does not prove installation or tool acceptance.",
                output.with_extension("zip").display()
            );
        }
    }
    Ok(())
}

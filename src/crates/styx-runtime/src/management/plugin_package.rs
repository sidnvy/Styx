//! Bounded, allowlisted plugin export. Embedded source assets are immutable;
//! no configuration, credentials, receipts or arbitrary paths enter the ZIP.
use crate::management::setup::{private_directory, write_new};
use serde_json::{Value, json};
use std::path::Path;

const SKILLS: [(&str, &[u8]); 4] = [
    (
        "skills/styx-native-onboarding/SKILL.md",
        include_bytes!("../../../styx/src/setup_onboarding_skill.md"),
    ),
    (
        "skills/styx-cli/SKILL.md",
        include_bytes!("../../../../plugin/skills/styx-cli/SKILL.md"),
    ),
    (
        "skills/styx-browser/SKILL.md",
        include_bytes!("../../../../plugin/skills/styx-browser/SKILL.md"),
    ),
    (
        "skills/styx-computer-use/SKILL.md",
        include_bytes!("../../../../plugin/skills/styx-computer-use/SKILL.md"),
    ),
];
pub fn plugin_name(display: &str) -> String {
    let mut slug = String::new();
    for c in display.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    let identity: String = match slug {
        "" => "styx".into(),
        s if s.starts_with("styx") => s.chars().take(64).collect(),
        s => format!("styx-{s}").chars().take(64).collect(),
    };
    identity.trim_end_matches('-').to_owned()
}
pub fn tunnel_id(value: &str) -> bool {
    value.strip_prefix("tunnel_").is_some_and(|v| {
        v.len() == 32
            && v.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}
fn files(
    profile: &super::plugin_presentation::Profile,
    tunnel: &str,
    discovery: &Value,
) -> Result<Vec<(String, Vec<u8>)>, &'static str> {
    let profile = profile.clone().normalized()?;
    let name = &profile.presentation.display_name;
    if !tunnel_id(tunnel) {
        return Err("invalid_plugin_presentation_or_tunnel");
    }
    let tools = discovery["tools"]
        .as_array()
        .ok_or("native_discovery_required")?;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "plugin_clock_unavailable")?
            .as_millis(),
    )
    .map_err(|_| "plugin_clock_unavailable")?;
    let verified = discovery["verified_at_unix_ms"]
        .as_u64()
        .ok_or("recent_native_discovery_required")?;
    if discovery["server_name"] != "styx-vnext"
        || discovery["tunnel_id"] != tunnel
        || verified > now.saturating_add(60000)
        || now.saturating_sub(verified) > 86400000
        || tools.iter().any(|t| {
            t.as_str().is_none_or(|t| {
                ["env_", "project_", "service_", "cas_"]
                    .iter()
                    .any(|prefix| t.starts_with(prefix))
            })
        })
        || tools
            .iter()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != tools.len()
    {
        return Err("recent_native_discovery_required");
    }
    if discovery["verification_scope"] != "authenticated-local-mcp-discovery"
        || [
            "list_execution_environments",
            "get_execution_environment_status",
            "exec_command",
            "write_stdin",
        ]
        .iter()
        .any(|name| !tools.iter().any(|t| t == name))
    {
        return Err("native_discovery_required");
    }
    let mut plugin: Value = serde_json::from_str(include_str!("../../../../plugin/plugin.json"))
        .map_err(|_| "invalid_embedded_plugin")?;
    // Account identity comes from the saved profile, never from an edited display name.
    plugin["name"] = json!(profile.id);
    let ui = &mut plugin["extensions"]["com.openai"]["interface"];
    ui["displayName"] = json!(name);
    ui["shortDescription"] = json!(profile.presentation.short_description);
    ui["longDescription"] = json!(profile.presentation.long_description);
    ui["logo"] = json!("./assets/icon.png");
    ui["composerIcon"] = json!("./assets/icon.png");
    let mcp = json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers":{"styx":{"type":"streamable-http", "extensions":{"com.openai":{"tunnelId":tunnel,"auth":{"type":"none"}}}}}});
    let mut out = vec![
        ("plugin.json".into(), json_bytes(&plugin)?),
        ("mcp.json".into(), json_bytes(&mcp)?),
    ];
    out.extend(SKILLS.iter().map(|(p, b)| ((*p).into(), b.to_vec())));
    out.push(("assets/icon.png".into(), profile.presentation.icon_bytes()?));
    Ok(out)
}
fn json_bytes(value: &Value) -> Result<Vec<u8>, &'static str> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| "plugin_serialization_failed")?;
    bytes.push(b'\n');
    Ok(bytes)
}
// Stored ZIP: fixed UTF-8 names, no compression or extraction. This ports the
// original minimal archive writer, with a bounded member set and checked sizes.
pub(super) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
fn u16le(out: &mut Vec<u8>, n: u16) {
    out.extend(n.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, n: u32) {
    out.extend(n.to_le_bytes());
}
fn zip(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, bytes) in files {
        let offset = u32::try_from(out.len()).map_err(|_| "plugin_too_large")?;
        let size = u32::try_from(bytes.len()).map_err(|_| "plugin_too_large")?;
        let len = u16::try_from(name.len()).map_err(|_| "plugin_too_large")?;
        let crc = crc32(bytes);
        u32le(&mut out, 0x04034b50);
        u16le(&mut out, 20);
        u16le(&mut out, 0x800);
        u16le(&mut out, 0);
        u16le(&mut out, 0);
        u16le(&mut out, 33);
        u32le(&mut out, crc);
        u32le(&mut out, size);
        u32le(&mut out, size);
        u16le(&mut out, len);
        u16le(&mut out, 0);
        out.extend(name.as_bytes());
        out.extend(bytes);
        u32le(&mut directory, 0x02014b50);
        u16le(&mut directory, 0x314);
        u16le(&mut directory, 20);
        u16le(&mut directory, 0x800);
        u16le(&mut directory, 0);
        u16le(&mut directory, 0);
        u16le(&mut directory, 33);
        u32le(&mut directory, crc);
        u32le(&mut directory, size);
        u32le(&mut directory, size);
        u16le(&mut directory, len);
        for _ in 0..4 {
            u16le(&mut directory, 0);
        }
        u32le(&mut directory, 0o100600 << 16);
        u32le(&mut directory, offset);
        directory.extend(name.as_bytes());
    }
    let start = u32::try_from(out.len()).map_err(|_| "plugin_too_large")?;
    let size = u32::try_from(directory.len()).map_err(|_| "plugin_too_large")?;
    out.extend(directory);
    u32le(&mut out, 0x06054b50);
    u16le(&mut out, 0);
    u16le(&mut out, 0);
    u16le(&mut out, files.len() as u16);
    u16le(&mut out, files.len() as u16);
    u32le(&mut out, size);
    u32le(&mut out, start);
    u16le(&mut out, 0);
    Ok(out)
}
pub fn write_profile(
    output: &Path,
    profile: &super::plugin_presentation::Profile,
    tunnel: &str,
    discovery: &Value,
) -> Result<(), &'static str> {
    if !output.is_absolute()
        || !matches!(output.file_name().and_then(|n| n.to_str()), Some(n) if n == "styx-native" || n == profile.id)
    {
        return Err("plugin_absolute_styx_native_path_required");
    }
    let files = files(profile, tunnel, discovery)?;
    let archive = zip(&files)?;
    let zip_path = output.with_extension("zip");
    if output.exists() || zip_path.exists() {
        return Err("plugin_output_must_be_fresh");
    }
    // All validation precedes publication. Partial exports are never overwritten.
    private_directory(output.parent().ok_or("plugin_parent_required")?)
        .map_err(|_| "plugin_private_parent_required")?;
    private_directory(output).map_err(|_| "plugin_publication_unknown")?;
    for (name, bytes) in files {
        let path = output.join(name);
        private_directory(path.parent().ok_or("plugin_parent_required")?)
            .map_err(|_| "plugin_publication_unknown")?;
        write_new(&path, &bytes).map_err(|_| "plugin_publication_unknown")?;
    }
    write_new(&zip_path, &archive).map_err(|_| "plugin_publication_unknown")?;
    Ok(())
}

pub fn verify_profile(
    output: &Path,
    profile: &super::plugin_presentation::Profile,
    tunnel: &str,
    discovery: &Value,
) -> Result<(), &'static str> {
    let expected = files(profile, tunnel, discovery)?;
    fn walk(root: &Path, path: &Path, found: &mut Vec<String>) -> Result<(), &'static str> {
        for entry in std::fs::read_dir(path).map_err(|_| "plugin_existing_export_invalid")? {
            let entry = entry.map_err(|_| "plugin_existing_export_invalid")?;
            let kind = entry
                .file_type()
                .map_err(|_| "plugin_existing_export_invalid")?;
            if kind.is_symlink() {
                return Err("plugin_existing_export_invalid");
            }
            if kind.is_dir() {
                walk(root, &entry.path(), found)?;
            } else if kind.is_file() {
                found.push(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|_| "plugin_existing_export_invalid")?
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            } else {
                return Err("plugin_existing_export_invalid");
            }
        }
        Ok(())
    }
    let mut found = Vec::new();
    walk(output, output, &mut found)?;
    let mut names: Vec<_> = expected.iter().map(|f| f.0.clone()).collect();
    names.sort();
    found.sort();
    if found != names {
        return Err("plugin_existing_export_invalid");
    }
    for (name, bytes) in &expected {
        if crate::management::setup::read_private(&output.join(name), 1024 * 1024)
            .map_err(|_| "plugin_existing_export_invalid")?
            != *bytes
        {
            return Err("plugin_existing_export_invalid");
        }
    }
    if crate::management::setup::read_private(&output.with_extension("zip"), 1024 * 1024)
        .map_err(|_| "plugin_existing_export_invalid")?
        != zip(&expected)?
    {
        return Err("plugin_existing_export_invalid");
    }
    Ok(())
}

/// Compatibility for a first export. Re-exports must use the saved Profile.
pub fn write(
    output: &Path,
    name: &str,
    tunnel: &str,
    discovery: &Value,
) -> Result<(), &'static str> {
    write_profile(
        output,
        &super::plugin_presentation::Profile::initial(name),
        tunnel,
        discovery,
    )
}
pub fn verify_existing(
    output: &Path,
    name: &str,
    tunnel: &str,
    discovery: &Value,
) -> Result<(), &'static str> {
    verify_profile(
        output,
        &super::plugin_presentation::Profile::initial(name),
        tunnel,
        discovery,
    )
}

/// In-memory export for an original native save panel; no caller path enters Core.
pub fn archive(
    profile: &super::plugin_presentation::Profile,
    tunnel: &str,
    discovery: &Value,
) -> Result<Vec<u8>, &'static str> {
    zip(&files(profile, tunnel, discovery)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proof() -> Value {
        json!({"verification_scope":"authenticated-local-mcp-discovery", "tools":["list_execution_environments","get_execution_environment_status","exec_command","write_stdin"],"server_name":"styx-vnext","verified_at_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,"tunnel_id":format!("tunnel_{}","a".repeat(32))})
    }
    #[test]
    fn plugin_name_is_derived_from_display_name() {
        assert_eq!(super::plugin_name("Styx (m600)"), "styx-m600");
        assert_eq!(super::plugin_name("Styx"), "styx");
        assert_eq!(super::plugin_name("Home Lab"), "styx-home-lab");
        assert_eq!(super::plugin_name("(!)"), "styx");
    }
    #[test]
    fn package_has_exact_allowlist_and_tunnel_auth_none() {
        let proof = proof();
        let files = files(
            &super::super::plugin_presentation::Profile::initial("Styx (test)"),
            &format!("tunnel_{}", "a".repeat(32)),
            &proof,
        )
        .unwrap();
        assert_eq!(
            files.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(),
            [
                "plugin.json",
                "mcp.json",
                "skills/styx-native-onboarding/SKILL.md",
                "skills/styx-cli/SKILL.md",
                "skills/styx-browser/SKILL.md",
                "skills/styx-computer-use/SKILL.md",
                "assets/icon.png"
            ]
        );
        let mcp: Value = serde_json::from_slice(&files[1].1).unwrap();
        assert_eq!(
            mcp["mcpServers"]["styx"]["extensions"]["com.openai"]["auth"],
            json!({"type":"none"})
        );
        assert_eq!(
            mcp["mcpServers"]["styx"]["extensions"]["com.openai"]["tunnelId"],
            format!("tunnel_{}", "a".repeat(32))
        );
        assert!(mcp["mcpServers"]["styx"].get("url").is_none());
        let onboarding = std::str::from_utf8(&files[2].1).unwrap();
        assert!(onboarding.contains("styx setup"));
        for retired in [
            "setup-native.mjs",
            "host/enroll.mjs",
            "linux-service.mjs",
            "macos-launchagent.mjs",
        ] {
            assert!(!onboarding.contains(retired));
        }
        let archive = zip(&files).unwrap();
        assert_eq!(&archive[..4], b"PK\x03\x04");
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert!(
            super::files(
                &super::super::plugin_presentation::Profile::initial("Styx"),
                "invalid",
                &proof
            )
            .is_err()
        );
        assert!(
            super::files(
                &super::super::plugin_presentation::Profile::initial("Styx"),
                &format!("tunnel_{}", "a".repeat(32)),
                &json!({})
            )
            .is_err()
        );
    }
    #[test]
    fn renamed_profile_exports_saved_identity_descriptions_and_exact_icon() {
        use super::super::plugin_presentation::{DEFAULT_ICON, Icon, Profile};
        let mut profile = Profile::initial("Styx original");
        profile.presentation.display_name = "我的电脑".into();
        profile.presentation.short_description = "我的已配对设备".into();
        profile.presentation.long_description = "第一行\nSecond line".into();
        let mut custom = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut custom, 48, 48);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&vec![120; 48 * 48 * 4]).unwrap();
        }
        profile.presentation.icon = Some(Icon::from_bytes(&custom).unwrap());
        let tunnel = format!("tunnel_{}", "a".repeat(32));
        let output = files(&profile, &tunnel, &proof()).unwrap();
        let manifest: Value = serde_json::from_slice(&output[0].1).unwrap();
        assert_eq!(manifest["name"], "styx-original");
        let ui = &manifest["extensions"]["com.openai"]["interface"];
        assert_eq!(ui["displayName"], "我的电脑");
        assert_eq!(ui["shortDescription"], "我的已配对设备");
        assert_eq!(ui["longDescription"], "第一行\nSecond line");
        assert_eq!(ui["logo"], ui["composerIcon"]);
        assert_eq!(
            output
                .iter()
                .find(|(n, _)| n == "assets/icon.png")
                .unwrap()
                .1,
            custom
        );
        let before = output[1].1.clone();
        profile.presentation.icon = None;
        let restored = files(&profile, &tunnel, &proof()).unwrap();
        assert_eq!(before, restored[1].1);
        assert_eq!(restored.last().unwrap().1, DEFAULT_ICON);
        assert!(
            archive(&profile, &tunnel, &proof())
                .unwrap()
                .starts_with(b"PK\x03\x04")
        );
    }
    #[test]
    fn package_writer_is_exclusive_and_existing_export_is_verified() {
        let proof = proof();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "setup-plugin-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        private_directory(&root).unwrap();
        let output = root.join("styx-native");
        let tunnel = format!("tunnel_{}", "a".repeat(32));
        assert!(write(&output, "bad\u{00ad}name", &tunnel, &proof).is_err());
        assert!(!output.exists());
        write(&output, "Styx (test)", &tunnel, &proof).unwrap();
        verify_existing(&output, "Styx (test)", &tunnel, &proof).unwrap();
        assert_eq!(
            write(&output, "Styx (test)", &tunnel, &proof).err(),
            Some("plugin_output_must_be_fresh")
        );
        #[cfg(target_os = "linux")]
        {
            // Independent archive reader verifies central-directory offsets,
            // member CRCs, byte equality and exactly one allowlisted member set.
            let result = std::process::Command::new("python3").args(["-c", "import pathlib,sys,zipfile; p=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(p.with_suffix('.zip')); expected=sorted(str(f.relative_to(p)) for f in p.rglob('*') if f.is_file()); assert sorted(z.namelist())==expected; assert z.testzip() is None; assert all(z.read(n)==(p/n).read_bytes() for n in expected)"]).arg(&output).status().unwrap();
            assert!(result.success());
        }
        write_new(&output.join("unexpected.txt"), b"not allowlisted").unwrap();
        assert!(verify_existing(&output, "Styx (test)", &tunnel, &proof).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

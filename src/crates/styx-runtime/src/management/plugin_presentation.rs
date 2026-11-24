//! Shared plugin presentation. Immutable revisions preserve identity and make
//! concurrent edits conflict without overwriting an export or saved selection.
use super::setup;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    io::{Cursor, Read},
    path::Path,
};

pub const DEFAULT_ICON: &[u8] = include_bytes!("../../../../assets/brand/styx-logo.png");
pub const MAX_ICON_BYTES: usize = 256 * 1024;
const MAX_PROFILE_BYTES: usize = 512 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Icon {
    pub mime_type: String,
    pub data_base64: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Presentation {
    pub display_name: String,
    pub short_description: String,
    pub long_description: String,
    #[serde(default)]
    pub icon: Option<Icon>,
}
impl Default for Presentation {
    fn default() -> Self {
        let template: serde_json::Value =
            serde_json::from_str(include_str!("../../../../plugin/plugin.json"))
                .expect("embedded plugin");
        let ui = &template["extensions"]["com.openai"]["interface"];
        Self {
            display_name: ui["displayName"].as_str().expect("name").into(),
            short_description: ui["shortDescription"]
                .as_str()
                .expect("short description")
                .into(),
            long_description: ui["longDescription"].as_str().expect("description").into(),
            icon: None,
        }
    }
}
fn text(value: &str, max: usize, multiline: bool) -> Result<String, &'static str> {
    static CONTROLS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[\p{Cc}\p{Cf}\u2028\u2029]").expect("fixed expression")
    });
    let value = if multiline {
        value.replace("\r\n", "\n")
    } else {
        value.to_owned()
    };
    let controls = if multiline {
        value.replace('\n', "")
    } else {
        value.clone()
    };
    if CONTROLS.is_match(&controls) {
        return Err("invalid_plugin_text");
    }
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max {
        return Err("invalid_plugin_text");
    }
    Ok(value.into())
}
pub fn validate_png(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < 57 || bytes.len() > MAX_ICON_BYTES || !bytes.starts_with(b"\x89PNG\r\n\x1a\n")
    {
        return Err("bounded_png_icon_required");
    }
    // Policy allowlist only; the maintained png decoder validates structure,
    // filters, checksums and actual pixel decoding under a resource limit.
    let mut offset = 8usize;
    let mut ended = false;
    let mut chunks = 0;
    while offset < bytes.len() {
        chunks += 1;
        let header = bytes
            .get(offset..offset + 8)
            .ok_or("invalid_png_structure")?;
        let size = u32::from_be_bytes(header[..4].try_into().expect("four bytes")) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|n| n.checked_add(size))
            .filter(|n| *n <= bytes.len())
            .ok_or("invalid_png_structure")?;
        if chunks > 1024
            || ended
            || !matches!(
                &header[4..],
                b"IHDR"
                    | b"PLTE"
                    | b"tRNS"
                    | b"IDAT"
                    | b"IEND"
                    | b"sRGB"
                    | b"gAMA"
                    | b"cHRM"
                    | b"pHYs"
            )
        {
            return Err("unsupported_png_chunk");
        }
        let expected = u32::from_be_bytes(bytes[end - 4..end].try_into().expect("four bytes"));
        if super::plugin_package::crc32(&bytes[offset + 4..end - 4]) != expected {
            return Err("invalid_png_checksum");
        }
        ended = &header[4..] == b"IEND";
        offset = end;
    }
    if !ended {
        return Err("invalid_png_structure");
    }
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_limits(png::Limits {
        bytes: 8 * 1024 * 1024,
    });
    let mut reader = decoder.read_info().map_err(|_| "invalid_png_structure")?;
    let info = reader.info();
    if info.width != info.height
        || !(48..=1024).contains(&info.width)
        || info.bit_depth != png::BitDepth::Eight
        || info.interlaced
        || info.animation_control.is_some()
    {
        return Err("unsupported_png_dimensions_or_format");
    }
    let palette = info.palette.as_ref().map(|p| p.len() / 3);
    let length = reader
        .output_buffer_size()
        .filter(|n| *n <= 4 * 1024 * 1024)
        .ok_or("invalid_png_pixels")?;
    let mut pixels = vec![0; length];
    let output = reader
        .next_frame(&mut pixels)
        .map_err(|_| "invalid_png_pixels")?;
    if output.color_type == png::ColorType::Indexed
        && pixels[..output.buffer_size()]
            .iter()
            .any(|i| Some(*i as usize) >= palette)
    {
        return Err("invalid_png_palette_index");
    }
    reader.finish().map_err(|_| "invalid_png_pixels")?;
    Ok(())
}
impl Icon {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        validate_png(bytes)?;
        Ok(Self {
            mime_type: "image/png".into(),
            data_base64: STANDARD.encode(bytes),
        })
    }
    pub fn from_file(path: &Path) -> Result<Self, &'static str> {
        let mut bytes = Vec::new();
        let file = std::fs::File::open(path).map_err(|_| "plugin_icon_unreadable")?;
        if !file
            .metadata()
            .map_err(|_| "plugin_icon_unreadable")?
            .is_file()
        {
            return Err("plugin_icon_regular_file_required");
        }
        file.take((MAX_ICON_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "plugin_icon_unreadable")?;
        Self::from_bytes(&bytes)
    }
    pub fn bytes(&self) -> Result<Vec<u8>, &'static str> {
        if self.mime_type != "image/png" || self.data_base64.len() > 4 * MAX_ICON_BYTES.div_ceil(3)
        {
            return Err("bounded_png_icon_required");
        }
        let bytes = STANDARD
            .decode(&self.data_base64)
            .map_err(|_| "bounded_png_icon_required")?;
        if STANDARD.encode(&bytes) != self.data_base64 {
            return Err("bounded_png_icon_required");
        }
        validate_png(&bytes)?;
        Ok(bytes)
    }
}
impl Presentation {
    pub fn normalized(mut self) -> Result<Self, &'static str> {
        self.display_name = text(&self.display_name, 64, false)?;
        self.short_description = text(&self.short_description, 30, false)?;
        self.long_description = text(&self.long_description, 2000, true)?;
        self.icon_bytes()?;
        Ok(self)
    }
    pub fn icon_bytes(&self) -> Result<Vec<u8>, &'static str> {
        self.icon
            .as_ref()
            .map_or_else(|| Ok(DEFAULT_ICON.to_vec()), Icon::bytes)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub presentation: Presentation,
}
impl Profile {
    pub fn initial(name: &str) -> Self {
        Self {
            id: super::plugin_package::plugin_name(name),
            presentation: Presentation {
                display_name: name.into(),
                ..Presentation::default()
            },
        }
    }
    pub fn normalized(mut self) -> Result<Self, &'static str> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self.id.as_bytes()[0].is_ascii_lowercase()
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || self.id.ends_with('-')
        {
            return Err("invalid_plugin_identity");
        }
        self.presentation = self.presentation.normalized()?;
        Ok(self)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Saved {
    pub schema: u16,
    pub revision: u64,
    pub profile: Profile,
}
pub fn load(directory: &Path) -> Result<Option<Saved>, &'static str> {
    if !directory.exists() {
        return Ok(None);
    }
    setup::private_directory(directory).map_err(|_| "plugin_profile_directory_refused")?;
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|_| "plugin_profile_unreadable")? {
        let entry = entry.map_err(|_| "plugin_profile_unreadable")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "plugin_profile_invalid")?;
        if !name.starts_with("profile-")
            || !name.ends_with(".json")
            || name.len() != 29
            || !entry
                .file_type()
                .map_err(|_| "plugin_profile_invalid")?
                .is_file()
        {
            return Err("plugin_profile_invalid");
        }
        paths.push(entry.path());
        if paths.len() > 4096 {
            return Err("plugin_profile_revision_limit");
        }
    }
    paths.sort();
    let mut last: Option<Saved> = None;
    for (index, path) in paths.iter().enumerate() {
        let raw = setup::read_private(path, MAX_PROFILE_BYTES)
            .map_err(|_| "plugin_profile_unreadable")?;
        let saved: Saved = serde_json::from_slice(&raw).map_err(|_| "plugin_profile_invalid")?;
        let expected = (index as u64) + 1;
        if saved.schema != 1
            || saved.revision != expected
            || path.file_name().and_then(|p| p.to_str())
                != Some(&format!("profile-{expected:016}.json"))
            || last
                .as_ref()
                .is_some_and(|p| p.profile.id != saved.profile.id)
            || saved.profile.clone().normalized()? != saved.profile
        {
            return Err("plugin_profile_invalid");
        }
        last = Some(saved);
    }
    Ok(last)
}
pub fn save(
    directory: &Path,
    expected_revision: u64,
    profile: Profile,
) -> Result<Saved, &'static str> {
    let profile = profile.normalized()?;
    let previous = load(directory)?;
    if previous.as_ref().map_or(0, |p| p.revision) != expected_revision
        || previous
            .as_ref()
            .is_some_and(|p| p.profile.id != profile.id)
    {
        return Err("plugin_profile_conflict");
    }
    if let Some(saved) = &previous
        && saved.profile == profile
    {
        return Ok(saved.clone());
    }
    if expected_revision >= 4096 {
        return Err("plugin_profile_revision_limit");
    }
    let saved = Saved {
        schema: 1,
        revision: expected_revision + 1,
        profile,
    };
    let bytes = serde_json::to_vec_pretty(&saved).map_err(|_| "plugin_profile_invalid")?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err("plugin_profile_too_large");
    }
    setup::private_directory(directory).map_err(|_| "plugin_profile_directory_refused")?;
    setup::write_new(
        &directory.join(format!("profile-{:016}.json", saved.revision)),
        &bytes,
    )
    .map_err(|_| "plugin_profile_save_unconfirmed_check_before_retry")?;
    Ok(saved)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn custom() -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, 48, 48);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            let mut pixels = vec![0; 48 * 48 * 4];
            pixels[..4].copy_from_slice(&[20, 100, 180, 128]);
            writer.write_image_data(&pixels).unwrap();
        }
        bytes
    }
    #[test]
    fn official_default_and_custom_transparency_are_preserved() {
        assert!(validate_png(DEFAULT_ICON).is_ok());
        let bytes = custom();
        let icon = Icon::from_bytes(&bytes).unwrap();
        assert_eq!(icon.bytes().unwrap(), bytes);
        assert_eq!(Presentation::default().icon_bytes().unwrap(), DEFAULT_ICON);
        let mut reader = png::Decoder::new(Cursor::new(icon.bytes().unwrap()))
            .read_info()
            .unwrap();
        let mut decoded = vec![0; reader.output_buffer_size().unwrap()];
        reader.next_frame(&mut decoded).unwrap();
        assert_eq!(&decoded[..4], &[20, 100, 180, 128]);
    }
    #[test]
    fn invalid_media_text_and_unknown_fields_are_rejected() {
        let mut broken = custom();
        broken[40] ^= 1;
        assert!(validate_png(&broken).is_err());
        let mut trailing = custom();
        trailing.extend_from_slice(b"secret");
        assert!(validate_png(&trailing).is_err());
        assert!(validate_png(&vec![0; MAX_ICON_BYTES + 1]).is_err());
        let mut icon = Icon::from_bytes(&custom()).unwrap();
        icon.data_base64.push('\n');
        assert!(icon.bytes().is_err());
        for value in ["", "abc\u{202e}def", "\tname", "name\n"] {
            let p = Presentation {
                display_name: value.into(),
                ..Presentation::default()
            };
            assert!(p.normalized().is_err());
        }
        assert!(
            Presentation {
                display_name: "中".repeat(64),
                ..Presentation::default()
            }
            .normalized()
            .is_ok()
        );
        assert!(
            Presentation {
                display_name: "中".repeat(65),
                ..Presentation::default()
            }
            .normalized()
            .is_err()
        );
        assert!(serde_json::from_value::<Presentation>(serde_json::json!({"displayName":"Styx","shortDescription":"hi","longDescription":"hello","token":"SECRET"})).is_err());
        let p = Presentation {
            long_description: "a\r\nb".into(),
            ..Presentation::default()
        }
        .normalized()
        .unwrap();
        assert_eq!(p.long_description, "a\nb");
    }
    #[test]
    fn png_metadata_and_animation_do_not_enter_profile() {
        for kind in [b"tEXt", b"iCCP", b"acTL", b"eXIf"] {
            let mut bytes = custom();
            let mut chunk = Vec::new();
            chunk.extend_from_slice(&0u32.to_be_bytes());
            chunk.extend_from_slice(kind);
            chunk.extend_from_slice(&super::super::plugin_package::crc32(kind).to_be_bytes());
            bytes.splice(33..33, chunk);
            assert_eq!(validate_png(&bytes), Err("unsupported_png_chunk"));
        }
    }
    #[test]
    fn revision_conflict_and_identity_change_never_replace_saved_profile() {
        let root =
            std::env::temp_dir().join(format!("styx-plugin-profile-{}", uuid::Uuid::new_v4()));
        let mut profile = Profile::initial("Styx original");
        profile.presentation.icon = Some(Icon::from_bytes(&custom()).unwrap());
        let first = save(&root, 0, profile.clone()).unwrap();
        assert_eq!(first.revision, 1);
        let id = profile.id.clone();
        profile.presentation.display_name = "Changed name".into();
        assert_eq!(
            save(&root, 0, profile.clone()).unwrap_err(),
            "plugin_profile_conflict"
        );
        save(&root, 1, profile.clone()).unwrap();
        profile.id = "another-plugin".into();
        assert_eq!(
            save(&root, 2, profile.clone()).unwrap_err(),
            "plugin_profile_conflict"
        );
        let saved = load(&root).unwrap().unwrap();
        assert_eq!(saved.profile.id, id);
        assert_eq!(saved.profile.presentation.display_name, "Changed name");
        assert!(saved.profile.presentation.icon.is_some());
        profile = saved.profile;
        profile.presentation.icon = None;
        save(&root, 2, profile).unwrap();
        let restored = load(&root).unwrap().unwrap();
        assert_eq!(
            restored.profile.presentation.icon_bytes().unwrap(),
            DEFAULT_ICON
        );
        assert_eq!(restored.profile.id, id);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn concurrent_edits_have_one_winner() {
        let root =
            std::env::temp_dir().join(format!("styx-plugin-conflict-{}", uuid::Uuid::new_v4()));
        save(&root, 0, Profile::initial("Styx")).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut tasks = Vec::new();
        for name in ["First edit", "Second edit"] {
            let root = root.clone();
            let barrier = barrier.clone();
            tasks.push(std::thread::spawn(move || {
                let mut p = Profile::initial("Styx");
                p.presentation.display_name = name.into();
                barrier.wait();
                save(&root, 1, p).is_ok()
            }));
        }
        assert_eq!(
            tasks
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        assert_eq!(load(&root).unwrap().unwrap().revision, 2);
        std::fs::remove_dir_all(root).unwrap();
    }
}

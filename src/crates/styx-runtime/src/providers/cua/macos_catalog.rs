//! Offline source-derived Mac native input schemas, NOT native execution proof.
//! See R53 catalog-authoring receipt: exact original ToolDef AST expressions and
//! original Core to_list_entry logic, including session/typed-target additions.
//! Captured from the official 0.47.24 Mac binary using finite dump-docs.
//! Only the ten consumed schemas are pinned; no private tool pair is required.
pub(super) const FROZEN_MACOS_CATALOG: super::FixedNativeCatalog = super::FixedNativeCatalog {
    schemas_json: include_str!("macos_catalog.json"),
};

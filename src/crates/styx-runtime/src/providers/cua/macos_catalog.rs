//! Offline source-derived Mac native input schemas, NOT native execution proof.
//! See R53 catalog-authoring receipt: exact original ToolDef AST expressions and
//! original Core to_list_entry logic, including session/typed-target additions.
//! No total Mac native-tool count is guessed; only bounded unique entries and
//! the ten consumed full schemas plus the private pair can pass admission.
pub(super) const FROZEN_MACOS_CATALOG: super::FixedNativeCatalog = super::FixedNativeCatalog {
    native_count: None,
    schemas_json: include_str!("macos_catalog.json"),
    full_catalog: false,
};

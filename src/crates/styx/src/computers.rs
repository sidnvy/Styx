//! Computer inventory and explicit revocation over the local Gateway admin API.
use super::{
    ComputersCommand,
    setup::{self, Failure},
    setup_prompt as prompt,
};
use std::path::{Path, PathBuf};
use styx_contracts::identity::DeviceId;
use styx_runtime::management::{native_gateway_admin as admin, setup as inputs};

fn visible(
    rows: &[admin::PairedComputer],
    all: bool,
) -> impl Iterator<Item = &admin::PairedComputer> {
    rows.iter()
        .filter(move |row| all || row.status != "revoked")
}
fn select<'a>(
    rows: &'a [admin::PairedComputer],
    selector: &str,
) -> Result<&'a admin::PairedComputer, Failure> {
    let active: Vec<_> = visible(rows, false).collect();
    if let Some(row) = active.iter().find(|row| row.device_id.as_str() == selector) {
        return Ok(row);
    }
    let matches: Vec<_> = active
        .into_iter()
        .filter(|row| row.label == selector)
        .collect();
    match matches.as_slice() {
        [row] => Ok(row),
        [] => Err(Failure::new("computers_not_found")),
        _ => {
            eprintln!("Several computers have that label. Use a device id:");
            for row in matches {
                eprintln!(
                    "  {:?}  {}  {}",
                    row.label,
                    row.platform,
                    row.device_id.as_str()
                );
            }
            Err(Failure::new("computers_ambiguous_label"))
        }
    }
}
fn protect_local(
    device: &DeviceId,
    local: Option<&DeviceId>,
    include: bool,
) -> Result<(), Failure> {
    if !include && local == Some(device) {
        return Err(Failure::new(
            "computers_this_computer_requires_include_this_computer",
        ));
    }
    Ok(())
}
fn local_device(root: &Path) -> Result<Option<DeviceId>, Failure> {
    if !root.join("host").exists() {
        return Ok(None);
    }
    let raw = inputs::read_private(&root.join("host/host-join-seed-v1.json"), 64 * 1024)
        .map_err(|_| Failure::new("computers_local_identity_unavailable"))?;
    let identity: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|_| Failure::new("computers_local_identity_invalid"))?;
    let device = identity["device_id"]
        .as_str()
        .ok_or_else(|| Failure::new("computers_local_identity_invalid"))?;
    DeviceId::try_from(device)
        .map(Some)
        .map_err(|_| Failure::new("computers_local_identity_invalid"))
}
fn connection(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "connected",
        Some(false) => "disconnected",
        None => "unknown",
    }
}
pub(super) async fn run(
    root: Option<PathBuf>,
    all: bool,
    command: Option<ComputersCommand>,
) -> Result<(), Failure> {
    let root = root.map(Ok).unwrap_or_else(setup::root_default)?;
    let gateway = root.join("gateway");
    let rows = admin::computers(&gateway).await.map_err(Failure::admin)?;
    let Some(ComputersCommand::Remove {
        selector,
        yes,
        include_this_computer,
    }) = command
    else {
        println!("LABEL  PLATFORM  DEVICE ID  STATUS  CONNECTIONS");
        for row in visible(&rows, all) {
            println!(
                "{:?}  {}  {}  {}  commands={}, browser={}, computer={}",
                row.label,
                row.platform,
                row.device_id.as_str(),
                row.status,
                connection(row.connections.exec),
                connection(row.connections.browser),
                connection(row.connections.computer)
            );
        }
        return Ok(());
    };
    let row = select(&rows, &selector)?;
    let local = if include_this_computer {
        None
    } else {
        local_device(&root)?
    };
    protect_local(&row.device_id, local.as_ref(), include_this_computer)?;
    println!(
        "Remove pairing for {:?} ({}, {})?",
        row.label,
        row.platform,
        row.device_id.as_str()
    );
    if !yes {
        if !prompt::terminal() {
            return Err(Failure::new("computers_confirmation_required_use_yes"));
        }
        if !prompt::confirm("Revoke this computer's access now?")? {
            return Err(Failure::new("setup_cancelled"));
        }
    }
    admin::revoke_computer(&gateway, row.device_id.clone())
        .await
        .map_err(Failure::admin)?;
    println!("Pairing revoked. Re-pair this computer to connect again.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(id: &str, label: &str, status: &str) -> admin::PairedComputer {
        admin::PairedComputer {
            device_id: DeviceId::try_from(id).unwrap(),
            label: label.into(),
            platform: "linux".into(),
            status: status.into(),
            connections: admin::ComputerConnections {
                exec: Some(false),
                browser: None,
                computer: None,
            },
        }
    }
    #[test]
    fn select_exact_id_or_label_refuses_ambiguity_and_revoked_records() {
        let mut rows = vec![
            row("styx-first", "Desk", "approved"),
            row("styx-old", "Old", "revoked"),
        ];
        assert_eq!(
            select(&rows, "Desk").unwrap().device_id.as_str(),
            "styx-first"
        );
        assert_eq!(select(&rows, "styx-first").unwrap().label, "Desk");
        assert_eq!(
            select(&rows, "Old").unwrap_err().code,
            "computers_not_found"
        );
        assert_eq!(visible(&rows, false).count(), 1);
        assert_eq!(visible(&rows, true).count(), 2);
        rows.push(row("styx-second", "Desk", "approved"));
        assert_eq!(
            select(&rows, "Desk").unwrap_err().code,
            "computers_ambiguous_label"
        );
        assert_eq!(
            select(&rows, "styx-second").unwrap().device_id.as_str(),
            "styx-second"
        );
    }
    #[test]
    fn this_computer_is_protected_even_with_yes_until_explicitly_included() {
        let local = DeviceId::try_from("styx-local").unwrap();
        let other = DeviceId::try_from("styx-other").unwrap();
        assert!(protect_local(&local, Some(&local), false).is_err());
        assert!(protect_local(&local, Some(&local), true).is_ok());
        assert!(protect_local(&other, Some(&local), false).is_ok());
    }
}

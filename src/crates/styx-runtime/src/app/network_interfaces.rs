//! Read-only OS interface discovery. Rust retains configuration authority;
//! discovering an address does not enable a listener or grant a remote peer.
use super::AppError;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Interface {
    name: String,
    address: Ipv4Addr,
    recommended: bool,
}

fn eligible(address: Ipv4Addr) -> bool {
    crate::gateway::auth::lan_address(true, Some(&address.to_string())).is_ok()
}

fn current_interfaces() -> Result<Vec<Interface>, AppError> {
    let interfaces = crate::management::setup::private_addresses()
        .map_err(|_| AppError("app_network_interfaces_unavailable"))?;
    let mut result = interfaces
        .into_iter()
        .map(|interface| Interface {
            name: interface
                .interface
                .chars()
                .filter(|c| !c.is_control())
                .take(128)
                .collect(),
            address: interface.address,
            recommended: false,
        })
        .collect::<Vec<_>>();
    let mut seen = std::collections::BTreeSet::new();
    result.retain(|interface| seen.insert(interface.address));
    if result.len() > 64 {
        return Err(AppError("app_network_interfaces_unavailable"));
    }
    // UDP connect asks the kernel for its current route/source selection. No
    // bytes are sent, DNS is not used, and the socket is immediately dropped.
    // An absent default route still permits a purely local/VPN network.
    let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .ok()
        .and_then(|socket| {
            socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
            Some(socket.local_addr().ok()?.ip())
        });
    if let Some(index) = result
        .iter()
        .position(|interface| Some(IpAddr::V4(interface.address)) == route)
    {
        result[index].recommended = true;
        result.swap(0, index);
    } else if let Some(first) = result.first_mut() {
        first.recommended = true;
    }
    Ok(result)
}

pub(super) fn snapshot() -> Result<serde_json::Value, AppError> {
    let interfaces = current_interfaces()?;
    Ok(
        serde_json::json!({"schema":1,"source":"os_interface_snapshot",
        "recommendedAddress":interfaces.first().map(|interface| interface.address),
        "interfaces":interfaces}),
    )
}

pub(super) fn resolve(enabled: bool, selected: Option<&str>) -> Result<Option<String>, AppError> {
    if !enabled && selected.is_none() {
        return Ok(None);
    }
    // An explicit empty/invalid address remains a definite preflight refusal.
    // Automatic discovery is represented by omitting the address, not by
    // weakening the frozen validation of an explicitly supplied value.
    let selected = selected
        .map(|value| {
            let address: Ipv4Addr = value
                .parse()
                .map_err(|_| AppError("app_lan_address_invalid"))?;
            if !eligible(address) {
                return Err(AppError("app_lan_address_invalid"));
            }
            Ok(address)
        })
        .transpose()?;
    let interfaces = current_interfaces()?;
    match selected {
        Some(selected) => {
            if !interfaces
                .iter()
                .any(|interface| interface.address == selected)
            {
                return Err(AppError("app_network_interface_changed"));
            }
            Ok(Some(selected.to_string()))
        }
        None => interfaces
            .first()
            .map(|interface| Some(interface.address.to_string()))
            .ok_or(AppError("app_network_interface_required")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_does_not_accept_wildcard_loopback_public_or_link_local() {
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "8.8.8.8",
            "169.254.1.2",
            "224.0.0.1",
        ] {
            assert!(!eligible(address.parse().unwrap()));
        }
        for address in ["10.0.8.165", "192.168.1.2", "172.20.1.2", "100.64.1.2"] {
            assert!(eligible(address.parse().unwrap()));
        }
        assert_eq!(resolve(false, None).unwrap(), None);
    }

    #[test]
    fn actual_os_snapshot_contains_only_bindable_current_private_addresses() {
        let interfaces = current_interfaces().unwrap();
        let raw = if_addrs::get_if_addrs().unwrap();
        for interface in &interfaces {
            assert!(
                raw.iter()
                    .any(|item| item.is_oper_up() && item.ip() == IpAddr::V4(interface.address))
            );
            let socket = UdpSocket::bind((interface.address, 0)).unwrap();
            assert_eq!(
                socket.local_addr().unwrap().ip(),
                IpAddr::V4(interface.address)
            );
        }
        assert_eq!(
            interfaces
                .iter()
                .filter(|interface| interface.recommended)
                .count(),
            usize::from(!interfaces.is_empty())
        );
    }
}

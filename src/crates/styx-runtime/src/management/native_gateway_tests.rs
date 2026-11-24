use super::*;
use serde_json::json;

#[test]
fn gateway_deployment_keeps_loopback_and_requires_explicit_valid_lan() {
    let base = json!({"schema":1,"mode":"create-local","gateway":{"url":"https://127.0.0.1:8795/","listenHost":"127.0.0.1"}});
    let endpoints = endpoints(&serde_json::to_vec(&base).unwrap()).unwrap();
    assert_eq!(endpoints.origin, "https://127.0.0.1:8795");
    assert_eq!(endpoints.address.to_string(), "127.0.0.1:8795");
    assert!(endpoints.lan_addresses.is_empty());
    for address in ["10.1.2.3", "172.16.1.2", "192.168.1.2", "100.64.1.2"] {
        let mut deployment = base.clone();
        deployment["gateway"]["allowRemoteHosts"] = json!(true);
        deployment["gateway"]["lanAddress"] = json!(address);
        let selected = super::endpoints(&serde_json::to_vec(&deployment).unwrap()).unwrap();
        assert_eq!(selected.address, endpoints.address);
        assert_eq!(
            selected.lan_origins(),
            vec![format!("https://{address}:8795")]
        );
    }
    for address in [
        "8.8.8.8",
        "127.0.0.1",
        "169.254.1.2",
        "0.0.0.0",
        "224.0.0.1",
        "100.128.0.1",
        "::1",
    ] {
        let mut deployment = base.clone();
        deployment["gateway"]["allowRemoteHosts"] = json!(true);
        deployment["gateway"]["lanAddress"] = json!(address);
        assert!(super::endpoints(&serde_json::to_vec(&deployment).unwrap()).is_err());
    }
    let mut missing = base.clone();
    missing["gateway"]["allowRemoteHosts"] = json!(true);
    assert!(super::endpoints(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut disabled = base.clone();
    disabled["gateway"]["lanAddress"] = json!("192.168.1.2");
    assert!(super::endpoints(&serde_json::to_vec(&disabled).unwrap()).is_err());
    let mut wildcard = base;
    wildcard["gateway"]["listenHost"] = json!("0.0.0.0");
    assert!(super::endpoints(&serde_json::to_vec(&wildcard).unwrap()).is_err());
}

#[test]
fn gateway_deployment_validates_multiple_private_addresses_and_exclusive_compatibility_input() {
    let base = json!({"schema":1,"mode":"create-local","gateway":{
        "url":"https://127.0.0.1:8795/","allowRemoteHosts":true,
        "lanAddresses":["10.118.53.220","10.0.2.19"]}});
    for addresses in [
        json!(["10.118.53.220"]),
        json!(["10.118.53.220", "10.0.2.19"]),
        json!(["192.168.1.2", "172.16.1.2", "100.64.1.2", "10.0.2.19"]),
    ] {
        let mut deployment = base.clone();
        deployment["gateway"]["lanAddresses"] = addresses.clone();
        let selected = endpoints(&serde_json::to_vec(&deployment).unwrap()).unwrap();
        let expected: Vec<_> = addresses
            .as_array()
            .unwrap()
            .iter()
            .map(|ip| format!("https://{}:8795", ip.as_str().unwrap()))
            .collect();
        assert_eq!(selected.lan_origins(), expected);
        assert_eq!(selected.address.to_string(), "127.0.0.1:8795");
    }
    for addresses in [
        json!([]),
        json!(["8.8.8.8"]),
        json!(["127.0.0.1"]),
        json!(["169.254.1.1"]),
        json!(["0.0.0.0"]),
        json!(["::1"]),
        json!(["100.128.0.1"]),
        json!(["10.0.2.19", "10.0.2.19"]),
        json!(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]),
        json!("10.0.2.19"),
        json!([1]),
    ] {
        let mut deployment = base.clone();
        deployment["gateway"]["lanAddresses"] = addresses;
        assert!(endpoints(&serde_json::to_vec(&deployment).unwrap()).is_err());
    }
    let mut both = base.clone();
    both["gateway"]["lanAddress"] = json!("192.168.1.2");
    assert!(endpoints(&serde_json::to_vec(&both).unwrap()).is_err());
    let mut disabled = base;
    disabled["gateway"]["allowRemoteHosts"] = json!(false);
    assert!(endpoints(&serde_json::to_vec(&disabled).unwrap()).is_err());
}

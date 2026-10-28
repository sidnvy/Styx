use super::*;
use serde_json::json;

#[test]
fn gateway_deployment_keeps_loopback_and_requires_explicit_valid_lan() {
    let base = json!({"schema":1,"mode":"create-local","gateway":{"url":"https://127.0.0.1:8795/","listenHost":"127.0.0.1"}});
    let endpoints = endpoints(&serde_json::to_vec(&base).unwrap()).unwrap();
    assert_eq!(endpoints.origin, "https://127.0.0.1:8795");
    assert_eq!(endpoints.address.to_string(), "127.0.0.1:8795");
    assert!(endpoints.lan_address.is_none());
    for address in ["10.1.2.3", "172.16.1.2", "192.168.1.2", "100.64.1.2"] {
        let mut deployment = base.clone();
        deployment["gateway"]["allowRemoteHosts"] = json!(true);
        deployment["gateway"]["lanAddress"] = json!(address);
        let selected = super::endpoints(&serde_json::to_vec(&deployment).unwrap()).unwrap();
        assert_eq!(selected.address, endpoints.address);
        assert_eq!(
            selected.lan_origin().unwrap(),
            format!("https://{address}:8795")
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

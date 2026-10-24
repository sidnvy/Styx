//! Focused negotiation/dispatch classification only. This does not attest a
//! granted lane or actual WS lifetime; root runs the paired transport journey.
use super::*;
#[test]
fn independent_feature_families_never_synthesize_exec_support() {
    let control = vec![
        "owner_open".into(),
        "owner_revoke".into(),
        "owner_cleanup".into(),
    ];
    let mut browser = control.clone();
    browser.push(BROWSER_HEADLESS_V1.into());
    assert!(!exec_negotiated(&browser, false, false, false));
    let mut computer = control;
    computer.push(COMPUTER_V1.into());
    assert!(!exec_negotiated(&computer, true, true, false));
    let exec: Vec<String> = [
        "prepare_start",
        "dispatch_start",
        "inspect_start",
        "read",
        "prepare_action",
        "dispatch_action",
        "inspect_action",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert!(exec_negotiated(&exec, true, true, false));
    assert!(!exec_negotiated(&exec, false, true, false));
    assert!(!exec_negotiated(&exec, true, false, false));
    assert!(!exec_negotiated(&exec, true, true, true));
    let mut incomplete = exec.clone();
    incomplete.pop();
    assert!(!exec_negotiated(&incomplete, true, true, false));
    let mut combined = exec;
    combined.push(BROWSER_HEADLESS_V1.into());
    combined.push(COMPUTER_V1.into());
    assert!(exec_negotiated(&combined, true, true, false));
}
#[test]
fn only_proven_pre_send_refusal_is_local_to_a_lane() {
    assert!(known_pre_send_refusal(RelayError::Unauthorized));
    assert!(known_pre_send_refusal(RelayError::Invalid));
    assert!(known_pre_send_refusal(RelayError::Unsupported));
    // Lost write/flush certainty can never be contained to an individual lane.
    assert!(!known_pre_send_refusal(RelayError::Unknown));
    assert!(!known_pre_send_refusal(RelayError::Offline));
    assert!(!known_pre_send_refusal(RelayError::Busy));
}

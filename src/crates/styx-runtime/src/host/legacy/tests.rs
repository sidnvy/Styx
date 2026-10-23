//! Source-bound raw-wire checks. These do not prove an actual old Gateway/CLI
//! journey; that requires the separately owned immutable legacy harness.
use super::wire::*;
use serde_json::json;
#[test]
fn existing_gateway_frames_keep_native_ids_cursors_and_raw_fields() {
    let initialize = Request::parse(r#"{"id":1,"method":"initialize","params":{"clientName":"styx-isolated-prototype","resumeSessionId":"original-session"}}"#).unwrap();
    let initialize: Initialize = initialize.typed().unwrap();
    assert!(initialize.valid());
    assert_eq!(
        initialize.resume_session_id.as_deref(),
        Some("original-session")
    );
    let initialized = Request::parse(r#"{"method":"initialized","params":{}}"#).unwrap();
    assert!(initialized.id.is_none());
    initialized.typed::<Initialized>().unwrap();
    let process = "24de742b-57f2-4c92-8adb-c73253972eaa";
    let write_id = "e604a5a7-c991-49ed-b372-ee0d1a535459";
    let start = json!({"id":2,"method":"process/start","params":{"processId":process,"argv":["/bin/sh","-c","printf owned"],"cwd":"file:///owned/fixture/","env":{"PATH":"/usr/bin:/bin"},"envPolicy":{"inherit":"all","ignoreDefaultExcludes":false,"exclude":[],"set":{},"includeOnly":["PATH"]},"tty":false,"pipeStdin":true,"arg0":null}});
    let request = Request::parse(&start.to_string()).unwrap();
    let parsed: Start = request.typed().unwrap();
    assert!(parsed.valid());
    assert_eq!(parsed.process_id, process);
    assert_eq!(serde_json::to_value(parsed).unwrap(), start["params"]);
    let request = Request::parse(&json!({"id":3,"method":"process/write","params":{"processId":process,"writeId":write_id,"chunk":"5L2g5aW9Cg=="}}).to_string()).unwrap();
    let parsed: Write = request.typed().unwrap();
    assert!(parsed.valid());
    assert_eq!(parsed.write_id, write_id);
    assert_eq!(parsed.chunk, "5L2g5aW9Cg==");
    let request = Request::parse(&json!({"id":4,"method":"process/read","params":{"processId":process,"afterSeq":123,"maxBytes":65536,"waitMs":1000}}).to_string()).unwrap();
    let parsed: Read = request.typed().unwrap();
    assert!(parsed.valid());
    assert_eq!(parsed.after_seq, Some(123));
    // Native base64/seq/unknown extension fields belong to the old reader;
    // serialization must not synthesize a decoded stdout or new cursor.
    let native = json!({"chunks":[{"seq":124,"stream":"pty","chunk":"5L2g"}],"nextSeq":125,"exited":false,"closed":false,"failure":null,"extension":{"preserved":true}});
    let response = Response::result(Id::Number(4), native.clone());
    let encoded = serde_json::to_value(response).unwrap();
    assert_eq!(encoded["result"], native);
    assert_eq!(encoded["id"], 4);
}
#[test]
fn invalid_legacy_fields_fail_before_any_execution_port() {
    let process = "24de742b-57f2-4c92-8adb-c73253972eaa";
    assert!(
        Request::parse(r#"{"id":1,"method":"initialize","params":{},"owner":"forged"}"#).is_err()
    );
    assert!(
        Request::parse(r#"{"jsonrpc":"3.0","id":1,"method":"initialize","params":{}}"#).is_err()
    );
    assert!(Request::parse(&"x".repeat(MAX_FRAME + 1)).is_err());
    let invalid = Read {
        process_id: process.into(),
        after_seq: None,
        max_bytes: 65537,
        wait_ms: 0,
    };
    assert!(!invalid.valid());
    let invalid = Write {
        process_id: process.into(),
        write_id: "not-a-uuid".into(),
        chunk: "YQ==".into(),
    };
    assert!(!invalid.valid());
    let invalid = Write {
        process_id: process.into(),
        write_id: "e604a5a7-c991-49ed-b372-ee0d1a535459".into(),
        chunk: "YQ".into(),
    };
    assert!(!invalid.valid());
    let terminate = Terminate {
        process_id: process.into(),
    };
    assert!(terminate.valid());
}

/// Runs the exact production duplicate classifier against real Core ledger
/// states. No native execution or platform acceptance is claimed by this case.
#[test]
fn observed_inflight_or_lost_ack_start_never_becomes_certain_rpc_rejection() {
    use super::{Handled, ProcessBinding};
    use styx_contracts::{capability::*, error::Recovery, identity::*, operation::*};
    use styx_core::{operations::OperationLedger, policy::AdmissionFacts};
    let mut ledger = OperationLedger::new("legacy-duplicate-host".try_into().unwrap());
    let owner = ledger
        .register_verified_owner(
            "legacy-duplicate-owner".try_into().unwrap(),
            "legacy-duplicate-epoch".try_into().unwrap(),
        )
        .unwrap();
    let context = PreparedContext {
        device_id: "legacy-device".try_into().unwrap(),
        grant_revision: 7,
        session: None,
        observation: None,
        capability: CapabilityId::ExecRun,
        deadline: MonotonicMillis(10000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    let facts = AdmissionFacts {
        device_id: context.device_id.clone(),
        grant_revision: 7,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: "codex".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 1,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: None,
        current_observation: None,
    };
    let prepared = ledger
        .prepare(
            &owner,
            context,
            b"original-legacy-payload".to_vec(),
            MonotonicMillis(1),
        )
        .unwrap();
    let target = ResourceTarget {
        operation_id: prepared.id.clone(),
        payload_digest: prepared.payload_digest,
    };
    let binding = ProcessBinding {
        target: Some(target.clone()),
        digest: prepared.payload_digest,
    };
    let _consumed = ledger
        .dispatch(
            &owner,
            &prepared.id,
            prepared.payload_digest,
            &facts,
            MonotonicMillis(2),
        )
        .unwrap();
    assert!(matches!(
        binding.duplicate_start(prepared.payload_digest, Id::Number(2)),
        Handled::Unknown
    ));
    assert_eq!(
        ledger
            .inspect(&owner, &prepared.id, prepared.payload_digest)
            .unwrap()
            .state,
        OperationState::Dispatched
    );
    ledger.mark_result_unknown(&prepared.id).unwrap();
    assert!(matches!(
        binding.duplicate_start(prepared.payload_digest, Id::Number(3)),
        Handled::Unknown
    ));
    assert!(matches!(
        binding.duplicate_start(Sha256Digest::of_bytes(b"changed-payload"), Id::Number(4)),
        Handled::Response(Response {
            outcome: Outcome::Error { .. },
            ..
        })
    ));
    assert_eq!(binding.target.as_ref(), Some(&target));
    assert_eq!(
        ledger
            .inspect(&owner, &prepared.id, prepared.payload_digest)
            .unwrap()
            .state,
        OperationState::Unknown
    );
}

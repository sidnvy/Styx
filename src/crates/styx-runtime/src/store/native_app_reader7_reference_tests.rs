//! Synthetic filesystem reference for App-managed reader 7 desired-state admission.
//! This does not launch a Host or establish native device acceptance.
use super::*;
use crate::management::native::{self, NativeComponent, NativeDesiredChange};
use std::sync::Arc;

#[tokio::test]
async fn app_reader7_selection_then_running_plan_apply_and_writer_busy_control() {
    let base = std::env::temp_dir().join(format!(
        "styx-app-reader7-reference-{}",
        uuid::Uuid::new_v4()
    ));
    directory(&base);
    let key = SigningKey::from_bytes(&[91; 32]);
    let initial = candidate(&base, "initial", &key, false);
    let selected = candidate_reader(&base, "reader7", &key, "native_pairing_lifecycle_v1");
    let parent = base.join("app-container");
    let mut tx = create_for_manager(
        &parent,
        &initial,
        b"synthetic fixture identity",
        NativeManager::AppManaged,
    );
    let scope = Arc::new(crate::app::HostScope::open_for_test(&parent.join("native")).unwrap());
    // Preserve a committed record from the retired App updater. The fixture
    // writes its historical target directly; no production App update writer
    // is needed to prove that current readers and desired-state changes accept it.
    let before = tx.readstate().unwrap();
    let mut target = before.state().clone();
    let transaction = NativeStateTransaction {
        transaction_id: "reference-select".try_into().unwrap(),
        sequence: 1,
    };
    target.schema = NATIVE_PAIRING_LIFECYCLE_STATE_SCHEMA;
    target.reader_contract = ReaderContract::NativePairingLifecycleStateV1;
    target.revision = 1;
    target.last_transaction = Some(transaction.clone());
    target.extensions.insert(
        NATIVE_RUNTIME_SELECTION_KEY.into(),
        serde_json::value::to_raw_value(&selected).unwrap(),
    );
    target.extensions.insert(
        NATIVE_RUNTIME_UPDATE_KEY.into(),
        serde_json::value::to_raw_value(&NativeRuntimeUpdate {
            schema: 1,
            bootstrap_runtime: initial.clone(),
            previous_runtime: initial,
            transaction: transaction.clone(),
            service_repair: None,
        })
        .unwrap(),
    );
    target.extensions.insert(
        NATIVE_PAIRING_RUNTIME_HISTORY_KEY.into(),
        serde_json::value::to_raw_value(&NativePairingRuntimeHistory::App).unwrap(),
    );
    let target_bytes = serde_json::to_vec(&target).unwrap();
    let intent = DesiredStateCommit {
        transaction_id: transaction.transaction_id.clone(),
        sequence: transaction.sequence,
        deployment_raw_sha256: target.deployment_raw_sha256,
        before_state_sha256: before.raw_sha256(),
        target_state_sha256: Sha256Digest::of_bytes(&target_bytes),
        reader: target.reader_contract,
    };
    styx_core::management::state::validate_app_runtime_transition(
        before.state(),
        &target,
        tx.marker(),
        &intent,
    )
    .unwrap();
    let maintenance = tx
        .configuration_root()
        .begin_standalone_native(transaction.transaction_id, false)
        .unwrap();
    let prepared = tx
        .journal
        .prepare(
            &maintenance,
            &serde_json::to_vec(&intent).unwrap(),
            before.raw_bytes(),
            &target_bytes,
        )
        .unwrap();
    let mut committed = ManagementTransaction::plan(intent.clone()).unwrap();
    committed
        .prepare(PreparedFacts {
            deployment_raw_sha256: intent.deployment_raw_sha256,
            canonical_state_sha256: intent.before_state_sha256,
            reader: intent.reader,
            intent,
            journal: prepared.journal,
        })
        .unwrap();
    fs::write(parent.join("native/state.json"), target_bytes).unwrap();
    tx.complete(&maintenance, committed, false, &|_, _| {})
        .unwrap();
    drop(maintenance);
    complete_chain(&tx);
    let current = tx.readstate().unwrap();
    assert_eq!(
        current.state().reader_contract,
        ReaderContract::NativePairingLifecycleStateV1
    );
    assert_eq!(
        current.state().runtime_selection().unwrap().unwrap(),
        selected
    );
    assert_eq!(
        current.state().desired.host.unwrap().run,
        NativeRunDesired::Stopped
    );
    let before_sha = current.raw_sha256();
    drop(tx);

    let change = |id: &str| NativeDesiredChange {
        component: NativeComponent::Host,
        run: NativeRunDesired::Running,
        transaction_id: id.try_into().unwrap(),
        sequence: 2,
    };
    let blocked = native::plan_for_app(scope.clone(), change("reference-busy"))
        .await
        .unwrap();
    let state_path = parent.join("native/state.json");
    let journal_path = parent.join("native/.styx-management-journal-v1");
    let journal = || {
        let mut entries: Vec<_> = fs::read_dir(&journal_path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    };
    let original_state = fs::read(&state_path).unwrap();
    let original_journal = journal();
    let held_writer = open(&parent);
    assert!(
        native::apply_for_app(scope.clone(), &blocked.plan_file)
            .await
            .is_err()
    );
    assert_eq!(fs::read(&state_path).unwrap(), original_state);
    assert_eq!(journal(), original_journal);
    drop(held_writer);

    // A new transaction is used after the intentional busy refusal.
    let plan = native::plan_for_app(scope.clone(), change("reference-running"))
        .await
        .unwrap();
    assert_eq!(plan.before_state_sha256, before_sha);
    assert_eq!(
        plan.before_desired.host.unwrap().run,
        NativeRunDesired::Stopped
    );
    assert_eq!(
        plan.target_desired.host.unwrap().run,
        NativeRunDesired::Running
    );
    let report = native::apply_for_app(scope.clone(), &plan.plan_file)
        .await
        .unwrap();
    assert_eq!(report.canonical_state_sha256, plan.target_state_sha256);
    assert_eq!(report.desired.host.unwrap().run, NativeRunDesired::Running);
    assert!(!report.admission_fenced);
    let tx = open(&parent);
    complete_chain(&tx);
    let id: TransactionId = "reference-running".try_into().unwrap();
    let observation = tx.query(&id).unwrap().unwrap();
    assert!(observation.prepared.is_some());
    assert_eq!(
        observation
            .phase_receipts
            .iter()
            .map(|receipt| receipt.stage)
            .collect::<Vec<_>>(),
        vec![
            DurableStage::Applied,
            DurableStage::Verified,
            DurableStage::Committed
        ]
    );
    assert_eq!(
        tx.readstate().unwrap().raw_sha256(),
        plan.target_state_sha256
    );
    drop(tx);
    drop(scope);
    fs::remove_dir_all(base).unwrap();
}

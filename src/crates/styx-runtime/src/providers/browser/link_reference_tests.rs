//! Synthetic completion/admission race controls; no native process is launched.
use super::*;
use styx_contracts::capability::CapabilityId;

fn snapshot() -> CallToolResult {
    serde_json::from_value(serde_json::json!({
        "content":[{"type":"text","text":"- button Owned [ref=e1]"}],
        "_meta":{"app.styx/browser-native":{"schema":1,"before":1,"after":1,"dispatched":true}}
    }))
    .unwrap()
}
fn token(result: &CallToolResult) -> String {
    let text = serde_json::to_string(result).unwrap();
    let at = text.find("[ref=styx-").expect("opaque ref") + 5;
    text[at..].split(']').next().unwrap().to_owned()
}
#[tokio::test]
async fn trusted_link_boundary_blocks_reserved_and_late_snapshot_remint() {
    let (_ledger, owner, parent, _, _) =
        super::tests::permit(vec![1], CapabilityId::BrowserHeadless);
    let target = styx_contracts::operation::ResourceTarget {
        operation_id: parent.id().clone(),
        payload_digest: Sha256Digest::of_bytes(parent.payload()),
    };
    let source = Arc::new(Semaphore::new(IO_BYTES));
    let worker = BrowserWorker::new(
        BrowserIoBudget::from_reserved(source.acquire_many_owned(IO_BYTES as u32).await.unwrap())
            .unwrap(),
    );
    let mut live = Live {
        child: None,
        client: None,
        stderr: None,
        client_close: None,
        io_join_failed: false,
        retired: false,
        references: styx_core::browser::BrowserReferenceScope::new(
            owner.clone(),
            target.clone(),
            [7; 32],
        ),
        reference_revision: 0,
        workspace: PathBuf::new(),
        output: PathBuf::new(),
        slot: None,
        pins: vec![],
        uncertain: false,
        context_closed: false,
        timeout: Duration::from_secs(1),
        actions: BTreeMap::new(),
        config_file: PathBuf::new(),
        scope: None,
        cleanup: None,
    };
    let captured = worker
        .inner
        .reference_link
        .lock()
        .unwrap()
        .current()
        .unwrap();
    synchronize_reference_revision(
        &mut live,
        captured,
        &worker.inner.reference_link.lock().unwrap(),
    )
    .unwrap();
    let mut initial = snapshot();
    let fact = references::fact(&initial).unwrap();
    assert!(
        !finish_reference_result(
            &mut live,
            captured,
            Some(&worker.inner.reference_link.lock().unwrap()),
            &mut initial,
            true,
            &fact
        )
        .unwrap()
    );
    let old = token(&initial);
    assert_eq!(
        live.references.resolve(&owner, &target, &old, 1).unwrap(),
        "e1"
    );
    // Boundary requires neither Live's asynchronous resource mutex nor native
    // completion. An already-reserved slot retains its old captured revision.
    worker.invalidate_link_references();
    assert!(matches!(
        synchronize_reference_revision(
            &mut live,
            captured,
            &worker.inner.reference_link.lock().unwrap()
        ),
        Err(BrowserError::StaleObservation)
    ));
    assert!(live.references.resolve(&owner, &target, &old, 1).is_err());
    let mut late = snapshot();
    assert!(
        finish_reference_result(
            &mut live,
            captured,
            Some(&worker.inner.reference_link.lock().unwrap()),
            &mut late,
            true,
            &fact
        )
        .unwrap()
    );
    assert!(!serde_json::to_string(&late).unwrap().contains("[ref=styx-"));
    let fresh_revision = worker
        .inner
        .reference_link
        .lock()
        .unwrap()
        .current()
        .unwrap();
    synchronize_reference_revision(
        &mut live,
        fresh_revision,
        &worker.inner.reference_link.lock().unwrap(),
    )
    .unwrap();
    let mut fresh = snapshot();
    assert!(
        !finish_reference_result(
            &mut live,
            fresh_revision,
            Some(&worker.inner.reference_link.lock().unwrap()),
            &mut fresh,
            true,
            &fact
        )
        .unwrap()
    );
    let new = token(&fresh);
    assert_ne!(old, new);
    assert_eq!(
        live.references.resolve(&owner, &target, &new, 1).unwrap(),
        "e1"
    );
    assert!(live.references.resolve(&owner, &target, &old, 1).is_err());
    // Exhaustion is permanent, not ABA. Neither a fresh reservation nor an old
    // completed snapshot can turn exhausted generation zero into valid refs.
    worker.inner.reference_link.lock().unwrap().revision = u64::MAX;
    worker.invalidate_link_references();
    worker.invalidate_link_references();
    assert!(
        worker
            .inner
            .reference_link
            .lock()
            .unwrap()
            .current()
            .is_err()
    );
    assert!(
        synchronize_reference_revision(
            &mut live,
            fresh_revision,
            &worker.inner.reference_link.lock().unwrap()
        )
        .is_err()
    );
    let mut exhausted = snapshot();
    assert!(
        finish_reference_result(
            &mut live,
            fresh_revision,
            Some(&worker.inner.reference_link.lock().unwrap()),
            &mut exhausted,
            true,
            &fact
        )
        .unwrap()
    );
    assert!(
        !serde_json::to_string(&exhausted)
            .unwrap()
            .contains("[ref=styx-")
    );
    assert!(
        !live.uncertain,
        "reference invalidation does not invent native Unknown or replace the resource"
    );
}

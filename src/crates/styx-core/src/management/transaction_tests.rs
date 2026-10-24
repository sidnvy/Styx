use super::*;
fn hash(value: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(value.as_bytes())
}
fn intent() -> DesiredStateCommit {
    DesiredStateCommit {
        transaction_id: "desired-state-17".try_into().unwrap(),
        sequence: 17,
        deployment_raw_sha256: hash("original deployment bytes"),
        before_state_sha256: hash("before"),
        target_state_sha256: hash("stopped: autostart disabled"),
        reader: ReaderContract::NativeManagementStateV1,
    }
}
fn journal(
    i: &DesiredStateCommit,
    stage: DurableStage,
    previous: Option<Sha256Digest>,
) -> JournalReceipt {
    let label = format!("{:?}", stage);
    JournalReceipt {
        transaction_id: i.transaction_id.clone(),
        sequence: i.sequence,
        stage,
        previous,
        record_sha256: hash(&label),
    }
}
fn prepare(tx: &mut ManagementTransaction, i: &DesiredStateCommit) -> JournalReceipt {
    let j = journal(i, DurableStage::Prepared, None);
    tx.prepare(PreparedFacts {
        intent: i.clone(),
        deployment_raw_sha256: i.deployment_raw_sha256,
        canonical_state_sha256: i.before_state_sha256,
        reader: i.reader,
        journal: j.clone(),
    })
    .unwrap();
    j
}
fn applied(tx: &mut ManagementTransaction, i: &DesiredStateCommit) -> JournalReceipt {
    let j = journal(i, DurableStage::Applied, tx.snapshot().journal_head);
    tx.applied(AppliedFacts {
        intent: i.clone(),
        deployment_raw_sha256: i.deployment_raw_sha256,
        canonical_state_sha256: i.target_state_sha256,
        journal: j.clone(),
    })
    .unwrap();
    j
}
fn verified(tx: &mut ManagementTransaction, i: &DesiredStateCommit) -> JournalReceipt {
    let j = journal(i, DurableStage::Verified, tx.snapshot().journal_head);
    tx.verified(VerificationFacts {
        intent: i.clone(),
        deployment_raw_sha256: i.deployment_raw_sha256,
        canonical_state_sha256: i.target_state_sha256,
        reader: i.reader,
        journal: j.clone(),
    })
    .unwrap();
    j
}
fn decision(
    tx: &ManagementTransaction,
    i: &DesiredStateCommit,
    state: Sha256Digest,
) -> RecoveryDecision {
    tx.recovery_decision(i, i.deployment_raw_sha256, state)
        .unwrap()
}

#[test]
fn desired_state_boundaries_and_atomic_refusals_batch() {
    let i = intent();
    let mut invalid = i.clone();
    invalid.sequence = 0;
    assert!(ManagementTransaction::plan(invalid).is_err());
    let mut invalid = i.clone();
    invalid.target_state_sha256 = invalid.before_state_sha256;
    assert!(ManagementTransaction::plan(invalid).is_err());
    let mut tx = ManagementTransaction::plan(i.clone()).unwrap();
    let planned = tx.snapshot();
    let skip = CommitFacts {
        intent: i.clone(),
        deployment_raw_sha256: i.deployment_raw_sha256,
        canonical_state_sha256: i.target_state_sha256,
        journal: journal(&i, DurableStage::Committed, None),
    };
    assert_eq!(tx.committed(skip), Err(TransactionError::PhaseMismatch));
    assert_eq!(tx.snapshot(), planned);
    let mut wrong = i.clone();
    wrong.transaction_id = "other".try_into().unwrap();
    let refused = PreparedFacts {
        intent: wrong,
        deployment_raw_sha256: i.deployment_raw_sha256,
        canonical_state_sha256: i.before_state_sha256,
        reader: i.reader,
        journal: journal(&i, DurableStage::Prepared, None),
    };
    assert_eq!(tx.prepare(refused), Err(TransactionError::BindingMismatch));
    assert_eq!(tx.snapshot(), planned);
    prepare(&mut tx, &i);
    let prepared = tx.snapshot();
    for bad in [
        journal(&i, DurableStage::Verified, prepared.journal_head),
        journal(&i, DurableStage::Applied, None),
    ] {
        assert_eq!(
            tx.applied(AppliedFacts {
                intent: i.clone(),
                deployment_raw_sha256: i.deployment_raw_sha256,
                canonical_state_sha256: i.target_state_sha256,
                journal: bad
            }),
            Err(TransactionError::JournalMismatch)
        );
        assert_eq!(tx.snapshot(), prepared);
    }
    let mut altered = i.clone();
    altered.target_state_sha256 = hash("unauthorized replacement");
    assert_eq!(
        tx.applied(AppliedFacts {
            intent: altered,
            deployment_raw_sha256: i.deployment_raw_sha256,
            canonical_state_sha256: i.target_state_sha256,
            journal: journal(&i, DurableStage::Applied, prepared.journal_head)
        }),
        Err(TransactionError::BindingMismatch)
    );
    assert_eq!(
        tx.applied(AppliedFacts {
            intent: i.clone(),
            deployment_raw_sha256: i.deployment_raw_sha256,
            canonical_state_sha256: hash("concurrent writer"),
            journal: journal(&i, DurableStage::Applied, prepared.journal_head)
        }),
        Err(TransactionError::StateMismatch)
    );
    assert_eq!(tx.snapshot(), prepared);
    applied(&mut tx, &i);
    verified(&mut tx, &i);
    let j = journal(&i, DurableStage::Committed, tx.snapshot().journal_head);
    tx.committed(CommitFacts {
        intent: i.clone(),
        deployment_raw_sha256: i.deployment_raw_sha256,
        canonical_state_sha256: i.target_state_sha256,
        journal: j,
    })
    .unwrap();
    assert_eq!(
        decision(&tx, &i, i.target_state_sha256),
        RecoveryDecision::AlreadyCommitted
    );
    assert_eq!(
        decision(&tx, &i, i.before_state_sha256),
        RecoveryDecision::UnknownInspect
    );
    assert_eq!(
        decision(&tx, &i, hash("newer revocation")),
        RecoveryDecision::UnknownInspect
    );
    let terminal = tx.snapshot();
    assert!(tx.mark_unknown().is_err());
    assert!(tx.mark_recoverable().is_err());
    assert_eq!(tx.snapshot(), terminal);
}

#[test]
fn original_transaction_recovery_and_unknown_history_batch() {
    let i = intent();
    let mut tx = ManagementTransaction::plan(i.clone()).unwrap();
    assert_eq!(
        decision(&tx, &i, i.before_state_sha256),
        RecoveryDecision::PrepareOriginal
    );
    assert_eq!(
        decision(&tx, &i, i.target_state_sha256),
        RecoveryDecision::UnknownInspect
    );
    let prepared = prepare(&mut tx, &i);
    tx.mark_recoverable().unwrap();
    assert_eq!(
        decision(&tx, &i, i.before_state_sha256),
        RecoveryDecision::ResumePrepared
    );
    assert_eq!(
        decision(&tx, &i, i.target_state_sha256),
        RecoveryDecision::VerifyTarget
    );
    let mut foreign = i.clone();
    foreign.sequence += 1;
    let unchanged = tx.snapshot();
    assert_eq!(
        tx.recovery_decision(&foreign, i.deployment_raw_sha256, i.target_state_sha256),
        Err(TransactionError::BindingMismatch)
    );
    assert_eq!(
        tx.reconcile_existing(
            &i,
            hash("new deployment"),
            i.before_state_sha256,
            i.reader,
            &prepared
        ),
        Err(TransactionError::BindingMismatch)
    );
    let mut tampered = prepared.clone();
    tampered.record_sha256 = hash("other journal");
    assert_eq!(
        tx.reconcile_existing(
            &i,
            i.deployment_raw_sha256,
            i.before_state_sha256,
            i.reader,
            &tampered
        ),
        Err(TransactionError::JournalMismatch)
    );
    assert_eq!(tx.snapshot(), unchanged);
    tx.reconcile_existing(
        &i,
        i.deployment_raw_sha256,
        i.before_state_sha256,
        i.reader,
        &prepared,
    )
    .unwrap();
    tx.mark_unknown().unwrap();
    // Before and target alone cannot retry/acknowledge an uncertain prepared write.
    for canonical in [
        i.before_state_sha256,
        i.target_state_sha256,
        hash("neither"),
    ] {
        assert_eq!(
            decision(&tx, &i, canonical),
            RecoveryDecision::UnknownInspect
        );
        assert!(
            tx.reconcile_existing(&i, i.deployment_raw_sha256, canonical, i.reader, &prepared)
                .is_err()
        );
    }
    assert!(tx.mark_recoverable().is_err());
    assert!(tx.snapshot().uncertain_history);

    // A receipt already validated BEFORE uncertainty can be reconciled without
    // minting a new boundary or rewriting the prior uncertainty audit.
    let mut tx = ManagementTransaction::plan(i.clone()).unwrap();
    prepare(&mut tx, &i);
    let applied = applied(&mut tx, &i);
    tx.mark_unknown().unwrap();
    assert_eq!(
        decision(&tx, &i, i.before_state_sha256),
        RecoveryDecision::UnknownInspect
    );
    assert!(
        tx.reconcile_existing(
            &i,
            i.deployment_raw_sha256,
            i.before_state_sha256,
            i.reader,
            &applied
        )
        .is_err()
    );
    tx.reconcile_existing(
        &i,
        i.deployment_raw_sha256,
        i.target_state_sha256,
        i.reader,
        &applied,
    )
    .unwrap();
    assert_eq!(tx.snapshot().state, TransactionState::Applied);
    assert!(tx.snapshot().uncertain_history);
    assert_eq!(tx.snapshot().journal_head, Some(applied.record_sha256));
    let v = verified(&mut tx, &i);
    tx.mark_recoverable().unwrap();
    assert_eq!(
        decision(&tx, &i, i.target_state_sha256),
        RecoveryDecision::CommitVerified
    );
    assert_eq!(
        decision(&tx, &i, i.before_state_sha256),
        RecoveryDecision::UnknownInspect
    );
    tx.reconcile_existing(
        &i,
        i.deployment_raw_sha256,
        i.target_state_sha256,
        i.reader,
        &v,
    )
    .unwrap();
    assert!(tx.snapshot().uncertain_history);
    let j = journal(&i, DurableStage::Committed, tx.snapshot().journal_head);
    tx.committed(CommitFacts {
        intent: i.clone(),
        deployment_raw_sha256: i.deployment_raw_sha256,
        canonical_state_sha256: i.target_state_sha256,
        journal: j,
    })
    .unwrap();
    assert!(tx.snapshot().uncertain_history);
}

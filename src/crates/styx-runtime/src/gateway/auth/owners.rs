//! Admission records live until cleanup; absent records remain fenced.
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Fenced,
}
#[derive(Default)]
pub(super) struct Owners {
    records: BTreeMap<u64, Phase>,
}
impl Owners {
    pub(super) fn mint(&mut self) -> Option<u64> {
        let seq = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()?;
        self.records.insert(seq, Phase::Open);
        Some(seq)
    }
    pub(super) fn fenced(&self, seq: u64) -> bool {
        self.records.get(&seq) != Some(&Phase::Open)
    }
    pub(super) fn fence(&mut self, seq: u64) {
        if let Some(phase) = self.records.get_mut(&seq)
            && *phase == Phase::Open
        {
            *phase = Phase::Fenced;
        }
    }
    pub(super) fn complete(&mut self, seq: u64) {
        self.records.remove(&seq);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_owners_release_records_while_active_and_unknown_owners_remain() {
        let mut ledger = Owners::default();
        let active = ledger.mint().unwrap();
        let unknown = ledger.mint().unwrap();
        ledger.fence(unknown);
        for _ in 1..5000 {
            let n = ledger.mint().unwrap();
            ledger.fence(n);
            ledger.complete(n);
            assert_eq!(ledger.records.len(), 2);
            assert!(!ledger.fenced(active));
            assert!(ledger.fenced(unknown));
            assert!(ledger.fenced(n));
        }
        let additional = ledger.mint().unwrap();
        ledger.complete(additional);
        ledger.fence(unknown);
        ledger.complete(unknown);
        assert!(!ledger.fenced(active));
        ledger.complete(active);
        assert!(ledger.fenced(active));
        assert!(ledger.records.is_empty());
        assert!(ledger.fenced(unknown));
        for _ in 0..2000 {
            let n = ledger.mint().unwrap();
            ledger.fence(n);
            ledger.complete(n);
            assert!(ledger.fenced(n));
        }
        assert!(ledger.records.is_empty());
    }
}

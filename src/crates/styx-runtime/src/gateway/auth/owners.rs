//! Space for a fence is reserved at mint time. Unknown cleanup pins the floor.
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(1);
const LIMIT: usize = 4096;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Fenced,
    Complete,
}
#[derive(Default)]
pub(super) struct Owners {
    watermark: u64,
    records: BTreeMap<u64, Phase>,
}
impl Owners {
    pub(super) fn mint(&mut self) -> Option<u64> {
        if self.records.len() == LIMIT {
            return None;
        }
        let seq = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()?;
        self.records.insert(seq, Phase::Open);
        Some(seq)
    }
    pub(super) fn fenced(&self, seq: u64) -> bool {
        seq < self.watermark || self.records.get(&seq) != Some(&Phase::Open)
    }
    pub(super) fn fence(&mut self, seq: u64) {
        if let Some(phase) = self.records.get_mut(&seq)
            && *phase == Phase::Open
        {
            *phase = Phase::Fenced;
        }
    }
    pub(super) fn complete(&mut self, seq: u64) {
        if let Some(phase) = self.records.get_mut(&seq) {
            *phase = Phase::Complete;
        }
        // Sequences belonging to another policy are never keys in this ledger.
        while let Some((&first, &Phase::Complete)) = self.records.first_key_value() {
            self.records.remove(&first);
            self.watermark = first + 1;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_cleanup_pins_watermark_new_admission_stops_but_fencing_never_fails() {
        let mut ledger = Owners::default();
        let unknown = ledger.mint().unwrap();
        ledger.fence(unknown);
        for _ in 1..LIMIT {
            let n = ledger.mint().unwrap();
            ledger.fence(n);
            ledger.complete(n);
        }
        assert_eq!(ledger.watermark, 0);
        assert!(ledger.mint().is_none());
        ledger.fence(unknown);
        ledger.complete(unknown);
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

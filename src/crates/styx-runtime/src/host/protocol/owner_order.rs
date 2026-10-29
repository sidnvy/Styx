//! Ordered, epoch-bound opaque owner keys. No frame or contract fields change.
use super::*;
#[derive(Default)]
struct History {
    watermark: u64,
    high: u64,
}
struct Record {
    epoch: GatewayEpoch,
    sequence: u64,
    complete: bool,
}
#[derive(Default)]
pub(super) struct Order {
    histories: BTreeMap<GatewayEpoch, History>,
    records: BTreeMap<(OwnerId, OwnerEpoch), Record>,
}
pub(crate) fn epoch_key(epoch: &GatewayEpoch, sequence: u64) -> OwnerEpoch {
    format!(
        "paired-{}-{sequence:016x}",
        Sha256Digest::of_bytes(epoch.as_str().as_bytes()).to_hex()
    )
    .try_into()
    .expect("bounded owner epoch key")
}
impl Order {
    fn sequence(epoch: &GatewayEpoch, owner: &OwnerRef) -> Result<u64, ErrorCategory> {
        let raw = owner.owner_epoch.as_str();
        let (prefix, suffix) = raw.rsplit_once('-').ok_or(ErrorCategory::Unauthorized)?;
        if prefix
            != format!(
                "paired-{}",
                Sha256Digest::of_bytes(epoch.as_str().as_bytes()).to_hex()
            )
            || suffix.len() != 16
        {
            return Err(ErrorCategory::Unauthorized);
        }
        let sequence = u64::from_str_radix(suffix, 16).map_err(|_| ErrorCategory::Unauthorized)?;
        if sequence == 0 {
            return Err(ErrorCategory::Unauthorized);
        }
        Ok(sequence)
    }
    pub(super) fn admit(
        &mut self,
        epoch: &GatewayEpoch,
        owner: &OwnerRef,
    ) -> Result<(), ErrorCategory> {
        let sequence = Self::sequence(epoch, owner)?;
        let history = self.histories.entry(epoch.clone()).or_default();
        if sequence <= history.high {
            return Err(ErrorCategory::Unauthorized);
        }
        if self.records.len() >= OWNER_LIMIT {
            return Err(ErrorCategory::Busy);
        }
        history.high = sequence;
        self.records.insert(
            (owner.owner_id.clone(), owner.owner_epoch.clone()),
            Record {
                epoch: epoch.clone(),
                sequence,
                complete: false,
            },
        );
        Ok(())
    }
    /// Unknown keys cannot own work. Advancing high refuses a late OwnerOpen
    /// even at full capacity, without allocating a tombstone for a failed open.
    pub(super) fn fence_unseen(
        &mut self,
        epoch: &GatewayEpoch,
        owner: &OwnerRef,
    ) -> Result<(), ErrorCategory> {
        let sequence = Self::sequence(epoch, owner)?;
        let history = self.histories.entry(epoch.clone()).or_default();
        history.high = history.high.max(sequence);
        Ok(())
    }
    pub(super) fn complete(&mut self, owner: &OwnerRef) -> Vec<(OwnerId, OwnerEpoch)> {
        let key = (owner.owner_id.clone(), owner.owner_epoch.clone());
        let Some(record) = self.records.get_mut(&key) else {
            return vec![];
        };
        record.complete = true;
        let epoch = record.epoch.clone();
        let mut removed = vec![];
        loop {
            let first = self
                .records
                .iter()
                .filter(|(_, r)| r.epoch == epoch)
                .min_by_key(|(_, r)| r.sequence);
            let Some((key, record)) = first else {
                break;
            };
            if !record.complete {
                break;
            }
            let key = key.clone();
            self.histories
                .get_mut(&epoch)
                .expect("owner history")
                .watermark = record.sequence + 1;
            self.records.remove(&key);
            removed.push(key);
        }
        removed
    }
    pub(super) fn completed(&self, epoch: &GatewayEpoch, owner: &OwnerRef) -> bool {
        let key = (owner.owner_id.clone(), owner.owner_epoch.clone());
        if let Some(record) = self.records.get(&key) {
            return record.complete;
        }
        Self::sequence(epoch, owner)
            .is_ok_and(|seq| self.histories.get(epoch).is_some_and(|h| seq <= h.high))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_pins_floor_and_full_registry_still_fences_unseen_keys() {
        let epoch = "owner-order-test".try_into().unwrap();
        let owner = |n| OwnerRef {
            owner_id: format!("fixture:{n}").try_into().unwrap(),
            owner_epoch: epoch_key(&epoch, n),
        };
        let mut order = Order::default();
        order.admit(&epoch, &owner(1)).unwrap();
        for n in 2..=OWNER_LIMIT as u64 {
            order.admit(&epoch, &owner(n)).unwrap();
            assert!(order.complete(&owner(n)).is_empty());
        }
        assert_eq!(order.histories[&epoch].watermark, 0);
        assert!(matches!(
            order.admit(&epoch, &owner(129)),
            Err(ErrorCategory::Busy)
        ));
        order.fence_unseen(&epoch, &owner(129)).unwrap();
        assert_eq!(order.complete(&owner(1)).len(), OWNER_LIMIT);
        for n in 130..=2200 {
            order.admit(&epoch, &owner(n)).unwrap();
            order.complete(&owner(n));
            assert!(order.admit(&epoch, &owner(n)).is_err());
        }
        assert!(order.records.is_empty());
        assert!(order.admit(&epoch, &owner(1)).is_err());
    }
}

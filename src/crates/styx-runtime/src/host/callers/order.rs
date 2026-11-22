//! Ordered, epoch-bound opaque owner keys. No frame or contract fields change.
use super::*;
#[derive(Default)]
pub(crate) struct Order {
    high: BTreeMap<GatewayEpoch, u64>,
}
#[cfg(not(target_os = "android"))]
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
    pub(crate) fn admit(
        &mut self,
        epoch: &GatewayEpoch,
        owner: &OwnerRef,
    ) -> Result<(), ErrorCategory> {
        let sequence = Self::sequence(epoch, owner)?;
        let high = self.high.entry(epoch.clone()).or_default();
        if sequence <= *high {
            return Err(ErrorCategory::Unauthorized);
        }
        *high = sequence;
        Ok(())
    }
    /// Unknown keys cannot own work. Advancing high refuses a late OwnerOpen
    /// without allocating a caller record for a failed or revoked open.
    pub(crate) fn fence_unseen(
        &mut self,
        epoch: &GatewayEpoch,
        owner: &OwnerRef,
    ) -> Result<(), ErrorCategory> {
        let sequence = Self::sequence(epoch, owner)?;
        let high = self.high.entry(epoch.clone()).or_default();
        *high = (*high).max(sequence);
        Ok(())
    }
    /// Registry entries own active leases and unresolved cleanup. Once an entry
    /// is removed, this fence still prevents opening its key again.
    pub(crate) fn fenced(&self, epoch: &GatewayEpoch, owner: &OwnerRef) -> bool {
        Self::sequence(epoch, owner)
            .is_ok_and(|seq| self.high.get(epoch).is_some_and(|high| seq <= *high))
    }
}

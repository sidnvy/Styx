//! Replay is a separate closed phase. Storage DTOs do not authenticate devices.
//! The trusted runtime must verify the complete hash chain, original bytes,
//! material contents and exclusive writer before creating these attestations.
use super::*;

pub struct RecoveryRecord {
    brand: Arc<()>,
    intent: PendingIntent,
    previous_receipt: Option<Sha256Digest>,
    receipt: Sha256Digest,
}
pub struct RecoveryUnresolved {
    brand: Arc<()>,
    intent: PendingIntent,
}
/// Storage's verified closed inventory, not a caller-supplied ready flag.
pub struct RecoveryClosure {
    brand: Arc<()>,
    revision: u64,
    sequence_high_water: u64,
    head: Option<Sha256Digest>,
    unresolved: Option<Sha256Digest>,
    clock_floor: u64,
    now: u64,
}
pub struct RecoveredLaneClosure {
    brand: Arc<()>,
    device: DeviceId,
    fingerprint: Sha256Digest,
    credential_hash: Sha256Digest,
    capability_generation: String,
    lane: Lane,
}
redacted!(
    RecoveryRecord,
    RecoveryUnresolved,
    RecoveryClosure,
    RecoveredLaneClosure
);

fn original(bytes: &[u8], digest: Sha256Digest) -> Result<PendingIntent> {
    if bytes.len() > 16384 || Sha256Digest::of_bytes(bytes) != digest {
        return Err(EnrollmentError::DurableMismatch);
    }
    let body = intent_contract::decode(bytes).map_err(|_| EnrollmentError::Invalid)?;
    Ok(PendingIntent {
        body,
        bytes: bytes.into(),
        digest,
    })
}
impl EnrollmentControl {
    /// Caller has verified actual immutable commit/prepared records and every
    /// material's role, digest, permissions and original bytes under writer lease.
    pub fn attest_recovery_record(
        &self,
        bytes: &[u8],
        digest: Sha256Digest,
        previous_receipt: Option<Sha256Digest>,
        receipt: Sha256Digest,
    ) -> Result<RecoveryRecord> {
        Ok(RecoveryRecord {
            brand: self.brand.clone(),
            intent: original(bytes, digest)?,
            previous_receipt,
            receipt,
        })
    }
    /// Prepared-only is Unknown even when all referenced files exist. This port
    /// restores its fence, never upgrades it to a committed mutation.
    pub fn attest_recovery_unresolved(
        &self,
        bytes: &[u8],
        digest: Sha256Digest,
    ) -> Result<RecoveryUnresolved> {
        Ok(RecoveryUnresolved {
            brand: self.brand.clone(),
            intent: original(bytes, digest)?,
        })
    }
    /// All namespace entries (including orphan/temp/aborted intents) must have
    /// been classified. An unreadable, ambiguous or forked inventory cannot seal.
    /// `clock_floor` includes durable failed/read-only TTL observations as well
    /// as committed/prepared timestamps; wall clock rollback must fail closed.
    pub fn attest_recovery_closure(
        &self,
        revision: u64,
        sequence_high_water: u64,
        head: Option<Sha256Digest>,
        unresolved: Option<Sha256Digest>,
        clock_floor: u64,
        now: u64,
    ) -> RecoveryClosure {
        RecoveryClosure {
            brand: self.brand.clone(),
            revision,
            sequence_high_water,
            head,
            unresolved,
            clock_floor,
            now,
        }
    }
    /// Requires actual quiescence of the previous Gateway transport owner. A
    /// closed socket is not evidence that a native Host operation exited.
    pub fn attest_recovered_lane_closed(
        &self,
        device: &Device,
        lane: Lane,
    ) -> RecoveredLaneClosure {
        RecoveredLaneClosure {
            brand: self.brand.clone(),
            device: device.id.clone(),
            fingerprint: device.fingerprint,
            credential_hash: device.credential_hash,
            capability_generation: device.generation.clone(),
            lane,
        }
    }
}

impl EnrollmentLedger {
    /// Apply only a verified committed record while all public admission remains
    /// closed. Historical epoch and timestamp are preserved; no current TTL,
    /// transport or OS state is substituted for historical facts.
    pub fn recover_committed(&mut self, record: RecoveryRecord) -> Result<()> {
        self.brand(&record.brand)?;
        if !self.recovering || self.staged.is_some() {
            return Err(EnrollmentError::Conflict);
        }
        let b = &record.intent.body;
        if record.previous_receipt != self.recovered_head
            || b.expected_revision != self.revision
            || b.sequence <= self.sequence
        {
            return Err(EnrollmentError::DurableMismatch);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(EnrollmentError::Capacity)?;
        self.validate_historical(b)?;
        self.apply_validated(&b.mutation, b.prepared_at);
        // Transport lifetime did not survive replay. Do not infer offline from
        // absence of an in-memory connection or a successful filesystem scan.
        if let Mutation::Approve { device, .. } = &b.mutation {
            for lane in [Lane::Exec, Lane::Computer, Lane::Browser] {
                self.lanes
                    .insert((device.id.clone(), lane), LaneState::RecoveredUnknown);
            }
        }
        self.revision = next_revision;
        self.sequence = b.sequence;
        self.time_floor = b.prepared_at;
        self.recovered_head = Some(record.receipt);
        Ok(())
    }
    pub fn recover_unresolved(&mut self, record: RecoveryUnresolved) -> Result<()> {
        self.brand(&record.brand)?;
        if !self.recovering || self.staged.is_some() {
            return Err(EnrollmentError::Conflict);
        }
        let b = &record.intent.body;
        if b.expected_revision != self.revision || b.sequence <= self.sequence {
            return Err(EnrollmentError::DurableMismatch);
        }
        self.validate_historical(b)?;
        self.sequence = b.sequence;
        self.time_floor = b.prepared_at;
        self.staged = Some(record.intent);
        Ok(())
    }
    pub fn finish_recovery(&mut self, closure: RecoveryClosure) -> Result<()> {
        self.brand(&closure.brand)?;
        if !self.recovering
            || closure.revision != self.revision
            || closure.head != self.recovered_head
            || closure.unresolved != self.staged.as_ref().map(|s| s.digest)
            || closure.sequence_high_water < self.sequence
            || closure.clock_floor < self.time_floor
        {
            return Err(EnrollmentError::DurableMismatch);
        }
        if closure.now < closure.clock_floor {
            return Err(EnrollmentError::Clock);
        }
        self.sequence = closure.sequence_high_water;
        self.time_floor = closure.clock_floor;
        self.observed_time.set(closure.now);
        self.recovering = false;
        Ok(())
    }
    /// Reconcile exactly a startup RecoveredUnknown lane. The private process brand,
    /// full device credential identity and current cap generation prevent a
    /// prior process/credential closure from clearing a new connection. Later
    /// transport uncertainty is a distinct Unknown state and cannot use this port.
    pub fn reconcile_recovered_lane(&mut self, proof: RecoveredLaneClosure) -> Result<()> {
        self.available()?;
        self.brand(&proof.brand)?;
        let d = self
            .devices
            .get(&proof.device)
            .ok_or(EnrollmentError::NotFound)?;
        if d.revoked
            || d.fingerprint != proof.fingerprint
            || d.credential_hash != proof.credential_hash
            || d.generation != proof.capability_generation
        {
            return Err(EnrollmentError::Proof);
        }
        let key = (proof.device, proof.lane);
        if self.lanes.get(&key) != Some(&LaneState::RecoveredUnknown) {
            return Err(EnrollmentError::Conflict);
        }
        self.lanes.insert(key, LaneState::Offline);
        Ok(())
    }
    // This snapshot is only for the trusted runtime's material/transport
    // reconciliation. It must not be exposed as an unauthenticated API.
    pub fn recovery_devices(&self, control: &EnrollmentControl) -> Result<Vec<Device>> {
        self.brand(&control.brand)?;
        Ok(self.devices.values().cloned().collect())
    }
    fn historical_generation(body: &IntentBody, device: &DeviceId) -> Result<String> {
        Ok(format!(
            "capability-{}",
            intent_contract::allocated_identity(
                "styx-enrollment-capability-generation-v1",
                &body.gateway_epoch,
                body.sequence,
                Some(device)
            )
            .map_err(|_| EnrollmentError::Invalid)?
            .to_hex()
        ))
    }
    /// Validation completes before any map is changed. This also guards normal
    /// staged writes, so replay cannot introduce a weaker second policy path.
    pub(super) fn validate_historical(&self, body: &IntentBody) -> Result<()> {
        let invalid = || EnrollmentError::Invalid;
        let expected_tx = format!(
            "enrollment-{}",
            intent_contract::allocated_identity(
                "styx-enrollment-transaction-v1",
                &body.gateway_epoch,
                body.sequence,
                None
            )
            .map_err(|_| invalid())?
            .to_hex()
        );
        if body.schema != 1
            || body.sequence == 0
            || body.transaction.as_str() != expected_tx
            || body.expected_revision != self.revision
            || body.prepared_at < self.time_floor
            || body.required_materials != self.required_materials(&body.mutation)?
        {
            return Err(EnrollmentError::DurableMismatch);
        }
        let now = body.prepared_at;
        match &body.mutation {
            Mutation::Invite { invitation: i } => {
                let ttl = i.expires.checked_sub(now).ok_or_else(invalid)?;
                if !(60000..=600000).contains(&ttl)
                    || ttl % 1000 != 0
                    || self.invitations.iter().any(|old| old.hash == i.hash)
                    || self
                        .invitations
                        .iter()
                        .filter(|old| old.expires > now)
                        .count()
                        >= self.limits.invitations
                {
                    return Err(invalid());
                }
                if let Some(scope) = &i.scope {
                    if scope.window.is_none() || scope.origin.len() > 2048 {
                        return Err(invalid());
                    }
                    PairingComparison {
                        gateway_origin: scope.origin.clone(),
                        certificate_sha256: scope.leaf,
                        request_id: "0123456789abcdef0123456789abcdef".into(),
                        device_fingerprint: i.hash,
                    }
                    .comparison_code()
                    .map_err(|_| invalid())?;
                }
            }
            Mutation::CloseWindow { .. } => {}
            Mutation::Join { pending: p } => {
                let f = &p.facts;
                let i = self
                    .invitations
                    .iter()
                    .find(|i| i.hash == f.invitation_hash && i.expires > now)
                    .ok_or(EnrollmentError::Expired)?;
                let comparison = PairingComparison {
                    gateway_origin: f.pairing.origin.clone(),
                    certificate_sha256: f.pairing.leaf,
                    request_id: f.request.as_str().to_owned(),
                    device_fingerprint: f.fingerprint,
                }
                .comparison_code()
                .map_err(|_| invalid())?;
                if p.status != PendingStatus::Pending
                    || p.expires != now.checked_add(900000).ok_or_else(invalid)?
                    || !exact_request(&f.request)
                    || f.pairing.origin.len() > 2048
                    || f.comparison != comparison
                    || i.scope.as_ref().is_some_and(|s| s != &f.pairing)
                    || self.retired.contains(&f.fingerprint)
                    || self.pending.len() >= self.limits.pending
                    || self.pending.contains_key(&f.request)
                    || self
                        .pending
                        .values()
                        .any(|p| p.facts.device == f.device || p.facts.fingerprint == f.fingerprint)
                    || self.registered_identity_conflict(&f.device, f.fingerprint)
                {
                    return Err(invalid());
                }
            }
            Mutation::Approve {
                request,
                target,
                device: d,
                claim_expires,
                ..
            } => {
                let p = self.pending.get(request).ok_or(EnrollmentError::NotFound)?;
                let active = self.devices.values().filter(|d| !d.revoked).count();
                if p.status != PendingStatus::Pending
                    || p.expires <= now
                    || *target != Self::target(p)?
                    || d.id != p.facts.device
                    || d.fingerprint != p.facts.fingerprint
                    || d.profile != p.facts.profile
                    || !d.grant.subset_of(p.facts.requested)
                    || d.revoked
                    || d.credential.0 != d.credential_hash
                    || d.generation != Self::historical_generation(body, &d.id)?
                    || *claim_expires != now.checked_add(1200000).ok_or_else(invalid)?
                    || self.registered_identity_conflict(&d.id, d.fingerprint)
                    || self.retained_device_count() >= self.limits.devices
                    || self.retired.len().checked_add(active).ok_or_else(invalid)?
                        >= self.limits.retired
                {
                    return Err(invalid());
                }
            }
            Mutation::Confirm { request } => {
                let p = self.pending.get(request).ok_or(EnrollmentError::NotFound)?;
                let PendingStatus::Approved {
                    credential,
                    claim_expires,
                    ..
                } = &p.status
                else {
                    return Err(invalid());
                };
                let d = self
                    .devices
                    .get(&p.facts.device)
                    .ok_or(EnrollmentError::NotFound)?;
                if *claim_expires <= now || d.revoked || d.credential != *credential {
                    return Err(invalid());
                }
            }
            Mutation::CollectPending { requests } => {
                let expected = self
                    .pending
                    .iter()
                    .filter_map(|(id, p)| {
                        let expired = match p.status {
                            PendingStatus::Pending => p.expires <= now,
                            PendingStatus::Approved { claim_expires, .. } => claim_expires <= now,
                            PendingStatus::Revoked => true,
                        };
                        expired.then(|| id.clone())
                    })
                    .collect::<Vec<_>>();
                if requests.is_empty() || *requests != expected {
                    return Err(invalid());
                }
            }
            Mutation::Revoke {
                device,
                fingerprint,
            } => {
                let d = self.devices.get(device).ok_or(EnrollmentError::NotFound)?;
                if d.revoked
                    || d.fingerprint != *fingerprint
                    || (self.retired.len() >= self.limits.retired
                        && !self.retired.contains(fingerprint))
                {
                    return Err(invalid());
                }
            }
            Mutation::SelfCas {
                device,
                expected_generation,
                generation,
                ..
            } => {
                let d = self.devices.get(device).ok_or(EnrollmentError::NotFound)?;
                if d.revoked
                    || d.generation != *expected_generation
                    || *generation != Self::historical_generation(body, device)?
                {
                    return Err(invalid());
                }
                // Live offline admission was checked before the original write;
                // replay does not invent historical socket closure from current lanes.
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;

//! Native maxBytes is a whole-chunk batching hint. Keep the original page
//! under its RPC budget, then deliver bounded pieces without another read.
use super::*;
use std::collections::VecDeque;
use zeroize::Zeroize;

pub(super) struct BufferedOutput {
    chunks: VecDeque<(String, Vec<u8>)>,
    offset: usize,
    _wire_budget: Option<tokio::sync::OwnedSemaphorePermit>,
    _buffer_slot: Option<tokio::sync::OwnedSemaphorePermit>,
    _event_budget: Vec<tokio::sync::OwnedSemaphorePermit>,
}
impl BufferedOutput {
    fn take(&mut self, mut remaining: usize) -> Vec<(String, Vec<u8>)> {
        let mut result = Vec::new();
        while remaining > 0 {
            let Some((stream, bytes)) = self.chunks.front() else {
                break;
            };
            let count = remaining.min(bytes.len() - self.offset);
            if count > 0 {
                result.push((
                    stream.clone(),
                    bytes[self.offset..self.offset + count].to_vec(),
                ));
                self.offset += count;
                remaining -= count;
            }
            if self.offset == bytes.len() {
                if let Some((_, mut bytes)) = self.chunks.pop_front() {
                    bytes.zeroize();
                }
                self.offset = 0;
            }
        }
        result
    }
}
impl Drop for BufferedOutput {
    fn drop(&mut self) {
        for (_, bytes) in &mut self.chunks {
            bytes.zeroize();
        }
    }
}
impl CodexStdio {
    pub(super) async fn read_decoded(
        &self,
        owner: &OwnerLease,
        handle: &ProcessHandle,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<ProcessOutput, ExecError> {
        if max_bytes == 0 || max_bytes > 65536 || wait > Duration::from_secs(1) {
            return Err(ExecError::InvalidRequest);
        }
        let mut record = self.owned(owner, handle).await?;
        record.select_read_mode(ReadMode::Decoded)?;
        if record.drained && record.pending_output.is_none() {
            if let Some(observation) = self.rpc.observation(&handle.process_id) {
                check_observation(&record, &observation)?;
                if record.last_exit.is_none() {
                    record.last_exit = observation.exited.map(|(_, c)| c);
                }
                if record.last_exit.is_some() {
                    self.rpc.unregister(&handle.process_id);
                }
            }
            return Ok(ProcessOutput {
                chunks: vec![],
                liveness: if record.last_exit.is_some() {
                    ExecutionLiveness::Exited
                } else {
                    ExecutionLiveness::Unknown
                },
                drain: OutputDrain::Drained,
                exit_code: record.last_exit,
            });
        }
        if record.pending_output.is_none()
            && let Some(events) = self
                .rpc
                .take_completed_events(&handle.process_id, record.cursor)
        {
            let observation = self
                .rpc
                .observation(&handle.process_id)
                .ok_or(ExecError::UnknownHandle)?;
            check_observation(&record, &observation)?;
            if observation.exited != Some(events.exit)
                || observation.closed != Some(events.closed)
                || record.last_exit.is_some_and(|code| code != events.exit.1)
            {
                return Err(ExecError::InvalidFrame);
            }
            let mut chunks = VecDeque::new();
            let mut budgets = Vec::new();
            for chunk in events.chunks {
                let (stream, bytes, budget) = chunk.into_parts();
                chunks.push_back((stream, bytes));
                budgets.push(budget);
            }
            record.cursor = Some(events.closed);
            record.last_exit = Some(events.exit.1);
            record.output_closed = true;
            // Every event from start through the original exit/close is present.
            // No native read (or retry of a missing native record) is required.
            record.drained = true;
            if !chunks.is_empty() {
                record.pending_output = Some(BufferedOutput {
                    chunks,
                    offset: 0,
                    _wire_budget: None,
                    _buffer_slot: None,
                    _event_budget: budgets,
                });
            }
        }
        if record.pending_output.is_none() && !record.drained {
            #[cfg(not(target_os = "macos"))]
            let slot = self.rpc.reserve_read_buffer()?;
            #[cfg(target_os = "macos")]
            let slot = self.rpc.reserve_read_buffer_wait().await?;
            let reply = self
                .rpc
                .request_budgeted(
                    "process/read",
                    json!({"processId":handle.process_id,
                "afterSeq":record.cursor,"maxBytes":max_bytes,"waitMs":wait.as_millis() as u64}),
                )
                .await?;
            let page: ReadPage =
                serde_json::from_value(reply.result?).map_err(|_| ExecError::InvalidFrame)?;
            // Keep all sequence/base64/liveness checks and the hard wire bound.
            // A native chunk can legitimately exceed the requested batch hint.
            let validated = output::validate(
                &page,
                record.cursor,
                record.gaps,
                styx_contracts::EXEC_FRAME_BYTES,
            )?;
            if page.failure.is_some() {
                return Err(ExecError::ProcessFailure);
            }
            let observation = self
                .rpc
                .observation(&handle.process_id)
                .ok_or(ExecError::UnknownHandle)?;
            if observation.invalid
                || page
                    .exit_code
                    .zip(record.last_exit)
                    .is_some_and(|(a, b)| a != b)
                || page
                    .exit_code
                    .zip(observation.exited.map(|(_, c)| c))
                    .is_some_and(|(a, b)| a != b)
            {
                return Err(ExecError::InvalidFrame);
            }
            record.cursor = Some(validated.cursor);
            record.gaps = validated.gaps;
            // closed with data is not a drained cursor: an empty native page
            // still has to prove the end after all retained bytes are delivered.
            record.output_closed |= page.closed;
            record.drained = page.closed && page.chunks.is_empty();
            record.last_exit = record
                .last_exit
                .or(page.exit_code)
                .or(observation.exited.map(|(_, c)| c));
            if !validated.chunks.is_empty() {
                record.pending_output = Some(BufferedOutput {
                    chunks: validated.chunks.into(),
                    offset: 0,
                    _wire_budget: Some(reply._permit),
                    _buffer_slot: Some(slot),
                    _event_budget: vec![],
                });
            }
        }
        let pieces = record
            .pending_output
            .as_mut()
            .map(|p| p.take(max_bytes))
            .unwrap_or_default();
        if record
            .pending_output
            .as_ref()
            .is_some_and(|p| p.chunks.is_empty())
        {
            record.pending_output = None;
        }
        let drained = record.drained && record.pending_output.is_none();
        let chunks = record.decoder.decode(pieces, drained)?;
        let observation = self
            .rpc
            .observation(&handle.process_id)
            .ok_or(ExecError::UnknownHandle)?;
        check_observation(&record, &observation)?;
        if record.last_exit.is_none() {
            record.last_exit = observation.exited.map(|(_, c)| c);
        }
        if drained && record.last_exit.is_some() {
            self.rpc.unregister(&handle.process_id);
        }
        let liveness = if record.last_exit.is_some() {
            ExecutionLiveness::Exited
        } else if record.output_closed || observation.lost {
            ExecutionLiveness::Unknown
        } else {
            ExecutionLiveness::Running
        };
        Ok(ProcessOutput {
            chunks,
            liveness,
            drain: if drained {
                OutputDrain::Drained
            } else {
                OutputDrain::Open
            },
            exit_code: record.last_exit,
        })
    }
}

fn check_observation(record: &Record, observation: &rpc::Observation) -> Result<(), ExecError> {
    if observation.invalid
        || record
            .last_exit
            .zip(observation.exited.map(|(_, code)| code))
            .is_some_and(|(a, b)| a != b)
    {
        Err(ExecError::InvalidFrame)
    } else {
        Ok(())
    }
}

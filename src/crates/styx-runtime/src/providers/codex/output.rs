use super::ExecError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use encoding_rs::{CoderResult, Decoder, UTF_8};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReadPage {
    pub chunks: Vec<WireChunk>,
    pub next_seq: u64,
    pub exited: bool,
    pub exit_code: Option<i32>,
    pub closed: bool,
    pub failure: Option<serde_json::Value>,
}
#[derive(Deserialize)]
pub(super) struct WireChunk {
    pub seq: u64,
    pub stream: String,
    pub chunk: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub stream: String,
    pub text: String,
}
pub(super) struct Validated {
    pub chunks: Vec<(String, Vec<u8>)>,
    pub cursor: u64,
    pub gaps: u64,
}
pub(super) fn validate(
    page: &ReadPage,
    cursor: Option<u64>,
    gaps: u64,
    max_bytes: usize,
) -> Result<Validated, ExecError> {
    if page.next_seq == 0
        || cursor.is_some_and(|c| page.next_seq <= c)
        || page.exited != page.exit_code.is_some()
    {
        return Err(ExecError::InvalidFrame);
    }
    let mut previous = cursor.unwrap_or(0);
    let mut missing = gaps;
    let mut chunks = vec![];
    let mut bytes = 0usize;
    for chunk in &page.chunks {
        if chunk.seq <= previous
            || chunk.seq >= page.next_seq
            || !matches!(chunk.stream.as_str(), "stdout" | "stderr" | "pty")
        {
            return Err(ExecError::InvalidFrame);
        }
        missing = missing
            .checked_add(chunk.seq - previous - 1)
            .ok_or(ExecError::InvalidFrame)?;
        previous = chunk.seq;
        let decoded = STANDARD
            .decode(&chunk.chunk)
            .map_err(|_| ExecError::InvalidFrame)?;
        if STANDARD.encode(&decoded) != chunk.chunk {
            return Err(ExecError::InvalidFrame);
        }
        bytes = bytes
            .checked_add(decoded.len())
            .ok_or(ExecError::InvalidFrame)?;
        if bytes > max_bytes {
            return Err(ExecError::InvalidFrame);
        }
        chunks.push((chunk.stream.clone(), decoded));
    }
    missing = missing
        .checked_add(page.next_seq - 1 - previous)
        .ok_or(ExecError::InvalidFrame)?;
    if missing > u64::from(page.exited) + u64::from(page.closed) {
        return Err(ExecError::InvalidFrame);
    }
    Ok(Validated {
        chunks,
        cursor: page.next_seq - 1,
        gaps: missing,
    })
}
#[derive(Default)]
pub(super) struct OutputDecoder {
    streams: BTreeMap<String, Decoder>,
}
impl OutputDecoder {
    pub fn decode(
        &mut self,
        chunks: Vec<(String, Vec<u8>)>,
        finish: bool,
    ) -> Result<Vec<OutputChunk>, ExecError> {
        let mut output = vec![];
        for (stream, bytes) in chunks {
            let decoder = self
                .streams
                .entry(stream.clone())
                .or_insert_with(|| UTF_8.new_decoder_without_bom_handling());
            let mut text = String::with_capacity(bytes.len().saturating_mul(3) + 16);
            let (result, read, _) = decoder.decode_to_string(&bytes, &mut text, false);
            if result != CoderResult::InputEmpty || read != bytes.len() {
                return Err(ExecError::InvalidFrame);
            }
            if !text.is_empty() {
                output.push(OutputChunk { stream, text });
            }
        }
        if finish {
            for (stream, decoder) in &mut self.streams {
                let mut text = String::with_capacity(16);
                let (result, _, _) = decoder.decode_to_string(b"", &mut text, true);
                if result != CoderResult::InputEmpty {
                    return Err(ExecError::InvalidFrame);
                }
                if !text.is_empty() {
                    output.push(OutputChunk {
                        stream: stream.clone(),
                        text,
                    });
                }
            }
            self.streams.clear();
        }
        Ok(output)
    }
}

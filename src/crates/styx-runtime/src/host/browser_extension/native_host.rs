//! Chrome Native Messaging stdio bridge connecting Chrome's `com.styx.browser_bridge`
//! Native Messaging port to the currently running local Styx Host.
use super::read_bridge_endpoint;
use serde_json::json;
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc,
};

const MAX_INBOUND_FROM_CHROME: usize = 16 * 1024 * 1024;
const MAX_OUTBOUND_TO_CHROME: usize = 1024 * 1024;
const RETRY_INTERVAL: Duration = Duration::from_millis(1500);

/// Reads a single Chrome Native Messaging length-prefixed UTF-8 frame.
/// Returns `Ok(None)` cleanly on EOF.
pub fn read_native_message<R: Read>(reader: &mut R) -> io::Result<Option<String>> {
    let mut len_buf = [0_u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_INBOUND_FROM_CHROME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native messaging inbound length",
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;
    let text = String::from_utf8(payload)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf8 frame"))?;
    Ok(Some(text))
}

/// Writes a single Chrome Native Messaging length-prefixed UTF-8 frame.
pub fn write_native_message<W: Write>(writer: &mut W, text: &str) -> io::Result<()> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_OUTBOUND_TO_CHROME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native messaging outbound length",
        ));
    }
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

/// Runs the long-lived Native Messaging stdio <-> local Host TCP relay loop.
/// Exits cleanly when Chrome closes stdin.
pub async fn run_native_messaging_bridge(state_dir: &Path) -> Result<(), &'static str> {
    let (in_tx, mut in_rx) = mpsc::channel::<String>(256);
    let (out_tx, mut out_rx) = mpsc::channel::<String>(256);

    let stdin_task = std::thread::Builder::new()
        .name("styx-ext-nm-stdin".into())
        .spawn(move || {
            let mut stdin = io::stdin().lock();
            while let Ok(Some(line)) = read_native_message(&mut stdin) {
                if in_tx.blocking_send(line).is_err() {
                    break;
                }
            }
        })
        .map_err(|_| "browser_extension_stdin_thread_failed")?;

    let stdout_task = std::thread::Builder::new()
        .name("styx-ext-nm-stdout".into())
        .spawn(move || {
            let mut stdout = io::stdout().lock();
            while let Some(line) = out_rx.blocking_recv() {
                if write_native_message(&mut stdout, &line).is_err() {
                    break;
                }
            }
        })
        .map_err(|_| "browser_extension_stdout_thread_failed")?;

    let send_status = |out_tx: &mpsc::Sender<String>, host_connected: bool| {
        let msg = json!({"type": "bridge.status", "hostConnected": host_connected}).to_string();
        let _ = out_tx.try_send(msg);
    };

    let mut notified_disconnected = false;
    loop {
        while let Ok(_stale) = in_rx.try_recv() {}
        let Some((port, token)) = read_bridge_endpoint(state_dir) else {
            if !notified_disconnected {
                send_status(&out_tx, false);
                notified_disconnected = true;
            }
            tokio::select! {
                maybe_msg = in_rx.recv() => {
                    if maybe_msg.is_none() {
                        break;
                    }
                }
                () = tokio::time::sleep(RETRY_INTERVAL) => {}
            }
            continue;
        };

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await
        else {
            if !notified_disconnected {
                send_status(&out_tx, false);
                notified_disconnected = true;
            }
            tokio::select! {
                maybe_msg = in_rx.recv() => {
                    if maybe_msg.is_none() {
                        break;
                    }
                }
                () = tokio::time::sleep(RETRY_INTERVAL) => {}
            }
            continue;
        };

        let (tcp_read, mut tcp_write) = stream.into_split();
        let auth_line = format!("{}\n", json!({ "type": "auth", "token": token }));
        if tcp_write.write_all(auth_line.as_bytes()).await.is_err() {
            tokio::time::sleep(RETRY_INTERVAL).await;
            continue;
        }
        let mut reader = BufReader::new(tcp_read);
        let mut ack_line = String::new();
        let authed = matches!(
            tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut ack_line)).await,
            Ok(Ok(n)) if n > 0
                && serde_json::from_str::<serde_json::Value>(&ack_line)
                    .is_ok_and(|v| v.get("type").and_then(|t| t.as_str()) == Some("auth_ok"))
        );
        if !authed {
            tokio::time::sleep(RETRY_INTERVAL).await;
            continue;
        }

        let _ = notified_disconnected;
        send_status(&out_tx, true);

        let mut stdin_closed = false;
        let mut line_buf = String::new();
        loop {
            line_buf.clear();
            tokio::select! {
                from_chrome = in_rx.recv() => {
                    match from_chrome {
                        Some(msg) => {
                            let clean = msg.trim();
                            if clean.is_empty() {
                                continue;
                            }
                            let frame = format!("{clean}\n");
                            if tcp_write.write_all(frame.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        None => {
                            stdin_closed = true;
                            break;
                        }
                    }
                }
                from_host = reader.read_line(&mut line_buf) => {
                    match from_host {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let clean = line_buf.trim();
                            if clean.is_empty() {
                                continue;
                            }
                            if out_tx.send(clean.to_owned()).await.is_err() {
                                stdin_closed = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if stdin_closed {
            break;
        }
        send_status(&out_tx, false);
        notified_disconnected = true;
        tokio::select! {
            maybe_msg = in_rx.recv() => {
                if maybe_msg.is_none() {
                    break;
                }
            }
            () = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }

    drop(out_tx);
    let _ = stdin_task.join();
    let _ = stdout_task.join();
    Ok(())
}

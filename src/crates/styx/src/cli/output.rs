use super::{setup, setup_prompt};
use std::{
    io::{self, Write},
    process::ExitCode,
};

pub(super) fn error(code: &str) -> ExitCode {
    // Curated codes only; runtime errors may contain private paths or inputs.
    eprintln!("{}", serde_json::json!({"schema":1,"error":code}));
    ExitCode::from(2)
}
pub(super) fn setup_result(result: Result<(), setup::Failure>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            if setup_prompt::enhanced() {
                setup_prompt::failure(failure.code, failure.hint(), failure.exit == 4);
            } else {
                eprintln!(
                    "{}",
                    serde_json::json!({"schema":1,"error":failure.code,"outcome":if failure.exit == 4 {"unknown"} else {"stopped"},"operations_replayed":false})
                );
                if let Some(hint) = failure.hint() {
                    eprintln!("{hint}");
                }
            }
            if failure.exit == 4 {
                eprintln!(
                    "Setup stopped with an unknown outcome. Preserve the original inputs and role roots. Check styx status and the original pending request/transaction before taking another action; do not request, approve or pair again automatically."
                );
                let _ = io::stdout().flush();
                let _ = io::stderr().flush();
                std::process::exit(4);
            }
            ExitCode::from(failure.exit)
        }
    }
}
pub(super) fn write_json(value: &impl serde::Serialize) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()
}
pub(super) fn native_error_output(
    value: &styx_runtime::management::native::NativeManagementError,
) -> serde_json::Value {
    serde_json::json!({"schema":1,"error":value.code()})
}
/// An unresolved owned migration/recovery job must survive until explicit
/// whole-process teardown. Dropping its result would leave runtime shutdown
/// waiting for the original blocking custody job.
pub(super) fn native_recovery_result<T: serde::Serialize>(
    result: Result<T, styx_runtime::management::native::NativeManagementError>,
    json: bool,
    summary: &'static str,
) -> ExitCode {
    #[cfg(any(
        target_os = "macos",
        target_os = "windows",
        all(target_os = "linux", target_env = "gnu")
    ))]
    if let Err(value) = &result
        && value.requires_process_teardown()
    {
        let mut output = native_error_output(value);
        output["outcome"] = serde_json::json!("unknown");
        output["operations_replayed"] = serde_json::json!(false);
        output["cleanup_confirmed"] = serde_json::json!(false);
        output["process_exit"] = serde_json::json!("explicit_scope_teardown");
        eprintln!("{output}");
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        // Keep the entire original result alive; this is not successful cleanup.
        std::process::exit(i32::from(value.exit_code()));
    }
    native_result(result, json, summary)
}
pub(super) fn native_result<T: serde::Serialize>(
    result: Result<T, styx_runtime::management::native::NativeManagementError>,
    json: bool,
    summary: &'static str,
) -> ExitCode {
    match result {
        Ok(value) => {
            if !json {
                eprintln!("{summary}");
            }
            if write_json(&value).is_err() {
                error("output_unavailable")
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(value) => {
            eprintln!("{}", native_error_output(&value));
            ExitCode::from(value.exit_code())
        }
    }
}
pub(super) fn gateway_admin_result(
    result: Result<
        styx_runtime::management::native_gateway_admin::AdminReport,
        styx_runtime::management::native_gateway_admin::AdminError,
    >,
    json: bool,
) -> ExitCode {
    match result {
        Ok(report) => {
            if !json {
                eprintln!("Native Gateway admin observation; invitation secrets are file-only:");
            }
            if write_json(&report).is_ok() {
                ExitCode::SUCCESS
            } else if matches!(
                report.operation,
                "gateway_invite" | "gateway_approve" | "gateway_reject"
            ) {
                eprintln!(
                    "{}",
                    serde_json::json!({"schema":1,"error":"native_gateway_admin_response_unknown","outcome":"unknown","operations_replayed":false})
                );
                ExitCode::from(4)
            } else {
                error("output_unavailable")
            }
        }
        Err(value) => {
            eprintln!(
                "{}",
                serde_json::json!({"schema":1,"error":value.code(),"outcome":value.outcome(),"operations_replayed":false})
            );
            ExitCode::from(value.exit_code())
        }
    }
}
pub(super) fn join_result(
    result: Result<
        styx_runtime::management::native_join::JoinReport,
        styx_runtime::management::native_join::JoinError,
    >,
    json: bool,
) -> ExitCode {
    match result {
        Ok(value) => {
            if !json {
                eprintln!("Native Host enrollment observed; runtime not started:");
            }
            if write_json(&value).is_err() {
                error("output_unavailable")
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(value) => {
            let mut report = serde_json::json!({"schema":1,"error":value.code()});
            if let Some(hint) = value.hint() {
                report["hint"] = hint.into();
                report["retryable"] = value.retryable().into();
                report["uncertain"] = value.uncertain().into();
            }
            if let Some((field, reason)) = value.detail() {
                report["field"] = field.into();
                report["reason"] = reason.into();
            }
            eprintln!("{report}");
            ExitCode::from(value.exit_code())
        }
    }
}

/// This binary's closed reader declaration, consumed only with build/source/hash
/// evidence. It does not claim installed state, readiness or platform acceptance.
pub(super) fn native_build_info() -> serde_json::Value {
    let target = if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc"
    )) {
        "x86_64-pc-windows-msvc"
    } else {
        "unsupported"
    };
    serde_json::json!({
        "schema": 1, "target": target,
        "minimum_release_reader": styx_contracts::native_release::NativeReleaseReader::NativePairingLifecycleV1,
        "supported_state_readers": [
            styx_contracts::management::ReaderContract::NativeManagementStateV1,
            styx_contracts::management::ReaderContract::NativeMigratedStateV1,
            styx_contracts::management::ReaderContract::NativeMigratedStateV2,
            styx_contracts::management::ReaderContract::NativeRuntimeSelectedStateV1,
            styx_contracts::management::ReaderContract::NativeAppRuntimeSelectedStateV1,
            styx_contracts::management::ReaderContract::NativeServiceRuntimeSelectedStateV1,
            styx_contracts::management::ReaderContract::NativeAppServiceTransferredStateV1,
            styx_contracts::management::ReaderContract::NativePairingLifecycleStateV1
        ]
    })
}

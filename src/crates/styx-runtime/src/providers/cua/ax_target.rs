//! Exact, bounded AX-only acquisition. This is not OS write authorization.
use super::{CuaError, Result};
use crate::store::ProcessIdentity;
use serde_json::{Map, Value};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

#[derive(Clone, Copy)]
pub(crate) struct AxReadRequest {
    pub(crate) pid: u32,
    pub(crate) window_id: u64,
}
impl AxReadRequest {
    pub(super) fn classify(name: &str, args: &Map<String, Value>) -> Result<Option<Self>> {
        if name != "get_window_state"
            || args.get("include_screenshot") != Some(&Value::Bool(false))
            || args.get("include_accessibility_tree") != Some(&Value::Bool(true))
            || args.get("tree_format").and_then(Value::as_str) != Some("elements")
        {
            return Ok(None);
        }
        const KEYS: &[&str] = &[
            "pid",
            "window_id",
            "include_screenshot",
            "include_accessibility_tree",
            "tree_format",
            "max_elements",
            "max_depth",
            "timeout_ms",
        ];
        if args.keys().any(|key| !KEYS.contains(&key.as_str())) {
            return Err(CuaError::Unsupported);
        }
        let pid = args
            .get("pid")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or(CuaError::InvalidRequest)?;
        let window_id = args
            .get("window_id")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0)
            .ok_or(CuaError::InvalidRequest)?;
        for (name, maximum) in [
            ("max_elements", 2048),
            ("max_depth", 64),
            ("timeout_ms", 2000),
        ] {
            let n = args
                .get(name)
                .and_then(Value::as_u64)
                .ok_or(CuaError::InvalidRequest)?;
            if n == 0 || n > maximum || (name == "timeout_ms" && n < 100) {
                return Err(CuaError::InvalidRequest);
            }
        }
        Ok(Some(Self { pid, window_id }))
    }
}
/// Original proc directory stays pinned until the native reply is settled.
/// PID alone and a remote window number never establish process ownership.
pub(crate) struct AxReadTarget {
    pub(crate) request: AxReadRequest,
    identity: ProcessIdentity,
    directory: File,
}
impl AxReadTarget {
    pub(crate) fn acquire(request: AxReadRequest) -> Result<Self> {
        let identity =
            ProcessIdentity::observe(request.pid).map_err(|_| CuaError::PermissionDenied)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(format!("/proc/{}", request.pid))
            .map_err(|_| CuaError::PermissionDenied)?;
        let value = Self {
            request,
            identity,
            directory,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let current = self
            .directory
            .metadata()
            .map_err(|_| CuaError::PermissionDenied)?;
        if !current.is_dir()
            || current.uid() != nix::unistd::Uid::current().as_raw()
            || !self.identity.still_current().unwrap_or(false)
        {
            return Err(CuaError::PermissionDenied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acquisition_is_only_exact_bounded_screenshot_free_read() {
        let good = serde_json::json!({"pid":42,"window_id":1234,"include_screenshot":false,"include_accessibility_tree":true,"tree_format":"elements","max_elements":64,"max_depth":8,"timeout_ms":2000});
        let args = good.as_object().unwrap();
        assert!(
            AxReadRequest::classify("get_window_state", args)
                .unwrap()
                .is_some()
        );
        for key in [
            "pid",
            "window_id",
            "max_elements",
            "max_depth",
            "timeout_ms",
        ] {
            let mut bad = args.clone();
            bad.remove(key);
            assert!(AxReadRequest::classify("get_window_state", &bad).is_err());
        }
        for (key, value) in [
            ("query", Value::String("secret".into())),
            ("since", Value::String("latest".into())),
            ("session", Value::String("foreign".into())),
            ("screenshot_out_file", Value::String("/tmp/no".into())),
            ("max_elements", Value::from(2049)),
            ("timeout_ms", Value::from(2001)),
        ] {
            let mut bad = args.clone();
            bad.insert(key.into(), value);
            assert!(AxReadRequest::classify("get_window_state", &bad).is_err());
        }
        let mut capture = args.clone();
        capture.insert("include_screenshot".into(), Value::Bool(true));
        assert!(
            AxReadRequest::classify("get_window_state", &capture)
                .unwrap()
                .is_none()
        );
        assert!(
            AxReadRequest::classify("set_value", args)
                .unwrap()
                .is_none()
        );
    }
}

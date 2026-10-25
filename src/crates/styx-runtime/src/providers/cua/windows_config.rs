use super::*;
use crate::store::PrivateRoot;
impl OwnedCuaConfig {
    pub(super) fn validate(&self) -> Result<()> {
        if self.launch.source.fenced()
            || self.rpc_timeout.is_zero()
            || self.rpc_timeout > Duration::from_secs(30)
        {
            return Err(CuaError::PermissionDenied);
        }
        // Bootstrap retains the authoritative private runtime root; these
        // fixed launch directories are reopened with existing store ACL rules.
        for path in [&self.workspace, &self.home] {
            if !path.is_absolute() {
                return Err(CuaError::InvalidRequest);
            }
            PrivateRoot::open(path).map_err(|_| CuaError::PermissionDenied)?;
        }
        for key in ["HOME", "USERPROFILE", "CUA_DRIVER_RS_HOME"] {
            if self.environment.get(key).map(PathBuf::from).as_ref() != Some(&self.home) {
                return Err(CuaError::PermissionDenied);
            }
        }
        let temporary = self
            .environment
            .get("TEMP")
            .map(PathBuf::from)
            .ok_or(CuaError::PermissionDenied)?;
        if !temporary.is_absolute()
            || self.environment.get("TMP").map(PathBuf::from).as_ref() != Some(&temporary)
        {
            return Err(CuaError::PermissionDenied);
        }
        PrivateRoot::open(&temporary).map_err(|_| CuaError::PermissionDenied)?;
        // No inherited CUA daemon/socket/plugin or loader settings. OS baseline
        // is already established by trusted profile bootstrap, not MCP input.
        const KEYS: &[&str] = &[
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "PATH",
            "PATHEXT",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "HOME",
            "USERPROFILE",
            "CUA_DRIVER_RS_HOME",
            "TEMP",
            "TMP",
            "CUA_DRIVER_RS_TELEMETRY_ENABLED",
            "DO_NOT_TRACK",
        ];
        if self
            .environment
            .keys()
            .any(|key| !KEYS.contains(&key.as_str()))
        {
            return Err(CuaError::PermissionDenied);
        }
        if self
            .environment
            .get("CUA_DRIVER_RS_TELEMETRY_ENABLED")
            .map(String::as_str)
            != Some("0")
            || self.environment.get("DO_NOT_TRACK").map(String::as_str) != Some("1")
        {
            return Err(CuaError::PermissionDenied);
        }
        self.driver
            .revalidate()
            .map_err(|_| CuaError::PermissionDenied)
    }
    pub(super) fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        bounded_bytes(&serde_json::json!({
            "session":self.launch.session,"native_source":self.launch.source.source_id(),
            "image":self.driver.source_path_for_suspended_spawn().map_err(|_|CuaError::PermissionDenied)?,
            "timeout_ms":self.rpc_timeout.as_millis(),"workspace":self.workspace,"home":self.home,
            "environment":self.environment
        }), REQUEST_BYTES).map(|v|Sha256Digest::of_bytes(&v))
    }
}

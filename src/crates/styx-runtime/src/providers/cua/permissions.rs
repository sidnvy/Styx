//! Read-only facts from the original authenticated native worker, never environment hints.
use super::*;
use crate::session::ProviderEvidence;
use styx_contracts::{
    capability::{Authorization, Availability},
    error::{ErrorCategory, Recovery},
};

pub(crate) const LIFETIME: Duration = Duration::from_secs(1);
#[derive(Clone, Copy)]
#[allow(dead_code)] // Both pinned platform reply shapes are tested on Linux.
pub(crate) enum Platform {
    Linux,
    Windows,
}
#[derive(Clone)]
pub(crate) struct DriverPermissions {
    platform: Platform,
    facts: Map<String, Value>,
    at: std::time::Instant,
}
impl DriverPermissions {
    fn parse(platform: Platform, reply: &CallToolResult) -> Result<Self> {
        if reply.is_error == Some(true) || bounded_bytes(reply, FRAME_BYTES).is_err() {
            return Err(CuaError::ProtocolMismatch);
        }
        let mut facts = reply
            .structured_content
            .as_ref()
            .and_then(Value::as_object)
            .ok_or(CuaError::ProtocolMismatch)?
            .clone();
        facts.retain(|key, _| {
            matches!(
                key.as_str(),
                "atspi" | "x11" | "wayland_enabled" | "xsend_event" | "uia" | "post_message"
            )
        });
        Ok(Self {
            platform,
            facts,
            at: std::time::Instant::now(),
        })
    }
    pub(crate) fn evidence(&self, capability: CapabilityId) -> ProviderEvidence {
        let (keys, restriction): (&[&str], &str) = match (self.platform, capability) {
            (
                Platform::Linux,
                CapabilityId::DesktopAccessibility | CapabilityId::DesktopWindowsControl,
            ) => (&["atspi"], "AT-SPI targets"),
            (Platform::Linux, CapabilityId::DesktopCapture) => (
                &["x11", "wayland_enabled"],
                "X11/XWayland or enabled Wayland capture",
            ),
            (Platform::Linux, CapabilityId::DesktopPointer | CapabilityId::DesktopKeyboard) => {
                (&["xsend_event"], "X11/XWayland input only")
            }
            (
                Platform::Windows,
                CapabilityId::DesktopAccessibility | CapabilityId::DesktopWindowsControl,
            ) => (
                &["uia"],
                "UIA targets; target OS authorization still applies",
            ),
            (Platform::Windows, CapabilityId::DesktopPointer | CapabilityId::DesktopKeyboard) => {
                (&["post_message"], "PostMessage targets; UIPI still applies")
            }
            _ => (
                &[],
                "no capture capability fact in Windows check_permissions",
            ),
        };
        let fresh = self.at.elapsed() < LIFETIME;
        let available = fresh
            && keys
                .iter()
                .any(|key| self.facts.get(*key).and_then(Value::as_bool) == Some(true));
        ProviderEvidence {
            capability,
            provider: "cua-native".try_into().expect("fixed provider"),
            availability: if available {
                Availability::Available
            } else {
                Availability::Unavailable
            },
            authorization: if available {
                Authorization::Granted
            } else {
                Authorization::Unknown
            },
            provenance: format!(
                "same authenticated cua check_permissions {}; {restriction}; fresh={fresh}",
                keys.iter()
                    .map(|key| format!(
                        "{key}={}",
                        self.facts
                            .get(*key)
                            .and_then(Value::as_bool)
                            .map_or("unproven", |v| if v { "true" } else { "false" })
                    ))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            reason: if available {
                None
            } else {
                Some(ErrorCategory::PermissionRequired)
            },
            recovery: if available {
                Recovery::None
            } else {
                Recovery::Rediscover
            },
        }
    }
}
pub(crate) fn unavailable(capability: CapabilityId) -> ProviderEvidence {
    ProviderEvidence {
        capability,
        provider: "cua-native".try_into().expect("fixed provider"),
        availability: Availability::Unavailable,
        authorization: Authorization::Unknown,
        provenance:
            "cua check_permissions missing, malformed, expired or original worker unavailable"
                .into(),
        reason: Some(ErrorCategory::PermissionRequired),
        recovery: Recovery::Rediscover,
    }
}
pub(super) fn query_allowed(name: &str, args: Option<&Map<String, Value>>) -> bool {
    name == "check_permissions"
        && args
            .is_some_and(|args| args.len() == 1 && args.get("prompt") == Some(&Value::Bool(false)))
}
pub(super) async fn query(live: &mut Live, stop: &CancellationToken, until: Instant) -> Result<()> {
    live.permissions = None;
    if !live.permissions_available {
        return Ok(());
    }
    let peer = live.client.as_ref().ok_or(CuaError::Unknown)?.peer();
    let params = CallToolRequestParams::new("check_permissions").with_arguments(
        serde_json::json!({"prompt":false})
            .as_object()
            .expect("literal object")
            .clone(),
    );
    let result = tokio::select! {
        _ = stop.cancelled() => return Err(CuaError::Unknown),
        result = timeout_at(until, peer.call_tool_once(params)) => result,
    };
    match result {
        Ok(Ok(CallToolResponse::Complete(reply))) => {
            #[cfg(target_os = "linux")]
            let platform = Platform::Linux;
            #[cfg(target_os = "windows")]
            let platform = Platform::Windows;
            live.permissions = DriverPermissions::parse(platform, &reply).ok();
            Ok(())
        }
        _ => {
            live.uncertain = true;
            stop.cancel();
            Err(CuaError::Unknown)
        }
    }
}
impl CuaHandle {
    pub(crate) async fn current_permissions(&self) -> Option<DriverPermissions> {
        let live = self.resource.live.lock().await;
        if live.retired || live.uncertain || self.resource.stop.is_cancelled() {
            None
        } else {
            live.permissions.clone()
        }
    }
    pub(crate) async fn refresh_permissions(&self) -> Result<Option<DriverPermissions>> {
        let mut live = self
            .resource
            .live
            .clone()
            .try_lock_owned()
            .map_err(|_| CuaError::Busy)?;
        if live.retired || live.uncertain || self.resource.stop.is_cancelled() {
            return Ok(None);
        }
        let until = Instant::now() + live.config.rpc_timeout;
        query(&mut live, &self.resource.stop, until).await?;
        Ok(live.permissions.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn desktop_permission_facts_from_same_transport_are_strict_and_expire() {
        let caps = [
            CapabilityId::DesktopAccessibility,
            CapabilityId::DesktopWindowsControl,
            CapabilityId::DesktopCapture,
            CapabilityId::DesktopPointer,
            CapabilityId::DesktopKeyboard,
        ];
        for bits in 0..16 {
            let facts = serde_json::json!({"atspi":bits&1!=0,"x11":bits&2!=0,"wayland_enabled":bits&4!=0,"xsend_event":bits&8!=0,"wayland":true});
            let driver =
                fake_driver::FakeDriver::start(facts, CallToolResult::structured(Value::Null))
                    .await;
            let (_, reply, _) = driver_result::invoke(
                &driver.peer,
                CallToolRequestParams::new("check_permissions").with_arguments(
                    serde_json::json!({"prompt":false})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(2),
            )
            .await;
            let mut parsed = DriverPermissions::parse(Platform::Linux, &reply.unwrap()).unwrap();
            for (cap, expected) in caps.into_iter().zip([
                bits & 1 != 0,
                bits & 1 != 0,
                bits & 6 != 0,
                bits & 8 != 0,
                bits & 8 != 0,
            ]) {
                let evidence = parsed.evidence(cap);
                assert_eq!(evidence.availability == Availability::Available, expected);
                assert_eq!(evidence.authorization == Authorization::Granted, expected);
            }
            parsed.at -= LIFETIME;
            for cap in caps {
                assert_eq!(parsed.evidence(cap).availability, Availability::Unavailable);
            }
            assert_eq!(driver.calls.lock().unwrap().len(), 1);
            driver.close().await;
        }
        for value in [
            serde_json::json!({}),
            serde_json::json!({"atspi":"true","x11":1,"wayland_enabled":null,"xsend_event":[]}),
        ] {
            let parsed =
                DriverPermissions::parse(Platform::Linux, &CallToolResult::structured(value))
                    .unwrap();
            for cap in caps {
                let evidence = parsed.evidence(cap);
                assert_eq!(evidence.availability, Availability::Unavailable);
                assert_eq!(evidence.authorization, Authorization::Unknown);
            }
        }
        assert!(
            DriverPermissions::parse(Platform::Linux, &CallToolResult::success(vec![])).is_err()
        );
        let windows = DriverPermissions::parse(
            Platform::Windows,
            &CallToolResult::structured(
                serde_json::json!({"uia":true,"post_message":true,"elevated":false}),
            ),
        )
        .unwrap();
        for cap in caps {
            assert_eq!(
                windows.evidence(cap).availability == Availability::Available,
                cap != CapabilityId::DesktopCapture
            );
        }
        assert!(!query_allowed(
            "check_permissions",
            Some(serde_json::json!({"prompt":true}).as_object().unwrap())
        ));
    }
}

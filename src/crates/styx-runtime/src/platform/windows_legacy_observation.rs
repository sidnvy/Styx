//! Read-only native facts. This object is NOT a settled-tree or activation grant.
//! Construct/use/drop on one retained blocking job. The caller keeps its original
//! JoinHandle through Unknown/timeout; COM calls are not cancellable by dropping
//! the response waiter. No runtime/host executor thread runs these blocking calls.
#![allow(unsafe_code)] // Official COM/WMI/TaskScheduler/Time ABI, with retained MTA ownership.
use std::{marker::PhantomData, rc::Rc};
use windows::{
    Win32::{
        Foundation::{FILETIME, RPC_E_TOO_LATE, SYSTEMTIME},
        System::{Com::*, TaskScheduler::*, Time::SystemTimeToFileTime, Variant::VT_BSTR, Wmi::*},
    },
    core::{BSTR, VARIANT, w},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationError {
    Native,
    Invalid,
    Changed,
    Active,
}
type Result<T> = std::result::Result<T, ObservationError>;
fn native<T>(_: T) -> ObservationError {
    ObservationError::Native
}
/// Same provider/UTC precision as old Get-CimInstance LastBootUpTime. WMI exposes
/// microseconds, old Date.parse uses milliseconds: never compare string inequality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootStamp {
    pub(crate) unix_micros: u64,
}
impl BootStamp {
    /// A strictly later *whole second* excludes false transitions caused by old
    /// Date.parse truncation, fractional formatting, or UTC offset spelling.
    /// It is not enough by itself: exact protected old owner/lock/config and all
    /// their timestamps must be before this boot, and restart admission fenced.
    pub(crate) fn definitely_after_old_ms(&self, old_ms: u64) -> bool {
        self.unix_micros / 1_000_000 > old_ms / 1_000
    }
}
fn decimal(bytes: &[u8]) -> Result<u16> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ObservationError::Invalid);
    }
    bytes.iter().try_fold(0u16, |v, b| {
        v.checked_mul(10)
            .and_then(|v| v.checked_add(u16::from(b - b'0')))
            .ok_or(ObservationError::Invalid)
    })
}
fn cim_boot(s: &str) -> Result<BootStamp> {
    let b = s.as_bytes();
    if b.len() != 25 || b[14] != b'.' || !matches!(b[21], b'+' | b'-') {
        return Err(ObservationError::Invalid);
    }
    let st = SYSTEMTIME {
        wYear: decimal(&b[0..4])?,
        wMonth: decimal(&b[4..6])?,
        wDay: decimal(&b[6..8])?,
        wHour: decimal(&b[8..10])?,
        wMinute: decimal(&b[10..12])?,
        wSecond: decimal(&b[12..14])?,
        ..Default::default()
    };
    let micros = u64::from(decimal(&b[15..18])?) * 1000 + u64::from(decimal(&b[18..21])?);
    let offset = i128::from(decimal(&b[22..25])?) * 60 * 1_000_000;
    let mut ft = FILETIME::default();
    unsafe {
        SystemTimeToFileTime(&st, &mut ft).map_err(native)?;
    }
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    let utc = i128::from(ticks / 10) - 11_644_473_600_000_000i128 + i128::from(micros)
        - if b[21] == b'+' { offset } else { -offset };
    let unix_micros = u64::try_from(utc).map_err(native)?;
    if unix_micros == 0 {
        return Err(ObservationError::Invalid);
    }
    Ok(BootStamp { unix_micros })
}
struct Apartment(PhantomData<Rc<()>>);
impl Apartment {
    fn enter() -> Result<Self> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(native)?;
        }
        Ok(Self(PhantomData))
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() }
    }
}
struct TaskAbsence {
    folder: ITaskFolder,
    name: BSTR,
}
impl TaskAbsence {
    /// Name selected by the trusted original install descriptor, not wire input.
    /// GetTask's exact ERROR_FILE_NOT_FOUND is the only accepted absence. Access
    /// denial, provider errors or a present disabled task are NOT absence.
    fn capture(name: &str) -> Result<Self> {
        if !(name == "Styx-Host"
            || name.strip_prefix("StyxPilot-").is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 30
                    && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            }))
        {
            return Err(ObservationError::Invalid);
        }
        unsafe {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).map_err(native)?;
            let empty = VARIANT::default();
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(native)?;
            let folder = service.GetFolder(&BSTR::from("\\")).map_err(native)?;
            let value = Self {
                folder,
                name: BSTR::from(name),
            };
            value.revalidate()?;
            Ok(value)
        }
    }
    fn revalidate(&self) -> Result<()> {
        match unsafe { self.folder.GetTask(&self.name) } {
            Err(error) if error.code().0 == 0x80070002u32 as i32 => Ok(()),
            Err(_) => Err(ObservationError::Native),
            Ok(_) => Err(ObservationError::Active),
        }
    }
}
/// Original COM objects and apartment never leave the dedicated original worker.
/// No Deserialize/Clone. No stop/set-enabled/delete or arbitrary remote WMI API.
pub(crate) struct WindowsLegacyObservation {
    task: TaskAbsence,
    task_name: String,
    wmi: IWbemServices,
    initial_boot: BootStamp,
    // Last field: all COM references above release before CoUninitialize.
    _apartment: Apartment,
}
impl WindowsLegacyObservation {
    pub(crate) fn capture_foreground_only(task_name: &str) -> Result<Self> {
        let apartment = Apartment::enter()?;
        unsafe {
            // Initialize standard COM process security once; if another trusted
            // component already did so, retain its policy and set our own proxy
            // blanket below. Never weaken/replace a pre-existing policy.
            if let Err(error) = CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            ) {
                if error.code() != RPC_E_TOO_LATE {
                    return Err(native(error));
                }
            }
            let locator: IWbemLocator =
                CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).map_err(native)?;
            let empty = BSTR::new();
            let wmi = locator
                .ConnectServer(
                    &BSTR::from("ROOT\\CIMV2"),
                    &empty,
                    &empty,
                    &empty,
                    WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
                    &empty,
                    None,
                )
                .map_err(native)?;
            // Microsoft WMI example values: WINNT authentication (10), no
            // authorization service (0), CALL auth and IMPERSONATE. Local only.
            CoSetProxyBlanket(
                &wmi,
                10,
                0,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
            .map_err(native)?;
            let initial_boot = read_boot(&wmi)?;
            let task = TaskAbsence::capture(task_name)?;
            if read_boot(&wmi)? != initial_boot {
                return Err(ObservationError::Changed);
            }
            Ok(Self {
                task,
                task_name: task_name.to_owned(),
                wmi,
                initial_boot,
                _apartment: apartment,
            })
        }
    }
    pub(crate) fn task_name(&self) -> &str {
        &self.task_name
    }
    pub(crate) fn checkpoint(&self) -> Result<BootStamp> {
        let before = read_boot(&self.wmi)?;
        if before != self.initial_boot {
            return Err(ObservationError::Changed);
        }
        self.task.revalidate()?;
        if read_boot(&self.wmi)? != before {
            return Err(ObservationError::Changed);
        }
        Ok(before)
    }
}
fn read_boot(wmi: &IWbemServices) -> Result<BootStamp> {
    unsafe {
        let query = wmi
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT LastBootUpTime FROM Win32_OperatingSystem"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(native)?;
        let mut values = [None, None];
        let mut count = 0;
        let status = query.Next(10_000, &mut values, &mut count);
        // Exactly one plus enumeration end; a timeout with one item is Unknown.
        if status.0 != WBEM_S_FALSE.0 || count != 1 {
            return Err(ObservationError::Native);
        }
        let object = values[0].take().ok_or(ObservationError::Native)?;
        let mut value = VARIANT::default();
        let mut kind = 0;
        object
            .Get(w!("LastBootUpTime"), 0, &mut value, Some(&mut kind), None)
            .map_err(native)?;
        if kind != CIM_DATETIME.0 || value.as_raw().Anonymous.Anonymous.vt != VT_BSTR.0 {
            return Err(ObservationError::Invalid);
        }
        cim_boot(&BSTR::try_from(&value).map_err(native)?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_precision_and_timezone_do_not_invent_a_reboot() {
        let utc = cim_boot("20261026112233.123456+000").unwrap();
        assert_eq!(utc, cim_boot("20261026192233.123456+480").unwrap());
        let legacy_ms = utc.unix_micros / 1000;
        assert!(!utc.definitely_after_old_ms(legacy_ms));
        assert!(
            !BootStamp {
                unix_micros: utc.unix_micros + 1
            }
            .definitely_after_old_ms(legacy_ms)
        );
        assert!(
            BootStamp {
                unix_micros: utc.unix_micros + 2_000_000
            }
            .definitely_after_old_ms(legacy_ms)
        );
        for invalid in [
            "20261026112233.******+000",
            "20260230112233.123456+000",
            "20261026112233.123456:000",
            "20261026112233.123456+***",
        ] {
            assert!(cim_boot(invalid).is_err());
        }
    }
}

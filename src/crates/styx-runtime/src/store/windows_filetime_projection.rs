//! Pure comparison/legacy-JSON projection only. Retained Windows file stamps
//! remain native FILETIME epoch; no stored bytes or file identities are changed.
const WINDOWS_TO_UNIX_SECONDS: i64 = 11_644_473_600;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// FileObservation is split from signed FILE_BASIC_INFO 100ns units since 1601.
/// Reject pre-Unix / invalid precision rather than wrap them into a modern time.
pub(super) fn unix_nanoseconds(seconds: i64, nanoseconds: i64) -> Option<u128> {
    if !(0..1_000_000_000).contains(&nanoseconds) || nanoseconds % 100 != 0 {
        return None;
    }
    let unix_seconds = u128::try_from(seconds.checked_sub(WINDOWS_TO_UNIX_SECONDS)?).ok()?;
    unix_seconds
        .checked_mul(1_000_000_000)?
        .checked_add(u128::try_from(nanoseconds).ok()?)
}

/// Exactly the existing JS BigIntStats.mtimeMs integer floor, within safe JSON.
pub(super) fn unix_millis_js(seconds: i64, nanoseconds: i64) -> Option<u64> {
    let millis = u64::try_from(unix_nanoseconds(seconds, nanoseconds)? / 1_000_000).ok()?;
    (millis <= MAX_SAFE_JSON_INTEGER).then_some(millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_native_seconds_and_1601_zero_are_not_unix_zero() {
        assert_eq!(unix_nanoseconds(i64::MIN, 0), None);
        assert_eq!(unix_nanoseconds(-1, 0), None);
        assert_eq!(unix_nanoseconds(0, 0), None);
        assert_eq!(
            unix_nanoseconds(WINDOWS_TO_UNIX_SECONDS - 1, 999_999_900),
            None
        );
    }
    #[test]
    fn unix_epoch_zero_and_100ns_are_exact() {
        assert_eq!(unix_nanoseconds(11_644_473_600, 0), Some(0));
        assert_eq!(unix_nanoseconds(11_644_473_600, 100), Some(100));
        assert_eq!(unix_millis_js(11_644_473_600, 999_900), Some(0));
        assert_eq!(unix_millis_js(11_644_473_600, 1_000_000), Some(1));
    }
    #[test]
    fn independently_known_2026_vector_preserves_fraction_and_floor() {
        // 2026-10-23T10:15:55.123456700Z, POSIX seconds 1792750555.
        assert_eq!(
            unix_nanoseconds(13_437_224_155, 123_456_700),
            Some(1_792_750_555_123_456_700)
        );
        assert_eq!(
            unix_millis_js(13_437_224_155, 123_456_700),
            Some(1_792_750_555_123)
        );
    }
    #[test]
    fn native_nanosecond_shape_is_checked() {
        for ns in [-1, 1, 99, 1_000_000_000, i64::MAX] {
            assert_eq!(unix_nanoseconds(13_437_224_155, ns), None);
        }
    }
    #[test]
    fn legacy_json_projection_rejects_integer_overflow_or_precision_loss() {
        assert_eq!(unix_millis_js(i64::MAX, 0), None);
        let last = WINDOWS_TO_UNIX_SECONDS + (MAX_SAFE_JSON_INTEGER / 1000) as i64;
        assert_eq!(
            unix_millis_js(last, ((MAX_SAFE_JSON_INTEGER % 1000) * 1_000_000) as i64),
            Some(MAX_SAFE_JSON_INTEGER)
        );
        assert_eq!(
            unix_millis_js(
                last,
                ((MAX_SAFE_JSON_INTEGER % 1000 + 1) * 1_000_000) as i64
            ),
            None
        );
    }
    #[test]
    fn strict_boot_comparison_does_not_discard_native_submicrosecond_bits() {
        // Boot 2026-10-23T10:25:50.500000Z. Strictly before only.
        let boot_ns = 1_792_751_150_500_000u128.checked_mul(1000).unwrap();
        assert!(unix_nanoseconds(13_437_224_750, 499_999_900).unwrap() < boot_ns);
        assert_eq!(unix_nanoseconds(13_437_224_750, 500_000_000), Some(boot_ns));
        assert!(unix_nanoseconds(13_437_224_750, 500_000_100).unwrap() > boot_ns);
    }
}

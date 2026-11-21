# China Unicom Android app: Pixel 7 Pro startup crash

Package: `com.sinovatech.unicom.ui`.
Evidence date: 2026-11-22, Pixel 7 Pro (`cheetah`), Android 17/API 37.
Installed version: **13.2.1**, versionCode 197, targetSdk 30; installed
2026-11-18. This is a diagnostic note, not a proven fix or product workaround.

## Verified device evidence

- Launch from the launcher reproducibly killed the main app process.
  `dumpsys activity exit-info` recorded multiple recent
  `reason=SIGNALED`, `status=11` (SIGSEGV), e.g. 2026-11-22 02:41:38,
  PID 20990. A Google WebView sandboxed process also exited.
- During initialization, the app logged restricted system-property accesses,
  an Android hidden-API access warning associated with a bundled
  `com/sdk/hijack/base/d` class, and attempts to inspect device/system
  properties. These lines do **not** prove root/tamper detection caused the
  SIGSEGV. There was no new readable native tombstone for this crash.
- The device's standard `su` command denied shell access; no root-level
  diagnostic or security changes were performed. Boot properties reported
  verified-boot state `green` and flash lock `1`; neither this nor the
  hidden-API warnings establish the specific crash cause.
- System Settings showed approx. 112 MB user data and 10.87 MB cache.
  The targeted Android-native `pm clear --cache-only` operation did not
  complete after more than a minute; its Host task was stopped with exit 137.
  Its completion/effect are **unknown**. It was not repeated, and no full
  storage-clear, reinstall, version downgrade or account logout was done.

## Public/community context (not a Pixel-specific diagnosis)

- A Xiaohongshu post dated 2025-07-02 described China Unicom App crashes
  persisting through restart/reinstall; the author said they used a mini
  program instead. That post did **not** identify Pixel as the device.
- Huawei's official support article records that China Unicom and some
  financial apps intentionally reject certain private-space/subuser
  environments. It does not establish the reason for this Pixel crash:
  https://consumer.huawei.com/cn/support/content/zh-cn15922205/
- Generic Pixel application crash troubleshooting:
  https://support.google.com/pixelphone/answer/9454904?hl=zh-Hans
- For official Android versions, APK signers and distribution must be checked
  against trusted sources. Do not install an unverified APK or disable app
  integrity/root detection to force the telecom app to run.

## Next bounded checks

1. Obtain a current native crash stack by supported, authorized Android
   debugging (dropbox/tombstone/bugreport), without exposing personal data.
2. Compare an authenticated same-version/signer build on another supported
   phone if available; keep operating system, Play services and network
   differences explicit. Do not infer anti-root solely from property probes.
3. Ask the app vendor to diagnose SIGSEGV with app 13.2.1 / Android 17 /
   Pixel 7 Pro, providing a sanitized timestamp and process exit receipt.
4. Use China Unicom's verified official web/mini-program channel for
   necessary account operations while awaiting a supported version.

## Official alternative while the App crashes

China Unicom maintains its [official web self-service portal](https://www.10010.com/wt_links/index.html)
for account balances, bills, package queries and relevant service handling,
and [official WeChat service information](https://iservice.10010.com/e4/PublicitychannelView/wechat_new.html).
Prefer these verified domains to third-party APK mirrors or unverified mini
programs until the vendor ships a compatible Android build.

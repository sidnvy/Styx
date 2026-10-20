# Native product compile validation — 2026-10-20

On the authorized isolated PilotMac directory `/tmp/styx-v6-native-CRF1LKDF`, both
production and `STYX_TESTING` variants compiled successfully with warnings treated as
errors. Compiler: Apple Swift 6.4 (`swiftlang-6.4.0.34.1`, driver 1.168.6).
Target `arm64-apple-macosx13.0`; SDK `MacOSX26.5.sdk`.

Flags: `-D STYX_PRODUCT_UI -warnings-as-errors -target arm64-apple-macosx13.0`, plus
`-D STYX_TESTING` for the test binary. Linked AppKit, ApplicationServices,
CoreGraphics, SwiftUI, WebKit. Inputs: root-owned `main.swift` and these four files.

Test command: `./Styx-test --self-test`. Exit code 0. Output:

```text
Styx native product protocol self-test passed; GUI, TCC and account acceptance NOT RUN
Styx native ownership, settings navigation, ZIP export and PNG picker validation self-test passed; GUI file dialogs and TCC NOT RUN
```

Frozen UI source SHA-256 (matches both local and transferred files):

```text
71dbfb9c9f7a48b9286ce8b20ac4d1e15338f259543eeb74b3190974c160c549  ProductCoreClient.swift
3c28950b8f9b773a83d78cb8f32bc42b5b077d79365b92bc685626bee4800435  ProductModel.swift
2e84d4a571999b36a6cca89f00694f6911678c9d1969a96f9d09fe942fd9739d  ProductViews.swift
6c1685ffcddb2005b0ed74e92d20b294a131da7248c856df3e15034ac428b0e9  ProductSelfTests.swift
```

The first compile exposed a missing devices-view scope brace, then the correct
MainActor boundary for the App delegate and a catch-variable shadow. Those were
fixed before the successful runs. This record does not erase those failures.

This check did not launch the App, Cua, permissions prompts, installed services,
real plugin/account, or an installer. Root integration owns the window smoke,
complete native interaction, permissions, account, lifecycle and package gates.

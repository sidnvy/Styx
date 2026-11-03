# Windows DPI-unaware window capture

Decision: route only DPI-unaware HWNDs through the existing Windows Graphics
Capture implementation in the pinned native Cua executor. Other targets keep
its original capture path. This is an upstream OS bridge repair, not a second
executor or an input/policy authority.

## Evidence and boundary

The real Gateway scene on NAB5 at source 20ea0df returned a 730x364 PNG for a
DPI-unaware WinForms target on a 120-DPI desktop. The Cua process was already
per-monitor aware. Independent OS queries and original PNG alpha analysis found
content occupying approximately 584x292 pixels with transparent right/bottom
padding. Successful PNG decoding alone did not prove a correct observation.
The original images and failed geometry receipt remain in the project artifacts.

The fixed upstream PrintWindow path sizes its bitmap from physical window bounds
but this target paints logical pixels. Do not change system scaling, target DPI
mode, source trust or crop/resize the partial image to declare success. The
existing upstream WGC path captures that HWND's compositor image. If this path
fails, return an error instead of falling back to the partial GDI image or a
screen region that could show another window. Unknown/invalid DPI context also
fails. WGC supplies no proven screen origin; FrameGeometry stays None and the
existing image-only observation cannot authorize mapped pixel input. Input
continues to require fresh AX evidence and current Core admission.

Upstream: [capture.rs](https://github.com/trycua/cua/blob/6d6c734c127025fb39ad5d585a10382808b39dc1/libs/cua-driver/rust/crates/platform-windows/src/capture.rs),
[wgc.rs](https://github.com/trycua/cua/blob/6d6c734c127025fb39ad5d585a10382808b39dc1/libs/cua-driver/rust/crates/platform-windows/src/wgc.rs).
No dependency versions or Cargo.lock are changed.

## Reproducible input

`src/tools/release/prepare-cua-windows-wgc.py` verifies the immutable upstream
archive, capture module and Cargo.lock, extracts bounded dependency inputs to a
fresh external directory, and inserts the reviewed
`src/host/windows/cua-window-dpi-capture.rs` fragment at one exact boundary.
It records every prepared file hash. Release preparation requires a clean exact
Styx source revision; `--development-check` explicitly labels an unfrozen check.
Preparation does not compile, sign, install or operate any profile.

Archive: `https://codeload.github.com/trycua/cua/tar.gz/6d6c734c127025fb39ad5d585a10382808b39dc1`
SHA256: `157acdc2fd0bf5c480af2bdbe4a69f75a709551627f851caee16346234fdedef`.
Original Cargo.lock SHA256:
`f9d49ce2dccdc43b2f7f027185301138fdd45eab4f9a556aace4cb0f4a98d46c`.

On NAB5 use the existing Rust 1.97.1/MSVC toolchain and one owned Cargo cache,
4 Cargo jobs and 2 CMake jobs. Verify the prepared file manifest before use.
Run check-only first. An explicit candidate uses
`src/tools/release/build-cua-windows-wgc.py` with the clean prepared source,
exact product revision, existing target directory and fresh output directory.
It runs `cargo build --locked -p cua-driver --release --target x86_64-pc-windows-msvc -j 4 --timings`,
checks every prepared file before/after, requires the affected native targets to
recompile, and retains Cargo diagnostics, timings and the exact binary receipt.
Set `CUA_DRIVER_GIT_SHA` to the pinned upstream commit. Do not enable review trust
roots, add elevated UIA helpers, install services or change pairing/configuration.
The worker remains `cua-driver mcp --direct` under the original Host owner.

The candidate worker release must identify this as a patched build, record the
source/fragment/binary hashes, retain the unchanged Codex and licenses, and be
signed by the existing m600 publisher without transferring its private key.
Compilation is not acceptance. Required acceptance is an original full HWND PNG
with independently checked DPI/geometry, fresh AX, one input, independent readback,
one click, stable result and actual normal App/Core/worker exit in the existing
single-owner test profile. Until those receipts close, screenshot geometry stays
NOT_PASSED and stable stays NO-GO.

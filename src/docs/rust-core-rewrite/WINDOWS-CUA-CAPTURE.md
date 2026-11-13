# Windows DPI-unaware window capture

The current retained repair is part of the single
`src/providers/cua-native/cua-0.47.24-styx-fixes.patch`, applied to official Cua
Driver 0.47.24. The source commit, archive and changed file hashes are in
`src/providers/cua-native/source.json`. It reuses upstream Windows Graphics
Capture for DPI-unaware HWNDs; it does not introduce a second capture engine.

## Concrete failure and retained boundary

The earlier NAB5 120-DPI WinForms fixture returned a 730x364 PNG whose actual
content occupied about 584x292 pixels, with transparent right/bottom padding.
The original PrintWindow path sized the bitmap using physical bounds while the
DPI-unaware target painted logical pixels. Successful PNG decoding did not prove
correct capture. The historical original image/geometry receipts remain evidence
of that failure, not execution proof for the new dependency.

Official 0.47.24 already has WGC for selected capture errors, XAML windows and
black frames, but source inspection did not establish a DPI-unaware branch that
catches this successful-but-partial GDI image. Retain the small explicit branch
until the original case is qualified upstream. Do not change scaling or resize
partial pixels to make a capture pass.

The repair uses the original HWND and upstream compositor capture. Unknown DPI
context or failed WGC is an error; it does not accept a partial GDI frame or a
screen-region substitute. WGC does not prove screen origin, so its image has no
mapped pixel-input geometry. Core's existing observed-target input rules remain.

## Build and validation

All three platforms use `src/ci/release-cua.py`: verify the official source
archive, apply the single patch with zero fuzz, verify original/final source
hashes, and compile the locked upstream graph in the existing native Cargo
cache. The former Windows-only preparation/build scripts and separate capture
fragment have been removed. Cargo.lock is unchanged.

Reuse the original target/profile/features/RUSTFLAGS. Choose parallel jobs from
observed CPU/memory and compile/link phase; do not use a fixed conservative cap
or force a recompilation to manufacture evidence. Source preparation and a
native compiler result do not qualify screenshot behavior.

The focused native regression remains: the owned 120-DPI DPI-unaware WinForms
window must return the full original HWND image with independently checked
content and dimensions, including the covered-window case. Retain ordinary
same-identity startup/cleanup evidence separately. No new platform-wide
acceptance campaign follows merely from this small repair.

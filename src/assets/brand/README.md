# Styx Brand Assets

Canonical source artwork (`1024x1024`, borderless):

- `styx-icon-light-source.jpg`: Black circular orb and waves on white background.
- `styx-icon-dark-source.jpg`: White circular orb and waves on black background.

Derived platform and connector assets:

- `styx-logo.png`: `512x512` transparent RGBA PNG (black glyph with 5% inset), used by `README.md`, Windows UI, plugin bundles, and Android icon generation (`src/host/android/render-icons.py`).
- `styx-custom-mcp-icon.png`: `128x128` transparent RGBA PNG (`9,110` bytes, under the 10 KB upload limit for ChatGPT Custom MCP), SHA-256 `a99bc08983557c2475cb12ac74f59d75ba5e627096ab4510e8cf45c445b1b48d`.
- `styx.ico`: Multi-resolution Windows icon (`256`, `64`, `48`, `32`, `24`, `16`, 32-bit RGBA) embedded into the Windows desktop binary and installer.
- macOS builds extract the transparent glyph via `src/host/macos/BrandGlyph.swift` and render the `.icns` iconset and plugin icon via `src/host/macos/render-brand-icons.swift`.

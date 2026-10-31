# Plugin PNG decoding dependency review

The plugin presentation feature pins `png = 0.18.1` in Cargo.toml and locks its registry archive and transitive inputs in Cargo.lock. Registry checksum: `60769b8b31b2a9f263dae2776c37b1b28ae246943cf719eb6946a1db05128a61`.

Scope: a byte decoder in styx-runtime management only. It does not enter styx-core, issue grants, connect to a network, execute images, select a process or change enrollment/tunnel state. The runtime is the shared validation boundary for CLI and native App inputs. The existing base64, regex and private-file adapters are reused.

The maintained [png decoder API](https://docs.rs/png/0.18.1/png/struct.Decoder.html) supports resource limits and real pixel decoding. The adapter caps encoded input at 256 KiB, decoder resources at 8 MiB, output pixels at 4 MiB, dimensions at 48–1024 square, and accepts only 8-bit noninterlaced frames. An explicit policy chunk allowlist excludes animation and embedded text/EXIF/ICC data. Existing package CRC code is reused; no new image decompressor is implemented in Styx.

Scenario evidence covers the exact default logo, a different transparent RGBA image, pixel alpha preservation, corrupt CRC, trailing data, oversized input, forbidden metadata/animation, canonical base64, Unicode/control limits, immutable identity through rename/reset, concurrent edit conflicts, and independent Python ZIP reading. These are input/export tests, not native GUI or ChatGPT account acceptance.

The dependency policy permits png only in styx-runtime. No pure-core or workspace dependency direction is widened. This records the integration review scope, not a claim of an exhaustive third-party security audit.

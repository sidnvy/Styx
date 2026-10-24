# Native configuration preview package · C08 subset

This format is an internal Linux x86_64 configuration-management preview. It is
not the unified three-platform candidate, a product installer, a Host/Gateway
runtime deployment, a same-identity migration, or a Stable release.

The schema2 signed manifest explicitly declares native_rust_v1, styx component,
configuration_preview scope, native_release_v1 reader, target triple, fixed native
entry, contract versions, source revision/input digest and the exact three data
members: bin/styx, LICENSE, source-inputs.json. External workers are empty. The
preview validator refuses additional JS Core, launch shims and undeclared workers;
it does not imply that all Rust runtime features have reached release acceptance.

Signatures cover exact manifest bytes with existing Ed25519 publisher primitives.
The NEW native codec stores a detached64-byte raw signature. Legacy packages keep
their original base64url-text signature codec and schema1 reader, unchanged. A
valid native signature translated to that old codec must still be refused by the
old reader because of schema2. Do not insert a Rust binary into a schema1 JS bundle.

`styx release verify --payload-dir /private/payload --publisher-file
/private/trusted-publisher.pem --expected-publisher <public-SPKI-SHA256> --json`
is read-only. The externally approved public key and pin are not taken from the
bundle. Verification uses existing dalek publisher checks, protected raw reads,
streamed complete payload inventory and a retained fixed ELF image. A validated
manifest DTO alone is not launch authority. Any future launcher must retain its
opaque verified object until actual child reaping; this command does not launch.

`src/tools/release/build-native-preview.py` packages a frozen, clean source and
PASS/exact-input build receipt. It never invokes Cargo or generates a publisher
key. The selected binary must match the receipt and Linux ELF64/x86_64 header.
The output is fresh/private only; the source binary/key are not modified. Mature
OpenSSL creates/verifies the detached signature; Python tarfile/gzip creates a
fixed-member USTAR archive with normalized metadata. Publisher public files are
outside payload, not automatic trust. Failure materials remain in their owned
output; an existing output is never overwritten or cleaned by retry.

Internal acceptance may use an explicitly temporary test publisher. Such a key
is not the original publisher, and its package must not be presented as trusted
production continuity. Original publisher/signing/TCC/device/pairing inputs remain
untouched. Root LICENSE is included; a complete distribution SBOM/third-party
license/security/reproducible-release audit is still a separate R25 obligation.

Required actual evidence: build-receipt/binary/source joins; raw signature checked
by independent mature crypto; Rust positive/negative admission; validly re-signed
wrong format/reader/target/entry; actual member/metadata tampering and old-reader
refusal; exact archive closure; fresh owned extraction and the real packaged CLI
configuration journey. Extracting to a test prefix is not a completed native
installer or service activation/rollback path. Read the Owner Control Report for
what actually ran and the exact source/artifact hashes.

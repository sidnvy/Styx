# Independent Node runtime packaging

The native publisher can prepare official Node 22.23.3 without an installed
Node dependency using Python 3:

```
python3 src/host/prepare-node.py /absolute/scratch/node-22.23.3
```

Only Linux x64, macOS x64/arm64 and Windows x64 are supported. The script pins
archive SHA-256 values from Node's official v22.23.3 SHASUMS256.txt, extracts
exact regular-file binary and LICENSE members without general archive extraction,
and records the official source URL, archive/binary/license checksums, target
and version. Existing destinations are refused. No system installation occurs.

Pass the resulting binary as `nodeBinary` to `buildHostRelease`, or the final
sixth CLI argument. This is optional on Linux/macOS and mandatory on Windows.
The binary must report exactly v22.23.3 and match its adjacent provenance and
LICENSE hashes. The publisher signs all three files in the release manifest:
`bin/node[.exe]`, `licenses/node-LICENSE`, and `provenance/node.json`. The manifest
upstream inventory records Node alongside Codex, Cua and ws. The provenance is
publisher evidence; it is not a Node project signature or an independent SBOM.

After staging, `refreshVerifiedBootstrap` copies a verified bundled runtime to
the per-user install root alongside the stable shims. On Windows it checks for
a changed existing node.exe before modifying any shim and refuses the refresh.
An identical executable is reused without replacement. Runtime upgrades require
a stopped-service/offline switch performed by the installation owner; this API
does not implement an offline installer or replace a running Windows executable.
Windows service plans default to the install-root node.exe. The launcher verifies
the active generation and uses its bundled Node for the Host child process.
Linux/macOS service planners automatically select the stable install-root Node
when the active signed bundle contains Node, after verifying its hash against
the publisher-signed active manifest. Run refresh-bootstrap before generating
the service unit/plist. A missing or tampered stable copy fails closed. An
explicit nodeBinary may select the exact signed active-generation binary, but
that path must be updated before pruning that generation. Arbitrary external
Node paths are rejected when Node is bundled. Linux/macOS retain system Node
compatibility when a bundle omits Node.

Validation: Python archive tests run without network; the Host runtime test
simulates signed Windows payloads on Linux and checks refusal before shim writes.
Set STYX_TEST_NODE_BINARY to a prepared native binary to exercise real packaging,
version execution and post-signing tamper rejection in native-build.test.mjs.
Native Windows/macOS cold install, restart, offline runtime upgrade, OS signing,
notarization and production acceptance remain separate release gates.

The three-OS CI matrix prepares real checksum-pinned Node/Codex/Cua artifacts,
builds and verifies a signed release with an ephemeral test publisher key,
stages it in a temporary directory, refreshes the bootstrap, executes Node,
and checks service planner selection and tamper rejection. It never installs
or starts an OS service. This is native packaging evidence, not a production
publisher signature, cold install acceptance, or GUI acceptance.

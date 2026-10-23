# Persistent local Mac signing — development acceptance

Source: `a9a3e539966f2772ddc16f4aaf2097904235f840`.
Package: `0.3.0-v6-dev.20261020.9`, arm64.

## Scope and identity

PilotMac now has a persistent, dedicated local development signing identity.
The user completed the native certificate approval. Trust is in the current
user's code-signing policy, not system/TLS trust or TCC authorization. The
private key remains nonextractable in its dedicated Mac keychain; no keychain,
private key or password was copied into the package or transferred off the Mac.

Certificate SHA-256:
`90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e`.

The build pins the certificate and stable bundle/code identifiers, signs native
payloads before recalculating Host provenance, then seals the App. Verification
checks the actual signature, designated requirement and both certificate hashes.
The public bundled descriptor alone does not establish trust. A previously
registered certificate cannot silently change or downgrade to ad-hoc signing.

The dedicated keychain is retained in the user search list while preserving
existing entries and the default keychain. Builds unlock only this keychain
locally. Certificate lookup alone was insufficient for private-key lookup.
Provisioning is idempotent; incomplete identity state fails closed rather than
generating another identity. Temporary plaintext key material is always removed.

Local signing does not require Apple Developer Program membership. It does not
provide Developer ID distribution trust or notarization. Public Developer ID
distribution is a separate release path requiring Apple's developer program.
See Apple's [Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
and [Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/).

## Existing installation transition

The installed PilotMac App and deployment registration were not replaced.
The first ad-hoc-to-certificate transition requires an explicit Core transaction:
`mac-signing-plan`, `mac-signing-apply --authorize`, and, if necessary,
`mac-signing-rollback --authorize`. Inputs and plans must be private files.

The plan binds the old configuration, state and relevant journals to the exact
verified App at `/Applications/Styx.app`. Apply preserves device identity,
pairings, credentials and role choices. It records exact before/after snapshots
and an execution journal; interrupted operations block unrelated lifecycle
changes until reconciliation. Rollback restores these recorded configuration
bytes; it does not restore an installed App bundle. Installer backup/rollback
must be coordinated separately. A process killed during rollback can leave a
recovery guard that requires inspection rather than automatic lock stealing.

Until this transition completes, the signed App refuses automatic foreground
and tunnel startup or mutating onboarding operations against an old ad-hoc
registration. This package must not be presented as a drop-in verified upgrade.
The identity transition can require one manual permission grant. Subsequent
permission retention still requires real upgrade testing.

## Actual evidence

- Integrated Core/signing/lifecycle/HTTP regression: 90 passed, no failures or
  skips, Node 22.23.3. A repeat under the restricted sandbox could not run all
  fixtures; the final run used an environment allowing local loopback listeners.
- Mac signing/build/launcher regression: 29 passed, one platform skip, no failures.
- Native certificate verification and real HTTP migration-boundary test: one
  passed. Core lifecycle calls were injected to avoid changing real services.
- Two genuinely different native executables had different CDHashes and the same
  certificate-bound designated requirement; both signatures verified and ran.
- Production Styx App and embedded Cua compiled and signed successfully. A full
  packaged App copy with changed version metadata and a new signature had a
  different CDHash while the same registered certificate was accepted. A wrong
  certificate was rejected. This is identity continuity, not TCC continuity.
- Read-only DMG: strict deep signature and seven native payload certificate
  checks passed; all 171 packaged source files matched the frozen source.
- A fresh packaged Core bootstrapped in 6619 ms. A testing-only native welcome
  window using that Core rendered in 486 ms. This is not production cold-launch
  or fresh-install acceptance.

Evidence is in task outputs `stable-signing-20261020/` and `v6-candidate-dev9/`.
Failed import/trust and sandbox attempts were retained; they are not counted as
successful native acceptance. No TCC database, protection setting, existing
App/configuration, piermini or NAB service was changed.

## Packaged and delivered; not installed

PilotMac Desktop:
`/Users/it-bootstrap/Desktop/Styx-0.3.0-v6-dev.20261020.9-macos-arm64.dmg`.

DMG SHA-256:
`c415f069873b6c1de53be29e584bc840fcf93c79d13a6f78465a43112024dcb1`.

ZIP SHA-256:
`7495d7a9737e2bffdc3d7fa2f394af62dcfcf7aff8a1c2801c407c2937f3a364`.

Remaining: controlled installed-App transition, actual user permission grant,
real subsequent signed upgrade and rollback, responsibility-chain observation,
login/reboot/crash recovery, and target ChatGPT account acceptance. Developer ID
signing and notarization were not performed. This remains a development preview.

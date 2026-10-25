# ADR-030: Explicit fresh native Gateway bootstrap

2026-10-25. Scope: the missing new-install Gateway-only vertical path; no new
control plane, public MCP tools, UI, services or legacy migration policy.

## Problem and decision

The ordinary native Gateway reader consumes a committed original migration. A
fresh root has no such history; requiring fabricated cutover/retirement evidence
would break the boundary. Configuration-only `styx init` remains unchanged.
`styx gateway bootstrap` explicitly creates a new private Gateway-only root from
a protected deployment file and externally publisher-pinned runtime selection.
The foreground-only first slice binds an IPv4 loopback HTTPS origin/port >=1024;
remote ingress/tunnel/service deployment remain separate existing gates.

## Ownership and persistent contract

The existing `FreshNativeRoot` is the only bootstrap authority. Root creation
refuses EEXIST. It holds the original configuration writer through private
material, clock-floor, canonical genesis and final readiness publication. A
normal opener cannot create a missing enrollment namespace or readiness file.
The fresh root contains fixed `gateway-ca.pem`, `gateway-ca-key.pem`,
`gateway-chain.pem`, `gateway-key.pem`, `gateway-admin.token`,
`gateway-model.token`; all use existing owner-only no-alias store primitives.
Admin and ordinary MCP tokens are separate 256-bit OS-entropy secrets and never
printed by the command. NativeState starts stopped/autostart-disabled, with no
Host or migration binding. Existing native plan/apply sets desired running;
`gateway run` is the explicit foreground process action.

`gateway-ready-v1.json` is versioned private DATA binding root identity, scope,
original deployment digest, original verified runtime selection, origin,
endpoint validity and exact fixed-material digests. The canonical state binds
its raw digest and selection as preserved extensions. It is created LAST after
six materials, existing fresh enrollment namespace's durable Unix-millisecond
clock floor and canonical genesis. Incomplete/bootstrap-Unknown roots are not
implicitly resumed, repaired or regenerated. The failure retains original
root/writer custody; scope teardown is not a claim that partial bytes vanished.
Explicit incomplete-bootstrap recovery is not implemented by this slice.

## Runtime and TLS

The shared foreground listener/enrollment/relay/MCP paths remain unchanged.
A fresh loader checks its ready binding, publisher-signed closure and actual
materials, obtains the existing original writer, and recovers only an already
Committed pure configuration tip. Pending/unknown native work never advances
implicitly. It retains candidate/store/transaction custody, then uses the same
Core enrollment recovery and transport shutdown contracts as ordinary runtime.
The migration reader remains distinct and retains all original-proof checks.

RSA-3072 CA generation uses existing rcgen/aws-lc and explicit validity. Existing
CA-preserving leaf issuance produces a distinct strictly verifiable server leaf.
Generated private keys remain in zeroizing typed custody. No CA-as-leaf workaround
or relaxed certificate verifier is introduced for fresh bootstrap. The current
issuer caps endpoint validity at 24 hours; automatic renewal/rotation is NOT
implemented. Expiry fails closed. This is a remaining unattended-operation gate,
not a Stable-ready deployment. No original CA or production identity is rotated.

## Verification boundaries

One store aggregate exercises actual private filesystem custody, clock units,
repeat creation refusal and partial-publication refusal; opaque material in that
fixture is not a TLS/pairing proof. A generated-CA aggregate verifies real strict
TLS, name rejection, key/chain constraints and invalid-clock refusal. Required
whole runtime evidence is actual CLI fresh bootstrap -> native plan/apply ->
strict TLS -> authorization/pairing -> owned executor effect -> actual shutdown,
with independent effects and unchanged old identities. Mocks/counts cannot close
that gate. Platform/source/artifact identities and NOT TESTED limits belong to
execution receipts, not this design record.

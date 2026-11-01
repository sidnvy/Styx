# Native Gateway reliability follow-up

Fresh native Gateways explicitly record `renew_endpoint: true` in the immutable,
configuration-bound ready document. Their CA identity, CA key, origins and LAN
SANs remain fixed; endpoint certificates are renewed in memory by the original
Gateway's owned blocking validation job. No bootstrap file or C07 receipt is
rewritten. TLS handshakes take a current immutable certificate snapshot, refuse
expired material, and bind enrollment requests to that connection's actual leaf.
The normal six-hour renewal margin shrinks near the CA's own expiry. CA expiry,
changed protected input or issuance failure stays closed.

A ready document without this policy retains its existing fixed endpoint pin and
expiry checks. Native admin calls for a renewing deployment use its protected CA
pin and normal hostname/validity verification; the actual response leaf still
binds pending enrollment and approval. Runtime updates preserve the same ready
binding. This does not migrate or repair expired old roots.

Linux service stop keeps the original executable, process birth, manager unit
reference and cgroup descriptors until completion. On kernfs, a removed cgroup
can keep its inode and nonzero link count while reads of its originally held
`cgroup.events` descriptor return `ENODEV`. Only that exact descriptor error
counts as an empty removed group; other I/O errors remain unknown. Clean manager
exit, original PID exit and original invocation/identity checks still apply.
This was reproduced on the Debian 12 VM and a new signed-runtime service stopped
successfully using the corrected, uninstalled development management CLI. It is
not evidence that a new publisher-signed release was deployed.

Linux login topology signals trigger stable reconciliation instead of revoking
all desktops. Session-property and lock invalidations are scoped using the
actual authenticated logind Session `Id`, not guessed D-Bus path escaping.
Unrelated accounting/idle properties cannot invalidate the selected desktop.
Changed login ownership, failed observations, lock/unlock boundaries, identity
changes, queue overflow and loss of the watch still fence the affected source.

Computer Use writes require the original worker's exact native once-only
editable-element ports. A stock worker that can read and click but lacks those
ports cannot write under this contract. The error is capability unsupported,
not an OS permission denial; no keyboard, foreground or unbound write fallback
is introduced. New native packages and full Windows/Linux desktop acceptance
must use the appropriate verified worker closure and the fixed publisher.

# Native private credentials and Windows recovery controls

Engineering baseline: `0f08b370a370f2dfcc0dd77101a4bd863251d1aa`.

The shared private-file check was recovered from unpublished Workstation
changes without altering that checkout. Gateway inbound/Exec/Computer/Host
tokens and native Host client keys now use the same fail-closed validation.
POSIX requires a regular non-symlink file, current UID ownership and no
permissions for group/other. Windows validates actual NTFS owner and Allow
ACEs, accepting only the current SID, SYSTEM and Administrators. A null DACL
is rejected. chmod mode bits are not evidence of a private NTFS credential.

This validation does not grant or repair permissions. A local installer must
create private directories/files; inherited broad ACLs are rejected. Strong
security between identities requires distinct native OS accounts.

Signed Host bundles include the shared verifier. Build tests import the actual
signed connector from the completed payload, ensuring local imports resolve.
The code does not read credential contents until private-file validation.

Windows Scheduled Task pilot now exposes enable/disable as well as explicit
start/stop. A logon trigger and one-minute native recovery trigger use the
same verified interactive SID, limited run level and IgnoreNew instance policy.
Explicit stop disables recovery before stopping the task; start/restart
re-enable it. Uninstall disables before stopping/removing only the owned task.
All existing task identity/marker/owner protections remain mandatory.

## Verification

PASS on Linux: fixture/protocol/Host tests, private mode, symlink, relative
path, directory and foreign-owner refusal; real Exec authentication and
outbound/disconnect tests. Windows CI executes the native ACL tests on scratch
files; Cua schema-only CI and PowerShell parsing do not prove task recovery.

BLOCKED on this local Linux context: real Windows installation, SID/session
binding, locked/logout behavior, Task Scheduler recovery and owned-window GUI.
On an authorized Windows native user, use a unique StyxPilot task and private
signed fixture. Verify install -> status -> disable -> enable -> start ->
stop -> restart -> uninstall; inspect exact SID and interactive session;
kill only the owned task process and measure recovery within two minutes.
After explicit stop wait beyond that interval and verify it stays stopped.
Run the owned-window Cua screenshot/UIA/action/readback separately. Repeat
with foreign marker/SID and require refusal without altering that task.
Record OS, SID/session match (not credentials), signed release hash, scheduler
state and independent process/window readback. Never use Session 0 for GUI.

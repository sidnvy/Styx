# ADR-023 — narrow AX read acquisition in the original operation ledger

Status: implementation in progress; no native acceptance claimed.

## Problem and decision

The Linux Desktop supervisor has real authenticated WindowsRead evidence. Other OS permissions are Unknown. Requiring a prior Granted AX descriptor before the first native tree read prevents acquiring that evidence. Promoting the entire `desktop.accessibility` descriptor after a read would also authorize `set_value`, which is not justified by reading a tree.

Keep the frozen public capability/tool contracts and ordinary execution policy. Introduce one internal immutable Core operation purpose, `DesktopAccessibilityReadAcquisition`. It is prepared only against an original DesktopAgent resource with the same current owner incarnation/device/session, AX capability, no input observation, and the same original operation ledger. Its dispatch permit remains move-only and contains the original bytes. No purpose flag is accepted from the network.

Only the trusted Linux Cua adapter can classify the existing `get_window_state` branch as acquisition: exact positive PID/window, `include_screenshot:false`, `include_accessibility_tree:true`, `tree_format:elements`, explicit bounded walk/depth/deadline, no session override, query/diff, output path or other branch. The provider rechecks this immutable payload when consuming that purpose. OS/native APIs still enforce the actual read. The original signed Cua remains unchanged.

Acquisition can try an Unknown/Required OS authorization and Unavailable AX provider. It still refuses explicit Denied/Revoked, missing remote grant/config/local policy, wrong device/session/generation, lock/disconnection, maintenance and deadline expiry. Ready/Degraded only; it does not use another session or imply input permission. Inspecting old Unknown metadata is not proof of availability: the exact source and original live worker are checked independently before and after the real native read. Ordinary execute/resource-access policy stays unchanged.

Delivery authorizes the exact acquisition action again, only after native ACK and original Core action success, with its parent resource still retained/live and current owner/grants/session/deadline. A lost native response remains Unknown and is never replayed. A completed but malformed/degraded/partial tree is a typed insufficient-read result, preserving the native ACK rather than claiming NotDispatched.

The first slice validates fixed upstream structured results, exact target, complete trusted elements and token consistency. Host replaces native snapshot/token strings with a nonreused Host presentation alias; no native snapshot is input authority. This slice does not publish AX Granted, mint an input ObservationId, retain a writable target map or open the existing input refusal gate. Later input admission needs separately proven operation-specific OS authorization, exact owned native observation/source/process lifetime bindings, live revocation and independent effect evidence.

## Compatibility and ownership

No public MCP schemas/tool counts, wire DTOs, installed member bytes, publisher/identity/pairing/TCC, or JS management authority change. Core owns purpose/once-only/outcome; Host owns source/grants/delivery; native adapter owns fixed branch and result parsing. Existing normal operation callers remain Execute. A future generic acquisition API or AX read-to-write promotion is explicitly excluded.

## Required evidence

Meaningful Core scenarios cover once-only, ordinary execution remaining refused, grant/revocation/session/deadline negatives, parent/owner-bound delivery and Unknown no replay. Parser scenarios cover real fixed-source shape, degraded/partial/count/token contradictions and bounded alias projection. One actual ordinary CLI/TLS/WSS/MCP owned GTK journey must read the exact window tree/nonce, keep input/capture refused, preserve independent unchanged input events, continue Exec and confirm original owned cleanup. Mock/parser PASS is not native/platform acceptance. Cross-platform implementations and full release gates remain open.

## Exact window capture extension

The AX-only slice passed its actual owned GTK read/refusal/Exec journey at fc470e6. A second fixed purpose, `DesktopWindowCaptureReadAcquisition`, now applies the same Core acquisition/delivery rules only to an exact PID/window screenshot with AX disabled and explicit bounded image dimension/deadline. It never permits the whole desktop, file output, implicit targets, AX, pointer or keyboard. Both purposes revalidate their own immutable branch in the native adapter. PNG/schema projection is only a protocol check: actual acceptance requires independently calculated pixels in the owned fixture and confirmed original cleanup. Full-frame/AX+capture combinations and input remain closed. No descriptor is promoted to Granted by either read.

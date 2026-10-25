# ADR 034 — Owned App Host composition through existing Rust authority

Status: implementation checkpoint; original native UI integration and platform acceptance remain open.

The original Windows `Styx.cs::Core` launches `core-bridge.mjs`; macOS `startSetup` launches Node. The Linux Control socket is read-only, so extending its authority or invoking a second Node Core is not the App migration path.

## Decision and implemented boundary

`styx __app-core --state-dir <private-container/profile> --deployment-file <private native join input>` is a private owned-child entry, currently a development backend for the original native Apps. It does not replace their signed bootstrap or imply their UI has been migrated. The native deployment input is the existing fresh-join format; it is not a new public API or an invitation-link UI adapter.

`app::HostScope` retains the original private container, its existing kernel execution-lease primitive (one cooperative App instance per container), a fixed child configuration path, and a once-bound original child root. The container is not a configuration root. This instance lease is not a child configuration writer or ledger. The CLI launch arguments are not desktop permission grants. Same-account malicious process isolation is not claimed.

The bounded, serial stdio envelope is `{schema:1,id,operation,input:{}}`; responses retain the original Windows envelope `{id,ok,result}` or `{id,ok:false,error}`. IDs strictly increase and frames are bounded to 2 MiB. Calls cannot supply arbitrary execution/configuration paths. The closed current calls are `startupStatus`, `status`, `requestJoin`, `claimJoin`, `inspectHost`, `connect`, `disconnect`, and `quitAdmission`. The result is typed native state and observed foreground status, not fabricated legacy `steps.succeeded`.

- `native_join` uses the existing identity/TLS/enrollment/credential phases. Actual App calls persist `AppManaged`; ordinary CLI calls retain `ForegroundCli`. Both require their exact original manager, with retained root/scope/error custody. No manager conversion, existing-profile adoption or re-pairing is implicit.
- `NativeHostSnapshot` and fresh profile composition retain the same C08/Ready/seed/credential/current-C07 validations, plus the original App scope. Ordinary foreground CLI readers do not accept App-managed profiles.
- Before an offline C07 operation, the App cancels and actually awaits its original Host, executor, I/O and supervised jobs. `native::inspect_for_app` acquires the child root's original sole writer and only re-establishes an already complete committed tip using existing `reconcile_complete_tip`. It checks exact fresh App-managed configuration first. Incomplete/pending/unknown histories remain refused; ordinary inspection stays read-only.
- `inspectHost` is the existing read-only full protected profile/C08 admission check, without connector/executor launch or inferred readiness.
- Connect uses existing C07 plan/apply and the original Host run/supervisor. Pause settles first, then commits Stopped. Quit settles only this App's role before admitting its ticket; durable desired run/autostart and unrelated CLI/services are separate. A ticket is not an independent physical cleanup oracle.
- EOF, signal, bad framing and output failure signal and join the original role. Dispatch futures are not dropped or retried after a lost response. A dropped server waiter signals cancellation through a retained role DropGuard; no joined receipt is manufactured for that path. An unknown cleanup or retained unknown transaction/enrollment error fences subsequent mutation.

No new daemon, network listener, interpreter, Core policy model, journal format, publisher, public MCP tool or model API is introduced. Tokio stdio/LinesCodec, existing Serde types, C07 transaction ownership, TLS/crypto and Codex execution are reused.

## Verification and remaining scope

Bind each actual run to its frozen source and executable. The new development Core may use the previously signed `.8` external-worker closure only if this distinction is explicit; that is not a newly signed candidate or installed UI acceptance.

The required first development journey is fresh join/comparison/approval/claim, two independently observed Exec effects across Pause/reconnect, actual owned-process settlement, an independent foreground Host still executing after App Quit/EOF, and both manager mismatch negatives when no active writer can mask the result. Native compile and local quality results alone do not close this journey.

Still required: original Windows Settings/tray adapter and verified Rust bootstrap packaging, Mac native client integration with unchanged App/Cua/TCC responsibility, local Gateway/Host composition, original-identity migration and JS retirement, login/autostart/update/rollback/tunnel/device-management/permission/account parity, same-SHA signed installers and real platform acceptance. This checkpoint does not replace those requirements.

## Actual integration finding: default Gateway admitted only one Host link

The first real two-device App/CLI journey completed both enrollments, then the ordinary foreground Host connected and the App WSS upgrade was refused. Pure protected App profile/C08 admission passed. `RelayHandle::new` reserves one slot per16MiB, while `foreground::gateway` allocated only16MiB to the relay and32MiB to MCP from its existing64MiB queue allocator: a second live Host could not fit, regardless of valid credentials.

The bootstrap now allocates the previously unused16MiB to the relay:32MiB for two simultaneously retained Host links and the unchanged32MiB MCP partition. Total and per-peer wire/queue limits, handshake authentication and retained/unknown capacity rules are unchanged. This is a bounded default, not an unlimited device-count or RSS claim. Future scaling needs an explicit budget policy; it must not silently reduce per-link reserves or evict unknown work. WSS HTTP capacity/admission/unavailability statuses remain distinct typed failures, without logging response headers, bodies or credentials.

The original failed journeys remain failed evidence. The new two-Host scenario must actually establish both links and observe independent execution across Pause/reconnect/Quit before this fix is accepted.

## Ordered MCP termination before App stop

After the two-Host repair, real App execution/Pause/reconnect/Quit and independent CLI execution succeeded, but Gateway shutdown reported two unconfirmed owner cleanups. The original native processes did exit; those facts cannot substitute for the Gateway's missing per-owner cleanup reply. The exact owner IDs were not established by the aggregate shutdown log.

`BoundedManager::close_session` previously returned success immediately after scheduling `Life::close` and the SDK close event. It now awaits the same retained supervised cleanup plus fenced and actual SDK transport-joined facts. `Life` notifications wake the bounded waiter; no new cleanup request, ledger or authority is created. HTTP waiter cancellation leaves the original supervised job owned. Original5s cleanup and outer HTTP deadlines stay unchanged; Unknown/deadline cannot become success. Drop still only fences/signals.

This repairs ordered explicit MCP termination followed by App Pause/Quit if actual cleanup completes. It does not establish a remote graceful stop when the Chat owner remains active. That case requires a separately reviewed, negotiated drain of the exact authenticated Host connection and its original bindings, preserving another device used by the same owner. Local process exit or a new Host generation must not clear an old remote Unknown. The external drain proposal is not implementation or acceptance.

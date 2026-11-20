# Reduced release scope (2026-10-27)

## Current interpretation (2026-11-19)

The 2026-10-27 migration cuts, stop conditions and execution sequence below describe the
original v1 delivery, which has since shipped. They are not instructions to reset current
Rust profiles, re-pair devices, restart that sequence or stop authorized refactor work.
Source refactoring leaves installed profiles and pairing untouched. The owner removed
backward compatibility as a design constraint on 2026-11-19; the current format has
no legacy import, desktop persistent-service transfer or historical reader path.
The implementation follows
[REFACTOR-PLAN.md](REFACTOR-PLAN.md), and uses only the remaining work in
[END-TO-END-DELIVERY-PLAN.md](END-TO-END-DELIVERY-PLAN.md). The explicit deferred-feature
list remains a scope boundary unless the owner changes it; absence of new acceptance is
not permission to promote a deferred feature into a blocking gate.

## Interactive Browser (owner decision, 2026-11-20)

Browser opens a visible dedicated window on the selected Host desktop. The user
can sign in and interact in that same session; the agent waits and observes the
current tab again before continuing. This replaces the former headless-only
product restriction. Host session ownership and shutdown behavior remain as
defined in [REFACTOR-PLAN.md](REFACTOR-PLAN.md). Existing-browser attachment, an
embedded ChatGPT view and restoring old page memory or execution authority are not added.

## Persistent Browser sign-ins (owner decision, 2026-11-21)

Keep each Browser profile as Host-local data across conversation changes, context
closure and Host restart. Reuse the existing session ID and takeover interface.
Reopen the same profile with fresh execution ownership and observations; keep
independent profiles available for concurrent work. This adds no cookie syncing,
existing everyday-browser attachment or separate browser management service.

## Historical v1 baseline

Owner decision, 2026-10-27: Styx is installed only on the owner's own devices. Re-pairing them is acceptable. **Legacy migration is out of the release scope.** Existing installs are retired by hand and replaced by a fresh Rust install plus a new pairing.

## Deployment roles (owner decision, 2026-11-14)

Each deployment has one Gateway. Its OpenAI Private MCP Tunnel is configured once on that Gateway. Hosts connect to their paired Gateway. Desktop installations on macOS, Windows and Linux offer Host only or Gateway + Host. Headless Linux runs Gateway only. This matrix governs the product configurations in this refactor and takes precedence over broader platform/role combinations in older plans. Existing installations and identities are handled explicitly during implementation. The [owner-confirmed architecture](REFACTOR-PLAN.md) governs onboarding, capabilities, conversation and task lifetimes, and device removal for this refactor. Its product decisions supersede conflicting older flows, including a second enrollment approval and a separate desktop Pause action.

## Product capability clarification (owner, 2026-11-10)

The target is a mature product with its promised capabilities. The owner's daily deployment uses `moedeu-apps` as a central Gateway and desktops as Hosts because that fits the network; this does not narrow platform support. macOS, Windows and Linux must retain their promised Gateway and Host roles and supported cross-platform connections. Choosing a Host-only acceptance journey on a platform does not establish that platform's Gateway acceptance or remove that responsibility.

The one-journey `Gateway + Host or Host-only` definition below was a minimum first-usable-release evidence budget, not a statement that unexercised product roles can be dropped from mature-product delivery. The current [delivery plan](END-TO-END-DELIVERY-PLAN.md) tracks the missing platform/role and connection evidence. Keep passed evidence and close missing boundaries without replaying the full suite for every topology. Existing legacy cuts and explicitly deferred features remain separate decisions; this clarification does not silently enable them.

This page overrides SPEC §7, EXECUTION-PLAN milestones M4/M6 migration parts, and the migration/interop scenarios in ACCEPTANCE.json and WORK-ITEMS.json wherever they conflict. The earlier handoff's "resume sequence" (HANDOFF-20261027-PAUSED.md §8) is superseded by the sequence below.

## What is cut

| Area | Cut | Why |
|---|---|---|
| Legacy state import, cutover, handoff, retirement, previous-boot recovery | All of it (`migration/`, `store/*legacy*`, `*migration*`, `*cutover*`, `*handoff*`, `*previous_boot*`, `enrollment/legacy_import*`, `host/legacy`, Linux `manager/legacy*`; about 78 files / 38k lines) | No installed base to preserve |
| Mixed old/new runtime interop, legacy wire/crypto compatibility | Old Gateway ↔ Rust Host, Rust Gateway ↔ old Host, RSA legacy claims | Every device is re-paired against a Rust Gateway |
| Signed bridge loader for old packages | No bootstrap bridge from old `vnext/` loaders | Fresh install replaces the old package |
| Preserving old device identity and pairing credentials | Not required | Re-pairing is acceptable |
| CLI `migrate`, `migrate-review`, legacy `recover` paths | Remove | No callers |
| Acceptance A01, A02, A29, A32, A33 | Removed | Migration/interop only |
| Work items R13, R26, R27 (interop part), R33, legacy parts of R05/R06 | Removed | Migration/interop only |

What stays: the publisher signing keys and pins on each machine (security, not migration), "unknown outcomes are not replayed" as runtime behavior, and the Gateway/Host/Core boundaries.

## What is deferred (not v1)

These are implemented partly or fully. Freeze them: no new work, no acceptance runs, until v1 ships.

- Persistent OS services on Mac (PKG/launchd) and Windows (SCM). Windows SCM also needs an owner account decision.
- The custom App maintenance protocol (`prepareAppMaintenance`, upgrade/uninstall fencing). v1 upgrade is "quit the App, install the new DMG / run the new Inno installer".
- Sparkle auto-update, notarization, Authenticode beyond what already works.
- Login startup acceptance (Mac SMAppService, Windows Startup LNK). Promote to v1 only if one native check passes without new code.
- Acceptance A03 (boot identity part), A06, A07, A10, A12, A16–A21, A23, A24, A26, A30, A31, A37, A39: valuable, but not blocking a first usable release.

## Post-v1 (owner decision 2026-10-28)

Not v1 work; revisit after v1 ships.

- App wording: show Gateway as "Hub" and Host as "Computer" (MCP calls the AI app the host). Code, wire and file names stay unchanged.
- Automatic hub handover (HUB-HANDOVER.md Flow A). v1 keeps the manual role switch: retiring a hub names every computer still using it and needs explicit confirmation; those computers are re-paired by hand.
- Claude as a client: first Claude Code / Claude Desktop against a local or LAN Gateway (docs and CA trust only); claude.ai connectors need a public route and OAuth on the Gateway and are a separate decision.

## v1 definition

One journey per platform, run on the final candidate, recorded in one short result file:

1. Install from the package (Linux package + `systemd --user` service already in tree; Mac DMG App; Windows Inno App).
2. First run: create a local Gateway + Host, **or** join an existing Gateway as Host-only. Host-only must not start a local Gateway.
3. Pair from the account side (ChatGPT plugin).
4. Exec: run a real command with a visible file effect. Browser: open a page and read it back. Computer Use: one observed click on a desktop target (where the platform has a desktop session).
5. Quit and reopen; the existing profile reconnects without re-pairing.
6. Uninstall leaves no running process.

Required scenarios: A04, A05, A08, A09, A11, A13, A14, A15, A22, A25 (Quit/Stop only), A27, A28, A34 (startup only), A35, A36, A38.

Startup targets, measured from process start to first connected Exec: **first local create under 10 s, reopen under 3 s**, on Linux first. Payload integrity is verified once at install/update via the signed manifest, not on every load.

## Sequence

Run sequentially. Do not start the next step until the current one passes.

1. **Delete legacy migration code** (time-box: one day). Remove the cut modules and CLI commands, let `cargo check -p styx-runtime -p styx` drive the removals, keep tests that cover the fresh path. If something on the fresh path depends on a legacy module, move the minimal piece instead of keeping the module. Commit in small steps.
2. **Linux startup.** Run with `STYX_GATEWAY_STARTUP_DIAGNOSTICS=1` locally, find repeated payload validation/scanning, verify once and reuse. Hit the startup targets on Linux before touching remote devices.
3. **Linux v1 journey** end to end on the Workstation (no reboot or logout; restart the user service instead).
4. **Mac v1 journey** on pho with a DMG built from the same source, signed by PilotMac's existing keys.
5. **Windows v1 journey** on NAB5 with an Inno App, isolated runtime (no SCM service).
6. **Retire the old installs** on each device by hand (stop/uninstall old services and App, keep a backup of the old profile directory), then install the v1 candidate and re-pair.
7. **Retire the JS core** (A38): delete it from `src/` except the bounded Browser worker and fixtures the Rust tests still read.
8. Freeze one SHA, build the four candidates, rerun the six-step journey on each. That is the Stable decision point.

## Working rules for this phase

- One agent, one platform at a time. No new worktrees.
- Time-box each task to about 2 hours. If no user-visible step of the journey works by then, stop and re-plan with the owner.
- Evidence is one `RESULT.md` per journey run under `/home/sid/Developer/Artifacts/Styx/<date>-<platform>/`: candidate version and hash, each step pass/fail with the observed effect, startup timings. No per-command receipts, no control report.
- Add a new invariant or check only for a concrete threat to these journeys, and say which one.
- Use plain names in code and docs. Do not grow vocabulary like "original custody" around ordinary process handles.
- Device rules stay: never operate piermini, never reboot or log out the Workstation, ask before any new installation outside the existing authorization.

## Current goal (set 2026-10-27)

Finish sequence steps 1–3 on the Linux workstation: legacy code deleted, Linux startup under the targets, Linux v1 journey passing. Stop and report to the owner when any of these happens:

- step 3 passes (write `RESULT.md` under `/home/sid/Developer/Artifacts/Styx/<date>-linux/`);
- a step needs the owner's device, account, signing key or installation approval;
- about 2 hours pass on one task without a visible journey step working;
- the work would add scope beyond this page.

Steps 4–5 (Mac, Windows) are a separate goal that starts with the owner.

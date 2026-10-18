# Release blockers and next verification

RC gate: BLOCKED. Production release decision: NO-GO.

| Gate | Status | Reproducible next work |
| --- | --- | --- |
| Physical Windows interactive lifecycle | BLOCKED | Run docs/native-private-state.md on an authorized native user/session; task enable/disable/start/stop, owner refusal, controlled crash recovery, locked/logout behavior and exact owned-window readback; never Session0 |
| Signed macOS release and TCC GUI | BLOCKED | docs/macos-app-packaging.md: eligible Developer ID Application + notary profile, explicit native user TCC grants via LaunchServices, signed upgrade/rollback and owned-window acceptance; no auto grants |
| Native cold install/durable publisher trust | NOT RUN | Install a verified per-platform product on a clean device with no existing agent; bundled runtime/bootstrap -> native pairing -> owner approval -> execution -> revoke/recover -> uninstall |
| Distinct native-account isolation | NOT RUN | Execute docs/multi-user-isolation.md across two actual OS accounts/separate Gateway realms; do not substitute same-UID fixtures |
| Full update recovery | NOT RUN | Validate post-switch service-health rollback and offline runtime replacement; current health API deliberately retains the old pointer before switching |
| Full native dependency/license inventory | NOT RUN | Obtain/reconcile native transitive binary/Cargo inventories; top-level copied notices and npm SBOM are narrower |
| Actual ChatGPT authorization | BLOCKED | Register isolated Gateway with account-owner authorization; use docs/device-readiness.md selection/readiness checklist, then real Exec/GUI flows; no local SDK substitution |
| 24-hour component/full-platform soak | NOT RUN | Final-code Exec soak is running; inspect receipt after real elapsed duration. Separately run service/GUI/session/resource acceptance per available native OS |

The prior baseline Exec soak was stopped after 1675 seconds when the EOF bug
was found and fixed. It is retained as BLOCKED/interrupted evidence and is not
counted toward the new immutable-code24h run. External signing/OS/account
consent gates are not bypassed. Remaining product work is not silently marked
complete merely because smaller fixtures or native pilots pass.

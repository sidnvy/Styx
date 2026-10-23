# Styx release convergence

- `src/` is the only product source. Root npm commands are management aliases; do not restore a legacy runtime or add a second configuration authority.
- Integrate validated changes into the existing `develop` checkout. Reuse assigned checkouts; do not automatically create a worktree per task, build, candidate or subagent.
- A new worktree needs a concrete conflict/isolation reason, a recorded owner and a cleanup outcome. Builds and test evidence belong outside tracked source, not in new worktrees.
- Before checkout removal, save its HEAD in a durable ref and record dirty/untracked/ignored input ownership. Never force-remove unknown work. Preserve live process paths and cross-tree dependency symlinks.
- Keep Gateway/Host/Core boundaries and existing product scope. No new UI redesign, tenants, Browser takeover modes or autonomous-task features during convergence.
- Preserve signed package layout, device identity, pairing credentials, permission responsibility and publisher pins. Repository source paths and installed bundle member paths are different contracts.
- Unknown outcomes are not replayed. Native actions require fresh target-bound observation. Never operate piermini or reboot the development Workstation.
- Report Product, Architecture, Integration, Release, Reliability and Decision as changes from the prior report, with evidence. Tests, packages, installation and real acceptance are distinct. Stable remains NO-GO until its explicit gates close.

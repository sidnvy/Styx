# Validation

Run the full local gate with pinned Node.js 22:

```sh
npm run quality -- /absolute/fresh/evidence-directory
```

The gate runs dependency trees, audits, SBOM generation, all deterministic suites and lockfile stability checks for `src/` and its providers. Required ignored native inputs must be prepared from their pinned manifests before running. Missing inputs are failures, not implicit skips.

After a source/layout change, record a new commit and quality receipt, then build all candidates from that same SHA. Separate source checks, package checks, installation, native effects, Quit/reopen, physical boot/login and account-side acceptance. Preserve original failures and version labels; a subsequent success does not rewrite old evidence.

See [release convergence](src/docs/release-convergence.md).

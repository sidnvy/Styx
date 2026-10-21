# Preview quality gates

From a source checkout, install the four checked-in dependency locks with
`npm ci --ignore-scripts` in `vnext` and each Exec, GUI and Browser provider.
No global dependency install or npm lifecycle scripts are required.
Prepare the pinned Codex fixture runtime with
`python3 packages/styx-exec-adapter/prepare-runtime.py` before the full suite;
the real GUI/Exec integration tests require that input and fail if it is absent.

`npm run quality -- /absolute/fresh/evidence-directory` is the shared local/CI
entrypoint. It checks every installed dependency tree, scans every lock for
moderate-or-higher advisories, emits four CycloneDX SBOMs and runs Gateway,
Exec contracts, GUI, Host, Windows bridge, Browser, plugin, onboarding and the
quality runner's own failure tests. Failed commands and missing inputs fail the
gate. Skipped native cases stay visible. All independent audits are attempted
even when an earlier audit fails. A lock changed during checking invalidates the
run; an existing output receipt cannot be overwritten.

For a distributable Linux/Windows preview use:

```
npm run build:checked -- linux /absolute/build.json /absolute/fresh/build-evidence
npm run build:checked -- windows /absolute/build.json /absolute/fresh/build-evidence
```

The checked build validates this checkout and its dependency tree before invoking
the existing platform builder. The configuration is the corresponding builder's
existing schema; it does not add deployment or role configuration. Linux includes
the same Core CLI and a signed independent Gateway runtime. Windows may only be
cross-staged on Linux: `STAGED` is not native compilation. Keep private publisher
keys outside source, output and artifacts. Low-level builders still support
isolated engineering fixtures; their success alone is not a checked distribution.

The VNext workflow uses the same quality command and archives its receipts even
on failure. A checked build PASS is scoped to dependency/contract checks and the
builder. It does not establish upstream authenticity of every optional input,
native desktop operation, clean installation, restart recovery, signer trust,
long-running reliability or ChatGPT account acceptance. In particular, the
Windows builder's executable-format check alone does not validate Node upstream
provenance. Separate artifact/native receipts are required for those gates.

## Current boundaries

The two prototype SDK locks are now pinned to the same patched `1.32.1` version
as Core. Dependency audits passed on the recorded local check; CI configuration
is present, but no hosted CI result or branch-protection enforcement is implied.

Mac UI development is owned by its local Mac thread. Its existing CI still needs
the complete product UI build and bundled-resource self-tests wired in. The
local bundled testing App has a recorded default-profile assertion failure; it
must not be hidden by running the binary without resources. Mac native/signing,
TCC, visual and account gates are not inferred from this Linux/Windows command.

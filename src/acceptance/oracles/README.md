# Independent acceptance observers (R03)

These are external Python-standard-library **test tools**, not a Node replacement,
product Core, or proof of native Styx execution. They import no Styx modules.
The execution baseline is `a21ea757ca9f9ca96769941a31e3f2cb3daab766`;
normative product behavior remains the frozen rewrite contracts.

Run the focused tools batch from checkout root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s src/acceptance/oracles -p test_oracles.py -v
```

## Effects and independent readback

`EffectLedger(root, nonce)` exclusively creates `effects.jsonl` under an already
private run directory. Use a cryptographically random 32-hex nonce for each real
run. No deduplication is performed: two actual actions must produce count 2.
The reader verifies the original file identity and exact run nonce. Root/file
ownership is a fixture authorization boundary, not a sandbox against hostile
same-user code. The 1 MiB cap bounds the fixture; overflow is explicit failure.
The root is supplied by the scenario controller; never use a product state root.

**Exec:** controller creates the ledger; the command submitted through the real
executor invokes:

```sh
python3 /absolute/observer/oracles.py exec-effect /private/run/effects.jsonl NONCE
```

The external controller reads `ledger.observe()`. It must also obtain the native
executor process identity independently and retain the actual executor version,
command result and candidate hashes. Directly running this helper is only observer
calibration. `linux_process_identity(pid)` observes kernel PID/start ticks/boot ID/
PID namespace; it never terminates processes. ABSENT is process liveness evidence,
not proof that an action did not happen. Windows creation-time/boot/session and
macOS native process observers are NOT implemented here; return unsupported rather
than substituting PID-only or Linux facts. A sandbox PID namespace is not host
process coverage. This observer cannot prove parent-child ownership by itself.

**Browser:** `BrowserOracle(ledger).start()` returns an exact ephemeral loopback
URL. The page has a button that POSTs the run nonce; the controller reads the ledger
out of band. A second POST increments again. HTTP self-tests prove server/observer
sensitivity only, not that a browser clicked. Native journeys must actually observe
and click through the packaged Browser provider. No control/readback endpoint is
exposed to the page. The listener is loopback-only, request reads are bounded by
2 seconds, and `close()` joins the listener and owned HTTP workers. Controller
must close server before ledger and record cleanup. Do not expose it as a service.

**Cua:** `validate_cua_observation` defines a tiny owned fixture state message:

```json
{"schema":1,"fixture_id":"owned-app","instance_id":"new-instance-uuid","session_generation":"bound-session-generation","nonce":"32-hex-run-nonce","effect_count":1}
```

Future platform fixture apps must increment their own state from a native UI
handler, and expose that state through a separately observed read channel. The
controller binds app/window/process/session facts independently. A JSON message,
matching strings, and simulated counts do **not** prove a real UI app, session
binding or Cua execution. No GUI app/automation is started by this module.

Calibrate every effect observer with zero, exactly one and two actions. Expected
acceptance for an exactly-once assertion is respectively false, true, false. Keep
these raw counts as evidence. Product `success`, cancel ack or socket closure is
never the final side-effect oracle. Unknown outcomes remain unknown even after
fixture/resource cleanup proves no remaining owned live process.

## Scenario-instance receipts

`receipt-schema.json` documents the external tool's v1 JSON shape. `receipt.py`
validates the semantic subset plus actual local evidence hashes without third-party
packages. It rejects unknown fields, missing scope decisions for N/A, stale files,
path escapes/aliases, fixture promotion to native and fixture PASS in release mode.
It does not replace the integrator's whole-release matrix/contract validator.

```sh
python3 src/acceptance/oracles/receipt.py RECEIPT_JSON EVIDENCE_ROOT
python3 src/acceptance/oracles/receipt.py RECEIPT_JSON EVIDENCE_ROOT --release
```

Receipt instance keys include scenario, OS, architecture, manager mode, topology,
runtime combination and session generation. `candidate_sha256` adds immutable
candidate binding. Do not aggregate by scenario ID alone. Final matrix enumeration,
required scopes and cross-version inheritance are deliberately NOT implemented;
these belong to the integrator's release gate. `--release` only checks one receipt.
A malicious or mistaken producer can still fabricate internally consistent JSON
and hashes. Review the oracle provenance/negative-control evidence, not just VALID.
The validator may reject unsupported schema evolution; change versions explicitly.

`native_execution` is a provenance declaration, not an observation made by this
checker. Real executor evidence can be retained as `real_executor`; final release
PASS must be `final_candidate` with an independent-effect evidence role. Development
slices cannot be relabelled as final candidates. Final candidates still need real
signature/install/account/OS scope gates beyond this tool.

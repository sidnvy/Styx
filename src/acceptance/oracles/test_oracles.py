"""Small meaningful observer tests. No Styx runtime, GUI or devices started."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from oracles import EffectLedger, BrowserOracle, linux_process_identity, validate_cua_observation
from receipt import validate

NONCE = "a" * 32

def retain(name, value):
    directory = os.environ.get("STYX_OBSERVER_EVIDENCE_DIR")
    if directory:
        target = Path(directory) / name
        with target.open("x") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")

class ObserverTests(unittest.TestCase):
    def test_exec_effect_negative_controls_and_process_identity(self):
        with tempfile.TemporaryDirectory() as root:
            ledger = EffectLedger(root, NONCE)
            self.addCleanup(ledger.close)
            counts = [ledger.observe()["count"]]
            for _ in range(2):
                subprocess.run([sys.executable, str(Path(__file__).with_name("oracles.py")),
                                "exec-effect", str(ledger.path), NONCE], check=True)
                counts.append(ledger.observe()["count"])
            self.assertEqual(counts, [0, 1, 2])
            self.assertEqual([n == 1 for n in counts], [False, True, False])
            with subprocess.Popen([sys.executable, "-c", "import sys;sys.stdin.read()"], stdin=subprocess.PIPE) as child:
                first = linux_process_identity(child.pid)
                if sys.platform == "linux":
                    self.assertEqual(first["status"], "OBSERVED")
                    self.assertEqual(first, linux_process_identity(child.pid))
                child.communicate(b"")
                if sys.platform == "linux":
                    self.assertEqual(linux_process_identity(child.pid)["status"], "ABSENT")
            # Process exit is never used to infer how many side effects happened.
            self.assertEqual(ledger.observe()["count"], 2)
            retain("exec-observations.json", {"tier": "fixture", "counts": counts, "raw": ledger.observe(), "child_before": first, "child_after": linux_process_identity(child.pid), "product_native": "NOT_RUN"})

    def test_browser_real_loopback_ledger_counts_duplicates_and_rejects_wrong_nonce(self):
        with tempfile.TemporaryDirectory() as root:
            ledger = EffectLedger(root, NONCE)
            server = BrowserOracle(ledger)
            url = server.start()
            try:
                counts = [ledger.observe()["count"]]
                with urllib.request.urlopen(url, timeout=2) as response:
                    self.assertIn(b"Record effect", response.read())
                for _ in range(2):
                    request = urllib.request.Request(url + "effect", data=NONCE.encode(), method="POST")
                    with urllib.request.urlopen(request, timeout=2) as response:
                        self.assertEqual(response.status, 204)
                    counts.append(ledger.observe()["count"])
                try:
                    urllib.request.urlopen(urllib.request.Request(url + "effect", data=b"b"*32), timeout=2)
                    self.fail("wrong nonce accepted")
                except urllib.error.HTTPError as error:
                    self.assertEqual(error.code, 400)
                    error.close()
                self.assertEqual(counts, [0, 1, 2])
                self.assertEqual([n == 1 for n in counts], [False, True, False])
                self.assertEqual(ledger.observe()["count"], 2)
                retain("http-observations.json", {"tier": "fixture", "counts": counts, "raw": ledger.observe(), "product_browser": "NOT_RUN"})
            finally:
                server.close()
                ledger.close()
            self.assertFalse(server.thread.is_alive())
            server.close()  # cleanup is idempotent
            unstarted = BrowserOracle(ledger)
            unstarted.close()  # initialization failure cannot hang cleanup

    def test_cua_protocol_binding_is_not_native_acceptance(self):
        expected = {"fixture_id": "owned-fixture", "instance_id": "instance-1",
                    "session_generation": "session-1", "nonce": NONCE}
        for count in (0, 1, 2):
            self.assertEqual(validate_cua_observation({"schema": 1, **expected, "effect_count": count}, expected), count)
        for key in ("instance_id", "session_generation", "nonce"):
            wrong = {"schema": 1, **expected, "effect_count": 1, key: "stale"}
            with self.assertRaises(ValueError):
                validate_cua_observation(wrong, expected)

    def test_ledger_replacement_and_alias_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            ledger = EffectLedger(root, NONCE)
            try:
                ledger.path.rename(ledger.path.with_suffix(".old"))
                ledger.path.write_text("")
                with self.assertRaisesRegex(ValueError, "ledger_replaced"):
                    ledger.observe()
            finally:
                ledger.close()

    def test_receipt_rejects_fixture_promotion_stale_hash_escape_and_missing_controls(self):
        with tempfile.TemporaryDirectory() as root:
            evidence = Path(root) / "observation.json"
            evidence.write_text('{"count":1}\n')
            r = {"schema": 1, "instance": {"scenario": "A08", "os": "linux", "arch": "x86_64",
                 "manager_mode": "foreground", "topology": "isolated", "runtime_combination": "probe-only",
                 "session_generation": "no-desktop-test-1"}, "status": "PASS", "evidence_tier": "fixture",
                 "source_revision": "a"*40, "contract_hash": "b"*64, "observer_hash": "c"*64,
                 "candidate_sha256": None, "native_execution": False, "scope_decision": None,
                 "negative_controls": [{"effect_count": i, "accepted": i == 1} for i in range(3)],
                 "recovery": {"status": "NOT_REQUIRED", "reason": "observer-only"},
                 "cleanup": {"status": "CONFIRMED", "reason": "owned processes and listeners stopped"},
                 "evidence": [{"path": evidence.name, "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                               "role": "independent_effect"}]}
            self.assertTrue(validate(r, root))
            with self.assertRaisesRegex(ValueError, "release_requires_final_candidate"):
                validate(r, root, release=True)
            for mutate in [lambda x: x.update(native_execution=True),
                           lambda x: x["negative_controls"].pop(),
                           lambda x: x["evidence"][0].update(path="../observation.json"),
                           lambda x: x["evidence"][0].update(sha256="0"*64),
                           lambda x: x.update(status="NOT_APPLICABLE")]:
                bad = copy.deepcopy(r)
                mutate(bad)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    validate(bad, root)
            # Editing a hashed effect after collection must invalidate the receipt.
            evidence.write_text('{"count":2}\n')
            with self.assertRaisesRegex(ValueError, "evidence_hash_changed"):
                validate(r, root)

if __name__ == "__main__":
    unittest.main(verbosity=2)

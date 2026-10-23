"""Receipt syntax/provenance checker; never proves the truth of a native claim.

Independent review must verify how observations were obtained. A forged receipt
with matching hashes remains a forged receipt. Local evidence paths stay private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

SHA = re.compile(r"^[a-f0-9]{64}$")
REV = re.compile(r"^[a-f0-9]{40}$")
INSTANCE_FIELDS = {"scenario", "os", "arch", "manager_mode", "topology", "runtime_combination", "session_generation"}
FIELDS = {"schema", "instance", "status", "evidence_tier", "source_revision", "contract_hash",
          "observer_hash", "candidate_sha256", "native_execution", "scope_decision",
          "negative_controls", "recovery", "cleanup", "evidence"}


def reject(condition, message):
    if not condition:
        raise ValueError(message)


def validate(receipt, evidence_root, *, release=False):
    reject(isinstance(receipt, dict) and set(receipt) == FIELDS, "receipt_fields")
    reject(type(receipt["schema"]) is int and receipt["schema"] == 1, "schema")
    inst = receipt["instance"]
    reject(isinstance(inst, dict) and set(inst) == INSTANCE_FIELDS, "instance_fields")
    reject(all(isinstance(v, str) and 0 < len(v) <= 256 for v in inst.values()), "instance_values")
    reject(re.fullmatch(r"A[0-9]{2}", inst["scenario"]) is not None, "scenario")
    reject(inst["os"] in {"linux", "windows", "macos"}, "os")
    reject(inst["arch"] in {"x86_64", "aarch64"}, "arch")
    reject(receipt["status"] in {"PASS", "FAIL", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"}, "status")
    reject(receipt["evidence_tier"] in {"fixture", "development_slice", "real_executor", "final_candidate"}, "tier")
    reject(isinstance(receipt["source_revision"], str) and REV.fullmatch(receipt["source_revision"]), "source_revision")
    for key in ("contract_hash", "observer_hash"):
        reject(isinstance(receipt[key], str) and SHA.fullmatch(receipt[key]), key)
    candidate = receipt["candidate_sha256"]
    reject(candidate is None or isinstance(candidate, str) and SHA.fullmatch(candidate), "candidate_hash")
    reject(type(receipt["native_execution"]) is bool, "native_boolean")
    reject(receipt["evidence_tier"] not in {"fixture", "development_slice"} or not receipt["native_execution"], "fixture_not_native")
    reject(receipt["evidence_tier"] != "final_candidate" or candidate is not None, "candidate_required")
    decision = receipt["scope_decision"]
    reject(decision is None or isinstance(decision, dict) and set(decision) == {"owner", "decision_sha256", "reason"}
           and all(isinstance(decision[k], str) and decision[k] for k in decision)
           and SHA.fullmatch(decision["decision_sha256"]), "scope_decision")
    reject(receipt["status"] != "NOT_APPLICABLE" or decision is not None, "not_applicable_needs_decision")
    controls = receipt["negative_controls"]
    reject(isinstance(controls, list), "controls")
    for c in controls:
        reject(isinstance(c, dict) and set(c) == {"effect_count", "accepted"}
               and type(c["effect_count"]) is int and type(c["accepted"]) is bool, "control_shape")
    if receipt["status"] == "PASS":
        reject(sorted((c["effect_count"], c["accepted"]) for c in controls) == [(0, False), (1, True), (2, False)], "sensitivity_not_proven")
    for key in ("recovery", "cleanup"):
        value = receipt[key]
        reject(isinstance(value, dict) and set(value) == {"status", "reason"}
               and value["status"] in {"CONFIRMED", "UNKNOWN", "NOT_REQUIRED"}
               and isinstance(value["reason"], str) and bool(value["reason"]), key)
    reject(receipt["status"] != "PASS" or receipt["cleanup"]["status"] != "UNKNOWN", "unknown_cleanup_not_pass")
    root = Path(evidence_root).resolve(strict=True)
    evidence = receipt["evidence"]
    reject(isinstance(evidence, list), "evidence")
    reject(receipt["status"] not in {"PASS", "FAIL", "BLOCKED"} or bool(evidence), "evidence_required")
    seen = set()
    for entry in evidence:
        reject(isinstance(entry, dict) and set(entry) == {"path", "sha256", "role"}, "evidence_entry")
        reject(isinstance(entry["path"], str) and entry["path"] and not Path(entry["path"]).is_absolute(), "relative_evidence_path")
        path = root / entry["path"]
        reject(".." not in Path(entry["path"]).parts and not any(p.is_symlink() for p in [path, *list(path.parents)[:len(Path(entry["path"]).parts)-1]]), "evidence_alias")
        reject(path.resolve(strict=True).is_relative_to(root) and path.is_file(), "evidence_escape")
        reject(entry["path"] not in seen, "duplicate_evidence")
        seen.add(entry["path"])
        reject(isinstance(entry["sha256"], str) and SHA.fullmatch(entry["sha256"]), "evidence_hash_shape")
        reject(hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], "evidence_hash_changed")
        reject(isinstance(entry["role"], str) and bool(entry["role"]), "evidence_role")
    if release and receipt["status"] == "PASS":
        reject(receipt["evidence_tier"] == "final_candidate", "release_requires_final_candidate")
        reject(receipt["native_execution"], "release_requires_native_evidence")
        reject(any(e["role"] == "independent_effect" for e in evidence), "independent_effect_required")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt")
    parser.add_argument("evidence_root")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    validate(json.loads(Path(args.receipt).read_text()), args.evidence_root, release=args.release)
    print(json.dumps({"status": "VALID", "scope": "syntax_and_evidence_integrity_only"}))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Freeze the original Gateway source/locked mature dependencies, not a worktree.
This prepares acceptance inputs only; it does not start Gateway/Host or claim PASS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

BASELINE = "44cf1470e6b0cfdfd2c2372e54e84ebd279c59c3"
NODE_SHA256 = "fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48"

def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()

def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        key = str(path.relative_to(root))
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root.resolve()):
                raise RuntimeError("dependency symlink escapes owned closure")
            result[key] = {"symlink": os.readlink(path)}
        elif path.is_file():
            result[key] = {"sha256": digest(path), "bytes": path.stat().st_size}
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--node22", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    repo = args.repo.resolve(strict=True)
    node = args.node22.resolve(strict=True)
    if digest(node) != NODE_SHA256:
        raise RuntimeError("Node input differs from frozen rc16 native Node22")
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", BASELINE + "^{commit}"], text=True).strip()
    if revision != BASELINE:
        raise RuntimeError("baseline revision mismatch")
    output = args.evidence.absolute()
    output.mkdir(parents=True, exist_ok=False)
    archive = output / "legacy-source.tar"
    with archive.open("wb") as sink:
        subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", BASELINE, "src"], stdout=sink, check=True)
    extracted = output / "legacy-source"
    extracted.mkdir()
    with tarfile.open(archive) as source:
        source.extractall(extracted, filter="data")
    legacy = extracted / "src"
    if digest(repo / "src/package-lock.json") != digest(legacy / "package-lock.json"):
        raise RuntimeError("reused dependency closure lock mismatch")
    subprocess.run(["cp", "--reflink=auto", "-a", "--", str(repo / "src/node_modules"), str(legacy / "node_modules")], check=True)
    for name, expected in [("@modelcontextprotocol/sdk", "1.32.1"), ("ws", "8.22.0")]:
        if json.loads((legacy / "node_modules" / name / "package.json").read_text())["version"] != expected:
            raise RuntimeError("locked mature dependency version mismatch")
    files = inventory(extracted)
    (output / "legacy-input-inventory.json").write_text(json.dumps(files, indent=2) + "\n")
    version = subprocess.check_output([str(node), "--version"], text=True).strip()
    receipt = {"schema": 1, "status": "INPUTS_PREPARED_NOT_RUN", "baseline": BASELINE,
        "source_archive_sha256": digest(archive), "source_and_dependency_inventory_sha256": digest(output / "legacy-input-inventory.json"),
        "source_root": str(legacy), "node22": str(node), "node22_sha256": digest(node), "node22_version": version,
        "package_lock_sha256": digest(legacy / "package-lock.json"), "gateway_source_changes": "NONE",
        "gateway_runtime": "NOT_STARTED", "host_runtime": "NOT_STARTED", "native_acceptance": "NOT_RUN", "new_worktree": False}
    (output / "prepared.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))

if __name__ == "__main__":
    main()

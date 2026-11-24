#!/usr/bin/env python3
"""Run a development command with this persistent project's Cargo cache."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: dev-env.py COMMAND [ARG ...]")
    # Native owners keep source/ inside their persistent project. The integration
    # checkout already owns target/; retain that populated cache in place.
    target = ROOT.parent / "cache/cargo-target" if ROOT.name == "source" else ROOT / "target"
    arguments = sys.argv[1:]
    for index, argument in enumerate(arguments):
        supplied = (argument.split("=", 1)[1] if argument.startswith("--target-dir=")
                    else arguments[index + 1] if argument == "--target-dir" and index + 1 < len(arguments)
                    else None)
        if supplied is not None and Path(supplied).resolve() != target.resolve():
            raise SystemExit("development entry requires the persistent project's Cargo target; see WORKSPACE.md")
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    if sys.platform.startswith("linux"):
        env.setdefault("CARGO_BUILD_JOBS", "8")
    return subprocess.call(arguments, cwd=ROOT, env=env)


if __name__ == "__main__":
    raise SystemExit(main())

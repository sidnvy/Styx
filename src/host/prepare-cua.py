#!/usr/bin/env python3
"""Provision an immutable, checksum-pinned Cua v0.47.24 binary in a scratch folder.

Does not install system packages, request OS permissions, or run a daemon.
Use the returned binary path from CI or an explicit local test runner.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import sys
import tarfile
import tempfile
import time
from urllib.request import urlopen
import zipfile

RELEASE = "cua-driver-rs-v0.47.24"
BASE = f"https://github.com/trycua/cua/releases/download/{RELEASE}"
ARTIFACTS = {
    "darwin": (
        "cua-driver-rs-0.47.24-darwin-universal-binary.tar.gz",
        "032039c3701727a76458b61a6649f950a9d52ba453da00be741ef00c185a2edd",
    ),
    "linux": (
        "cua-driver-rs-0.47.24-linux-x86_64-binary.tar.gz",
        "e5333da45b233e8ec93550ec8061fdc9513b23621145def3a3ea22a01c328738",
    ),
    "win32": (
        "cua-driver-rs-0.47.24-windows-x86_64-binary.zip",
        "db7079d8f420ced9f4925b5b8f4b7b34c5573c3592859be7d3029a7259ad7d32",
    ),
}


def host() -> str:
    key = "win32" if sys.platform == "win32" else (
        "darwin" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else ""
    )
    machine = platform.machine().lower()
    if key not in ARTIFACTS or machine not in ("x86_64", "amd64") and key != "darwin":
        raise RuntimeError(f"Unsupported native host: {sys.platform}/{machine}")
    return key


def fetch(name: str, dst: Path) -> None:
    url = f"{BASE}/{name}"
    for attempt in range(3):
        try:
            with urlopen(url, timeout=45) as response, dst.open("wb") as output:
                if response.status != 200:
                    raise RuntimeError("Download returned non-200 status")
                shutil.copyfileobj(response, output, length=1024 * 1024)
            return
        except Exception:
            dst.unlink(missing_ok=True)
            if attempt == 2:
                raise
            time.sleep(1 + attempt)


def sha256_file(dst: Path) -> str:
    digest = hashlib.sha256()
    with dst.open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def extract_single(archive: Path, target: Path) -> None:
    executable = "cua-driver.exe" if archive.suffix.lower() == ".zip" else "cua-driver"
    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as z:
            names = [
                name for name in z.namelist()
                if name.split("/")[-1].lower() == executable.lower()
                and not name.endswith("/")
            ]
            if len(names) != 1:
                raise RuntimeError("Expected exactly one native executable in Cua ZIP")
            with z.open(names[0]) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    else:
        with tarfile.open(archive, "r:gz") as z:
            members = [
                m for m in z.getmembers()
                if m.isfile() and m.name.rsplit("/", 1)[-1] == executable
            ]
            if len(members) != 1:
                raise RuntimeError("Expected exactly one native executable in Cua TAR")
            source = z.extractfile(members[0])
            if source is None:
                raise RuntimeError("Unable to read native executable")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    if os.name != "nt":
        target.chmod(0o700)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=None,
                        help="Unique scratch directory; never a production install directory")
    args = parser.parse_args()
    key = host()
    name, expected = ARTIFACTS[key]
    root = Path(args.output).resolve() if args.output else Path(
        tempfile.mkdtemp(prefix="styx-native-cua-")
    )
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = root / name
    executable = root / ("cua-driver.exe" if key == "win32" else "cua-driver")
    if executable.exists():
        raise RuntimeError("Refusing to overwrite an existing native executable")
    fetch(name, archive)
    actual = sha256_file(archive)
    if actual != expected:
        archive.unlink(missing_ok=True)
        raise RuntimeError("Cua archive SHA-256 mismatch")
    extract_single(archive, executable)
    archive.unlink(missing_ok=True)
    print(f"binary={executable}")
    print(f"version=0.47.24")
    print(f"artifact_sha256={actual}")


if __name__ == "__main__":
    main()

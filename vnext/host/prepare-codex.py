#!/usr/bin/env python3
"""Fetch a checksum-pinned Codex Exec Server into an isolated Host directory.

No system package manager, no runtime service registration, no login, and no
changes to the existing Coder / Charon deployment.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tarfile
import tempfile
from urllib.request import urlopen

RELEASE = "rust-v0.163.0"
ARTIFACTS = {
    ("Linux", "x86_64"): (
        "codex-x86_64-unknown-linux-musl.tar.gz",
        "beb339e8ecd9ba057a6bb2dc81ad8ca474812edfbf0fc5056ca818797648dde4",
        "codex",
    ),
    ("Darwin", "arm64"): (
        "codex-aarch64-apple-darwin.tar.gz",
        "61c4d9a92521bdb42b0c1d9f87c673f6da628a06de5945cbdd9a0010632f6d10",
        "codex",
    ),
    ("Windows", "AMD64"): (
        "codex-x86_64-pc-windows-msvc.exe.tar.gz",
        "dbdd5ab5ecce1358e69fac8db1cb3538659c48e99498f3d2ea0e3e7ae878ef8c",
        "codex.exe",
    ),
}


def sha256(p):
    d=hashlib.sha256()
    with p.open("rb") as src:
        for b in iter(lambda: src.read(1048576), b""):
            d.update(b)
    return d.hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output", required=True, help="Fresh, empty isolated Host root")
    args=parser.parse_args()
    platform_key=(platform.system(),platform.machine())
    if platform_key not in ARTIFACTS:
        raise SystemExit("unsupported_native_platform")
    artifact, expected, filename=ARTIFACTS[platform_key]
    root=Path(args.output).expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit("refusing_nonempty_output_dir")
    root.mkdir(parents=True,mode=0o700,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix="codex-",suffix=".tar.gz",dir=root)
    os.close(fd)
    archive=Path(tmp)
    try:
        with urlopen(
            "https://github.com/openai/codex/releases/download/"+RELEASE+"/"+artifact,
            timeout=90
        ) as response, archive.open("wb") as out:
            if response.status!=200:raise RuntimeError("download_http_status")
            shutil.copyfileobj(response,out,1024*1024)
        if sha256(archive)!=expected:
            raise RuntimeError("codex_archive_sha256_mismatch")
        with tarfile.open(archive,"r:gz") as tar:
            members=[m for m in tar.getmembers()
                     if m.isfile() and m.name.rsplit("/",1)[-1].lower().startswith("codex")
                     and not m.name.rsplit("/",1)[-1].lower().endswith((".sha256",".sigstore"))]
            if len(members)!=1:raise RuntimeError("unexpected_codex_archive_members")
            member=members[0]
            src=tar.extractfile(member)
            if src is None:raise RuntimeError("codex_binary_unreadable")
            with src,(root/filename).open("xb") as out:
                shutil.copyfileobj(src,out)
        binary=root/filename
        if os.name!="nt":binary.chmod(0o700)
        manifest={
            "source":"openai/codex","release":RELEASE,
            "platform":"/".join(platform_key),
            "archive_sha256":expected,"binary_sha256":sha256(binary)
        }
        (root/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
        print(json.dumps({"binary":str(binary),"release":RELEASE,
                          "binary_sha256":manifest["binary_sha256"]}))
    finally:
        archive.unlink(missing_ok=True)


if __name__=="__main__":
    main()

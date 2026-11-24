#!/usr/bin/env python3
"""Deterministic external-dependency cache keys and Cargo target pruning for CI."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_PREFIXES = ('styx', 'libstyx')


def external_deps_hash(root: Path, extras: list[Path]) -> str:
    lock = tomllib.loads((root / 'Cargo.lock').read_text(encoding='utf-8'))
    external = sorted(
        (
            pkg.get('name', ''),
            pkg.get('version', ''),
            pkg.get('source', ''),
            pkg.get('checksum', ''),
        )
        for pkg in lock.get('package', [])
        if 'source' in pkg
    )
    payload = {
        'schema': 1,
        'toolchain': (root / 'rust-toolchain.toml').read_text(encoding='utf-8'),
        'external_packages': external,
        'extras': {
            str(extra.relative_to(root).as_posix()) if extra.is_relative_to(root) else str(extra):
            hashlib.sha256(extra.read_bytes()).hexdigest()
            for extra in sorted(extras)
        },
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _is_workspace_artifact(name: str) -> bool:
    return any(
        name == prefix
        or name.startswith(prefix + '-')
        or name.startswith(prefix + '_')
        or name.startswith(prefix + '.')
        for prefix in WORKSPACE_PREFIXES
    )


def _prune_profile_dir(profile_dir: Path) -> None:
    if not profile_dir.is_dir():
        return
    for subdir in ('incremental', 'examples'):
        target = profile_dir / subdir
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
    for entry in profile_dir.iterdir():
        if entry.is_symlink():
            continue
        if entry.is_file() and _is_workspace_artifact(entry.name):
            entry.unlink()
    deps = profile_dir / 'deps'
    if deps.is_dir() and not deps.is_symlink():
        for entry in deps.iterdir():
            if entry.is_symlink():
                continue
            if entry.is_file() and _is_workspace_artifact(entry.name):
                entry.unlink()
    fingerprint = profile_dir / '.fingerprint'
    if fingerprint.is_dir() and not fingerprint.is_symlink():
        for entry in fingerprint.iterdir():
            if entry.is_dir() and not entry.is_symlink() and _is_workspace_artifact(entry.name):
                shutil.rmtree(entry)


def prune_target(target_dir: Path) -> None:
    if not target_dir.is_dir():
        return
    for top_noise in ('tmp', 'cargo-timings'):
        noise = target_dir / top_noise
        if noise.is_dir() and not noise.is_symlink():
            shutil.rmtree(noise)
    for profile in ('debug', 'release'):
        _prune_profile_dir(target_dir / profile)
    for child in target_dir.iterdir():
        if not child.is_dir() or child.is_symlink() or child.name in ('debug', 'release'):
            continue
        for profile in ('debug', 'release'):
            _prune_profile_dir(child / profile)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)

    deps = sub.add_parser('deps-hash', help='Hash external Cargo.lock dependencies + toolchain')
    deps.add_argument('--root', type=Path, default=ROOT)
    deps.add_argument('--extra', type=Path, action='append', default=[])

    prune = sub.add_parser('prune-target', help='Strip workspace binaries/tests before caching target/')
    prune.add_argument('--target-dir', type=Path, required=True)

    args = parser.parse_args()
    if args.command == 'deps-hash':
        root = args.root.resolve()
        extras = [(root / p if not p.is_absolute() else p).resolve() for p in args.extra]
        print(external_deps_hash(root, extras))
    elif args.command == 'prune-target':
        prune_target(args.target_dir)


if __name__ == '__main__':
    main()

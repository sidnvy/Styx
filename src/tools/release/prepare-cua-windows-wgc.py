#!/usr/bin/env python3
"""Prepare fixed upstream Cua source with one bounded Windows capture routing fix.

No compiler, executable, profile, pairing, OS setting or publisher key is used.
The output is third-party build input, never another Styx source checkout.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

REPO = Path(__file__).resolve().parents[3]
COMMIT = '6d6c734c127025fb39ad5d585a10382808b39dc1'
ARCHIVE_SHA = '157acdc2fd0bf5c480af2bdbe4a69f75a709551627f851caee16346234fdedef'
CAPTURE = 'libs/cua-driver/rust/crates/platform-windows/src/capture.rs'
CAPTURE_SHA = '480e7715c970df0d32459e3ac97fe13911f20f79d01d76f08f75c7fdc0fc8b98'
LOCK = 'libs/cua-driver/rust/Cargo.lock'
LOCK_SHA = 'f9d49ce2dccdc43b2f7f027185301138fdd45eab4f9a556aace4cb0f4a98d46c'
FRAGMENT = REPO / 'src/host/windows/cua-window-dpi-capture.rs'
ANCHOR = 'fn screenshot_window_mapped(hwnd: u64) -> Result<(Vec<u8>, bool, Option<FrameGeometry>)> {\n'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-revision')
    parser.add_argument('--development-check', action='store_true')
    args = parser.parse_args()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True)
    if not args.development_check:
        require(not dirty and args.source_revision == head, 'frozen_product_source_required')
    archive = args.archive.resolve()
    output = args.output.resolve()
    require(archive.is_file() and not archive.is_symlink(), 'original_archive_required')
    require(digest(archive) == ARCHIVE_SHA, 'fixed_upstream_archive_mismatch')
    require(not output.exists() and not output.is_relative_to(REPO), 'fresh_external_build_input_required')
    fragment = FRAGMENT.read_bytes()
    require(fragment and len(fragment) <= 16384, 'bounded_reviewed_fragment_required')
    output.mkdir(mode=0o700, parents=False)
    names = set()
    total = 0
    with tarfile.open(archive) as tar:
        for item in tar:
            parts = PurePosixPath(item.name).parts
            require(parts and not PurePosixPath(item.name).is_absolute() and '..' not in parts,
                    'archive_path_refused')
            relative = PurePosixPath(*parts[1:])
            name = str(relative)
            if not (name.startswith(('libs/cua-driver/', 'libs/cua/'))
                    or name in ('LICENSE', 'LICENSE.md', 'libs/images/sandbox-images.json')):
                continue
            require(name not in names and (item.isfile() or item.isdir()), 'source_alias_or_link_refused')
            names.add(name)
            target = output.joinpath(*relative.parts)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += item.size
            require(0 <= item.size <= 16 * 1024 * 1024 and total <= 128 * 1024 * 1024
                    and len(names) <= 16384, 'source_input_budget')
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(item) as source, target.open('xb') as destination:
                while block := source.read(1024 * 1024):
                    destination.write(block)
            target.chmod(0o600)
    capture = output / CAPTURE
    require(digest(capture) == CAPTURE_SHA and digest(output / LOCK) == LOCK_SHA,
            'fixed_upstream_capture_or_lock_mismatch')
    original = capture.read_text(encoding='utf-8')
    require(original.count(ANCHOR) == 1, 'original_capture_boundary_required')
    injected = (fragment.decode('utf-8') + '\n' + ANCHOR
                + '    if let Some(capture) = capture_dpi_unaware_window(hwnd)? {\n'
                + '        return Ok(capture);\n'
                + '    }\n')
    capture.write_text(original.replace(ANCHOR, injected), encoding='utf-8', newline='\n')
    files = {str(path.relative_to(output)).replace('\\', '/'): digest(path)
             for path in sorted(output.rglob('*')) if path.is_file()}
    receipt = {'schema': 1, 'scope': 'THIRD_PARTY_BUILD_INPUT_NOT_BUILT_OR_SIGNED',
               'upstream_repository': 'trycua/cua', 'upstream_commit': COMMIT,
               'upstream_archive_sha256': ARCHIVE_SHA, 'upstream_capture_sha256': CAPTURE_SHA,
               'upstream_cargo_lock_sha256': LOCK_SHA, 'product_source_revision': head,
               'product_source_status': 'DIRTY_CHECK_ONLY' if dirty else 'CLEAN',
               'development_check': args.development_check,
               'fragment_sha256': hashlib.sha256(fragment).hexdigest(),
               'patched_capture_sha256': digest(capture), 'files': files}
    with (output / 'prepared-inputs.json').open('x', encoding='utf-8') as f:
        json.dump(receipt, f, sort_keys=True, separators=(',', ':'))
        f.write('\n')
    print(json.dumps({key: value for key, value in receipt.items() if key != 'files'}, sort_keys=True))


if __name__ == '__main__':
    main()

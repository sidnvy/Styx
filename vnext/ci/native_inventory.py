#!/usr/bin/env python3
"""Pinned upstream SOURCE inventory; never infers shipped binary composition."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading
import hashlib
import io
import json
from pathlib import Path
import re
import posixpath
import sys
import shutil
import subprocess
import tarfile
import time
import tomllib
from urllib.request import Request, urlopen
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / 'licenses/native-source-pins.json'
HEX = re.compile(r'^[a-f0-9]{64}$')
NAME = re.compile(r'^[A-Za-z0-9_-]+$')
VERSION = re.compile(r'^[A-Za-z0-9.+_-]+$')
MAX_DOWNLOAD = 32 * 1024 * 1024
SCOPE = 'upstream-source-resolution; includes dev/optional/all-platform entries; not binary-equivalent'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def download(url):
    require(url.startswith(('https://raw.githubusercontent.com/', 'https://crates.io/api/v1/crates/',
                            'https://static.crates.io/crates/',
                            'https://github.com/openai/codex/releases/download/rust-v0.163.0/',
                            'https://github.com/trycua/cua/releases/download/cua-driver-rs-v0.36.0/')),
            'unsupported_source_url')
    last_error = None
    for attempt in range(3):
        try:
            request = Request(url, headers={'User-Agent': 'StyxNativeInventory/1.0 (https://github.com/sidnvy/Styx)'})
            with urlopen(request, timeout=30) as response:
                data = response.read(MAX_DOWNLOAD + 1)
            require(len(data) <= MAX_DOWNLOAD, 'source_download_too_large')
            return data
        except HTTPError as error:
            error.close()
            if error.code == 429 or attempt == 2:
                raise
        except OSError as error:
            last_error = error
            if attempt == 2:
                break
        time.sleep(1 + attempt)
    # Optional public, idempotent GET fallback for TLS transport EOFs. TLS
    # verification stays enabled; no shell or caller-supplied command runs.
    if shutil.which('curl'):
        try:
            result = subprocess.run(['curl', '--http1.1', '--silent', '--show-error', '--fail',
                                 '--location', '--max-time', '45', '--max-filesize', str(MAX_DOWNLOAD),
                                 '--user-agent', 'StyxNativeInventory/1.0 (https://github.com/sidnvy/Styx)',
                                 '--write-out', '%{stderr}HTTP_STATUS:%{http_code}', url],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        except subprocess.SubprocessError as error:
            raise OSError('public_http_fallback_failed') from error
        if b'HTTP_STATUS:429' in result.stderr:
            raise HTTPError(url, 429, 'registry_rate_limited', None, None)
        if result.returncode == 0:
            require(len(result.stdout) <= MAX_DOWNLOAD, 'source_download_too_large')
            return result.stdout
    raise last_error or OSError('public_source_fetch_failed')


def cached(cache, digest, url, fetch):
    require(bool(HEX.fullmatch(digest)), 'invalid_source_checksum')
    file = cache / digest
    if file.exists():
        data = file.read_bytes()
    else:
        require(fetch, 'missing_cached_source:' + digest)
        data = download(url)
        require(sha(data) == digest, 'source_checksum_mismatch')
        file.write_bytes(data)
    require(sha(data) == digest, 'cached_source_checksum_mismatch')
    return data


def lock_packages(data, component):
    document = tomllib.loads(data.decode('utf-8'))
    require(document.get('version') in (3, 4), 'unsupported_cargo_lock_version')
    result = []
    seen = set()
    for package in document.get('package', []):
        name, version, source = package['name'], package['version'], package.get('source')
        require(NAME.fullmatch(name) and VERSION.fullmatch(version), 'invalid_locked_package')
        key = (name, version, source)
        require(key not in seen, 'duplicate_locked_package')
        seen.add(key)
        kind = 'workspace' if source is None else 'registry' if source.startswith('registry+') else 'git' if source.startswith('git+') else 'unknown'
        checksum = package.get('checksum')
        if kind == 'registry':
            require(HEX.fullmatch(checksum or ''), 'registry_checksum_missing')
        result.append(dict(origin=component, name=name, version=version, source=source,
                           source_kind=kind, checksum=checksum,
                           dependency_constraints=package.get('dependencies', []),
                           license={'status': 'UNRESOLVED'}))
    require(result, 'empty_cargo_lock')
    return sorted(result, key=lambda p: (p['name'], p['version'], p['source'] or ''))


def registry_license(data, package):
    version = json.loads(data)['version']
    require(version.get('crate') == package['name'] and version.get('num') == package['version'],
            'registry_identity_mismatch')
    require(version.get('checksum') == package['checksum'], 'registry_checksum_mismatch')
    expression = version.get('license')
    require(expression is None or isinstance(expression, str), 'invalid_registry_license')
    return dict(status='REGISTRY_METADATA' if expression else 'UNRESOLVED',
                declared_expression=expression, metadata_sha256=sha(data),
                archive_checksum_matches_lock=True,
                note='Registry declaration; license field is not authenticated by the archive checksum.')


def crate_license(data, package):
    require(sha(data) == package['checksum'], 'crate_archive_checksum_mismatch')
    prefix = package['name'] + '-' + package['version'] + '/'
    notices = []
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        require(len(members) <= 50000, 'crate_archive_too_many_members')
        manifests = [m for m in members if m.name == prefix + 'Cargo.toml']
        require(len(manifests) == 1 and manifests[0].isfile() and manifests[0].size <= 1024 * 1024,
                'crate_manifest_not_regular')
        raw_manifest = archive.extractfile(manifests[0]).read()
        manifest = tomllib.loads(raw_manifest.decode())['package']
        require(manifest['name'] == package['name'] and manifest['version'] == package['version'],
                'crate_manifest_identity_mismatch')
        expression, declared_file = manifest.get('license'), manifest.get('license-file')
        require(expression is None or isinstance(expression, str), 'inherited_archive_license_unresolved')
        if declared_file:
            require(isinstance(declared_file, str) and not declared_file.startswith(('/', '\\')) and
                    all(p and p not in ('.', '..') for p in declared_file.split('/')) and
                    '\\' not in declared_file and ':' not in declared_file, 'unsafe_declared_license_file')
        for member in members:
            if not member.name.startswith(prefix):
                continue
            relative = member.name[len(prefix):]
            top_notice = '/' not in relative and relative.upper().startswith(('LICENSE', 'COPYING', 'NOTICE'))
            if not top_notice and relative != declared_file:
                continue
            require(member.isfile() and member.size <= 1024 * 1024, 'crate_notice_not_regular')
            require(len(notices) < 32, 'too_many_crate_notices')
            content = archive.extractfile(member).read()
            notices.append(dict(path=relative, sha256=sha(content), bytes=content))
        if declared_file:
            require(any(n['path'] == declared_file for n in notices), 'declared_license_file_missing')
    return dict(status='CHECKSUM_VERIFIED_ARCHIVE', declared_expression=expression,
                declared_license_file=declared_file, archive_sha256=sha(data),
                manifest_sha256=sha(raw_manifest), notices=notices,
                note='Source archive declaration and selected notices; no legal or binary-completeness conclusion.')


def node_notices(data):
    # Preserve headings as observations. Do not infer versions/SPDX expressions from prose.
    result = []
    for line_number, line in enumerate(data.decode('utf-8').splitlines(), 1):
        match = re.match(r'^- (.+), located at (.+), is licensed as follows:', line)
        if match:
            result.append(dict(name=match[1], source_path=match[2], line=line_number))
    require(result, 'node_notice_headings_missing')
    return result


def manifest_licenses(pins, cache):
    evidence = {}
    for source in pins['sources']:
        documents = {}
        for item in source['files']:
            if item['kind'] in ('cargo-manifest', 'package-manifest'):
                documents[item['path']] = (item, tomllib.loads((cache / item['sha256']).read_text()))
        for file, (item, document) in documents.items():
            package = document.get('package')
            if not package:
                continue
            roots = [(p, d.get('workspace', {}).get('package', {}), meta)
                     for p, (meta, d) in documents.items()
                     if 'workspace' in d and (file == p or not posixpath.dirname(p) or file.startswith(posixpath.dirname(p) + '/'))]
            explicit = package.get('workspace')
            if explicit is not None:
                require(isinstance(explicit, str), 'invalid_explicit_workspace')
                target = posixpath.normpath(posixpath.join(posixpath.dirname(file), explicit, 'Cargo.toml'))
                roots = [r for r in roots if r[0] == target]
            workspace = max(roots, key=lambda r: len(r[0])) if roots else None
            def resolved(field):
                value = package.get(field)
                if isinstance(value, dict) and value.get('workspace') is True:
                    return workspace[1].get(field) if workspace else None
                return value
            name, version, expression = package.get('name'), resolved('version'), resolved('license')
            if not (isinstance(name, str) and isinstance(version, str) and isinstance(expression, str)):
                continue
            key = (source['component'], name, version, item.get('package_source'))
            record = dict(status='PINNED_MANIFEST', declared_expression=expression,
                          manifest_version=version,
                          manifest_sha256=item['sha256'], source_url=item['url'],
                          note='Exact source manifest declaration; does not prove complete license texts or binary inclusion.')
            if isinstance(package.get('license'), dict):
                record['workspace_manifest_sha256'] = workspace[2]['sha256']
            if key in evidence:
                require(evidence[key]['declared_expression'] == expression, 'ambiguous_manifest_license')
            evidence[key] = record
    return evidence


def dependency_edges(packages):
    by_name = {}
    for package in packages:
        by_name.setdefault((package['origin'], package['name']), []).append(package)
    edges, diagnostics = [], []
    for package in packages:
        targets = set()
        for raw in package['dependency_constraints']:
            match = re.fullmatch(r'([^ ()]+)(?: ([^ ()]+))?(?: \((.+)\))?', raw)
            choices = []
            if match:
                name, version, source = match.groups()
                choices = [p for p in by_name.get((package['origin'], name), [])
                           if (version is None or p['version'] == version) and
                           (source is None or p['source'] == source)]
            if len(choices) == 1:
                targets.add(component_ref(choices[0]))
            else:
                diagnostics.append({'origin': package['origin'], 'package_ref': component_ref(package),
                                    'constraint': raw, 'reason': 'ambiguous' if len(choices) > 1 else 'unresolved',
                                    'candidate_count': len(choices)})
        edges.append({'ref': component_ref(package), 'dependsOn': sorted(targets)})
    return edges, diagnostics


def component_ref(package):
    identity = [package['origin'], package['name'], package['version'], package['source']]
    return 'urn:styx:source:' + sha(json.dumps(identity, separators=(',', ':')).encode())


def cyclonedx(packages, sources):
    components = [{'type': 'application', 'bom-ref': 'urn:styx:upstream-source:' + source['component'],
                   'name': source['component'], 'version': source.get('version', source.get('release', 'unknown')),
                   'properties': [{'name': 'styx:inventory-scope', 'value': 'upstream source root; binary equivalence NOT RUN'},
                                  {'name': 'styx:source-commit', 'value': source['commit']}]} for source in sources]
    for package in packages:
        properties = [{'name': 'styx:inventory-scope', 'value': SCOPE},
                      {'name': 'styx:source-origin', 'value': package['origin']},
                      {'name': 'styx:source-kind', 'value': package['source_kind']},
                      {'name': 'styx:license-evidence', 'value': package['license']['status']}]
        expression = package['license'].get('declared_expression')
        if expression:
            properties.append({'name': 'styx:declared-license', 'value': expression})
        observation = package.get('source_manifest_license_observation')
        if observation:
            properties.extend([{'name': 'styx:source-manifest-license-observation', 'value': observation['declared_expression']},
                               {'name': 'styx:manifest-version-mismatch', 'value': observation['manifest_version']}])
        if package['checksum']:
            properties.append({'name': 'styx:source-archive-sha256', 'value': package['checksum']})
        components.append({'type': 'library', 'bom-ref': component_ref(package), 'name': package['name'],
                           'version': package['version'], 'properties': properties})
    edges, diagnostics = dependency_edges(packages)
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'properties': [{'name': 'styx:inventory-scope', 'value': SCOPE},
                                       {'name': 'styx:binary-equivalence', 'value': 'NOT RUN'},
                                       {'name': 'styx:source-commits', 'value': json.dumps({s['component']: s['commit'] for s in sources}, sort_keys=True)}]},
            'components': components, 'dependencies': edges,
            'properties': [{'name': 'styx:unresolved-source-edges', 'value': str(len(diagnostics))}],
            'compositions': [{'aggregate': 'incomplete'}]}


def build(pins, cache, output, fetch=False, metadata_limit=0, crates=(), registry_pins=None,
          workers=1, allow_incomplete_metadata=False):
    require(not output.exists(), 'inventory_output_already_exists')
    require(0 <= metadata_limit <= 2000, 'invalid_metadata_limit')
    require(workers in (1, 2, 3, 4), 'invalid_metadata_workers')
    cache.mkdir(parents=True, exist_ok=True)
    packages, node, release_evidence = [], [], []
    for source in pins['sources']:
        for item in source['files']:
            data = cached(cache, item['sha256'], item['url'], fetch)
            require(len(data) == item['size'], 'source_size_mismatch')
            if item['kind'] == 'unverified-release-signature':
                document = json.loads(data)
                require(all(k in document for k in ('base64Signature', 'cert', 'rekorBundle')), 'unrecognized_release_signature_bundle')
                release_evidence.append({'component': source['component'], 'format': 'legacy-cosign-blob',
                                         'url': item['url'], 'sha256': item['sha256'], 'verification': 'NOT RUN',
                                         'note': 'Bundle presence/hash is evidence availability, not cryptographic verification or an SBOM.'})
            if item['kind'] == 'cargo-lock':
                packages.extend(lock_packages(data, source['component']))
            if source['component'] == 'node' and item['kind'] == 'license':
                node = node_notices(data)
    manifests = manifest_licenses(pins, cache)
    for package in packages:
        key = (package['origin'], package['name'], package['version'], package['source'])
        if key in manifests:
            package['license'] = manifests[key].copy()
        else:
            observations = [e for k, e in manifests.items() if
                            k[0] == package['origin'] and k[1] == package['name'] and k[3] == package['source']]
            if len(observations) == 1:
                package['source_manifest_license_observation'] = {**observations[0],
                    'locked_version': package['version'], 'version_identity_matches': False,
                    'note': 'Exact source declaration observed, but manifest version differs from lock identity; no equivalence inferred.'}
    registry = {}
    for package in packages:
        if package['source'] == 'registry+https://github.com/rust-lang/crates.io-index':
            key = (package['name'], package['version'], package['checksum'])
            registry.setdefault(key, []).append(package)
    selected = list(sorted(registry))[:metadata_limit]
    registry_snapshot = {}
    metadata_errors = []
    rate_lock, stop = threading.Lock(), threading.Event()
    next_request = [0.0]

    def metadata_record(key):
        require(not stop.is_set(), 'registry_fetch_stopped')
        name, version, checksum = key
        cache_file = cache / ('registry-' + name + '-' + version + '.json')
        try:
            if cache_file.exists():
                data = cache_file.read_bytes()
            else:
                require(fetch, 'missing_registry_metadata')
                require(not stop.is_set(), 'registry_fetch_stopped')
                with rate_lock:
                    require(not stop.is_set(), 'registry_fetch_stopped')
                    wait = max(0, next_request[0] - time.monotonic())
                    if wait:
                        time.sleep(wait)
                    next_request[0] = time.monotonic() + 0.5
                require(not stop.is_set(), 'registry_rate_limit_stop')
                data = download(f'https://crates.io/api/v1/crates/{name}/{version}')
                # Never cache a mismatched version or archive identity.
                registry_license(data, registry[key][0])
                cache_file.write_bytes(data)
            snapshot_key = name + '@' + version
            if registry_pins is not None:
                require(registry_pins.get(snapshot_key) == sha(data), 'registry_snapshot_checksum_mismatch')
            return key, registry_license(data, registry[key][0]), sha(data), None
        except HTTPError as error:
            error.close()
            if error.code == 429:
                stop.set()
                raise
            if not allow_incomplete_metadata:
                stop.set()
                raise
            return key, None, None, {'crate': name, 'version': version, 'error': 'HTTP_' + str(error.code)}
        except OSError as error:
            if not allow_incomplete_metadata:
                stop.set()
                raise
            return key, None, None, {'crate': name, 'version': version, 'error': type(error).__name__}
        except ValueError:
            stop.set()
            raise

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for index, (key, evidence, digest, error) in enumerate(executor.map(metadata_record, selected), 1):
            if error:
                metadata_errors.append(error)
            else:
                registry_snapshot[key[0] + '@' + key[1]] = digest
                for package in registry[key]:
                    package['license'] = evidence.copy()
            if index % 50 == 0:
                print(f'registry_metadata {index}/{len(selected)} errors={len(metadata_errors)}', file=sys.stderr, flush=True)
    archive_results = []
    for requested in sorted(set(crates)):
        require('@' in requested, 'crate_selection_requires_name_at_version')
        name, version = requested.rsplit('@', 1)
        matches = [key for key in registry if key[:2] == (name, version)]
        require(len(matches) == 1, 'selected_crate_not_uniquely_locked')
        key = matches[0]
        data = cached(cache, key[2], f'https://static.crates.io/crates/{name}/{name}-{version}.crate', fetch)
        evidence = crate_license(data, registry[key][0])
        archive_results.append((name, version, evidence))
        summary = {k: v for k, v in evidence.items() if k != 'notices'}
        summary['notices'] = [{k: v for k, v in n.items() if k != 'bytes'} for n in evidence['notices']]
        for package in registry[key]:
            package['license'] = summary.copy()
    edges, edge_diagnostics = dependency_edges(packages)
    inventory = {'schema': 1, 'scope': SCOPE, 'source_pins': pins,
                 'gates': {'binary_equivalence': 'NOT RUN', 'native_license_completeness': 'BLOCKED',
                           'upstream_signature_verification': 'NOT RUN',
                           'registry_metadata': 'FAIL' if metadata_errors else 'PASS' if selected else 'NOT RUN'},
                 'counts': {'lock_entries': len(packages),
                            'manifest_version_mismatch_entries': sum('source_manifest_license_observation' in p for p in packages),
                            'pinned_manifest_license_entries': sum(p['license']['status'] == 'PINNED_MANIFEST' for p in packages),
                            'resolved_source_edges': sum(len(e['dependsOn']) for e in edges),
                            'unresolved_source_edges': len(edge_diagnostics), 'distinct_crates_io_archives': len(registry),
                            'registry_metadata_selected': len(selected), 'registry_metadata_errors': len(metadata_errors),
                            'crate_archives_verified': len(archive_results),
                            'license_expression_unresolved_entries': sum(not p['license'].get('declared_expression') for p in packages)},
                 'node_notice_headings': node, 'upstream_release_evidence': release_evidence,
                 'registry_metadata_errors': metadata_errors, 'dependency_edge_diagnostics': edge_diagnostics, 'packages': packages,
                 'remaining_gaps': ['Git/workspace licenses not resolved from lockfiles alone.',
                                    'Locks include dev/optional/all-target packages and do not prove binary inclusion.',
                                    'Native/system libraries, selected features and upstream build provenance require separate verification.',
                                    'Registry license metadata is a declaration; only selected crate archives have checksum-verified source notices.',
                                    'Node notice headings have no inferred package versions or SPDX mapping.']}
    output.mkdir(parents=True)
    for name, version, evidence in archive_results:
        for notice in evidence['notices']:
            # Use a hash filename: never extract upstream archive paths into the filesystem.
            dest = output / 'notices' / (name + '-' + version) / notice['sha256']
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(notice['bytes'])
    (output / 'registry-metadata-pins.json').write_text(json.dumps(registry_snapshot, indent=2, sort_keys=True) + '\n')
    (output / 'inventory.json').write_text(json.dumps(inventory, indent=2, sort_keys=True) + '\n')
    (output / 'source-inventory.cdx.json').write_text(json.dumps(cyclonedx(packages, pins['sources']), indent=2, sort_keys=True) + '\n')
    return inventory['counts']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pins', type=Path, default=PINS)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fetch', action='store_true', help='Explicit network opt-in; cached input hashes are always checked.')
    parser.add_argument('--metadata-limit', type=int, default=0)
    parser.add_argument('--crate', action='append', default=[])
    parser.add_argument('--workers', type=int, default=1, choices=range(1, 5))
    parser.add_argument('--allow-incomplete-metadata', action='store_true',
                        help='Record bounded network failures and continue; returns exit2/FAIL if any remain. Never suppresses checksum failures or429.')
    parser.add_argument('--registry-pins', type=Path, help='Optional exact raw registry metadata snapshot hashes for deterministic replay.')
    args = parser.parse_args()
    counts = build(json.loads(args.pins.read_text()), args.cache, args.output,
                   args.fetch, args.metadata_limit, args.crate,
                   json.loads(args.registry_pins.read_text()) if args.registry_pins else None,
                   args.workers, args.allow_incomplete_metadata)
    print(json.dumps(counts, sort_keys=True))
    if counts['registry_metadata_errors']:
        raise SystemExit(2)

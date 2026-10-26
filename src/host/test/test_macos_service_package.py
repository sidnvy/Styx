"""Builder contract only; not pkgbuild/Installer/launchd acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('macos_service_package', Path(__file__).parents[1] / 'build-macos-service-package.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    uid = 501
    root = {'device': 123, 'inode': 456, 'uid': uid}
    label = 'app.styx.native.501.' + m.digest(b'styx-native-system-service-v1:123:456:501')[:32] + '.gateway'
    selection = {'schema': 1, 'payload_path': '/Users/test/native payload', 'payload_root': {'platform': 'macos', 'device': 123, 'inode': 789, 'uid': uid}, 'manifest_sha256': 'a' * 64, 'publisher_file': '/Users/test/public/publisher.pem', 'publisher_spki_sha256': m.PIN}
    exe = selection['payload_path'] + '/bin/styx'
    state = "/Users/test/profile 'quoted' $(literal)"
    raw = plistlib.dumps({'Label': label, 'ProgramArguments': [exe, '__service-run', '--state-dir', state, '--role', 'gateway'], 'UserName': 'test', 'WorkingDirectory': '/Users/test', 'EnvironmentVariables': {'HOME': '/Users/test', 'PATH': '/usr/bin:/bin'}, 'RunAtLoad': True, 'KeepAlive': False, 'ProcessType': 'Background'}, sort_keys=False).decode()
    request = {'schema': 1, 'kind': 'launchd_first_start', 'uid': uid, 'username': 'test', 'role': 'gateway', 'state_dir': state, 'state_root': root, 'canonical_sha256': 'b' * 64, 'transaction_id': 'first-start-1', 'revision': 2, 'definition_path': '/Library/LaunchDaemons/' + label + '.plist', 'definition_plist': raw, 'definition_sha256': m.digest(raw.encode()), 'label': label, 'executable_path': exe, 'executable_sha256': 'c' * 64, 'runtime_selection': selection}
    report = {k: request[k] for k in ['schema', 'uid', 'revision', 'definition_path', 'definition_plist', 'label', 'runtime_selection']}
    report.update(operation='prepare_first_start', configuration_only=True, desired={'gateway': {'manager': 'persistent_service', 'run': 'running', 'autostart': 'enabled'}, 'host': None}, requires_initial_disabled=True, os=None, operations_replayed=False, transaction_observation={'status': 'committed', 'state_scope': 'committed_target', 'transaction_id': 'first-start-1', 'revision': 2, 'canonical_raw_sha256': 'b' * 64, 'receipt': {}}, installation_request_v1=request)
    return report


class MacServicePackageTests(unittest.TestCase):
    def test_prepare_preserves_exact_plist_and_fixed_nonexecuting_plan(self):
        report = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'request.json'; source.write_text(json.dumps(report))
            out = Path(tmp) / 'out'
            receipt = m.build(source, out, '0.4.0', prepare_only=True)
            request = report['installation_request_v1']
            self.assertEqual((out / 'payload/Library/LaunchDaemons' / (request['label'] + '.plist')).read_bytes(), request['definition_plist'].encode())
            self.assertEqual(receipt['status'], 'PREPARED_NOT_BUILT')
            self.assertFalse(receipt['actual_wait'])
            self.assertFalse(receipt['registration_dispatched'])
            for script in ['preinstall', 'postinstall']:
                subprocess.run(['/bin/sh', '-n', str(out / 'scripts' / script)], check=True)
            post = (out / 'scripts/postinstall').read_text()
            self.assertEqual(post.count('/bin/launchctl enable '), 1)
            self.assertEqual(post.count('/bin/launchctl bootstrap system '), 1)
            self.assertNotIn('sudo', post)
            self.assertIn(m.shlex.quote(request['state_dir']), post)
            with self.assertRaises(FileExistsError):
                m.build(source, out, '0.4.0', prepare_only=True)

    def test_only_explicit_original_job_not_found_diagnostics_are_absent(self):
        request = m.validate(fixture())
        pre = m.scripts(request)[0].decode()
        start = pre.index(" expected_missing=")
        end = pre.index("\n}\n", start)
        fragment = pre[start:end]
        for diagnostic, expected in [('Could not find service "fixed.label" in domain for system', 0), ('Bad request.\nCould not find service "fixed.label" in domain for system', 0), ("permission denied", 1), ('Could not find service "other.label" in domain for system', 1)]:
            shell = "fail() { exit 1; }; set -- fixed.label; observation=" + m.shlex.quote(diagnostic) + ";\n" + fragment
            result = subprocess.run(["/bin/sh", "-c", shell])
            self.assertEqual(result.returncode, expected)

    def test_foreign_root_label_publisher_and_transaction_refused(self):
        for edit in [lambda r: r['installation_request_v1']['state_root'].update(inode=999), lambda r: r['installation_request_v1']['runtime_selection'].update(publisher_spki_sha256='d' * 64), lambda r: r['transaction_observation'].update(transaction_id='other')]:
            report = fixture(); edit(report)
            with self.assertRaises(ValueError): m.validate(report)

    def test_arbitrary_plist_command_and_partial_request_refused(self):
        for change in ['command', 'root_user', 'extra_key', 'partial']:
            report = fixture(); request = report['installation_request_v1']
            if change == 'partial': del request['canonical_sha256']
            else:
                plist = plistlib.loads(request['definition_plist'].encode())
                if change == 'command': plist['ProgramArguments'] = ['/bin/sh', '-c', 'anything']
                elif change == 'root_user': plist['UserName'] = 'root'
                else: plist['MachServices'] = {'foreign': True}
                request['definition_plist'] = plistlib.dumps(plist).decode(); request['definition_sha256'] = m.digest(request['definition_plist'].encode()); report['definition_plist'] = request['definition_plist']
            with self.assertRaises(ValueError): m.validate(report)

    def test_duplicate_json_or_plist_never_last_key_wins(self):
        with self.assertRaisesRegex(ValueError, 'duplicate_json_key'): m.decode(b'{"schema":1,"schema":1}')
        report = fixture(); request = report['installation_request_v1']
        raw = request['definition_plist'].replace('<key>Label</key>', '<key>Label</key><string>foreign</string><key>Label</key>', 1)
        request['definition_plist'] = raw; request['definition_sha256'] = m.digest(raw.encode()); report['definition_plist'] = raw
        with self.assertRaisesRegex(ValueError, 'duplicate_plist_key'): m.validate(report)


if __name__ == '__main__':
    unittest.main()

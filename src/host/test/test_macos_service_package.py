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


def fixture(role='gateway'):
    uid = 501
    root = {'device': 123, 'inode': 456, 'uid': uid}
    label = 'app.styx.native.501.' + m.digest(b'styx-native-system-service-v1:123:456:501')[:32] + '.' + role
    selection = {'schema': 1, 'payload_path': '/Users/test/native payload', 'payload_root': {'platform': 'macos', 'device': 123, 'inode': 789, 'uid': uid}, 'manifest_sha256': 'a' * 64, 'publisher_file': '/Users/test/public/publisher.pem', 'publisher_spki_sha256': m.PIN}
    exe = selection['payload_path'] + '/bin/styx'
    state = "/Users/test/profile 'quoted' $(literal)"
    raw = plistlib.dumps({'Label': label, 'ProgramArguments': [exe, '__service-run', '--state-dir', state, '--role', role], 'UserName': 'test', 'WorkingDirectory': '/Users/test', 'EnvironmentVariables': {'HOME': '/Users/test', 'PATH': '/usr/bin:/bin'}, 'RunAtLoad': True, 'KeepAlive': False, 'ProcessType': 'Background'}, sort_keys=False).decode()
    request = {'schema': 1, 'kind': 'launchd_first_start', 'uid': uid, 'username': 'test', 'role': role, 'state_dir': state, 'state_root': root, 'canonical_sha256': 'b' * 64, 'transaction_id': 'first-start-1', 'revision': 2, 'definition_path': '/Library/LaunchDaemons/' + label + '.plist', 'definition_plist': raw, 'definition_sha256': m.digest(raw.encode()), 'label': label, 'executable_path': exe, 'executable_sha256': 'c' * 64, 'runtime_selection': selection}
    report = {k: request[k] for k in ['schema', 'uid', 'revision', 'definition_path', 'definition_plist', 'label', 'runtime_selection']}
    desired = {'gateway': None, 'host': None}
    desired[role] = {'manager': 'persistent_service', 'run': 'running', 'autostart': 'enabled'}
    report.update(operation='prepare_first_start', configuration_only=True, desired=desired, requires_initial_disabled=True, os=None, operations_replayed=False, transaction_observation={'status': 'committed', 'state_scope': 'committed_target', 'transaction_id': 'first-start-1', 'revision': 2, 'canonical_raw_sha256': 'b' * 64, 'receipt': {}}, installation_request_v1=request)
    return report


def repair_fixture():
    report = fixture(); request = report['installation_request_v1']
    old = copy.deepcopy(request['runtime_selection']); old['payload_path'] = '/Users/test/old runtime'
    old['payload_root']['inode'] = 788; old['manifest_sha256'] = 'd' * 64
    observed = {'path': request['definition_path'], 'program': old['payload_path'] + '/bin/styx', 'username': request['username'], 'arguments': [old['payload_path'] + '/bin/styx', '__service-run', '--state-dir', request['state_dir'], '--role', 'gateway'], 'pid': None, 'runs': 2, 'last_exit_code': 4, 'signaled_exit': False, 'state': 'not running'}
    request.update(kind='launchd_failed_registration_repair', old_definition_sha256='e' * 64, old_definition_identity={'device': 123, 'inode': 321, 'uid': 0, 'mode': 0o644, 'links': 1}, old_runtime_selection=old, original_registration=observed)
    report.update(operation='prepare_runtime_repair', os=copy.deepcopy(observed))
    return report


def printed_registration(request):
    observed = request['original_registration']
    rows = ['system/' + request['label'] + ' = {']
    rows += [' ' + key + ' = ' + str(observed[key]) for key in ['path', 'program', 'username']]
    rows += [' arguments = {'] + [' ' + value for value in observed['arguments']] + [' }']
    rows += [' runs = ' + str(observed['runs']), ' state = ' + observed['state']]
    if observed['last_exit_code'] is not None: rows += [' last exit code = ' + str(observed['last_exit_code'])]
    if observed['signaled_exit']: rows += [' last terminating signal = Killed: 9']
    return '\n'.join(rows + ['}']) + '\n'


class MacServicePackageTests(unittest.TestCase):
    def test_host_first_start_keeps_fixed_original_uid_and_single_role(self):
        report = fixture('host')
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'host-request.json'; source.write_text(json.dumps(report))
            out = Path(tmp) / 'out'
            receipt = m.build(source, out, '0.4.0', prepare_only=True)
            request = report['installation_request_v1']
            payload = out / 'payload/Library/LaunchDaemons' / (request['label'] + '.plist')
            self.assertEqual(payload.read_bytes(), request['definition_plist'].encode())
            plist = plistlib.loads(payload.read_bytes())
            self.assertEqual(plist['ProgramArguments'], [request['executable_path'], '__service-run', '--state-dir', request['state_dir'], '--role', 'host'])
            self.assertEqual(plist['UserName'], request['username'])
            self.assertFalse(receipt['registration_dispatched'])
            self.assertFalse(receipt['installation_performed'])
            for script in ['preinstall', 'postinstall']:
                subprocess.run(['/bin/sh', '-n', str(out / 'scripts' / script)], check=True)
        for change in [
                lambda r: r['desired'].update(gateway=copy.deepcopy(r['desired']['host'])),
                lambda r: r['desired']['host'].update(manager='app_managed'),
                lambda r: r['installation_request_v1'].update(role='gateway'),
                lambda r: r['installation_request_v1'].update(role='other')]:
            refused = fixture('host'); change(refused)
            with self.assertRaises(ValueError): m.validate(refused)
        refused = repair_fixture(); refused['installation_request_v1']['role'] = 'host'
        with self.assertRaisesRegex(ValueError, 'service_install_role_refused'): m.validate(refused)

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


class MacServiceRepairTests(unittest.TestCase):
    def test_repair_keeps_fixed_program_and_once_only_admin_order(self):
        report = repair_fixture(); request = m.validate(report)
        pre, post = [value.decode() for value in m.scripts(request)]
        for script in [pre, post]:
            subprocess.run(['/bin/sh', '-n'], input=script, text=True, check=True)
            self.assertNotIn('sudo', script)
        self.assertEqual(pre.count('/bin/launchctl disable '), 1)
        self.assertEqual(pre.count('/bin/launchctl bootout '), 1)
        self.assertLess(pre.index('original_registration_changed'), pre.index('/bin/launchctl disable '))
        self.assertLess(pre.index('/bin/launchctl disable '), pre.index('/bin/launchctl bootout '))
        self.assertNotIn('/bin/launchctl bootstrap ', pre)
        self.assertEqual(post.count('/bin/launchctl enable '), 1)
        self.assertEqual(post.count('/bin/launchctl bootstrap system '), 1)
        self.assertIn('old_definition_identity', pre)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'request.json'; source.write_text(json.dumps(report))
            receipt = m.build(source, Path(tmp) / 'out', '0.4.0', prepare_only=True)
            self.assertEqual(receipt['installation_kind'], 'launchd_failed_registration_repair')
            self.assertFalse(receipt['installation_performed'])

    def test_registration_parser_rejects_changes_and_never_executes_observed_text(self):
        request = m.validate(repair_fixture()); raw = printed_registration(request)
        def result(value):
            return subprocess.run(['awk', m.registration_check_program(request)], input=value, text=True, capture_output=True).returncode
        self.assertEqual(result(raw), 0)
        # Real shell metacharacters in fixture paths are literal AWK data.
        for changed in [raw.replace(' runs = 2', ' runs = 3'), raw.replace(' state = not running', ' state = running'), raw.replace(' runs = 2', ' pid = 123\n runs = 2'), raw.replace(' runs = 2', ' runs = 2\n runs = 2'), raw.replace(' last exit code = 4', ' last exit code = 0'), raw.replace(' username = test', ' username = other'), raw.replace(' __service-run', ' __other-run'), raw.replace(' last exit code = 4\n', ''), raw.replace(' arguments = {', ' arguments = {\n /bin/sh')]:
            self.assertNotEqual(result(changed), 0)
        signaled = repair_fixture(); signaled['installation_request_v1']['original_registration'].update(last_exit_code=None, signaled_exit=True); signaled['os'] = copy.deepcopy(signaled['installation_request_v1']['original_registration'])
        request = m.validate(signaled)
        self.assertEqual(result(printed_registration(request)), 0)
        self.assertNotEqual(result(printed_registration(request).replace(' last terminating signal = Killed: 9\n', '')), 0)

    def test_partial_foreign_live_and_clean_repair_reports_are_refused(self):
        changes = [lambda q: q['old_definition_identity'].update(uid=501), lambda q: q['old_definition_identity'].update(mode=0o666), lambda q: q['old_runtime_selection'].update(publisher_spki_sha256='f' * 64), lambda q: q['original_registration'].update(pid=123), lambda q: q['original_registration'].update(runs=0), lambda q: q['original_registration'].update(last_exit_code=0), lambda q: q['original_registration'].update(program='/bin/sh'), lambda q: q.pop('old_definition_sha256')]
        for change in changes:
            report = repair_fixture(); change(report['installation_request_v1']); report['os'] = copy.deepcopy(report['installation_request_v1']['original_registration'])
            with self.assertRaises(ValueError): m.validate(report)


if __name__ == '__main__':
    unittest.main()

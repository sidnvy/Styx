import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {nativeAcceptanceShell,snapshotReference,runWindowsNativeMcpAcceptance} from './native-mcp-acceptance.mjs';
test('Windows acceptance target uses native PowerShell allowlist, not POSIX sh',()=>{assert.equal(nativeAcceptanceShell({SystemRoot:'C:\\Windows'},'win32'),'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');assert.equal(nativeAcceptanceShell({},'linux'),'/bin/sh');});
test('reference assertion accepts only scoped refs from owned snapshot label',()=>{const result={content:[{type:'text',text:'- button "Store (own)" [ref=styx-aabbcc]\n- button "Other" [ref=e2]'}]};assert.equal(snapshotReference(result,'Store (own)'),'styx-aabbcc');assert.throws(()=>snapshotReference(result,'Other'),/owned_snapshot_reference_missing/);assert.throws(()=>snapshotReference(result,'Missing'),/owned_snapshot_reference_missing/);});
test('native acceptance requires explicit opt-in before creating state',async()=>{const old=process.env.STYX_RUN_WINDOWS_NATIVE_ACCEPTANCE;delete process.env.STYX_RUN_WINDOWS_NATIVE_ACCEPTANCE;const directory=path.join(os.tmpdir(),'styx-native-no-authority-'+process.pid);try{await assert.rejects(runWindowsNativeMcpAcceptance({directory}),/explicit_windows_native_acceptance_required/);assert.equal(fs.existsSync(directory),false);}finally{if(old!==undefined)process.env.STYX_RUN_WINDOWS_NATIVE_ACCEPTANCE=old;}});

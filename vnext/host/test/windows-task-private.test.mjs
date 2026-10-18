import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory} from '../private-storage.mjs';

// Parse/extract only the file checker; do not invoke task/session lifecycle code.
test('Windows task setup refuses broad native config ACL before task operations',
  {skip:process.platform!=='win32'},t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-task-config-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const dir=path.join(root,'private');ensurePrivateDirectory(dir);
  const config=path.join(dir,'setup.json');fs.writeFileSync(config,'{}');
  const script=[
    "$ErrorActionPreference='Stop'",
    '$tokens=$null;$errors=$null',
    '$ast=[Management.Automation.Language.Parser]::ParseFile($env:STYX_TEST_TASK_SCRIPT,[ref]$tokens,[ref]$errors)',
    'if($errors.Count){exit 4}',
    "$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Require-PrivateFile'},$true)",
    'if($null -eq $fn){exit 5}',
    '. ([scriptblock]::Create($fn.Extent.Text))',
    'Require-PrivateFile $env:STYX_TEST_TASK_CONFIG'
  ].join('\n');
  const check=()=>execFileSync('powershell.exe',['-NoProfile','-NonInteractive',
    '-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{
    env:{...process.env,STYX_TEST_TASK_SCRIPT:fileURLToPath(new URL('../windows-task.ps1',import.meta.url)),
      STYX_TEST_TASK_CONFIG:config},stdio:'pipe',windowsHide:true,timeout:30000});
  assert.doesNotThrow(check);
  execFileSync('icacls.exe',[config,'/grant','*S-1-1-0:(R)'],
    {stdio:'ignore',windowsHide:true,timeout:30000});
  assert.throws(check);
});

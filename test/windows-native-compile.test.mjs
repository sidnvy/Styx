import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {powershellCommand} from '../src/desktop/exec.mjs';
import {createWindowsNativeScript} from '../src/desktop/windows-native-source.mjs';

// Compiles both exact embedded C# declarations. Does not invoke Read/Capture,
// inspect session state, touch windows, or override PowerShell execution policy.
test('embedded Windows native declarations compile without desktop access',{
 skip:process.platform!=='win32'?'Requires Windows PowerShell and native reference assemblies':false,
 timeout:30000
},async()=>{
 const {stdout,stderr}=await promisify(execFile)('powershell.exe',powershellCommand(createWindowsNativeScript({compileOnly:true})),{
   encoding:'utf8',windowsHide:true,timeout:20000,maxBuffer:1048576
 });
  assert.equal(stdout,'compiled');assert.equal(stderr,'');
});

test('native command transport preserves Unicode and literal PowerShell arguments in both size paths',{
 skip:process.platform!=='win32'?'Requires Windows PowerShell':false,timeout:30000
},async()=>{
 const literal="引号' and $(throw 'must not execute'); `literal`";
 for(const padding of ['', '# '+ 'bounded local source '.repeat(1200)+'\n']){
  const source="param([string]$value)\n"+padding+"[Console]::Out.Write($value)";
  const {stdout,stderr}=await promisify(execFile)('powershell.exe',powershellCommand(source,[literal]),{
   encoding:'utf8',windowsHide:true,timeout:10000,maxBuffer:1048576
  });
  assert.equal(stdout,literal);assert.equal(stderr,'');
 }
});

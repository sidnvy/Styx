import test from 'node:test';
import assert from 'node:assert/strict';
import {installedBrowserCandidates,resolveInstalledBrowser} from '../installed.mjs';
import {normalizeBrowserConfig} from '../config.mjs';

test('installed selection prefers Chrome, honors Edge and never falls back to a daily profile or managed download',()=>{
  const options={platform:'linux',isExecutable:file=>['/usr/bin/google-chrome','/usr/bin/microsoft-edge'].includes(file)};
  assert.equal(resolveInstalledBrowser({channel:'auto'},options).channel,'chrome');
  assert.equal(resolveInstalledBrowser({channel:'msedge'},options).executablePath,'/usr/bin/microsoft-edge');
  assert.throws(()=>resolveInstalledBrowser({channel:'chrome'},{...options,isExecutable:()=>false}),/installed_browser_not_found/);
  assert.equal(resolveInstalledBrowser({},options),null);
  for(const channel of ['auto','chrome','msedge'])assert.equal(normalizeBrowserConfig({enabled:true,profileRoot:'/private/browser',channel}).channel,channel);
  assert.throws(()=>normalizeBrowserConfig({enabled:true,profileRoot:'/private/browser',channel:'firefox'}),/invalid_browser_channel/);
});

test('Windows detects installed program files without treating arbitrary relative environment paths as executables',()=>{
  const candidates=installedBrowserCandidates({platform:'win32',env:{PROGRAMFILES:'C:\\Program Files','PROGRAMFILES(X86)':'C:\\Program Files (x86)',LOCALAPPDATA:'C:\\Users\\fixture\\AppData\\Local'}});
  assert.equal(candidates.length,6);
  assert.deepEqual(candidates[0],['chrome','C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe']);
  assert.deepEqual(candidates[3],['msedge','C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe']);
  assert.deepEqual(installedBrowserCandidates({platform:'win32',env:{PROGRAMFILES:'relative'}}),[]);
  assert.equal(resolveInstalledBrowser({channel:'msedge'},{platform:'win32',env:{PROGRAMFILES:'C:\\Apps'},isExecutable:p=>p.endsWith('msedge.exe')}).channel,'msedge');
});

test('explicit executable remains an executable-only override and is checked before launch',()=>{
  assert.throws(()=>resolveInstalledBrowser({executablePath:'/missing'},{isExecutable:()=>false}),/browser_executable_unavailable/);
  assert.deepEqual(resolveInstalledBrowser({executablePath:'/custom/browser'},{isExecutable:()=>true}),{executablePath:'/custom/browser',channel:'custom',source:'configured_executable'});
});

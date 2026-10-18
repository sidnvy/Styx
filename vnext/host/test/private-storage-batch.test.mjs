import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory,requirePrivatePaths} from '../private-storage.mjs';
const windows=process.platform==='win32';
function fixture(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-private-batch-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const state=path.join(root,'state');ensurePrivateDirectory(state);
  const file=path.join(state,'test-only.txt');fs.writeFileSync(file,'not-a-secret',{mode:0o600});
  return {root,state,file,entries:[{path:state,kind:'directory'},{path:file,kind:'file'}]};
}
test('native batch freshly validates every private directory and file without retaining authorization',async t=>{
  const f=fixture(t);
  const infos=requirePrivatePaths(f.entries);
  assert.equal(infos.length,2);assert.equal(infos[0].isDirectory(),true);assert.equal(infos[1].isFile(),true);
  await new Promise(resolve=>setImmediate(resolve));
  if(windows)execFileSync('icacls.exe',[f.file,'/grant','*S-1-1-0:(R)'],{stdio:'ignore',windowsHide:true,timeout:30000});
  else fs.chmodSync(f.file,0o644);
  assert.throws(()=>requirePrivatePaths(f.entries),/private_(paths_acl_not_owner_only|file_permissions)/);
});
test('one symlink or junction member refuses the entire native batch',t=>{
  const f=fixture(t),alias=path.join(f.root,'alias');fs.symlinkSync(f.state,alias,windows?'junction':'dir');
  assert.throws(()=>requirePrivatePaths([...f.entries,{path:alias,kind:'directory'}]),/private_directory_not_regular/);
});
test('batch bounds, path types and requested kinds fail closed before validation',t=>{
  const f=fixture(t);
  for(const bad of [[],Array(1),Array(33).fill(f.entries[0]),[{path:f.file,kind:'anything'}],
    [{path:f.file,kind:'file',cached:true}]])
    assert.throws(()=>requirePrivatePaths(bad),/private_paths_invalid/);
  assert.throws(()=>requirePrivatePaths([{path:path.parse(f.file).root+'x'.repeat(17000),kind:'file'}]),/private_paths_limit/);
  assert.throws(()=>requirePrivatePaths([{path:f.state,kind:'file'}]),/private_file_not_regular/);
  assert.throws(()=>requirePrivatePaths([{path:'relative',kind:'file'}]),/private_file_absolute_path_required/);
});
test('one foreign owner refuses every result in a native batch',t=>{
  const f=fixture(t);let foreign;
  if(windows){
    try{execFileSync('icacls.exe',[f.file,'/setowner','*S-1-5-32-544'],{stdio:'ignore',windowsHide:true,timeout:30000})}
    catch{t.skip('scratch owner reassignment unavailable to this Windows account');return}
    foreign={path:f.file,kind:'file'};
  }else{
    const directory=fs.realpathSync('/etc');
    if(fs.statSync(directory).uid===process.getuid()){t.skip('no foreign system directory under this account');return}
    foreign={path:directory,kind:'directory'};
  }
  assert.throws(()=>requirePrivatePaths([f.entries[0],foreign]),/private_(paths_acl_not_owner_only|directory_owner_mismatch)/);
});


test('native batch preserves single and multiple path values including spaces and Unicode',t=>{
  const f=fixture(t),second=path.join(f.state,'two words-私有.test');
  fs.writeFileSync(second,'test-only',{mode:0o600});
  assert.equal(requirePrivatePaths([f.entries[1]]).length,1);
  const entries=[...f.entries,{path:second,kind:'file'}];
  const infos=requirePrivatePaths(entries);
  assert.equal(infos.length,3);assert.equal(infos[0].isDirectory(),true);
  assert.equal(infos[1].isFile(),true);assert.equal(infos[2].isFile(),true);
});

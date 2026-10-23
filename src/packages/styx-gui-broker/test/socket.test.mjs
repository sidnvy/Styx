import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,realpathSync,rmSync,writeFileSync,symlinkSync,existsSync,renameSync,unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';import path from 'node:path';import net from 'node:net';import {once} from 'node:events';
import {spawnSync} from 'node:child_process';
import {socketIdentity,removeStaleSocket} from '../socket-policy.mjs';
function fixture(t){
 const root=mkdtempSync(path.join(realpathSync(tmpdir()),'styx-socket-test-')),file=path.join(root,'driver.sock');
 t.after(()=>rmSync(root,{recursive:true,force:true}));
 return {root,file};
}
function stale(file){const p=spawnSync('python3',['-c','import socket,sys;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.close()',file]);assert.equal(p.status,0);}
test('proven stale owned socket is removed',async t=>{
 const f=fixture(t);stale(f.file);const receipt=socketIdentity(f.file,f.root);
 assert.deepEqual(await removeStaleSocket({...f,receipt,proveDead:async()=>true}),{removed:true});assert.equal(existsSync(f.file),false);
});
test('active listener is not removed even when caller claims an old process died',async t=>{
 const f=fixture(t),server=net.createServer();server.listen(f.file);await once(server,'listening');t.after(()=>server.close());
 const receipt=socketIdentity(f.file,f.root);
 await assert.rejects(removeStaleSocket({...f,receipt,proveDead:async()=>true}),/socket_live_or_unknown/);
 assert.equal(existsSync(f.file),true);
});
test('live or uncertain owner proof is not enough to unlink',async t=>{
 const f=fixture(t);stale(f.file);const receipt=socketIdentity(f.file,f.root);
 for(const proof of [false,null])await assert.rejects(removeStaleSocket({...f,receipt,proveDead:async()=>proof}));
 assert.equal(existsSync(f.file),true);
});
test('symlink and regular files are never treated as owned socket',async t=>{
 const f=fixture(t);writeFileSync(f.file,'sentinel');assert.throws(()=>socketIdentity(f.file,f.root));
 unlinkSync(f.file);symlinkSync(path.join(f.root,'missing'),f.file);assert.throws(()=>socketIdentity(f.file,f.root));
});
test('socket replacement during the refusal probe invalidates the cleanup receipt',async t=>{
 const f=fixture(t);stale(f.file);const receipt=socketIdentity(f.file,f.root);
 await assert.rejects(removeStaleSocket({...f,receipt,proveDead:async()=>true,probe:async()=>{
  renameSync(f.file,path.join(f.root,'old.sock'));stale(f.file);return 'refused';
 }}),/socket_not_owned/);assert.equal(existsSync(f.file),true);
});
test('wrong owner receipt and unresolved listener state fail closed',async t=>{
 const f=fixture(t);stale(f.file);const receipt=socketIdentity(f.file,f.root);
 await assert.rejects(removeStaleSocket({...f,receipt:{...receipt,uid:receipt.uid+1},proveDead:async()=>true}));
 await assert.rejects(removeStaleSocket({...f,receipt,proveDead:async()=>true,probe:async()=> 'unknown'}));
 assert.equal(existsSync(f.file),true);
});

import {lstatSync,realpathSync,unlinkSync} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {GuiError} from './broker.mjs';
const reject=()=>{throw new GuiError('socket_not_owned');};
export function socketIdentity(file,root,uid=process.getuid()) {
  if(path.dirname(file)!==root || realpathSync(root)!==root)reject();
  const dir=lstatSync(root);
  if(!dir.isDirectory()||dir.isSymbolicLink()||dir.uid!==uid||(dir.mode&0o077)!==0)reject();
  const s=lstatSync(file);
  if(!s.isSocket()||s.isSymbolicLink()||s.uid!==uid)reject();
  return {dev:s.dev,ino:s.ino,uid:s.uid};
}
const equal=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.uid===b.uid;
export function probeSocket(file) {
  return new Promise(resolve=>{
    const s=net.createConnection(file);let done=false;
    const finish=x=>{if(!done){done=true;s.destroy();resolve(x);}};
    s.once('connect',()=>finish('live'));
    s.once('error',e=>finish(e.code==='ECONNREFUSED'?'refused':'unknown'));
    s.setTimeout(500,()=>finish('unknown'));
  });
}
export async function removeStaleSocket({file,root,receipt,proveDead,probe=probeSocket}) {
  const initial=socketIdentity(file,root);
  if(!equal(initial,receipt))reject();
  if(await proveDead()!==true)reject();
  if(await probe(file)!=='refused')throw new GuiError('socket_live_or_unknown');
  const final=socketIdentity(file,root);
  if(!equal(final,receipt))reject();
  // No await between final inode check and unlink. Same-UID hostile filesystem
  // mutation is not claimed to be an OS security boundary.
  unlinkSync(file);return {removed:true};
}

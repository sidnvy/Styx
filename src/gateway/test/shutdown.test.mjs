import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import WebSocket from 'ws';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';

test('Gateway shutdown closes a connected outbound Host before awaiting HTTP close',{timeout:6000},async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-shutdown-'));const token=randomBytes(32).toString('hex');
 const tokenFile=path.join(dir,'host-token');fs.writeFileSync(tokenFile,token,{mode:0o600});
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const gateway=createStyxGateway({catalog:{version:1,targets:[{id:'shutdown-fixture',kind:'host',platform:'linux',generation:'test',cwd:dir,shell:'/bin/sh',shells:['/bin/sh'],allowed:true,exec:{transport:'outbound',token_file:tokenFile}}]}});
 const allowedHosts=[];const server=await createGatewayHttp(gateway,{token:randomBytes(32).toString('hex'),port:0,allowedHosts});
 const host='127.0.0.1:'+server.address.port;allowedHosts.push(host);
 const socket=new WebSocket('ws://'+host+'/styx/hosts/shutdown-fixture/exec',{headers:{Authorization:'Bearer '+token}});
 t.after(async()=>{socket.terminate();await server.close()});
 await new Promise((resolve,reject)=>{socket.once('open',resolve);socket.once('error',reject)});
 assert.equal(gateway.relay.connected('shutdown-fixture'),true);
 let timer;try{await Promise.race([server.close(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('shutdown_blocked_by_host')),1500)})])}finally{clearTimeout(timer)}
 assert.equal(gateway.relay.connected('shutdown-fixture'),false);
});

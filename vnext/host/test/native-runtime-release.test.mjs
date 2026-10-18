// Opt-in official native artifacts prepared by the three-OS CI matrix.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {buildHostRelease} from '../build-host-release.mjs';
import {stageSignedRelease,activateRelease,refreshVerifiedBootstrap,verifiedServiceNode} from '../installer.mjs';
import {linuxUserUnit} from '../linux-service.mjs';
import {macLaunchAgent} from '../macos-launchagent.mjs';
const env=process.env;
const enabled=!!(env.STYX_TEST_NODE_BINARY&&env.STYX_TEST_CODEX_BINARY&&env.STYX_TEST_CUA_BINARY);
test('official native Node is signed, staged, selected by service planner and tamper checked',
  {skip:!enabled,timeout:90000},t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-runtime-native-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const pem=publicKey.export({type:'spki',format:'pem'});
  const privateKeyFile=path.join(root,'publisher.key'),trustPublicKeyFile=path.join(root,'publisher.pub');
  fs.writeFileSync(privateKeyFile,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  fs.writeFileSync(trustPublicKeyFile,pem,{mode:0o600});
  const sourceDir=path.join(root,'bundle'),installRoot=path.join(root,'installed');
  buildHostRelease({destination:sourceDir,version:'runtime-native',privateKeyFile,
    nodeBinary:env.STYX_TEST_NODE_BINARY,codexBinary:env.STYX_TEST_CODEX_BINARY,cuaBinary:env.STYX_TEST_CUA_BINARY});
  stageSignedRelease({sourceDir,installRoot,publicKeyPem:pem});
  activateRelease(installRoot,'runtime-native',pem);
  refreshVerifiedBootstrap(installRoot,pem,'runtime-native');
  const selected=verifiedServiceNode({installRoot,publicKeyPem:pem});
  assert.equal(execFileSync(selected,['--version'],{encoding:'utf8'}).trim(),'v22.23.3');
  const hostConfigFile=path.join(root,'config.json');
  fs.writeFileSync(hostConfigFile,'{}',{mode:0o600});
  const options={installRoot,hostConfigFile,trustPublicKeyFile,logDir:root};
  if(process.platform==='linux')assert.ok(linuxUserUnit(options).includes('ExecStart='+selected+' '));
  if(process.platform==='darwin')assert.ok(macLaunchAgent(options).includes('<string>'+selected+'</string>'));
  fs.appendFileSync(selected,'tampered');
  assert.throws(()=>verifiedServiceNode({installRoot,publicKeyPem:pem}),/service_node_hash_mismatch/);
});

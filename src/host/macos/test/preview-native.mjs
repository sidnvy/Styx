// Local helper for the resource-bearing fast-native-build.mjs outputs.
// Verifies that the testing binary matches current Swift sources before opening
// its explicitly isolated UI fixture. Never launches the installed application.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
const source=path.resolve(fileURLToPath(new URL('../../../../',import.meta.url)));
const builds=path.resolve(source,'../builds');
const supplied=process.argv[2];
const candidates=supplied?[path.dirname(path.resolve(supplied))]:fs.readdirSync(builds).filter(name=>name.startsWith('native-')).map(name=>path.join(builds,name)).sort((a,b)=>fs.statSync(b).mtimeMs-fs.statSync(a).mtimeMs);
let app;
for(const directory of candidates){
 try{
  const receipt=JSON.parse(fs.readFileSync(path.join(directory,'receipt.json'),'utf8'));
  if(receipt.kind!=='local_native_testing_iteration'||receipt.testing!==true||receipt.status!=='PASS'||receipt.bundledSelfTest!=='PASS')continue;
  if(supplied&&path.resolve(supplied)!==receipt.app)continue;
  if(!receipt.swiftInputs?.length||!receipt.swiftInputs.every(({file,sha256})=>file.startsWith(source+path.sep)&&createHash('sha256').update(fs.readFileSync(file)).digest('hex')===sha256))continue;
  app=receipt.app;break;
 }catch{ /* Incomplete/failed builds are not launch candidates. */ }
}
if(!app)throw Error('No passing testing App matches current Swift sources. Run ../vendor/node-22.23.3/node ../fast-native-build.mjs first.');
execFileSync('/usr/bin/open',['-n','-a',app,'--args','--ui-preview'],{stdio:'inherit'});
console.log('Opened isolated UI preview: '+app+' (synthetic state; connection actions disabled; Cmd-Q exits).');

import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {deflateSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {buildPackageArchive} from '../archive.mjs';
import {buildPackageFiles,crc32} from '../package.mjs';
const now=Date.parse('2026-10-20T12:00:00Z'),connection={tunnelId:'tunnel_'+'a'.repeat(32)};
const receipt=()=>({version:1,connection,independentStyx:true,freshConnection:true,verifiedAt:new Date(now).toISOString(),serverName:'styx-vnext',tools:['list_execution_environments','get_execution_environment_status','exec_command','write_stdin'],method:'authenticated-local-mcp-discovery'});
function icon(){
 const chunk=(type,data)=>{const b=Buffer.alloc(data.length+12);b.writeUInt32BE(data.length,0);b.write(type,4);data.copy(b,8);b.writeUInt32BE(crc32(b.subarray(4,-4)),b.length-4);return b};
 const header=Buffer.alloc(13);header.writeUInt32BE(48,0);header.writeUInt32BE(48,4);header[8]=8;header[9]=6;
 return {mimeType:'image/png',dataBase64:Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',deflateSync(Buffer.alloc(193*48))),chunk('IEND',Buffer.alloc(0))]).toString('base64')};
}
test('archive has one stable root, only package members, stored UTF8 records and deterministic bytes',()=>{
 const config={connection},built=buildPackageArchive(config,receipt(),{now}),files=buildPackageFiles(config,receipt(),{now});
 assert.equal(built.fileName,'styx-native.zip');assert.equal(built.contentType,'application/zip');assert.equal(built.status,'archive_created_not_installed');assert.equal(built.verificationScope,'local_gateway_only');
 assert.deepEqual(built.entries,['styx-native/plugin.json','styx-native/mcp.json','styx-native/skills/styx-native-onboarding/SKILL.md']);
 assert.deepEqual(built.archive,buildPackageArchive(config,receipt(),{now}).archive);
 const end=built.archive.subarray(-22);assert.equal(end.readUInt32LE(0),0x06054b50);assert.equal(end.readUInt16LE(8),3);assert.equal(end.readUInt16LE(10),3);assert.equal(end.readUInt16LE(20),0);
 let offset=0;
 for(const file of files.files){
  const header=built.archive.subarray(offset,offset+30);assert.equal(header.readUInt32LE(0),0x04034b50);assert.equal(header.readUInt16LE(6),0x0800);assert.equal(header.readUInt16LE(8),0);assert.equal(header.readUInt32LE(18),file.data.length);assert.equal(header.readUInt32LE(22),file.data.length);
  const length=header.readUInt16LE(26);assert.equal(built.archive.toString('utf8',offset+30,offset+30+length),'styx-native/'+file.path);assert.deepEqual(built.archive.subarray(offset+30+length,offset+30+length+file.data.length),file.data);offset+=30+length+file.data.length;
 }
 assert.equal(end.readUInt32LE(16),offset);assert.equal(offset+end.readUInt32LE(12)+22,built.archive.length);
 const text=built.archive.toString('utf8');assert.doesNotMatch(text,/verificationFile|verifiedAt|independentStyx|freshConnection|consume_token|modelCredential/);assert.doesNotMatch(text,/"headerScheme"/);
});
test('Python standard ZIP reader validates all CRCs, central directory, icon bytes and App-owned tunnel authentication',{skip:process.platform==='win32'},()=>{
 const image=icon(),config={connection,presentation:{displayName:'我的设备',shortDescription:'我的 Styx',icon:image}},built=buildPackageArchive(config,receipt(),{now});
 const script=`import sys,io,zipfile,json,hashlib,stat
z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()))
assert z.testzip() is None
assert len(z.namelist()) == 4
assert all(x.startswith('styx-native/') and '..' not in x and '\\\\' not in x for x in z.namelist())
assert all(i.compress_type == zipfile.ZIP_STORED and stat.S_ISREG(i.external_attr >> 16) for i in z.infolist())
m=json.loads(z.read('styx-native/plugin.json'))
s=json.loads(z.read('styx-native/mcp.json'))['mcpServers']['styx']
assert m['name']=='styx-native'
assert s['extensions']['com.openai']['auth']=={'type':'none'}
print(json.dumps({'displayName':m['extensions']['com.openai']['interface']['displayName'],'iconSha256':hashlib.sha256(z.read('styx-native/assets/icon.png')).hexdigest()}))`;
 const check=spawnSync('python3',['-c',script],{input:built.archive,maxBuffer:65536});assert.equal(check.status,0,String(check.stderr));const summary=JSON.parse(String(check.stdout));assert.equal(summary.displayName,'我的设备');assert.equal(summary.iconSha256,createHash('sha256').update(Buffer.from(image.dataBase64,'base64')).digest('hex'));
});
test('archive refuses arbitrary paths, secrets, assets and unverified or stale proof',()=>{
 for(const extra of [{files:[{path:'../secret',data:'SECRET'}]},{directory:'/private/credentials'},{verificationFile:'/private/key'},{token:'SECRET'},{auth:{type:'none'}}])assert.throws(()=>buildPackageArchive({connection,...extra},receipt(),{now}));
 for(const extra of [{credential:'SECRET'},{method:'unauthenticated'},{freshConnection:false},{verifiedAt:new Date(now-25*3600000).toISOString()}])assert.throws(()=>buildPackageArchive({connection},{...receipt(),...extra},{now}));
 assert.throws(()=>buildPackageArchive({connection,presentation:{icon:{mimeType:'image/svg+xml',dataBase64:'PHN2Zz4='}}},receipt(),{now}));
 assert.throws(()=>buildPackageArchive({connection,presentation:{icon:{path:'../../secrets.png'}}},receipt(),{now}));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {deflateSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {buildPackage,buildPackageFiles,normalizePresentation,crc32,validate,connection} from '../package.mjs';

const now=Date.parse('2026-10-20T12:00:00Z');
const url='https://styx.unit.test/mcp';
function receipt(c={url}) {return {version:1,connection:c,independentStyx:true,freshConnection:true,
  verifiedAt:new Date(now).toISOString(),serverName:'styx-vnext',
  tools:['list_execution_environments','get_execution_environment_status','exec_command','write_stdin'],method:'authenticated-mcp-discovery'};}
function fixture(t,c={url}) {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-plugin-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const verificationFile=path.join(root,'verified.json'), config=path.join(root,'config.json'), output=path.join(root,'styx-native');
 fs.writeFileSync(verificationFile,JSON.stringify(receipt(c)));
 fs.writeFileSync(config,JSON.stringify({connection:c,verificationFile}));
 return {root,verificationFile,config,output};
}
function chunk(type,body=Buffer.alloc(0)){
 const out=Buffer.alloc(body.length+12);out.writeUInt32BE(body.length,0);out.write(type,4,'latin1');body.copy(out,8);out.writeUInt32BE(crc32(out.subarray(4,-4)),out.length-4);return out;
}
export function png({size=48,width=size,height=size,depth=8,color=6,interlace=0,filter=0,raw,extra=[],tail=Buffer.alloc(0),idat,palette}={}){
 const header=Buffer.alloc(13);header.writeUInt32BE(width,0);header.writeUInt32BE(height,4);header[8]=depth;header[9]=color;header[12]=interlace;
 const stride=width*({0:1,2:3,3:1,4:2,6:4}[color]??4),pixels=raw??Buffer.alloc((stride+1)*height);
 if(raw===undefined)for(let y=0;y<height;y++)pixels[y*(stride+1)]=filter;
 return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),...(palette?[chunk('PLTE',palette)]:[]),...extra,chunk('IDAT',idat??deflateSync(pixels)),chunk('IEND'),tail]);
}
const icon=bytes=>({mimeType:'image/png',dataBase64:bytes.toString('base64')});
test('HTTPS package is allowlisted and declares bearer without embedding receipt or credentials',t=>{
 const f=fixture(t);const r=buildPackage(f.config,f.output,{now});assert.equal(r.status,'package_created_not_installed');
 const m=JSON.parse(fs.readFileSync(path.join(f.output,'plugin.json')));
 assert.equal(m.name,'styx-native');assert.equal(m.$schema,'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json');
 assert.ok(m.extensions['com.openai'].interface.shortDescription.length<=30);
 for(const key of ['skills','mcpServers','apps','interface'])assert.equal(Object.hasOwn(m,key),false);
 const s=JSON.parse(fs.readFileSync(path.join(f.output,'mcp.json'))).mcpServers.styx;
 assert.equal(s.url,url);assert.deepEqual(s.extensions['com.openai'],{auth:{type:'api_key',headerScheme:'bearer'}});
 assert.deepEqual(fs.readdirSync(f.output).sort(),['assets','mcp.json','plugin.json','skills']);
 assert.deepEqual(fs.readFileSync(path.join(f.output,'assets/icon.png')),fs.readFileSync(new URL('../../assets/brand/styx-logo.png',import.meta.url)));
 assert.equal(m.extensions['com.openai'].interface.logo,'./assets/icon.png');
 const skill=fs.readFileSync(path.join(f.output,'skills/styx-native-onboarding/SKILL.md'),'utf8');
 assert.match(skill,/^---\nname: styx-native-onboarding\ndescription: [^\n]+\n---\n/);
 assert.match(skill,/setup-native\.mjs prepare/);assert.match(skill,/owner\/admin keys/);
 assert.throws(()=>buildPackage(f.config,f.output,{now}),/output_must_be_fresh/);
});
test('fresh verified tunnel excludes URL and lives in OpenAI connection options',t=>{
 const c={tunnelId:'tunnel_'+'a'.repeat(32)},f=fixture(t,c);buildPackage(f.config,f.output,{now});
 const s=JSON.parse(fs.readFileSync(path.join(f.output,'mcp.json'))).mcpServers.styx;
 assert.equal(Object.hasOwn(s,'url'),false);assert.equal(s.extensions['com.openai'].tunnelId,c.tunnelId);
});
test('invalid connection forms and placeholder/credential URLs refuse',()=>{
 for(const c of [{},{url,tunnelId:'tunnel_'+'a'.repeat(32)},{url:'http://styx.unit.test/mcp'},
  {url:'https://secret@styx.unit.test/mcp'},{url:'https://styx.unit.test/mcp?token=secret'},
  {url:'https://styx.unit.test/mcp#x'},{url:'https://example.com/mcp'},{url:'https://127.0.0.1/mcp'},
  {url:'https://localhost/mcp'},{url:'https://styx.example.invalid/mcp'},{tunnelId:'tunnel_bad'},
  {url,headers:{Authorization:'secret'}}])assert.throws(()=>connection(c));
});
test('missing, stale, mismatched, foreign and unverified receipts refuse before filesystem mutation',t=>{
 const f=fixture(t);
 for(const patch of [{independentStyx:false},{freshConnection:false},{serverName:'charon'},
  {verifiedAt:'2026-10-18T12:00:00Z'},{verifiedAt:'2026-10-21T12:00:00Z'},
  {connection:{url:'https://other.unit.test/mcp'}},{tools:['exec_command']},
  {tools:[...receipt().tools,'service_deploy']},{token:'never-package'}]) {
  fs.writeFileSync(f.verificationFile,JSON.stringify({...receipt(),...patch}));
  assert.throws(()=>buildPackage(f.config,f.output,{now}));assert.equal(fs.existsSync(f.output),false);
 }
});
test('strict config excludes secrets and unknown bindings',()=>{
 for(const patch of [{token:'secret'},{appId:'asdk_app_foreign'},{auth:{}},{output:'elsewhere'}])
  assert.throws(()=>validate({connection:{url},verificationFile:'/verification.json',...patch},receipt(),{now}));
});
test('symlink receipt and unknown package directory refuse',t=>{
 const f=fixture(t),link=path.join(f.root,'link.json');fs.symlinkSync(f.verificationFile,link);
 fs.writeFileSync(f.config,JSON.stringify({connection:{url},verificationFile:link}));
 assert.throws(()=>buildPackage(f.config,f.output,{now}),/regular_bounded_json_required/);
 assert.throws(()=>buildPackage(f.config,path.join(f.root,'foreign'),{now}),/directory_must_match_plugin_name/);
});
test('pure package files customize only presentation, retain stable identity and bearer, and share disk output',t=>{
 const f=fixture(t),image=png(),presentation={displayName:'我的 Styx 电脑',shortDescription:'受控的本机工具',longDescription:'通过我已批准的 Styx 设备执行任务。',icon:icon(image)};
 const normalized=normalizePresentation(presentation);assert.deepEqual(normalizePresentation(normalized),normalized);
 const config={connection:{url},presentation},built=buildPackageFiles(config,receipt(),{now});assert.equal(built.status,'package_files_ready_not_installed');assert.equal(fs.existsSync(f.output),false);
 const files=new Map(built.files.map(f=>[f.path,f.data])),manifest=JSON.parse(files.get('plugin.json'));
 assert.equal(manifest.name,'styx-native');assert.equal(manifest.extensions['com.openai'].interface.displayName,presentation.displayName);assert.equal(manifest.extensions['com.openai'].interface.shortDescription,presentation.shortDescription);assert.equal(manifest.extensions['com.openai'].interface.logo,'./assets/icon.png');assert.equal(manifest.extensions['com.openai'].interface.composerIcon,'./assets/icon.png');assert.deepEqual(files.get('assets/icon.png'),image);
 assert.deepEqual(JSON.parse(files.get('mcp.json')).mcpServers.styx.extensions['com.openai'].auth,{type:'api_key',headerScheme:'bearer'});
 fs.writeFileSync(f.config,JSON.stringify({...config,verificationFile:f.verificationFile}));const made=buildPackage(f.config,f.output,{now});
 for(const [name,data]of files)assert.deepEqual(fs.readFileSync(path.join(f.output,name)),data);
 assert.equal(made.verificationSha256,createHash('sha256').update(fs.readFileSync(f.verificationFile)).digest('hex'));
 assert.deepEqual(normalizePresentation(),normalizePresentation({icon:null}));assert.equal(normalizePresentation().displayName,'Styx');
});
test('presentation bounds, controls, unknown fields and arbitrary media never reach package output',t=>{
 const f=fixture(t);
 for(const presentation of [null,[],{displayName:''},{displayName:'\u202Ehidden'},{displayName:'a'.repeat(65)},{shortDescription:'x'.repeat(31)},{longDescription:'x'.repeat(2001)},{longDescription:'line\tline'},{name:'other'},{token:'SECRET'},{icon:{mimeType:'image/svg+xml',dataBase64:'PHN2Zz4='}},{icon:{url:'https://remote.invalid/image.png'}},{icon:{mimeType:'image/png',dataBase64:'data:image/png;base64,aaaa'}}]){
  assert.throws(()=>normalizePresentation(presentation));fs.writeFileSync(f.config,JSON.stringify({connection:{url},verificationFile:f.verificationFile,presentation}));assert.throws(()=>buildPackage(f.config,f.output,{now}));assert.equal(fs.existsSync(f.output),false);
 }
 const defaults=normalizePresentation();defaults.displayName='changed';assert.equal(normalizePresentation().displayName,'Styx');assert.equal(normalizePresentation({shortDescription:' 短描述 '}).shortDescription,'短描述');
});
test('long descriptions normalize CRLF and preserve paragraphs while other controls and multiline titles refuse',()=>{
 const input='  第一段。\r\n\r\n第二段。\n第三行。  ',expected='第一段。\n\n第二段。\n第三行。';
 const normalized=normalizePresentation({longDescription:input});assert.equal(normalized.longDescription,expected);
 const files=buildPackageFiles({connection:{url},presentation:normalized},receipt(),{now});assert.equal(JSON.parse(files.files.find(f=>f.path==='plugin.json').data).extensions['com.openai'].interface.longDescription,expected);
 for(const text of ['line\rline','line\tline','line\u0000line','line\u0085line','line\u2028line','line\u2029line'])assert.throws(()=>normalizePresentation({longDescription:text}));
 for(const key of ['displayName','shortDescription'])for(const text of ['line\nline','line\r\nline','line\u2028line'])assert.throws(()=>normalizePresentation({[key]:text}));
});
test('PNG validates CRC, bounded square dimensions, chunks and bounded inflated scanlines',()=>{
 assert.equal(crc32(Buffer.from('123456789')),0xcbf43926);
 for(const size of [48,256,1024])assert.equal(normalizePresentation({icon:icon(png({size}))}).icon.mimeType,'image/png');
 const corrupt=png();corrupt[29]^=1;
 for(const image of [corrupt,png({size:47}),png({size:1025}),png({width:48,height:49}),png({interlace:1}),png({depth:16}),png({filter:5}),png({raw:Buffer.alloc(100000)}),png({idat:Buffer.from('not zlib')}),png({idat:Buffer.concat([deflateSync(Buffer.alloc(48*193)),Buffer.from('trailing')])}),png({extra:[chunk('tEXt',Buffer.from('SECRET'))]}),png({extra:[chunk('acTL',Buffer.alloc(8))]}),png({extra:[chunk('iCCP',Buffer.alloc(8))]}),png({tail:Buffer.from('SECRET')})])assert.throws(()=>normalizePresentation({icon:icon(image)}));
 const b64=png().toString('base64');for(const dataBase64 of [b64+'\n',b64.slice(0,-1),'A'.repeat(4*Math.ceil((256*1024+1)/3))])assert.throws(()=>normalizePresentation({icon:{mimeType:'image/png',dataBase64}}));
 const palette=Buffer.from([255,0,0]);assert.equal(normalizePresentation({icon:icon(png({color:3,palette}))}).icon.mimeType,'image/png');
 const indexed=Buffer.alloc(49*48);indexed[1]=1;assert.throws(()=>normalizePresentation({icon:icon(png({color:3,palette,raw:indexed}))}),/palette_index/);
});
test('App-owned tunnel omits a second remote credential without claiming remote verification',()=>{
 const c={tunnelId:'tunnel_'+'a'.repeat(32)},local={...receipt(c),method:'authenticated-local-mcp-discovery'};
 const built=buildPackageFiles({connection:c,presentation:normalizePresentation()},local,{now});assert.equal(built.verificationScope,'local_gateway_only');
 const server=JSON.parse(built.files.find(f=>f.path==='mcp.json').data).mcpServers.styx;assert.equal(server.extensions['com.openai'].tunnelId,c.tunnelId);assert.deepEqual(server.extensions['com.openai'].auth,{type:'none'});
 assert.equal(buildPackageFiles({connection:{url}},receipt(),{now}).verificationScope,'supplied_discovery_receipt');
 for(const method of ['unauthenticated-discovery','tunnel-configured','authenticated-mcp-discovery-and-readonly-call'])assert.throws(()=>buildPackageFiles({connection:c},{...local,method},{now}));
 assert.throws(()=>buildPackageFiles({connection:c,token:'SECRET'},local,{now}));assert.throws(()=>buildPackageFiles({connection:c},{...local,adminToken:'SECRET'},{now}));
});

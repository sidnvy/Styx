import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {buildPackage,validate,connection} from '../package.mjs';

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
test('HTTPS package is allowlisted and declares bearer without embedding receipt or credentials',t=>{
 const f=fixture(t);const r=buildPackage(f.config,f.output,{now});assert.equal(r.status,'package_created_not_installed');
 const m=JSON.parse(fs.readFileSync(path.join(f.output,'plugin.json')));
 assert.equal(m.name,'styx-native');assert.equal(m.$schema,'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json');
 assert.ok(m.extensions['com.openai'].interface.shortDescription.length<=30);
 for(const key of ['skills','mcpServers','apps','interface'])assert.equal(Object.hasOwn(m,key),false);
 const s=JSON.parse(fs.readFileSync(path.join(f.output,'mcp.json'))).mcpServers.styx;
 assert.equal(s.url,url);assert.deepEqual(s.extensions['com.openai'],{auth:{type:'api_key',headerScheme:'bearer'}});
 assert.deepEqual(fs.readdirSync(f.output).sort(),['mcp.json','plugin.json','skills']);
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

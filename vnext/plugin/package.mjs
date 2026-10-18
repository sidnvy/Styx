import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

const root=path.dirname(fileURLToPath(import.meta.url));
const requiredTools=['list_execution_environments','get_execution_environment_status','exec_command','write_stdin'];
const fail=code=>{throw Error(code);};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function exact(x,keys,code) {
  if(!object(x)||Object.keys(x).some(k=>!keys.includes(k)))fail(code);
}
export function connection(value) {
  exact(value,['url','tunnelId'],'invalid_connection');
  if(Object.hasOwn(value,'url')===Object.hasOwn(value,'tunnelId'))fail('choose_exactly_one_connection');
  if(Object.hasOwn(value,'tunnelId')) {
    if(typeof value.tunnelId!=='string'||!/^tunnel_[a-z0-9]{32}$/.test(value.tunnelId))fail('invalid_tunnel_id');
    return {tunnelId:value.tunnelId};
  }
  let url; try {url=new URL(value.url);}catch{fail('invalid_https_endpoint');}
  if(typeof value.url!=='string'||url.protocol!=='https:'||url.username||url.password||url.search||url.hash||
    !url.hostname||url.hostname==='localhost'||url.hostname.endsWith('.localhost')||
    url.hostname.endsWith('.invalid')||url.hostname.endsWith('.example')||
    ['example.com','example.org','example.net'].includes(url.hostname)||
    /^127\./.test(url.hostname)||['[::1]','0.0.0.0'].includes(url.hostname))fail('invalid_https_endpoint');
  return {url:url.href};
}
export function validate(config,receipt,{now=Date.now()}={}) {
  exact(config,['connection','verificationFile'],'invalid_package_config');
  if(typeof config.verificationFile!=='string'||!path.isAbsolute(config.verificationFile))fail('absolute_verification_file_required');
  const selected=connection(config.connection);
  exact(receipt,['version','connection','independentStyx','freshConnection','verifiedAt','serverName','tools','method'],'invalid_verification_receipt');
  if(receipt.version!==1||receipt.independentStyx!==true||receipt.freshConnection!==true||
    receipt.serverName!=='styx-vnext'||receipt.method!=='authenticated-mcp-discovery')fail('independent_verified_styx_required');
  if(JSON.stringify(selected)!==JSON.stringify(connection(receipt.connection)))fail('verification_connection_mismatch');
  const time=typeof receipt.verifiedAt==='string'?Date.parse(receipt.verifiedAt):NaN;
  if(!Number.isFinite(time)||time>now+60000||now-time>24*60*60*1000)fail('recent_verification_required');
  if(!Array.isArray(receipt.tools)||receipt.tools.some(t=>typeof t!=='string')||
    new Set(receipt.tools).size!==receipt.tools.length||requiredTools.some(t=>!receipt.tools.includes(t)))fail('native_discovery_required');
  if(receipt.tools.some(t=>/^(env_|project_|service_|cas_)/.test(t)))fail('foreign_tool_contract');
  return selected;
}
function regularJson(file) {
  const stat=fs.lstatSync(file);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>1024*1024)fail('regular_bounded_json_required');
  return JSON.parse(fs.readFileSync(file,'utf8'));
}
export function buildPackage(configFile,output,{now=Date.now()}={}) {
  if(!path.isAbsolute(configFile)||!path.isAbsolute(output))fail('absolute_paths_required');
  if(fs.existsSync(output))fail('output_must_be_fresh');
  if(path.basename(output)!=='styx-native')fail('directory_must_match_plugin_name');
  const config=regularJson(configFile);
  exact(config,['connection','verificationFile'],'invalid_package_config');
  if(typeof config.verificationFile!=='string'||!path.isAbsolute(config.verificationFile))fail('absolute_verification_file_required');
  const receipt=regularJson(config.verificationFile);
  const selected=validate(config,receipt,{now});
  const manifest=regularJson(path.join(root,'plugin.json'));
  const server={type:'streamable-http',...('url'in selected?selected:{}),extensions:{'com.openai':{
    ...('tunnelId'in selected?selected:{}),auth:{type:'api_key',headerScheme:'bearer'}
  }}};
  const mcp={$schema:'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',mcpServers:{styx:server}};
  // Exclusive creation after validation; no output on invalid receipt. No shell or archive extraction.
  fs.mkdirSync(output,{mode:0o700});
  fs.mkdirSync(path.join(output,'skills'));
  fs.mkdirSync(path.join(output,'skills','styx-native-onboarding'));
  fs.writeFileSync(path.join(output,'plugin.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});
  fs.writeFileSync(path.join(output,'mcp.json'),JSON.stringify(mcp,null,2)+'\n',{flag:'wx'});
  fs.copyFileSync(path.join(root,'skills/styx-native-onboarding/SKILL.md'),path.join(output,'skills/styx-native-onboarding/SKILL.md'),fs.constants.COPYFILE_EXCL);
  return {package:output,connection:selected,verificationSha256:createHash('sha256').update(fs.readFileSync(config.verificationFile)).digest('hex'),status:'package_created_not_installed'};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    if(process.argv.length!==4)fail('usage_node_package_mjs_absolute_config_absolute_output_styx_native');
    console.log(JSON.stringify(buildPackage(process.argv[2],process.argv[3])));
  }catch {console.error('Styx package generation failed; validate configuration and verification receipt locally.');process.exitCode=1;}
}

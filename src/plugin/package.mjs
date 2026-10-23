import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {inflateSync} from 'node:zlib';

const root=path.dirname(fileURLToPath(import.meta.url));
const requiredTools=['list_execution_environments','get_execution_environment_status','exec_command','write_stdin'];
const fail=code=>{throw Error(code);};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const MAX_ICON_BYTES=256*1024;
const PNG_SIGNATURE=Buffer.from([137,80,78,71,13,10,26,10]);
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
function verifiedConnection(selected,receipt,{now=Date.now()}={}) {
  exact(receipt,['version','connection','independentStyx','freshConnection','verifiedAt','serverName','tools','method'],'invalid_verification_receipt');
  if(receipt.version!==1||receipt.independentStyx!==true||receipt.freshConnection!==true||
    receipt.serverName!=='styx-vnext'||!['authenticated-mcp-discovery','authenticated-local-mcp-discovery'].includes(receipt.method))fail('independent_verified_styx_required');
  if(JSON.stringify(selected)!==JSON.stringify(connection(receipt.connection)))fail('verification_connection_mismatch');
  const time=typeof receipt.verifiedAt==='string'?Date.parse(receipt.verifiedAt):NaN;
  if(!Number.isFinite(time)||time>now+60000||now-time>24*60*60*1000)fail('recent_verification_required');
  if(!Array.isArray(receipt.tools)||receipt.tools.some(t=>typeof t!=='string')||
    new Set(receipt.tools).size!==receipt.tools.length||requiredTools.some(t=>!receipt.tools.includes(t)))fail('native_discovery_required');
  if(receipt.tools.some(t=>/^(env_|project_|service_|cas_)/.test(t)))fail('foreign_tool_contract');
  return selected;
}
export function validate(config,receipt,{now=Date.now()}={}) {
  exact(config,['connection','verificationFile','presentation'],'invalid_package_config');
  if(typeof config.verificationFile!=='string'||!path.isAbsolute(config.verificationFile))fail('absolute_verification_file_required');
  normalizePresentation(config.presentation);
  return verifiedConnection(connection(config.connection),receipt,{now});
}

// The same standard CRC-32 covers PNG chunks and stored ZIP members. No archive
// dependency, arbitrary file paths, remote image fetch or script image format.
export function crc32(bytes){
 let value=0xffffffff;
 for(const byte of bytes){value^=byte;for(let bit=0;bit<8;bit++)value=(value>>>1)^((value&1)?0xedb88320:0);}
 return (value^0xffffffff)>>>0;
}
function pngIcon(value){
 exact(value,['mimeType','dataBase64'],'invalid_plugin_icon');
 if(value.mimeType!=='image/png'||typeof value.dataBase64!=='string'||value.dataBase64.length>4*Math.ceil(MAX_ICON_BYTES/3)||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.dataBase64))fail('bounded_png_icon_required');
 const bytes=Buffer.from(value.dataBase64,'base64');
 if(bytes.length<57||bytes.length>MAX_ICON_BYTES||bytes.toString('base64')!==value.dataBase64||!bytes.subarray(0,8).equals(PNG_SIGNATURE))fail('bounded_png_icon_required');
 let offset=8,header=null,palette=0,idat=false,ended=false,dataEnded=false,count=0;const seen=new Set(),compressed=[];
 const ancillary=new Set(['sRGB','gAMA','cHRM','pHYs']);
 while(offset<bytes.length){
  if(++count>1024||offset+12>bytes.length)fail('invalid_png_structure');
  const length=bytes.readUInt32BE(offset),end=offset+12+length;
  if(length>MAX_ICON_BYTES||end>bytes.length)fail('invalid_png_structure');
  const type=bytes.toString('latin1',offset+4,offset+8),body=bytes.subarray(offset+8,end-4);
  if(!/^[A-Za-z]{4}$/.test(type)||bytes.readUInt32BE(end-4)!==crc32(bytes.subarray(offset+4,end-4)))fail('invalid_png_structure');
  if(!header&&type!=='IHDR'||ended)fail('invalid_png_structure');
  if(type==='IHDR'){
   if(header||length!==13)fail('invalid_png_structure');
   const width=body.readUInt32BE(0),height=body.readUInt32BE(4),color=body[9];
   if(width!==height||width<48||width>1024||body[8]!==8||![0,2,3,4,6].includes(color)||body[10]!==0||body[11]!==0||body[12]!==0)fail('unsupported_png_dimensions_or_format');
   header={width,height,color};
  }else if(type==='PLTE'){
   if(seen.has(type)||idat||[0,4].includes(header.color)||length<3||length>768||length%3!==0)fail('invalid_png_structure');palette=length/3;
  }else if(type==='tRNS'){
   if(seen.has(type)||idat||![0,2,3].includes(header.color)||header.color===3&&(!palette||length<1||length>palette)||header.color===0&&(length!==2||body.readUInt16BE(0)>255)||header.color===2&&(length!==6||[0,2,4].some(n=>body.readUInt16BE(n)>255)))fail('invalid_png_structure');
  }else if(type==='IDAT'){
   if(dataEnded||header.color===3&&!palette)fail('invalid_png_structure');idat=true;compressed.push(body);
  }else if(type==='IEND'){
   if(length!==0||!idat||end!==bytes.length)fail('invalid_png_structure');ended=true;
  }else if(ancillary.has(type)){
   if(seen.has(type)||idat||type==='sRGB'&&(length!==1||body[0]>3)||type==='gAMA'&&(length!==4||body.readUInt32BE(0)===0)||type==='cHRM'&&length!==32||type==='pHYs'&&(length!==9||body[8]>1))fail('invalid_png_structure');
  }else fail('unsupported_png_chunk'); // Excludes scripts, text/profile payloads, EXIF and animation.
  if(idat&&type!=='IDAT')dataEnded=true;
  seen.add(type);offset=end;
 }
 if(!header||!ended)fail('invalid_png_structure');
 const channels={0:1,2:3,3:1,4:2,6:4}[header.color],stride=header.width*channels,expected=(stride+1)*header.height;
 let pixels;const input=Buffer.concat(compressed);
 try{const result=inflateSync(input,{maxOutputLength:expected,info:true});pixels=result.buffer;if(result.engine.bytesWritten!==input.length||pixels.length!==expected)fail('invalid_png_pixels');}catch{fail('invalid_png_pixels')}
 for(let y=0;y<header.height;y++)if(pixels[y*(stride+1)]>4)fail('invalid_png_pixels');
 if(header.color===3){
  let previous=Buffer.alloc(stride);
  for(let y=0;y<header.height;y++){
   const line=Buffer.alloc(stride),filter=pixels[y*(stride+1)];
   for(let x=0;x<stride;x++){
    const left=x?line[x-1]:0,up=previous[x],upperLeft=x?previous[x-1]:0,p=left+up-upperLeft,dist=[Math.abs(p-left),Math.abs(p-up),Math.abs(p-upperLeft)];
    const paeth=dist[0]<=dist[1]&&dist[0]<=dist[2]?left:dist[1]<=dist[2]?up:upperLeft;
    line[x]=(pixels[y*(stride+1)+1+x]+[0,left,up,Math.floor((left+up)/2),paeth][filter])&255;
    if(line[x]>=palette)fail('invalid_png_palette_index');
   }
   previous=line;
  }
 }
 return {mimeType:'image/png',dataBase64:bytes.toString('base64')};
}
const template=JSON.parse(fs.readFileSync(path.join(root,'plugin.json'),'utf8'));
export const PACKAGED_SKILLS = Object.freeze(['styx-native-onboarding', 'styx-cli', 'styx-browser', 'styx-computer-use']);
const skills=PACKAGED_SKILLS.map(name=>({path:`skills/${name}/SKILL.md`,data:fs.readFileSync(path.join(root,`skills/${name}/SKILL.md`))}));
export function normalizePresentation(value={}){
 exact(value,['displayName','shortDescription','longDescription','icon'],'invalid_plugin_presentation');
 const defaults=template.extensions['com.openai'].interface,out={};
 for(const [key,max]of [['displayName',64],['shortDescription',30],['longDescription',2000]]){
  const input=value[key]===undefined?defaults[key]:value[key];
  if(typeof input!=='string')fail('invalid_plugin_'+key);
  const text=key==='longDescription'?input.replace(/\r\n/g,'\n'):input;
  const controls=key==='longDescription'?text.replaceAll('\n',''):text;
  if(/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u.test(controls)||!text.trim()||Array.from(text.trim()).length>max)fail('invalid_plugin_'+key);
  out[key]=text.trim();
 }
 out.icon=value.icon==null?null:pngIcon(value.icon);return out;
}
export function buildPackageFiles(config,receipt,{now=Date.now()}={}){
 exact(config,['connection','presentation'],'invalid_package_config');
 const selected=verifiedConnection(connection(config.connection),receipt,{now}),presentation=normalizePresentation(config.presentation);
 // The same approved borderless orb is used by the native App and default plugin.
 if(!presentation.icon)presentation.icon=pngIcon({mimeType:'image/png',dataBase64:fs.readFileSync(path.join(root,'../assets/brand/styx-logo.png')).toString('base64')});
 const manifest=structuredClone(template),ui=manifest.extensions['com.openai'].interface;
 for(const key of ['displayName','shortDescription','longDescription'])ui[key]=presentation[key];
 if(presentation.icon){ui.logo='./assets/icon.png';ui.composerIcon='./assets/icon.png';}
 const server={type:'streamable-http',...('url'in selected?selected:{}),extensions:{'com.openai':{
  // The App-owned tunnel adds the Gateway credential for discovery and calls.
  // A direct HTTPS connection still needs its own remote bearer contract.
  ...('tunnelId'in selected?selected:{}),auth:'tunnelId'in selected?{type:'none'}:{type:'api_key',headerScheme:'bearer'}
 }}};
 const mcp={$schema:'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',mcpServers:{styx:server}};
 const json=data=>Buffer.from(JSON.stringify(data,null,2)+'\n');
 const files=[{path:'plugin.json',data:json(manifest)},{path:'mcp.json',data:json(mcp)},...skills.map(file=>({path:file.path,data:Buffer.from(file.data)})),...(presentation.icon?[{path:'assets/icon.png',data:Buffer.from(presentation.icon.dataBase64,'base64')}]:[])];
 return {files,connection:selected,verificationScope:receipt.method==='authenticated-local-mcp-discovery'?'local_gateway_only':'supplied_discovery_receipt',status:'package_files_ready_not_installed'};
}
function regularJson(file,{withBytes=false}={}) {
  const stat=fs.lstatSync(file);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>1024*1024)fail('regular_bounded_json_required');
  const bytes=fs.readFileSync(file),value=JSON.parse(bytes.toString('utf8'));
  return withBytes?{value,bytes}:value;
}
export function buildPackage(configFile,output,{now=Date.now()}={}) {
  if(!path.isAbsolute(configFile)||!path.isAbsolute(output))fail('absolute_paths_required');
  if(fs.existsSync(output))fail('output_must_be_fresh');
  if(path.basename(output)!=='styx-native')fail('directory_must_match_plugin_name');
  const config=regularJson(configFile);
  exact(config,['connection','verificationFile','presentation'],'invalid_package_config');
  if(typeof config.verificationFile!=='string'||!path.isAbsolute(config.verificationFile))fail('absolute_verification_file_required');
  const {value:receipt,bytes:receiptBytes}=regularJson(config.verificationFile,{withBytes:true});
  validate(config,receipt,{now});
  const built=buildPackageFiles({connection:config.connection,presentation:config.presentation},receipt,{now});
  // Exclusive creation after validation; no output on invalid receipt. No shell or archive extraction.
  fs.mkdirSync(output,{mode:0o700});
  for(const file of built.files){fs.mkdirSync(path.dirname(path.join(output,file.path)),{recursive:true,mode:0o700});fs.writeFileSync(path.join(output,file.path),file.data,{flag:'wx',mode:0o600});}
  return {package:output,connection:built.connection,verificationScope:built.verificationScope,verificationSha256:createHash('sha256').update(receiptBytes).digest('hex'),status:'package_created_not_installed'};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    if(process.argv.length!==4)fail('usage_node_package_mjs_absolute_config_absolute_output_styx_native');
    console.log(JSON.stringify(buildPackage(process.argv[2],process.argv[3])));
  }catch {console.error('Styx package generation failed; validate configuration and verification receipt locally.');process.exitCode=1;}
}

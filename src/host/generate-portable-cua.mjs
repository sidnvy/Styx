import fs from 'node:fs';
import {createHash} from 'node:crypto';

const root=new URL('./',import.meta.url);
const platforms=['darwin','linux','win32'];
const names=['list_apps','list_windows','get_window_state','get_desktop_state',
  'click','set_value','type_text','press_key','scroll','verify_state'];
const files=platforms.map(p=>new URL('./fixture-cua-'+p+'.json',root));
const sources=files.map(f=>JSON.parse(fs.readFileSync(f,'utf8')));
const version=sources[0].serverVersion;
if(version!=='0.36.0' || sources.some((r,i)=>r.platform!==platforms[i]||r.serverVersion!==version))
  throw Error('Cua native source version/platform mismatch');
const notSemantic=new Set(['description','title','default','examples','$comment']);
function structural(x){
  if(Array.isArray(x))return x.map(structural);
  if(x&&typeof x==='object')return Object.fromEntries(Object.entries(x)
    .filter(([k])=>!notSemantic.has(k)).map(([k,v])=>[k,structural(v)]));
  return x;
}
const tools=names.map(name=>{
  const definitions=sources.map(s=>s.tools.find(t=>t.name===name));
  if(definitions.some(x=>!x?.inputSchema?.properties))throw Error('Missing official Cua tool '+name);
  const definitionsByOs=definitions.map(d=>d.inputSchema);
  const common=Object.keys(definitionsByOs[0].properties).filter(key=>
    definitionsByOs.every(s=>Object.hasOwn(s.properties,key)));
  const properties={};
  for(const key of common){
    const candidate=definitionsByOs[0].properties[key];
    if(definitionsByOs.every(s=>JSON.stringify(structural(s.properties[key]))===
      JSON.stringify(structural(candidate))))properties[key]=candidate;
  }
  const required=[...new Set(definitionsByOs.flatMap(s=>s.required||[]))].sort();
  if(required.some(key=>!Object.hasOwn(properties,key)))
    throw Error(name+': required property not portable');
  const inputSchema={type:'object',properties,required,additionalProperties:false};
  const first=definitions[0];
  return {name,
    description:'Cua Driver v'+version+' portable '+name+
      '. Select execution host with environment_id; native platform constraints still apply.',
    inputSchema, ...(first.annotations?{annotations:first.annotations}:{})};
});
const manifest={driver:'cua-driver',version,platforms,tools,
  source_sha256:Object.fromEntries(files.map((f,i)=>[platforms[i],
    createHash('sha256').update(fs.readFileSync(f)).digest('hex')]))};
const destination=new URL('../gateway/cua-portable-0.36.0.json',root);
fs.writeFileSync(destination,JSON.stringify(manifest,null,2)+'\n');
console.log(JSON.stringify({version,platforms,tools:tools.length,
  fields:Object.fromEntries(tools.map(t=>[t.name,Object.keys(t.inputSchema.properties).length])),
  destination:destination.pathname}));

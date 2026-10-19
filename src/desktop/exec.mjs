import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {gzipSync} from 'node:zlib';
import {DesktopError} from './primitives.mjs';
const exec=promisify(execFile);
// Preserve only a bounded provider error code, never raw stdout or request data.
export function nativeCommandErrorCode(stdout){
 try{const code=JSON.parse(String(stdout??'')).error?.code;return typeof code==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(code)?code:undefined;}catch{return undefined;}
}
export async function localDesktopExec(executable,args=[],options={}){
 if(!Array.isArray(args)||args.some(x=>typeof x!=='string'))throw new DesktopError('invalid_argument','Executable arguments must be strings');
 try{
  const r=await exec(executable,args,{encoding:'utf8',timeout:options.timeout_ms??10000,maxBuffer:4194304,windowsHide:true});
  return r.stdout;
 }catch(e){
  const detail=String(e.stderr||e.message).slice(0,350);
  const error=new DesktopError(e.code==='ENOENT'?'driver_unavailable':e.killed?'timeout':'driver_error',executable+': '+detail);
  error.native_code=nativeCommandErrorCode(e.stdout);throw error;
 }
}
export function parseCommandJson(data,backend){
 try{return JSON.parse(data);}catch{throw new DesktopError('invalid_driver_response',backend+' returned invalid JSON');}
}

// Pass bundled native source as a command without changing ExecutionPolicy or
// writing an unsigned .ps1. Literal arguments are quoted for PowerShell itself;
// no command shell interprets this argv. Leave room below Windows' argv limit.
export function powershellCommand(source,args=[]){
 if(typeof source!=='string'||source.includes('\0')||!Array.isArray(args)||
   args.some(value=>typeof value!=='string'||value.includes('\0')))throw new TypeError('Invalid PowerShell source or arguments');
 if(Buffer.byteLength(source)>262144)throw new RangeError('PowerShell source exceeds limit');
 const literals=args.map(value=>"'"+value.replaceAll("'","''")+"'").join(' ');
 const prelude="$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;";
 let invocation=prelude+' & {\n'+source+'\n} '+literals+'\n';
 let encoded=Buffer.from(invocation,'utf16le').toString('base64');
 if(encoded.length>32000){
  // The exact bundled C# declarations can exceed the Windows command-line
  // limit when UTF-16/base64 encoded. Compress only this bounded local source;
  // never fetch executable text or substitute a different probe.
  const packed=gzipSync(Buffer.from(source,'utf8')).toString('base64');
  invocation=prelude+"$styxSourceReader=[IO.StreamReader]::new([IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"')),[IO.Compression.CompressionMode]::Decompress));try { & ([scriptblock]::Create($styxSourceReader.ReadToEnd())) "+literals+" } finally { $styxSourceReader.Dispose() }";
  encoded=Buffer.from(invocation,'utf16le').toString('base64');
 }
 if(encoded.length>32000)throw new RangeError('PowerShell command exceeds Windows argument limit');
 return ['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded];
}

// New native Mac Exec evidence, independent of app TCC or signing approval.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {ExecAdapter} from '../packages/styx-exec-adapter/adapter.mjs';
import {ExecConnection,stdioClient} from '../packages/styx-exec-adapter/rpc.mjs';
const assert=(ok,why)=>{if(!ok)throw Error(why)};
const sha=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
export async function runMacNativeExecPilot({directory,codexBinary,expectedCodexSha256}={}){
  assert(process.platform==='darwin','native_macos_exec_required');
  assert([directory,codexBinary].every(p=>typeof p==='string'&&path.isAbsolute(p)),'absolute_mac_exec_paths_required');
  assert(!fs.existsSync(directory),'fresh_mac_exec_directory_required');
  const st=fs.lstatSync(codexBinary);assert(st.isFile()&&!st.isSymbolicLink(),'regular_mac_codex_required');
  // The expected hash comes from the independently checksum-verified official
  // archive prepared for this pilot; it is recorded without trusting a model.
  assert(/^[a-f0-9]{64}$/.test(expectedCodexSha256)&&sha(codexBinary)===expectedCodexSha256,'official_mac_codex_digest_mismatch');
  assert(execFileSync(codexBinary,['--version'],{encoding:'utf8',timeout:5000}).trim()==='codex-cli 0.163.0','pinned_mac_codex_version_required');
  fs.mkdirSync(directory,{mode:0o700});const state=path.join(directory,'private');fs.mkdirSync(state,{mode:0o700});
  const home=path.join(state,'codex-home');fs.mkdirSync(home,{mode:0o700});
  const receipt={schema:1,status:'NOT RUN',kind:'macos-owned-native-exec-adapter',node:process.version,
    codex:'0.163.0',codex_binary_sha256:expectedCodexSha256,
    evidence:{pipe_stdout_stderr_exit:'NOT RUN',pty_stdin_readback:'NOT RUN',cross_owner_refusal:'NOT RUN',
      owned_process_cleanup:'NOT RUN',fresh_transport_reconnect:'NOT RUN',private_state_cleanup:'NOT RUN'},
    signed_app:'NOT RUN',tcc:'NOT RUN',gui:'NOT RUN',gateway_http:'NOT RUN'};
  const owner='mac-native-pilot-owner';let runtime,adapter,phase='pipe_stdout_stderr_exit';
  async function connect(){
    runtime=await new ExecConnection(()=>stdioClient({binary:codexBinary,cwd:state,
      env:{PATH:'/usr/bin:/bin',HOME:state,CODEX_HOME:home,LANG:'en_US.UTF-8'},timeoutMs:10000})).initialize();
    adapter=new ExecAdapter({resolve:async(id,caller)=>{
      assert(caller===owner&&(id===undefined||id==='mac-owned'),'native_pilot_owner_refused');
      return {id:'mac-owned',generation:'owned-native-1',runtime,cwd:state,platform:'darwin',
        shell:'/bin/sh',shells:['/bin/sh'],env:{PATH:'/usr/bin:/bin',HOME:state,LANG:'en_US.UTF-8'}};
    }});
  }
  async function complete(result){
    let output=result.output;
    for(let i=0;result.session_id&&i<20;i++){
      result=await adapter.writeStdin({session_id:result.session_id,chars:'',yield_time_ms:250},owner);output+=result.output;
    }
    assert(!result.session_id,'owned_native_command_not_complete');return {...result,output};
  }
  try{
    await connect();
    let result=await complete(await adapter.execCommand({cmd:"printf STYX_MAC_STDOUT; printf STYX_MAC_STDERR >&2; exit 7",login:false,yield_time_ms:250},owner));
    assert(result.exit_code===7&&result.output.includes('STYX_MAC_STDOUT')&&result.output.includes('STYX_MAC_STDERR'),'native_mac_pipe_readback_mismatch');
    receipt.evidence[phase]='PASS';phase='pty_stdin_readback';
    result=await adapter.execCommand({cmd:"printf STYX_MAC_PTY_READY; IFS= read -r answer; printf 'STYX_MAC_REPLY:%s' \"$answer\"",tty:true,login:false,yield_time_ms:250},owner);
    assert(result.session_id&&result.output.includes('STYX_MAC_PTY_READY'),'native_mac_pty_not_ready');
    const session=result.session_id;
    await adapter.writeStdin({session_id:session,chars:'OWNED\n',yield_time_ms:250},'different-owned-conversation').then(
      ()=>{throw Error('cross_owner_session_was_allowed')},error=>{assert(error.code==='unknown_session','cross_owner_refusal_wrong_reason');receipt.evidence.cross_owner_refusal='PASS'});
    result=await complete(await adapter.writeStdin({session_id:session,chars:'OWNED\n',yield_time_ms:250},owner));
    assert(result.exit_code===0&&result.output.includes('STYX_MAC_REPLY:OWNED'),'native_mac_pty_readback_mismatch');
    receipt.evidence[phase]='PASS';phase='owned_process_cleanup';
    result=await adapter.execCommand({cmd:"printf 'STYX_PID=%s\\n' \"$$\"; IFS= read -r answer",login:false,yield_time_ms:250},owner);
    const match=/STYX_PID=(\d+)/.exec(result.output);assert(match&&result.session_id,'native_mac_owned_cleanup_fixture_missing');
    const pid=Number(match[1]),stops=await adapter.cleanup();assert(stops.length===1&&stops[0].confirmed,'native_mac_owned_cleanup_not_confirmed');
    let gone=false;for(let i=0;i<25;i++){
      try{process.kill(pid,0)}catch(error){if(error.code==='ESRCH'){gone=true;break}}
      await new Promise(resolve=>setTimeout(resolve,40));
    }
    assert(gone,'native_mac_owned_os_process_not_gone');receipt.evidence[phase]='PASS';
    await runtime.close();runtime=null;adapter=null;phase='fresh_transport_reconnect';await connect();
    result=await complete(await adapter.execCommand({cmd:'printf STYX_MAC_RECONNECTED',login:false,yield_time_ms:250},owner));
    assert(result.exit_code===0&&result.output==='STYX_MAC_RECONNECTED','native_mac_fresh_transport_readback_mismatch');
    receipt.evidence[phase]='PASS';receipt.status='PASS';
  }catch{receipt.status='FAIL';receipt.failed_phase=phase;receipt.evidence[phase]='FAIL'}
  finally{
    const stops=await adapter?.cleanup().catch(()=>null);
    await runtime?.close().catch(()=>{});
    if(stops===null||stops?.some(stop=>!stop.confirmed)){receipt.status='FAIL';receipt.evidence.owned_process_cleanup='FAIL'}
    if(stops!==null&&!stops?.some(stop=>!stop.confirmed)){
      fs.rmSync(state,{recursive:true,force:true});receipt.evidence.private_state_cleanup='PASS';
    }else receipt.evidence.private_state_cleanup='BLOCKED';
    fs.writeFileSync(path.join(directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
  }
  return receipt;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
  try{const result=await runMacNativeExecPilot(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));console.log(JSON.stringify(result));process.exitCode=result.status==='PASS'?0:1}
  catch{console.error('Styx native Mac Exec pilot BLOCKED before acceptance.');process.exitCode=2}
}

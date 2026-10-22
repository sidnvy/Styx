import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolveLinuxDesktopSession} from './linux-desktop.mjs';

const root=path.resolve(fileURLToPath(new URL('..',import.meta.url)));
const binary=process.env.STYX_CUA_NATIVE_BINARY;
const unmet=[];
const session=resolveLinuxDesktopSession();
if(process.platform!=='linux')unmet.push('native_gui_fixture_linux_only');
if(!session.available)unmet.push(session.reason);
else if(session.type!=='wayland')unmet.push('native_wayland_session_required');
if(!binary || !path.isAbsolute(binary) || !fs.existsSync(binary))
  unmet.push('STYX_CUA_NATIVE_BINARY_not_configured');
else try{fs.accessSync(binary,fs.constants.X_OK)}catch{unmet.push('native_cua_binary_not_executable')}
if(!fs.existsSync('/usr/bin/zenity'))unmet.push('zenity_fixture_not_available');
if(!fs.existsSync(path.join(root,'packages/styx-exec-adapter/.runtime/codex')))
  unmet.push('pinned_codex_executor_not_prepared');
else try{fs.accessSync(path.join(root,'packages/styx-exec-adapter/.runtime/codex'),fs.constants.X_OK)}catch{unmet.push('pinned_codex_executor_not_executable')}
if(unmet.length){
  console.log(JSON.stringify({pilot:'styx-native-cua',status:'BLOCKED',reasons:unmet}));
  process.exitCode=2;
}else{
  const child=spawn(process.execPath,['--test','--test-concurrency=1',
    'gateway/test/computer-outbound.test.mjs'],{
      cwd:root,stdio:'inherit',
      env:{...process.env,...session.env,DO_NOT_TRACK:'1',
        STYX_LIVE_CUA_TEST:'1',STYX_LIVE_CUA_GUI_TEST:'1'}
    });
  const status=await new Promise(resolve=>{
    child.on('error',()=>resolve(2));
    child.on('close',code=>resolve(code===0?0:1));
  });
  process.exitCode=status;
}

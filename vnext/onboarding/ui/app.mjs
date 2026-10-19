const $=selector=>document.querySelector(selector);
const form=$('#setup'),notice=$('#notice');
const LABELS={'gateway.prepare':'准备本机 Gateway','gateway.start':'启动前台 Gateway','host.prepare':'验证并准备 Host','host.invite':'生成一次性设备邀请','host.request':'提交设备加入请求','host.claim':'领取管理员审批结果','host.doctor':'检查 Host'};
const STATUS={pending:'待执行',running:'执行中',succeeded:'已记录成功',failed:'执行失败',uncertain:'结果不确定 · 不可重放',blocked:'前置条件未就绪',awaiting_approval:'等待管理员审批',skipped:'已跳过'};
const fragment=new URLSearchParams(location.hash.slice(1)),bootstrap=fragment.get('session');
if(bootstrap){sessionStorage.setItem('styx.local.session',bootstrap);history.replaceState(null,'',location.pathname)}
const session=sessionStorage.getItem('styx.local.session');
let csrf,capabilities,deployment=null,dependencies=[],locked=false;
function message(text){notice.textContent=text;notice.hidden=false}
async function api(route,{method='GET',data}={}){
 const response=await fetch('/api/'+route,{method,credentials:'omit',cache:'no-store',headers:{Authorization:'Bearer '+session,...(method==='POST'?{'Content-Type':'application/json','X-Styx-CSRF':csrf}:{})},...(data!==undefined?{body:JSON.stringify(data)}:{})});
 const value=await response.json();if(!response.ok)throw Error(value.error??'request_failed');return value;
}
function mode(){return new FormData(form).get('mode')}
function fields(){
 const join=mode()==='join-existing';$('#join-fields').hidden=!join;
 form.elements.invitationFile.required=join;
 $('#mac-fields').hidden=!(capabilities?.platform==='darwin'&&form.elements.computer.checked);
 form.elements.macTeamID.required=!$('#mac-fields').hidden;
 $('#wayland-field').hidden=capabilities?.platform!=='linux';
 $('#create').disabled=locked||(!join&&!capabilities?.localGatewayAvailable);
}
function render(){
 form.hidden=!!deployment;$('#progress').hidden=!deployment;$('#maintenance').hidden=!deployment;
 $('#pause').disabled=locked||!capabilities?.pauseSupported||deployment?.mode!=='create-local'||deployment?.gatewayRuntime!=='running';
 $('#start-gateway').disabled=locked||!capabilities?.startSupported||deployment?.mode!=='create-local'||deployment?.gatewayRuntime==='running'||!deployment?.steps.some(s=>s.id==='gateway.prepare'&&s.status==='succeeded');
 $('#steps').replaceChildren();
 if(!deployment)return;
 const running=deployment.gatewayRuntime==='running';
 $('#runtime').textContent=deployment.mode==='join-existing'?'加入现有环境；本页面不控制远端 Gateway。':running?'当前 Gateway：本设置进程正在运行。系统服务尚未安装。':'当前 Gateway：本进程未持有运行实例。先前步骤记录不等于正在运行；不要重复执行结果不确定的操作。';
 for(const step of deployment.steps){
  const item=document.createElement('li');item.className='step';
  const detail=document.createElement('div'),title=document.createElement('strong'),status=document.createElement('p');
  title.textContent=LABELS[step.id]??step.id;status.className='status '+step.status;status.textContent=STATUS[step.status]??'状态待核实';detail.append(title,status);
  if(step.error){const error=document.createElement('p');error.textContent='本地诊断代码：'+step.error;detail.append(error)}
  if(step.ownerApproval==='REQUIRED'){const approval=document.createElement('p');approval.textContent='请管理员在受信任的管理端核对设备指纹并审批。';detail.append(approval)}
  if(step.fingerprint){const fingerprint=document.createElement('p');fingerprint.textContent='设备指纹：'+step.fingerprint;detail.append(fingerprint)}
  const execute=document.createElement('button');execute.type='button';execute.className='secondary';
  execute.textContent=step.status==='awaiting_approval'?'重新检查审批':['failed','blocked'].includes(step.status)?'检查后重试':step.id==='host.doctor'?'运行检查':'授权并执行';
  const required=dependencies.find(p=>p.id===step.id)?.requires??[];
  const ready=required.every(id=>deployment.steps.some(s=>s.id===id&&s.status==='succeeded'));
  execute.disabled=locked||!ready||!['pending','failed','blocked','awaiting_approval'].includes(step.status);
  execute.addEventListener('click',()=>mutate('advance',{authorize:[step.id]},'该步骤已结束，请检查更新后的状态。'));
  item.append(detail,execute);$('#steps').append(item);
 }
}
async function refresh(){
 try{const state=await api('status');deployment=state.deployment;dependencies=state.dependencies??[];locked=!!state.busy;render()}
 catch{message('无法读取本地部署状态。请保留状态目录，查看本机诊断；不要删除状态后盲目重试。')}
}
async function mutate(route,data,success){
 if(locked)return;locked=true;message('正在执行已授权的操作，请保留此页面与本地状态目录。');render();fields();
 try{await api(route,{method:'POST',data});message(success)}
 catch{message('操作未完成。请先检查最新状态与本地诊断；结果不确定的步骤不会自动重放。')}
 finally{locked=false;await refresh();fields()}
}
form.addEventListener('change',fields);
form.addEventListener('submit',async event=>{
 event.preventDefault();if(!form.reportValidity())return;
 const values=new FormData(form),join=mode()==='join-existing';
 const host={bundle:values.get('bundle').trim(),publisherKeyFile:values.get('publisherKeyFile').trim(),publisherSha256:values.get('publisherSha256').trim(),baseDir:values.get('baseDir').trim(),label:values.get('label').trim(),computer:values.has('computer')};
 if(host.computer&&capabilities.platform==='darwin')host.macTeamID=values.get('macTeamID').trim();
 if(capabilities.platform==='linux'&&values.has('wayland'))host.wayland=true;
 const gateway={url:values.get('gatewayUrl').trim()};if(join&&values.get('caFile').trim())gateway.caFile=values.get('caFile').trim();
 const config={schema:1,mode:join?'join-existing':'create-local',gateway,host,...(join?{invitationFile:values.get('invitationFile').trim()}:{})};
 localStorage.setItem('styx.local.startupPreference',values.has('startup')?'requested':'manual');
 await mutate('create',config,'配置已保存。请逐项授权执行，不会自动启动全部服务。');
});
$('#refresh').addEventListener('click',refresh);
$('#start-gateway').addEventListener('click',()=>mutate('start',{},'前台 Gateway 启动请求已完成，请检查当前运行状态。'));
$('#pause').addEventListener('click',()=>mutate('pause',{},'停止请求已提交。请检查 Gateway 当前运行状态；部署步骤记录会保留。'));
if(!session){$('#access').hidden=false}
else{
 try{
  capabilities=await api('session');csrf=capabilities.csrf;
  $('#platform').textContent=({darwin:'macOS',win32:'Windows',linux:'Linux'})[capabilities.platform]??'本地设备';
  form.hidden=false;fields();await refresh();
  $('#startup-note').textContent=localStorage.getItem('styx.local.startupPreference')==='requested'?'你的偏好：希望登录后自动启动。系统服务安装尚未执行。':'当前为手动启动偏好。系统服务安装尚未执行。';
  if(!capabilities.localGatewayAvailable)message('本机尚未配置可信的 TLS 准备工具，创建本机 Gateway 暂不可用。可先加入现有环境，或由本地启动器配置可信工具后重新打开设置。');
  if(capabilities.trustedForwarding)message('正在使用明确配置的本机端口转发。请保持受信任的转发连接；不要把设置端口发布到局域网或公网。');
  setInterval(()=>{if(!document.hidden&&!locked)void refresh()},5000);
 }catch{$('#access').hidden=false;form.hidden=true;message('此设置会话已失效。请从本地终端重新打开当前私有链接。')}
}

const $=selector=>document.querySelector(selector);
const form=$('#setup'),notice=$('#notice');
const LABELS={'gateway.prepare':'准备本机 Gateway','gateway.start':'启动前台 Gateway','gateway.verify':'验证 Gateway 认证与工具发现','host.prepare':'验证并准备 Host','host.invite':'生成一次性设备邀请','host.request':'提交设备加入请求','host.claim':'领取管理员审批结果','host.doctor':'检查 Host','host.pair':'批准并配对这台 Host','host.service.install':'安装 Host 系统服务','host.service.start':'启动 Host 并启用登录后自动运行','host.service.status':'检查 Host 系统服务状态'};
const STATUS={pending:'待执行',running:'执行中',succeeded:'已记录成功',failed:'执行失败',uncertain:'结果不确定 · 不可重放',blocked:'前置条件未就绪',awaiting_approval:'等待管理员审批',skipped:'已跳过'};
const fragment=new URLSearchParams(location.hash.slice(1)),bootstrap=fragment.get('session');
if(bootstrap){sessionStorage.setItem('styx.local.session',bootstrap);history.replaceState(null,'',location.pathname)}
const session=sessionStorage.getItem('styx.local.session');
let serviceObservations={};
let csrf,capabilities,deployment=null,dependencies=[],ownerPairingScope=null,locked=false;
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
 $('#host-service').hidden=!capabilities?.hostServiceSupported;$('#gateway-service').hidden=!capabilities?.gatewayServiceSupported||deployment?.mode!=='create-local';
 for(const button of document.querySelectorAll('[data-service]'))button.disabled=locked||(button.dataset.service==='host'&&['install','start'].includes(button.dataset.action)&&deployment?.hostServiceMaintenance?.hasUncertainMutation)||(button.dataset.service==='gateway'&&button.dataset.action==='start'&&deployment?.gatewayRuntime==='running');
 for(const role of ['host','gateway']){const observation=serviceObservations[role]??(role==='host'?deployment?.hostServiceMaintenance?.lastObservation:null);if(observation)$('#'+role+'-service-status').textContent='本机观察：'+['status','state','active','enabled','persistence'].filter(k=>observation[k]).map(k=>k+' = '+observation[k]).join(' · ')+'（'+(observation.observedAt??'持久记录，需重新读取状态确认')+'）';}
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
  execute.disabled=locked||!ready||(['host.service.install','host.service.start'].includes(step.id)&&deployment?.hostServiceMaintenance?.hasUncertainMutation)||!['pending','failed','blocked','awaiting_approval'].includes(step.status);
  execute.addEventListener('click',()=>{
   if(step.id==='host.pair'){
    if(!ownerPairingScope)return;
    const scope=ownerPairingScope;
    if(!confirm('批准这台设备加入 Gateway？\nGateway：'+scope.gatewayUrl+'\n设备：'+scope.label+'\n桌面能力：'+(scope.enableComputer?'启用':'不启用')+'\n此操作将实际批准设备身份。'))return;
    void mutate('advance',{authorize:[step.id],ownerApproval:{approve:true,...scope}},'配对操作已结束，请检查设备状态。');
   }else void mutate('advance',{authorize:[step.id]},'该步骤已结束，请检查更新后的状态。');
  });
  item.append(detail,execute);$('#steps').append(item);
 }
}
async function refresh(){
 try{const state=await api('status');deployment=state.deployment;dependencies=state.dependencies??[];ownerPairingScope=state.ownerPairingScope??null;serviceObservations=state.services??serviceObservations;locked=!!state.busy;render()}
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
 await mutate('create',config,'配置已保存。请逐项授权执行，不会自动启动全部服务。');
});
$('#refresh').addEventListener('click',refresh);
$('#start-gateway').addEventListener('click',()=>mutate('start',{},'前台 Gateway 启动请求已完成，请检查当前运行状态。'));
$('#pause').addEventListener('click',()=>mutate('pause',{},'停止请求已提交。请检查 Gateway 当前运行状态；部署步骤记录会保留。'));
for(const button of document.querySelectorAll('[data-service]'))button.addEventListener('click',async()=>{
 if(locked)return;const role=button.dataset.service,action=button.dataset.action;
 const description=role==='host'&&action==='start'?'启动 Host 并启用登录后自动运行':role==='host'&&action==='stop'?'停止 Host 并关闭自动运行':role+' 系统服务操作：'+action;
 if(action!=='status'&&!confirm('明确授权：'+description+'？这将修改当前设备上受范围绑定保护的服务。'))return;
 locked=true;render();message('正在执行固定系统服务操作…');
 try{const result=await api('service',{method:'POST',data:{role,action,authorize:true}});serviceObservations[role]=result.service;message('服务操作已返回。请查看本机观察结果；进程运行不等于账号或工具链验收通过。')}catch{message('服务操作被拒绝或未完成。保留本地状态，先读取状态；不要重复结果不确定的变更。')}finally{locked=false;await refresh()}
});
$('#discovery-form').addEventListener('submit',async event=>{
 event.preventDefault();const f=event.currentTarget;if(!f.reportValidity()||locked)return;const values=new FormData(f);
 const config={url:values.get('url').trim(),tokenFile:values.get('tokenFile').trim(),independentStyx:values.has('independentStyx'),freshConnection:values.has('freshConnection')};if(values.get('caFile').trim())config.caFile=values.get('caFile').trim();
 locked=true;$('#discovery-result').textContent='正在检查独立 Gateway…';render();
 try{await api('verify-gateway',{method:'POST',data:config});$('#discovery-result').textContent='Gateway 认证与 SDK 工具发现已验证。ChatGPT 账号连接：尚未验收。'}catch{$('#discovery-result').textContent='连接验证失败。请核对独立 Gateway 地址、私有凭据文件权限和 CA；页面不会显示凭据或服务端错误。'}finally{f.elements.tokenFile.value='';locked=false;await refresh()}
});
if(!session){$('#access').hidden=false}
else{
 try{
  capabilities=await api('session');csrf=capabilities.csrf;
  $('#platform').textContent=({darwin:'macOS',win32:'Windows',linux:'Linux'})[capabilities.platform]??'本地设备';
  const d=capabilities.defaults??{};for(const name of ['label','baseDir','bundle','publisherKeyFile','publisherSha256'])if(d[name])form.elements[name].value=d[name];if(d.gatewayUrl)form.elements.gatewayUrl.value=d.gatewayUrl;
  $('#artifacts').open=!d.bundle;$('#discovery').hidden=false;
  form.hidden=false;fields();await refresh();

  if(!capabilities.localGatewayAvailable)message('本机尚未配置可信的 TLS 准备工具，创建本机 Gateway 暂不可用。可先加入现有环境，或由本地启动器配置可信工具后重新打开设置。');
  if(capabilities.trustedForwarding)message('正在使用明确配置的本机端口转发。请保持受信任的转发连接；不要把设置端口发布到局域网或公网。');
  setInterval(()=>{if(!document.hidden&&!locked)void refresh()},5000);
 }catch{$('#access').hidden=false;form.hidden=true;message('此设置会话已失效。请从本地终端重新打开当前私有链接。')}
}

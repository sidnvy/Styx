const $=selector=>document.querySelector(selector);
const form=$('#setup'),notice=$('#notice');
const LABELS={'gateway.prepare':'准备本机 Gateway','gateway.start':'启动前台 Gateway','gateway.verify':'验证 Gateway 认证与工具发现','host.prepare':'验证并准备 Host','host.invite':'生成一次性设备邀请','host.request':'提交设备加入请求','host.claim':'领取管理员审批结果','host.doctor':'检查 Host','host.pair':'批准并配对这台 Host','host.service.install':'安装 Host 系统服务','host.service.start':'启动 Host 并启用登录后自动运行','host.service.status':'检查 Host 系统服务状态'};
const comparisonCode=fp=>fp.slice(0,16).match(/.{1,4}/g).join(' ');
const STATUS={pending:'待执行',running:'执行中',succeeded:'已记录成功',failed:'执行失败',uncertain:'结果不确定 · 不可重放',blocked:'前置条件未就绪',awaiting_approval:'等待管理员审批',skipped:'已跳过'};
const fragment=new URLSearchParams(location.hash.slice(1)),bootstrap=fragment.get('session');
if(bootstrap){sessionStorage.setItem('styx.local.session',bootstrap);history.replaceState(null,'',location.pathname)}
const session=sessionStorage.getItem('styx.local.session');
let linkInspection,joinLinkId;
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
 form.elements.invitationFile.required=join&&!joinLinkId;$('#link-import').hidden=!join||!capabilities?.pairingLinkImportSupported;
 $('#mac-fields').hidden=!(capabilities?.platform==='darwin'&&form.elements.computer.checked);
 form.elements.macTeamID.required=!$('#mac-fields').hidden;
 $('#wayland-field').hidden=capabilities?.platform!=='linux';
 $('#network-exposure').hidden=join||!capabilities?.localGatewayAddresses?.length;form.elements.listenHost.disabled=join||!form.elements.allowRemoteHosts.checked;form.elements.listenHost.required=!join&&form.elements.allowRemoteHosts.checked;
 $('#create').disabled=locked||(!join&&!capabilities?.localGatewayAvailable);
}
function render(){
 form.hidden=!!deployment;$('#progress').hidden=!deployment;$('#maintenance').hidden=!deployment;
 $('#pause').disabled=locked||!capabilities?.pauseSupported||deployment?.mode!=='create-local'||deployment?.gatewayRuntime!=='running';
 $('#start-gateway').disabled=locked||!capabilities?.startSupported||deployment?.mode!=='create-local'||deployment?.gatewayRuntime==='running'||!deployment?.steps.some(s=>s.id==='gateway.prepare'&&s.status==='succeeded');
 $('#host-service').hidden=!capabilities?.hostServiceSupported;$('#gateway-service').hidden=!capabilities?.gatewayServiceSupported||deployment?.mode!=='create-local';
 for(const button of document.querySelectorAll('[data-service]'))button.disabled=locked||(button.dataset.service==='host'&&['install','start'].includes(button.dataset.action)&&deployment?.hostServiceMaintenance?.hasUncertainMutation)||(button.dataset.service==='gateway'&&button.dataset.action==='start'&&deployment?.gatewayRuntime==='running');
 for(const role of ['host','gateway']){const observation=serviceObservations[role]??(role==='host'?deployment?.hostServiceMaintenance?.lastObservation:null);if(observation)$('#'+role+'-service-status').textContent='本机观察：'+['status','state','active','enabled','persistence'].filter(k=>observation[k]).map(k=>k+' = '+observation[k]).join(' · ')+'（'+(observation.observedAt??'持久记录，需重新读取状态确认')+'）';}
 $('#pairing-owner').hidden=!deployment||deployment.mode!=='create-local'||!capabilities?.pairingLinkCreateSupported;
 $('#create-link').disabled=locked;$('#list-pending').disabled=locked||!capabilities?.pendingApprovalSupported;
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
  if(step.fingerprint){const fingerprint=document.createElement('p');fingerprint.textContent='设备比较码：'+comparisonCode(step.fingerprint)+'（人工核对用）';const full=document.createElement('details'),summary=document.createElement('summary'),value=document.createElement('p');summary.textContent='展开完整设备指纹';value.textContent=step.fingerprint;full.append(summary,value);detail.append(fingerprint,full)}
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
form.addEventListener('change',event=>{if(event.target.name==='listenHost'&&event.target.value){try{const url=new URL(form.elements.gatewayUrl.value);url.hostname=event.target.value;form.elements.gatewayUrl.value=url.origin}catch{}}if(event.target.name==='allowRemoteHosts'&&!event.target.checked){try{const url=new URL(form.elements.gatewayUrl.value);url.hostname='127.0.0.1';form.elements.gatewayUrl.value=url.origin}catch{}}if(['mode','gatewayUrl','invitationFile','caFile'].includes(event.target.name)){joinLinkId=null;$('#link-import-result').textContent='连接条件已改变，请重新检查配对链接或使用手动邀请文件。'}fields()});
form.addEventListener('submit',async event=>{
 event.preventDefault();if(!form.reportValidity())return;
 const values=new FormData(form),join=mode()==='join-existing';
 const host={bundle:values.get('bundle').trim(),publisherKeyFile:values.get('publisherKeyFile').trim(),publisherSha256:values.get('publisherSha256').trim(),baseDir:values.get('baseDir').trim(),label:values.get('label').trim(),computer:values.has('computer')};
 if(host.computer&&capabilities.platform==='darwin')host.macTeamID=values.get('macTeamID').trim();
 if(capabilities.platform==='linux'&&values.has('wayland'))host.wayland=true;
 const gateway={url:values.get('gatewayUrl').trim()};if(!join&&values.has('allowRemoteHosts')){gateway.allowRemoteHosts=true;gateway.listenHost=values.get('listenHost');}if(join&&!joinLinkId&&values.get('caFile').trim())gateway.caFile=values.get('caFile').trim();
 const config={schema:1,mode:join?'join-existing':'create-local',gateway,host,...(join?(joinLinkId?{joinLinkId}:{invitationFile:values.get('invitationFile').trim()}):{})};
 await mutate('create',config,'配置已保存。请逐项授权执行，不会自动启动全部服务。');
});
$('#refresh').addEventListener('click',refresh);
$('#start-gateway').addEventListener('click',()=>mutate('start',{},'前台 Gateway 启动请求已完成，请检查当前运行状态。'));
$('#pause').addEventListener('click',()=>mutate('pause',{},'停止请求已提交。请检查 Gateway 当前运行状态；部署步骤记录会保留。'));

$('#inspect-link').addEventListener('click',async()=>{
 if(locked)return;locked=true;render();const input=$('#pairing-link-input'),link=input.value;input.value='';
 try{linkInspection=await api('pairing-link/inspect',{method:'POST',data:{link}});const p=linkInspection.preview;$('#link-preview-text').textContent='Gateway：'+p.origin+'\n过期时间：'+new Date(p.expiresAt).toLocaleString()+'\n'+(p.caSha256?'证书 SHA-256：'+p.caSha256:'使用系统标准 TLS 信任。')+'\n请通过可信渠道核对以上地址与证书。';$('#link-preview').hidden=false;$('#link-import-result').textContent='链接尚未接受，设备也尚未获批。'}catch{linkInspection=null;$('#link-preview').hidden=true;$('#link-import-result').textContent='链接无效或已过期。不要把链接发送到聊天；请管理员重新提供。'}finally{locked=false;render()}
});
$('#accept-link').addEventListener('click',async()=>{
 if(locked||!linkInspection)return;const p=linkInspection.preview;if(!confirm('已通过可信渠道核对 Gateway '+p.origin+' 及显示的证书指纹？接受链接仅保存私有配对材料，不自动批准设备。'))return;
 locked=true;render();try{const result=await api('pairing-link/accept',{method:'POST',data:{inspectionId:linkInspection.inspectionId,approvedGatewayOrigin:p.origin,...(p.caSha256?{approvedCaSha256:p.caSha256}:{})}});joinLinkId=result.joinLinkId;form.elements.gatewayUrl.value=result.origin;form.elements.invitationFile.value='';form.elements.caFile.value='';$('#link-preview').hidden=true;$('#link-import-result').textContent='私有配对材料已保存。填写或确认软件包信息后保存配置；设备身份仍需 Gateway 所有者单独审批。';fields()}catch{$('#link-import-result').textContent='配对材料未保存。请保留本地状态并重新检查链接。'}finally{locked=false;render();fields()}
});
$('#create-link').addEventListener('click',async()=>{
 if(locked||!confirm('创建一次性私有配对链接？该链接不自动批准设备，请核对生成结果中的网络可达性。'))return;locked=true;render();
 try{const result=await api('pairing-link/create',{method:'POST',data:{authorize:true}});$('#created-link-value').value=result.link;$('#created-link').hidden=false;$('#created-link-note').textContent='有效期至 '+new Date(result.expiresAt).toLocaleString()+'。'+(result.reachability==='local_interface_configured_unverified'?'已配置本机网络接口，跨设备可达性尚未验证。':result.remoteUsable===true?'按已核验的网络可达性使用。':'仅本机或受信任的明确转发可用；不能直接跨设备连接。')}catch{message('无法创建链接。需要该部署的受信任 Gateway 运行，并且本机所有者凭据有效。')}finally{locked=false;render()}
});
$('#copy-link').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('#created-link-value').value);message('私有链接已复制。只通过可信渠道提供，不要发送到聊天。')}catch{message('浏览器未允许复制。请使用受信任浏览器的本机复制功能。')}});
$('#list-pending').addEventListener('click',async()=>{
 if(locked)return;locked=true;render();try{const result=await api('pending/list',{method:'POST',data:{authorize:true}});$('#pending-devices').replaceChildren();
 for(const row of result.pending){const card=document.createElement('div');card.className='prerequisite';const title=document.createElement('strong');title.textContent=row.label+' · '+row.platform;const scope=document.createElement('p');scope.textContent='工作目录：'+row.cwd+'\nShell：'+row.shell+'\n请求桌面能力：'+(row.computer_requested?'是':'否')+'\n设备比较码：'+comparisonCode(row.fingerprint)+'（人工核对用，不替代完整身份绑定）';
 const field=document.createElement('label');field.textContent='输入从设备侧独立核对的 16 位比较码（也接受完整指纹）';const fingerprint=document.createElement('input');fingerprint.maxLength=80;fingerprint.autocomplete='off';field.append(fingerprint);
 const gui=document.createElement('input');gui.type='checkbox';gui.disabled=!row.computer_requested;const guiLabel=document.createElement('label');guiLabel.className='check';guiLabel.append(gui,document.createTextNode('明确允许此设备请求的桌面能力'));
 const approve=document.createElement('button');approve.type='button';approve.textContent='核对指纹并批准此设备';approve.addEventListener('click',async()=>{const typed=fingerprint.value.replace(/[\s-]/g,'').toLowerCase();if(locked||!(typed===row.fingerprint||typed===row.fingerprint.slice(0,16))){message('输入的独立指纹与该设备不匹配，不批准。');return}if(!confirm('批准设备 '+row.label+'，已核对指纹，并且桌面能力选择为 '+(gui.checked?'允许':'不允许')+'？'))return;locked=true;render();try{await api('pending/approve',{method:'POST',data:{authorize:true,requestId:row.request_id,fingerprintConfirmation:fingerprint.value.trim(),enableComputer:gui.checked}});card.replaceChildren(document.createTextNode('设备已批准；请设备侧领取结果并重新检查状态。'))}catch{message('审批未完成，请重新读取待审批状态，不要盲目重试。')}finally{locked=false;render()}});const full=document.createElement('details'),summary=document.createElement('summary'),hash=document.createElement('p');summary.textContent='展开完整设备指纹';hash.textContent=row.fingerprint;full.append(summary,hash);card.append(title,scope,full,field,guiLabel,approve);$('#pending-devices').append(card)}
 if(!result.pending.length)$('#pending-devices').textContent='当前没有待审批设备。';
 }catch{message('无法读取待审批列表。请确认该部署的 Gateway 运行且本机所有者凭据有效。')}finally{locked=false;render()}
});

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
  for(const address of capabilities.localGatewayAddresses??[]){const option=document.createElement('option');option.value=address;option.textContent=address;form.elements.listenHost.append(option)}
  const d=capabilities.defaults??{};for(const name of ['label','baseDir','bundle','publisherKeyFile','publisherSha256'])if(d[name])form.elements[name].value=d[name];if(d.gatewayUrl)form.elements.gatewayUrl.value=d.gatewayUrl;
  $('#artifacts').open=!d.bundle;$('#discovery').hidden=false;
  form.hidden=false;fields();await refresh();

  if(!capabilities.localGatewayAvailable)message('本机尚未配置可信的 TLS 准备工具，创建本机 Gateway 暂不可用。可先加入现有环境，或由本地启动器配置可信工具后重新打开设置。');
  if(capabilities.trustedForwarding)message('正在使用明确配置的本机端口转发。请保持受信任的转发连接；不要把设置端口发布到局域网或公网。');
  setInterval(()=>{if(!document.hidden&&!locked)void refresh()},5000);
 }catch{$('#access').hidden=false;form.hidden=true;message('此设置会话已失效。请从本地终端重新打开当前私有链接。')}
}

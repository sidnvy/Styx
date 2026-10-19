const $=selector=>document.querySelector(selector);
const form=$('#setup'),notice=$('#notice');
const LABELS={'gateway.runtime.prepare':'准备独立签名 Gateway 运行时','gateway.prepare':'准备本机 Gateway','gateway.start':'启动前台 Gateway','gateway.verify':'验证 Gateway 认证与工具发现','host.prepare':'验证并准备 Host','host.invite':'生成一次性设备邀请','host.request':'提交设备加入请求','host.claim':'领取管理员审批结果','host.doctor':'检查 Host','host.pair':'批准并配对这台 Host','host.service.install':'安装 Host 系统服务','host.service.start':'启动 Host 并启用登录后自动运行','host.service.status':'检查 Host 系统服务状态'};
const comparisonCode=fp=>fp.slice(0,16).match(/.{1,4}/g).join(' ');
const STATUS={pending:'待执行',running:'执行中',succeeded:'已记录成功',failed:'执行失败',uncertain:'结果不确定 · 不可重放',blocked:'前置条件未就绪',awaiting_approval:'等待管理员审批',skipped:'已跳过'};
const fragment=new URLSearchParams(location.hash.slice(1)),bootstrap=fragment.get('session');
if(bootstrap){sessionStorage.setItem('styx.local.session',bootstrap);history.replaceState(null,'',location.pathname)}
const session=sessionStorage.getItem('styx.local.session');
let linkInspection,joinLinkId;
let serviceObservations={};
let csrf,capabilities,deployment=null,dependencies=[],ownerPairingScope=null,locked=false;
let journey=null,acceptance=null,tunnelObservation=null,backgroundObservation=null,handoffTimer,desktopReadbackTimer,renderedChallengeId;
const JOURNEY=[['local_setup','本机准备','先准备这台电脑'],['system_permissions','权限与可用性','检查终端与桌面权限'],['background','后台偏好','选择本次运行方式'],['external_entry','连接账号平台','在官方浏览器完成账号平台设置'],['chat_connection','添加到 ChatGPT','添加专用 Styx 连接并完成认证'],['chat_request_proof','聊天中真实调用','在目标聊天中执行本次验证请求'],['target_chat_confirmation','确认目标聊天','核对本次请求与实际聊天来源']];
const REASONS={local_setup_required:'先完成本机准备，再继续下一步。',interactive_desktop_session_required:'没有可用的交互桌面会话；终端能力可以单独检查。',desktop_permission_or_native_proof_required:'系统权限与真实桌面操作尚未完成验证。',chat_request_not_verified:'等待目标聊天通过 Styx 执行真实验证请求。',target_chat_not_confirmed:'请在目标聊天看到真实结果后，记录你的来源确认。',background_choice_required:'选择后台运行或本次保持前台。',native_permissions_require_user_authorization_and_restart:'请亲自完成系统授权，然后退出并重新打开 Styx。',permissions_native_state_not_observed:'尚未读取当前 App 的授权，请保持 App 运行并刷新。',native_permission_preflight_granted_desktop_test_separate:'系统权限预检查已通过，真实桌面操作仍需聊天验收。'};
function message(text){notice.textContent=text;notice.hidden=false}
const ERROR_MESSAGES={foreground_host_handoff_required:'检测到另一个前台设备进程。请先由 Styx 或 Codex 核实并交接该进程，再启用后台服务；没有启动重复进程。',tunnel_running_or_interrupted:'连接正在运行或上次中断尚未核实。请先停止并检查连接，再修改配置。',tunnel_client_integrity_failed:'内置连接组件校验失败，请重新获取完整的官方安装包。',background_uncertain_requires_reconciliation:'上次后台变更的结果不确定。已保留现场，请诊断后继续。',capability_uncertain_requires_reconciliation:'上次能力变更未完成，需先诊断；不会自动重复变更。'};
async function api(route,{method='GET',data}={}){
 const response=await fetch('/api/'+route,{method,credentials:'omit',cache:'no-store',headers:{Authorization:'Bearer '+session,...(method==='POST'?{'Content-Type':'application/json','X-Styx-CSRF':csrf}:{})},...(data!==undefined?{body:JSON.stringify(data)}:{})});
 const value=await response.json();if(!response.ok)throw Error(value.error??'request_failed');return value;
}
function mode(){return new FormData(form).get('mode')}
function fields(){
 const join=mode()==='join-existing';$('#join-fields').hidden=!join;$('#gateway-address').hidden=!join&&!!capabilities?.packagedPreviewTrusted;
 form.elements.invitationFile.required=join&&!joinLinkId;$('#link-import').hidden=!join||!capabilities?.pairingLinkImportSupported;
 $('#mac-fields').hidden=!(capabilities?.platform==='darwin'&&form.elements.computer.checked&&!capabilities?.packagedPreviewTrusted);
 form.elements.macTeamID.required=!$('#mac-fields').hidden;
 $('#wayland-field').hidden=capabilities?.platform!=='linux';
 $('#network-exposure').hidden=join||!capabilities?.localGatewayAddresses?.length;form.elements.listenHost.disabled=join||!form.elements.allowRemoteHosts.checked;form.elements.listenHost.required=!join&&form.elements.allowRemoteHosts.checked;
 const artifactsReady=['bundle','publisherKeyFile','publisherSha256','baseDir'].every(name=>form.elements[name].value.trim());
 const missingTeam=form.elements.macTeamID.required&&!form.elements.macTeamID.value.trim();
 $('#create').disabled=locked||(!join&&!capabilities?.localGatewayAvailable)||!artifactsReady||missingTeam;
 $('#create').textContent=join?'加入这台电脑':'开始本机设置';
 $('#setup-blocker').textContent=!artifactsReady?'安装组件尚未完整带入。请使用完整 Styx App 重新打开；高级部署可展开安装详情检查。':missingTeam?'桌面 App 的签名信息尚未带入。可以先只启用终端，或在高级详情核对签名信息。':!join&&!capabilities?.localGatewayAvailable?'本机连接准备组件暂不可用，请使用完整安装包重新打开。':'';
}
function clearHandoff(){
 clearTimeout(handoffTimer);$('#connection-credential').value='';$('#connection-target').value='';$('#connection-handoff').hidden=true;
}
function renderAcceptance(){
 const challenge=acceptance?.challenge,expired=acceptance?.status==='acceptance_expired'||challenge&&(!Number.isFinite(challenge.expiresAt)||challenge.expiresAt<=Date.now());
 if(renderedChallengeId!==challenge?.id){$('#desktop-acceptance-input').value='';$('#observed-target-chat').checked=false;renderedChallengeId=challenge?.id;}
 const proof=acceptance?.requestProof?.status==='verified';
 const desktop=acceptance?.desktop?.status??'pending',desktopReady=['not_required','verified'].includes(desktop);
 const confirmed=acceptance?.targetChatConfirmation?.status==='user_confirmed';
 if(confirmed)$('#observed-target-chat').checked=true;
 $('#challenge-box').hidden=!challenge||expired;
 $('#challenge-prompt').value=challenge&&!expired?String(challenge.prompt??''):'';
 $('#challenge-expiry').textContent=challenge&&!expired?'本次请求有效至 '+new Date(challenge.expiresAt).toLocaleTimeString()+'，仅用于这一次验证。':'';
 $('#request-proof-status').textContent=!capabilities?.acceptanceSupported?'此版本尚未提供真实聊天验证接口，请使用完整 Styx App 重新打开。':proof?'已收到并验证本次真实工具请求。':expired?'本次验证请求已过期，请重新生成后再从聊天执行。':challenge?'等待来自目标聊天的真实工具请求。':'尚未生成本次验证请求。';
 const canBegin=journey?.connectionHandoff?.status==='available';
 $('#begin-acceptance').disabled=locked||!capabilities?.acceptanceSupported||!canBegin;
 if(capabilities?.acceptanceSupported&&!canBegin&&!challenge)$('#request-proof-status').textContent='请先完成本机准备并保存专用聊天入口，再生成本次验证请求。';
 $('#begin-acceptance').textContent=challenge?'生成新的验证请求':'生成本次聊天验证请求';
 $('#refresh-acceptance').disabled=locked||!capabilities?.acceptanceSupported;
 $('#desktop-acceptance-status').textContent=desktop==='verified'?'桌面真实观察、输入和重新观察已验证。':desktop==='not_required'?'本次未请求桌面能力，验收范围为终端。':'请保持 Styx App 打开。聊天中的桌面工具需通过 get_window_state 观察当前 Styx 设置窗口、填写并重新观察同一窗口；系统授权本身不代表完成。若尚未识别当前 App，请完成授权并重新打开 Styx，再生成新的验证请求。';
 const input=$('#desktop-acceptance-input');input.disabled=locked||!challenge||expired||desktop!=='pending';
 $('#desktop-readback').hidden=desktop==='not_required'||!challenge;
 if(!challenge||expired)input.value='';
 $('#confirm-target-chat').disabled=locked||!proof||!desktopReady||!challenge||expired||!$('#observed-target-chat').checked||confirmed;
 $('#observed-target-chat').disabled=locked||!proof||!desktopReady||confirmed;
 $('#target-chat-status').textContent=confirmed?'已记录你在目标聊天中看到结果的确认。此来源仍是用户确认，未认证账号平台身份。':!proof?'先等待本次真实请求通过验证。':!desktopReady?'终端请求已验证；所选桌面能力仍待真实验收。':'真实请求已验证。请回到目标聊天核对结果，再记录来源确认。';
 $('#acceptance-completion').textContent=acceptance?.complete===true?'本次所选能力的聊天验收条件已满足。':proof&&desktopReady&&!confirmed?'还差一步：确认这次结果来自你的目标聊天。':'';
}
function renderJourney(){
 $('#journey-overview').hidden=!session;
 const joinedComplete=deployment?.mode==='join-existing'&&journey?.status==='complete';
 const current=journey?.currentStep??(acceptance?.complete?'target_chat_confirmation':joinedComplete?'background':'local_setup'),index=Math.max(0,JOURNEY.findIndex(row=>row[0]===current));
 $('#journey-position').textContent='第 '+(index+1)+' 步，共 '+JOURNEY.length+' 步';
 $('#journey-title').textContent=acceptance?.complete?'本次聊天验收已完成':joinedComplete?'这台设备的加入准备已完成':JOURNEY[index][2];
 const step=journey?.steps?.find(row=>row.id===current);
 $('#journey-description').textContent=REASONS[step?.reason]??(step?.status==='needs_attention'?'进度已保留。请按当前步骤检查状态，再继续。':'本机状态、系统权限和真实聊天分别核验，完成一项再继续。');
 $('#journey-progress').textContent=acceptance?.complete?'本次验收条件已满足':journey?.steps?'已完成 '+journey.steps.filter(row=>row.status==='completed').length+' / '+journey.steps.filter(row=>row.status!=='not_required').length+' 项':'读取实际进度…';
 for(const link of document.querySelectorAll('[data-journey]')){
  if(link.dataset.journey==='local_setup')link.href=deployment?'#progress':'#configure';
  const record=journey?.steps?.find(row=>row.id===link.dataset.journey);link.dataset.status=record?.status??'pending';
  if(link.dataset.journey===current)link.setAttribute('aria-current','step');else link.removeAttribute('aria-current');
 }
 const exec=journey?.readiness?.exec,desktop=journey?.readiness?.desktop;
 $('#readiness-exec').textContent=({connected:'设备连接已观察到',preflight_passed:'本机预检查通过',not_ready:'尚未就绪',unknown:'等待检查'})[exec?.status]??'等待检查';
 $('#readiness-exec-detail').textContent=exec?.status==='connected'?'连接已经建立，真实命令仍需在聊天中验证。':exec?.status==='preflight_passed'?'安装与本机预检查已完成；这不是实际命令或账号验收。':'运行状态尚未确认，先完成本机准备并重新检查。';
 $('#readiness-desktop').textContent=({not_requested:'本次未启用',not_verified:'尚未验收',session_unavailable:'没有交互桌面会话',verified:'真实桌面操作已验证'})[desktop?.status]??'等待检查';
 $('#readiness-desktop-detail').textContent=desktop?.status==='not_requested'?'可以使用已准备的终端能力。':desktop?.status==='session_unavailable'?'登录图形桌面后重新检查；现在不会宣称桌面可用。':desktop?.status==='verified'?'系统权限与实际桌面操作分别记录。':'请在系统中完成授权，再在聊天中进行真实观察和操作。';
 $('#permissions-list').replaceChildren();
 for(const permission of journey?.permissions??[]){const item=document.createElement('div');item.className='permission-row';const label=document.createElement('span'),status=document.createElement('span');label.textContent=permission.label??({accessibility:'辅助功能',screen_recording:'屏幕录制',automation:'应用自动化'})[permission.id]??'系统权限';status.textContent=({not_observed:'尚未观察',granted:'系统已授予',denied:'尚未授予',not_required:'本次不需要'})[permission.status]??'待核实';item.append(label,status);$('#permissions-list').append(item)}
 $('#mac-permission-help').hidden=capabilities?.platform!=='darwin';
 $('#run-diagnostics').disabled=locked||!capabilities?.diagnosticsSupported;
 $('#diagnostics-status').textContent=!capabilities?.diagnosticsSupported?'此版本未提供本机诊断接口，请从完整 Styx App 重新打开。':locked?'正在读取本机状态…':'重新检查只读取本机状态，不会替你授予系统权限。';
 const join=deployment?.mode==='join-existing';
 $('#account-connection').hidden=!deployment||join;
 $('#join-account-note').hidden=!join;
 $('#chatgpt-title').textContent=join?'回主台完成聊天验收':'在 ChatGPT 添加 Styx';
 $('#chat-request-proof').hidden=!deployment||join;$('#target-chat-confirmation').hidden=!deployment||join;
 $('#main-account-instructions').hidden=join;
 $('#prepare-handoff').hidden=join;$('#connection-handoff').hidden=join||!$('#connection-credential').value;
 $('#handoff-status').hidden=join;
 if(join)clearHandoff();
 const handoffReady=journey?.connectionHandoff?.status==='available';
 if(!handoffReady)clearHandoff();
 $('#prepare-handoff').disabled=locked||!capabilities?.connectionHandoffSupported||!handoffReady;
 if(!capabilities?.connectionHandoffSupported)$('#handoff-status').textContent='此版本未提供安全连接信息交接，请从完整 Styx App 重新打开。';
 else if(!handoffReady)$('#handoff-status').textContent='先完成本机准备，在上一步保存专用隧道后才能取得连接信息。';
 const tunnelStatus=tunnelObservation?.status??'not_configured';
 $('#tunnel-fields').disabled=locked||!capabilities?.tunnelSupported||['running','interrupted'].includes(tunnelStatus);
 $('#tunnel-start').disabled=locked||!capabilities?.tunnelSupported||tunnelStatus!=='configured';
 $('#tunnel-stop').disabled=locked||!capabilities?.tunnelSupported||!['running','interrupted'].includes(tunnelStatus);
 $('#tunnel-blocker').textContent=!capabilities?.tunnelSupported?'此安装包没有可用的聊天入口组件，请使用完整安装包。':tunnelStatus==='running'?'连接正在运行。修改 ID 或运行密钥前，请先明确停止连接。':tunnelStatus==='interrupted'?'上次连接已中断。请先停止并检查结果，不会自动重放启动。':tunnelStatus==='not_configured'?'先从官方账号平台取得专用隧道 ID 与运行密钥并保存。':'';
 const localPrepared=deployment?.steps?.some(step=>step.id===(deployment.roles?.host==='disabled'?'gateway.verify':'host.doctor')&&step.status==='succeeded');
 $('#keep-foreground').disabled=locked||!localPrepared||!capabilities?.journeySupported||!capabilities?.foregroundSupported;
 $('#keep-foreground').textContent=journey?.background?.preference==='foreground'?'启动／恢复本次前台连接':'保持 App 打开并启动本次连接';
 if(!capabilities?.foregroundSupported)$('#background-blocker').textContent+=' 当前版本未提供前台连接管理，请使用完整安装包。';
 renderAcceptance();
}
function render(){
 form.hidden=!!deployment;$('#advanced-settings').hidden=!deployment;$('#account-connection').hidden=!deployment||!capabilities?.tunnelSupported;$('#progress').hidden=!deployment;$('#maintenance').hidden=!deployment;
 $('#pause').disabled=locked||!capabilities?.pauseSupported||deployment?.mode!=='create-local'||deployment?.gatewayRuntime!=='running';
 $('#start-gateway').disabled=locked||!capabilities?.startSupported||deployment?.mode!=='create-local'||deployment?.gatewayRuntime==='running'||!deployment?.steps.some(s=>s.id==='gateway.prepare'&&s.status==='succeeded');
 const gatewayStartup=capabilities?.gatewayService?.startEnablesStartup===true;
 $('#gateway-service-title').textContent='本机 Gateway 系统服务 · '+({linux:'Linux 用户服务',darwin:'macOS 用户服务',win32:'Windows 登录任务'}[capabilities?.platform]??'平台服务');
 $('#gateway-service-policy').textContent=gatewayStartup?'这是持久服务，与本设置进程的前台 Gateway 不同。启动会同时启用登录后自动运行，停止会禁用；先停止前台 Gateway 再启动持久服务。实际状态以本机观察为准，未知不推断为已启用。':'这是持久服务，与本设置进程的前台 Gateway 不同。先停止前台 Gateway，再启动持久服务。启动与登录启用是分别授权的操作；实际状态以本机观察为准。';
 for(const button of document.querySelectorAll('[data-service="gateway"]')){if(button.dataset.action==='start')button.textContent=gatewayStartup?'启动并启用登录后自动运行':'启动 Gateway 服务';if(button.dataset.action==='stop')button.textContent=gatewayStartup?'停止并关闭自动运行':'停止 Gateway 服务';if(button.dataset.action==='enable')button.textContent=capabilities?.gatewayService?.enableCanTriggerRecovery?'启用登录启动与每分钟恢复':'启用登录启动'}
 if(capabilities?.gatewayService?.enableCanTriggerRecovery)$('#gateway-service-policy').textContent+=' Windows 任务启用后，每分钟后台恢复可能在下一分钟自动启动任务。';
 $('#host-service').hidden=!capabilities?.hostServiceSupported||deployment?.roles?.host==='disabled';$('#gateway-service').hidden=!capabilities?.gatewayServiceSupported||deployment?.mode!=='create-local';
 for(const button of document.querySelectorAll('[data-service]'))button.disabled=locked||(button.dataset.service==='host'&&['install','start'].includes(button.dataset.action)&&deployment?.hostServiceMaintenance?.hasUncertainMutation)||(button.dataset.service==='gateway'&&button.dataset.action==='start'&&deployment?.gatewayRuntime==='running');
 for(const role of ['host','gateway']){const observation=serviceObservations[role]??(role==='host'?deployment?.hostServiceMaintenance?.lastObservation:deployment?.gatewayServiceMaintenance?.lastObservation);if(observation)$('#'+role+'-service-status').textContent='本机观察：'+['status','state','active','enabled','persistence'].filter(k=>observation[k]).map(k=>k+' = '+observation[k]).join(' · ')+'（'+(observation.observedAt??'持久记录，需重新读取状态确认')+'）';}
 $('#pairing-owner').hidden=!deployment||deployment.mode!=='create-local'||!capabilities?.pairingLinkCreateSupported;
 $('#create-link').disabled=locked;$('#list-pending').disabled=locked||!capabilities?.pendingApprovalSupported;
 $('#steps').replaceChildren();
 for(const id of ['readiness-permissions','background-options','chatgpt-connect','chat-request-proof','target-chat-confirmation'])$('#'+id).hidden=!deployment;
 if(!deployment){renderJourney();return;}
 const hasHost=deployment.roles?.host!=='disabled';
 const prepared=deployment.steps.some(s=>s.id===(hasHost?'host.doctor':'gateway.verify')&&s.status==='succeeded');
 const needsAttention=deployment.steps.some(s=>['uncertain','blocked','failed'].includes(s.status));
 $('#setup-summary').textContent=prepared?'本机准备完成。后台运行、桌面权限和聊天连接将分别检查。':needsAttention?'设置需要处理一个问题，已保留进度。请查看技术详情或让 Codex 协助诊断。':'正在准备这台电脑。';
 $('#continue-setup').hidden=!hasHost||deployment.mode!=='create-local'||prepared;
 $('#continue-setup').disabled=locked||needsAttention;
 $('#enable-background').hidden=false;
 $('#enable-background').disabled=locked||!prepared||!capabilities?.backgroundSupported;
 $('#background-blocker').textContent=!prepared?'先完成本机准备，再选择后台运行。':!capabilities?.backgroundSupported?'当前版本不能管理后台运行，请保留前台窗口。':'';
 $('#device-settings').hidden=!prepared||deployment.mode!=='create-local';
 $('#local-desktop-settings').hidden=!hasHost;
 for(const id of ['desktop-enable','desktop-disable','load-devices'])$('#'+id).disabled=locked;
 $('#setup-recovery').hidden=!needsAttention;
 const problem=deployment.steps.find(s=>['uncertain','blocked','failed'].includes(s.status));
 $('#setup-recovery-reason').textContent=problem?'“'+(LABELS[problem.id]??'本机设置')+'”尚未完成。先重新读取状态；结果不确定时请保留当前身份与配对，让 Codex 根据执行详情协助处理，不要删除重装。':'';
 $('#recheck-setup').disabled=locked||!capabilities?.diagnosticsSupported;
 const joinPending=deployment.mode==='join-existing'&&!prepared;
 $('#join-approval').hidden=!joinPending;
 const request=deployment.steps.find(s=>s.id==='host.request'),claim=deployment.steps.find(s=>s.id==='host.claim');
 $('#join-comparison').textContent=request?.fingerprint?'本机设备比较码：'+comparisonCode(request.fingerprint)+'。请通过独立可信渠道与主台显示值核对。':'配对请求提交后，这里会显示本机设备比较码。';
 $('#continue-join').disabled=locked||needsAttention;
 $('#continue-join').textContent=claim?.status==='awaiting_approval'?'重新检查主台审批':'继续加入已有环境';
 const running=deployment.gatewayRuntime==='running';
 $('#runtime').textContent=deployment.mode==='join-existing'?'加入现有环境；本页面不控制远端 Gateway。':running?'当前 Gateway：本设置进程正在运行。系统服务的安装和登录启动状态请在下方单独读取。':'当前 Gateway：本进程未持有运行实例。先前步骤记录不等于正在运行；不要重复执行结果不确定的操作。';
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
 renderJourney();
}
async function refresh(){
 try{const state=await api('status');deployment=state.deployment;dependencies=state.dependencies??[];ownerPairingScope=state.ownerPairingScope??null;serviceObservations=state.services??serviceObservations;locked=!!state.busy;tunnelObservation=state.tunnel??null;backgroundObservation=state.background??null;
  const extras=await Promise.allSettled([capabilities?.journeySupported?api('journey'):Promise.resolve(null),capabilities?.acceptanceSupported?api('acceptance'):Promise.resolve(null)]);
  journey=extras[0].status==='fulfilled'?extras[0].value?.journey??null:null;acceptance=extras[1].status==='fulfilled'?extras[1].value?.acceptance??null:null;
  render();if(state.deviceCapabilities?.computer!==null&&state.deviceCapabilities?.computer!==undefined)$('#desktop-setting-status').textContent='桌面能力：'+(state.deviceCapabilities.computer?'已启用':'已停用')+' · '+state.deviceCapabilities.status; if(state.tunnel)$('#tunnel-status').textContent='连接进程：'+({running:'正在运行，真实聊天尚需验收',configured:'已配置，未启动',not_configured:'尚未配置',interrupted:'上次运行中断，需检查'}[state.tunnel.status]??'状态待核实');if(state.background)$('#background-summary').textContent=state.background.status==='running'?'本机当前观察：后台进程正在运行（'+(state.background.observedAt??state.background.updatedAt??'时间未知')+'）。':'后台运行尚未确认。';if(journey?.background?.preference==='foreground')$('#background-summary').textContent+=' 已选择本次保持前台，关闭 App 可能停止相关进程。';}
 catch{clearHandoff();$('#readiness-exec').textContent='当前状态暂不可读';$('#readiness-desktop').textContent='当前状态暂不可读';message('无法读取本地部署状态。请保留状态目录，查看本机诊断；不要删除状态后盲目重试。')}
}
async function mutate(route,data,success){
 if(locked)return;locked=true;message('正在执行已授权的操作，请保留此页面与本地状态目录。');render();fields();
 try{const result=await api(route,{method:'POST',data});message(success);return result??true}
 catch(error){message(ERROR_MESSAGES[error.message]??'操作未完成。请先检查最新状态与本地诊断；结果不确定的步骤不会自动重放。');return null}
 finally{locked=false;await refresh();fields()}
}
form.addEventListener('change',event=>{if(event.target.name==='listenHost'&&event.target.value){try{const url=new URL(form.elements.gatewayUrl.value);url.hostname=event.target.value;form.elements.gatewayUrl.value=url.origin}catch{}}if(event.target.name==='allowRemoteHosts'&&!event.target.checked){try{const url=new URL(form.elements.gatewayUrl.value);url.hostname='127.0.0.1';form.elements.gatewayUrl.value=url.origin}catch{}}if(['mode','gatewayUrl','invitationFile','caFile'].includes(event.target.name)){joinLinkId=null;$('#link-import-result').textContent='连接条件已改变，请重新检查配对链接或使用手动邀请文件。'}fields()});
form.addEventListener('submit',async event=>{
 event.preventDefault();if(!form.reportValidity())return;
 const values=new FormData(form),join=mode()==='join-existing';
 const host={bundle:values.get('bundle').trim(),publisherKeyFile:values.get('publisherKeyFile').trim(),publisherSha256:values.get('publisherSha256').trim(),baseDir:values.get('baseDir').trim(),label:values.get('label').trim(),computer:values.has('computer')};
 if(host.computer&&capabilities.platform==='darwin'&&!capabilities.packagedPreviewTrusted)host.macTeamID=values.get('macTeamID').trim();
 if(capabilities.platform==='linux'&&values.has('wayland'))host.wayland=true;
 const gateway={url:values.get('gatewayUrl').trim()};if(!join&&values.has('allowRemoteHosts')){gateway.allowRemoteHosts=true;gateway.listenHost=values.get('listenHost');}if(join&&!joinLinkId&&values.get('caFile').trim())gateway.caFile=values.get('caFile').trim();
 const config={schema:1,mode:join?'join-existing':'create-local',gateway,host,...(join?(joinLinkId?{joinLinkId}:{invitationFile:values.get('invitationFile').trim()}):{})};
 await mutate('create',config,'配置已保存。');
 if(!join&&deployment)await runLocalSetup();
 if(join&&deployment)await runJoinSetup();
});
async function runLocalSetup(){
 if(locked||!ownerPairingScope)return;
 const scope={approve:true,...ownerPairingScope};
 await mutate('local-setup',{ownerApproval:scope},'本机设置操作已结束，请查看设备状态。');
}
async function runJoinSetup(){
 if(locked||deployment?.mode!=='join-existing')return;
 const allowed=new Set(['host.prepare','host.request','host.claim','host.doctor']);
 for(let count=0;count<4;count++){
  const next=deployment.steps.find(step=>step.status!=='succeeded');
  if(!next||!allowed.has(next.id)||!['pending','awaiting_approval'].includes(next.status))return;
  const result=await mutate('advance',{authorize:[next.id]},next.id==='host.request'?'已提交本机身份，请在已有主台核对并审批。':'加入流程已更新，请查看本机状态。');
  if(!result||deployment.steps.find(step=>step.id===next.id)?.status!=='succeeded')return;
 }
}
$('#continue-join').addEventListener('click',runJoinSetup);
$('#recheck-setup').addEventListener('click',()=>$('#run-diagnostics').click());
$('#open-recovery-details').addEventListener('click',()=>{$('#technical-progress').open=true;$('#technical-progress').scrollIntoView({block:'nearest',behavior:'smooth'})});
$('#continue-setup').addEventListener('click',()=>{
 if(!ownerPairingScope)return;
 if(confirm('继续设置 '+ownerPairingScope.label+'？允许终端操作'+(ownerPairingScope.enableComputer?'及桌面控制（仍需系统授权）':'')+'，自动完成本机准备、配对与检查。'))void runLocalSetup();
});
$('#enable-background').addEventListener('click',async()=>{
 if(locked||!confirm('允许 Styx 的连接服务和设备服务在后台运行，并在登录后自动启动？聊天账号连接和系统权限将单独验证。'))return;
 if(capabilities?.journeySupported&&!await mutate('journey/background-preference',{background:'login',authorize:true},'已记录登录恢复偏好，接下来检查实际后台状态。'))return;
 await mutate('background',{authorize:true},'后台设置已返回，请查看实际状态。');
});
$('#keep-foreground').addEventListener('click',async()=>{
 if(locked||!capabilities?.foregroundSupported)return;
 if(!await mutate('journey/background-preference',{background:'foreground',authorize:true},'已记录本次前台偏好，接下来启动并检查本次连接。'))return;
 await mutate('foreground',{authorize:true},'本次前台连接操作已返回，请查看实际状态。保持 App 打开；退出时会结束本次拥有的连接进程，不改变已有系统服务。');
});
$('#run-diagnostics').addEventListener('click',async()=>{
 if(locked||!capabilities?.diagnosticsSupported)return;locked=true;render();
 try{await api('diagnostics');message('已重新读取本机诊断。请查看终端、桌面权限和运行状态。')}
 catch{message('本机诊断暂不可读。进度已保留，请从 Styx 重新打开设置或稍后重试。')}
 finally{locked=false;await refresh()}
});
$('#prepare-handoff').addEventListener('click',async()=>{
 if(locked||!capabilities?.connectionHandoffSupported||deployment?.mode==='join-existing')return;
 clearHandoff();locked=true;render();
 try{
  const result=await api('connection-handoff',{method:'POST',data:{authorize:true}}),handoff=result.handoff??result;
  const secret=handoff.authentication?.modelCredential;
  if(handoff.status!=='prepared'||handoff.authentication?.type!=='bearer'||typeof secret!=='string'||!Number.isFinite(handoff.expiresAt)||handoff.expiresAt<=Date.now())throw Error('handoff_unavailable');
  $('#connection-target').value=handoff.connection?.tunnelId??handoff.connection?.url??'';
  $('#connection-credential').value=secret;$('#connection-handoff').hidden=false;
  $('#handoff-status').textContent='仅供 ChatGPT 连接认证使用。请在 60 秒内复制到认证字段，不要发到聊天。';
  handoffTimer=setTimeout(()=>{clearHandoff();$('#handoff-status').textContent='临时显示已清除。需要时可重新明确读取。'},Math.min(60000,handoff.expiresAt-Date.now()));
 }catch{clearHandoff();$('#handoff-status').textContent='连接信息尚未准备好。请先完成本机连接与专用隧道设置，再重试。'}
 finally{locked=false;render()}
});
$('#copy-credential').addEventListener('click',async()=>{
 const field=$('#connection-credential');if(!field.value)return;
 try{await navigator.clipboard.writeText(field.value);$('#handoff-status').textContent='已复制。仅粘贴到 ChatGPT 的 Bearer 认证字段，不要发送到聊天。'}catch{$('#handoff-status').textContent='未获得剪贴板权限，请在此私有字段中使用系统复制。'}
});
$('#clear-credential').addEventListener('click',()=>{clearHandoff();$('#handoff-status').textContent='临时显示已清除。'});
document.addEventListener('visibilitychange',()=>{if(document.hidden){clearHandoff();$('#tunnel-form').elements.apiKey.value=''}});
window.addEventListener('pagehide',()=>{clearHandoff();$('#tunnel-form').elements.apiKey.value='';$('#pairing-link-input').value='';$('#created-link-value').value=''});
$('#begin-acceptance').addEventListener('click',async()=>{
 if(locked||!capabilities?.acceptanceSupported)return;
 if(acceptance?.challenge&&!confirm('生成新的验证请求会替换本次旧请求。继续？'))return;
 $('#observed-target-chat').checked=false;$('#desktop-acceptance-input').value='';
 await mutate('acceptance/begin',{authorize:true},'本次验证请求已生成。请复制到真实目标聊天，由 Styx 工具执行。');
});
$('#copy-challenge').addEventListener('click',async()=>{const prompt=$('#challenge-prompt').value;if(!prompt)return;try{await navigator.clipboard.writeText(prompt);message('已复制本次验证请求。请粘贴到目标 ChatGPT 聊天。')}catch{message('浏览器未允许复制，请选中上方验证请求并使用系统复制。')}});
$('#refresh-acceptance').addEventListener('click',async()=>{
 if(locked||!capabilities?.acceptanceSupported)return;
 clearTimeout(desktopReadbackTimer);
 const challenge=acceptance?.challenge,input=$('#desktop-acceptance-input');
 // Native AX set_value may change the WKWebView value without a DOM event.
 // This explicit check reads the current field; Core still requires actual
 // same-window Cua action/image evidence independently of this local readback.
 const readback=challenge&&Number.isFinite(challenge.expiresAt)&&challenge.expiresAt>Date.now()&&acceptance?.desktop?.status==='pending'&&!input.disabled?{challengeId:challenge.id,value:input.value,authorize:true}:null;
 locked=true;render();
 try{if(readback)await api('acceptance/desktop-readback',{method:'POST',data:readback})}
 catch{message('当前桌面输入尚未读回。请保留本次请求并重试；读回本身不会使真实桌面验收通过。')}
 finally{locked=false;await refresh()}
});
$('#observed-target-chat').addEventListener('change',renderAcceptance);
$('#confirm-target-chat').addEventListener('click',async()=>{
 const challenge=acceptance?.challenge;if(locked||!challenge||$('#confirm-target-chat').disabled)return;
 await mutate('acceptance/confirm',{challengeId:challenge.id,observedInTargetChat:true,authorize:true},'已记录你的目标聊天来源确认。实际请求、桌面能力和平台身份仍按各自证据显示。');
});
async function desktopReadback(){
 clearTimeout(desktopReadbackTimer);
 const challenge=acceptance?.challenge,input=$('#desktop-acceptance-input');
 if(!challenge||input.disabled||acceptance?.desktop?.status!=='pending')return;
 const value=input.value;
 desktopReadbackTimer=setTimeout(async()=>{
  if(acceptance?.challenge?.id!==challenge.id||document.hidden)return;
  try{await api('acceptance/desktop-readback',{method:'POST',data:{challengeId:challenge.id,value,authorize:true}});await refresh()}
  catch{$('#desktop-acceptance-status').textContent='桌面输入读回尚未记录，请保留当前请求并重新检查；不会仅凭手动输入标记通过。'}
 },400);
}
$('#desktop-acceptance-input').addEventListener('input',desktopReadback);
$('#desktop-acceptance-input').addEventListener('change',desktopReadback);
for(const link of document.querySelectorAll('[data-journey]'))link.addEventListener('click',event=>{
 const target=$(link.hash);if(!target||target.hidden){event.preventDefault();message(deployment?.mode==='join-existing'?'这台设备的账号连接和聊天验收由已有主台管理。请回主台的目标聊天选择此设备。':'先完成本机准备，后续步骤会在这里展开。');}
});
for(const [id,computer]of [['desktop-enable',true],['desktop-disable',false]])$('#'+id).addEventListener('click',()=>{
 if(locked||!confirm((computer?'启用':'停用')+'这台设备的桌面控制？设备连接会短暂重启，正在执行的操作可能中断。'))return;
 void mutate('capabilities',{authorize:true,computer},'能力设置已更新；请重新检查桌面权限与连接。');
});
$('#load-devices').addEventListener('click',async()=>{
 if(locked)return;locked=true;render();
 try{const result=await api('devices',{method:'POST',data:{}});const select=$('#default-device');select.replaceChildren();
  for(const device of result.devices){const option=document.createElement('option');option.value=device.device_id;option.textContent=device.label+(device.is_default?'（默认）':'');option.selected=device.is_default;select.append(option)}
  $('#device-setting-status').textContent=result.devices.some(d=>d.is_default)?'当前默认设备已标出。':'尚未选择默认设备，请选择后保存。';
 }catch{message('无法读取设备，请确认本机连接服务正在运行。')}finally{locked=false;render()}
});
$('#default-device-form').addEventListener('submit',async event=>{
 event.preventDefault();if(locked||!event.currentTarget.reportValidity())return;
 await mutate('default-device',{authorize:true,deviceId:$('#default-device').value},'默认设备已保存。');
});
$('#tunnel-form').addEventListener('submit',async event=>{
 event.preventDefault();const f=event.currentTarget;if(locked||!f.reportValidity())return;
 const values=new FormData(f),data={tunnelId:values.get('tunnelId').trim(),apiKey:values.get('apiKey').trim(),authorize:values.has('authorize'),autoStart:values.has('autoStart')};
 f.elements.apiKey.value='';locked=true;render();message('正在安全保存连接配置…');
 try{await api('tunnel/configure',{method:'POST',data});data.apiKey='';await api('tunnel/start',{method:'POST',data:{authorize:true}});message('连接进程已启动；请完成账号连接并在聊天中验证一次工具调用。')}
 catch{message('连接未完成。密钥不会显示在错误信息中；请检查连接状态。')}
 finally{data.apiKey='';locked=false;await refresh()}
});
$('#tunnel-start').addEventListener('click',()=>mutate('tunnel/start',{authorize:true},'已请求启动连接，请检查状态。'));
$('#tunnel-stop').addEventListener('click',()=>mutate('tunnel/stop',{authorize:true},'连接已停止。'));
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
let ingressOrigin;
$('#inspect-ingress').addEventListener('click',async()=>{
 if(locked||!capabilities?.deviceIngressSupported)return;locked=true;render();
 try{const {ingress}=await api('device-ingress/plan',{method:'POST',data:{}});ingressOrigin=ingress.configuredOrigin;
  const notes={gateway_not_prepared:'Gateway 尚未准备',gateway_certificate_not_prepared:'TLS 证书尚未准备',loopback_cannot_accept_other_computers:'当前仅限本机，其他电脑不能直接连接',network_exposure_not_authorized:'尚未授权开放网络入口',gateway_certificate_not_currently_valid:'证书已过期或尚未生效'};
  $('#ingress-status').textContent='入口：'+ingress.configuredOrigin+'。'+ingress.blockers.map(x=>notes[x]??x).join('；')+'。新电脑仍需独立验证 TLS、核对身份并获批；本机检查不证明跨设备可达。'+(ingress.tls.gatewayCertificate?.renewalDue?'证书即将到期，需要安排续期。':'');
  $('#verify-ingress').disabled=ingress.blockers.some(x=>x==='gateway_not_prepared'||x==='gateway_certificate_not_prepared');
 }catch{ingressOrigin=null;$('#verify-ingress').disabled=true;$('#ingress-status').textContent='无法读取入口条件，请保留部署状态并检查配置。'}finally{locked=false;render()}
});
$('#verify-ingress').addEventListener('click',async()=>{
 if(locked||!ingressOrigin)return;locked=true;render();
 try{await api('device-ingress/verify',{method:'POST',data:{url:ingressOrigin}});$('#ingress-status').textContent='本机 TLS 与入口认证边界检查通过。远端可达性、Host 连接和聊天账号仍未验收。'}catch{$('#ingress-status').textContent='入口验证未通过，请检查地址、网络和证书。不会自动更改监听地址或信任。'}finally{locked=false;render()}
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
 const startupLinked=role==='host'||(role==='gateway'&&capabilities?.gatewayService?.startEnablesStartup===true);
 const description=role==='gateway'&&action==='enable'&&capabilities?.gatewayService?.enableCanTriggerRecovery?'启用 Gateway 登录启动与每分钟后台恢复（下一分钟可能自动启动任务）':startupLinked&&action==='start'?'启动 '+role+' 并启用登录后自动运行':startupLinked&&action==='stop'?'停止 '+role+' 并关闭自动运行':role+' 系统服务操作：'+action;
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
  const d=capabilities.defaults??{};for(const name of ['label','baseDir','bundle','publisherKeyFile','publisherSha256','macTeamID'])if(d[name])form.elements[name].value=d[name];if(d.gatewayUrl)form.elements.gatewayUrl.value=d.gatewayUrl;
  $('#artifacts').open=false;$('#discovery').hidden=false;
  if(capabilities.packagedPreviewTrusted){
   $('#artifacts summary').textContent='内置软件包 · 高级详情';
   $('#artifacts .hint').textContent='软件包路径和发布者信息已由本机 App 带入；实际签名与完整性由 Styx 检查。';
   $('#package-review').textContent='使用此 App 内置的安装组件，并按以上能力准备这台电脑。后台运行和聊天连接稍后分别选择。';
  }
  form.hidden=false;fields();await refresh();

  if(!capabilities.localGatewayAvailable)message('本机尚未配置可信的 TLS 准备工具，创建本机 Gateway 暂不可用。可先加入现有环境，或由本地启动器配置可信工具后重新打开设置。');
  if(capabilities.trustedForwarding)message('正在使用明确配置的本机端口转发。请保持受信任的转发连接；不要把设置端口发布到局域网或公网。');
  setInterval(()=>{if(!document.hidden&&!locked)void refresh()},5000);
 }catch{$('#access').hidden=false;form.hidden=true;message('此设置会话已失效。请从 Styx 菜单重新打开 Setup / Settings。')}
}

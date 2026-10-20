import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {projectOnboardingJourney,readOnboardingJourney,readOnboardingDiagnostics,readOnboardingTunnel,publicAcceptance} from '../journey.mjs';
import {ensurePrivateDirectory,writePrivateFile,requirePrivateFile} from '../../host/private-storage.mjs';
import {createDeployment,readDeployment} from '../core.mjs';
import {main} from '../cli.mjs';
import {browserAcceptanceChallenge} from '../../shared/onboarding-evidence.mjs';
const ready=()=>({mode:'create-local',roles:{gateway:'local',host:'local',exec:'enabled',computer:'requested'},gatewayRuntime:{status:'running'},steps:['gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.doctor'].map(id=>({id,status:'succeeded',evidence:{secret:'SECRET_TOKEN',config:'/private/SECRET_PATH'}}))});
const row=(j,id)=>j.steps.find(s=>s.id===id);
const accepted=()=>({status:'user_confirmed_with_mcp_evidence',requestProof:{status:'verified'},targetChatConfirmation:{status:'user_confirmed'},desktop:{status:'verified'},complete:true});
function temp(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-journey-'));ensurePrivateDirectory(root);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
function snapshot(root){return Object.fromEntries(fs.readdirSync(root,{recursive:true}).filter(n=>fs.lstatSync(path.join(root,n)).isFile()).map(n=>[n,createHash('sha256').update(fs.readFileSync(path.join(root,n))).digest('hex')]))}

test('a running process, requested desktop, doctor or SDK success never verifies the account',()=>{
 const j=projectOnboardingJourney({deployment:ready(),background:{observation:'last_recorded',status:'running',hostConnection:'exec_connected'},acceptance:{complete:true},tunnel:{status:'running',transport:'ready'}});
 assert.equal(j.readiness.exec.status,'preflight_passed');assert.equal(j.readiness.desktop.status,'not_verified');assert.equal(j.account.status,'not_verified');
 assert.equal(row(j,'local_setup').status,'completed');assert.equal(row(j,'system_permissions').status,'pending');assert.equal(row(j,'external_entry').status,'completed');assert.equal(row(j,'chat_request_proof').status,'pending');
 assert.equal(j.acceptance.requestProof.status,'pending');assert.equal(j.acceptance.complete,false);assert.doesNotMatch(JSON.stringify(j),/SECRET|\/private/);
});
test('plugin export, account installation attestation and actual MCP evidence remain separate in journey',()=>{
 const plugin={required:true,profileSaved:true,selection:{mode:'create',accountLabel:'PRIVATE_ACCOUNT_REMARK'},presentation:{icon:{dataBase64:'PRIVATE_ICON'}},export:{status:'exported'},accountActions:{upload:'user_confirmed',installation:'not_observed'}};
 let j=projectOnboardingJourney({deployment:ready(),plugin,acceptance:accepted()});
 assert.equal(row(j,'chat_connection').status,'pending');assert.equal(row(j,'chat_connection').nextAction,'configure_or_reuse_plugin');
 assert.doesNotMatch(JSON.stringify(j.plugin),/PRIVATE|presentation|icon|accountLabel/);
 plugin.accountActions.installation='user_confirmed';j=projectOnboardingJourney({deployment:ready(),plugin});
 assert.equal(row(j,'chat_connection').status,'pending');assert.equal(j.account.status,'not_verified');
 j=projectOnboardingJourney({deployment:ready(),plugin,acceptance:accepted()});assert.equal(row(j,'chat_connection').status,'completed');assert.equal(j.plugin.providerIdentity,'not_verified');
});
test('proof, desktop readback and target-chat user attestation are distinct and provider identity remains unverified',()=>{
 const proof={status:'request_observed',requestProof:{status:'verified'},targetChatConfirmation:{status:'pending'},desktop:{status:'pending'},complete:false};
 let j=projectOnboardingJourney({deployment:ready(),acceptance:proof});
 assert.equal(row(j,'chat_connection').status,'completed');assert.equal(row(j,'chat_request_proof').status,'pending');assert.equal(row(j,'target_chat_confirmation').status,'pending');
 proof.desktop.status='verified';j=projectOnboardingJourney({deployment:ready(),acceptance:proof});assert.equal(row(j,'chat_request_proof').status,'completed');assert.equal(j.account.status,'not_verified');
 j=projectOnboardingJourney({deployment:ready(),acceptance:accepted()});assert.equal(row(j,'target_chat_confirmation').status,'completed');assert.equal(j.account.status,'user_attested_with_mcp_evidence');assert.equal(j.account.providerIdentity,'not_verified');assert.equal(j.acceptance.targetChatConfirmation.source,'user_attested');assert.equal(row(j,'system_permissions').status,'pending');assert.equal(j.permissions[0].status,'not_observed');
 assert.equal(j.readiness.desktop.status,'not_verified');assert.equal(j.readiness.desktop.reason,'historical_desktop_proof_not_current_readiness');
 j=projectOnboardingJourney({deployment:ready(),acceptance:accepted(),permissionObservation:{source:'current_native_app_preflight',accessibility:'granted',screenRecording:'granted'},foreground:{status:'connected',execConnection:'connected',desktopConnection:'connected'}});assert.equal(j.readiness.desktop.status,'verified');assert.equal(j.acceptance.complete,true);
});
test('foreground choice records no service mutation; login completion requires current role observations',()=>{
 const deployment=ready(),preference={background:'foreground',configurationBound:true};
 let j=projectOnboardingJourney({deployment,preference,background:{status:'running',observation:'last_recorded'}});assert.equal(row(j,'background').status,'pending');assert.equal(j.background.status,'not_observed');assert.equal(j.background.appExit,'connection_may_stop');
 j=projectOnboardingJourney({deployment,preference,foreground:{status:'started',execConnection:'connecting'}});assert.equal(row(j,'background').status,'active');assert.equal(j.account.status,'not_verified');
 j=projectOnboardingJourney({deployment,preference,foreground:{status:'connected',execConnection:'connected'}});assert.equal(row(j,'background').status,'completed');assert.equal(j.readiness.exec.status,'connected');assert.equal(j.account.status,'not_verified');
 preference.background='login';j=projectOnboardingJourney({deployment,preference,background:{status:'running',observation:'last_recorded'}});assert.equal(row(j,'background').status,'needs_attention');
 j=projectOnboardingJourney({deployment,preference,background:{status:'running',observation:'current',gateway:'running',host:'running',hostConnection:'not_connected'}});assert.equal(row(j,'background').status,'needs_attention');
 j=projectOnboardingJourney({deployment,preference,background:{status:'running',observation:'current',gateway:'running',host:'running',hostConnection:'exec_connected'}});assert.equal(row(j,'background').status,'completed');assert.equal(j.readiness.exec.status,'connected');
 preference.configurationBound=false;j=projectOnboardingJourney({deployment,preference});assert.equal(j.background.preference,'not_decided');
});
test('post-install capability selection changes requested desktop intent without granting permissions or readiness',()=>{
 const deployment=ready();deployment.roles.computer='disabled';
 let j=projectOnboardingJourney({deployment,capabilities:{status:'updated',phase:'complete',computer:true}});assert.equal(j.readiness.desktop.status,'not_verified');assert.equal(row(j,'system_permissions').status,'pending');assert.equal(j.permissions[0].status,'not_observed');
 j=projectOnboardingJourney({deployment,capabilities:{status:'updated',phase:'complete',computer:false}});assert.equal(j.readiness.desktop.status,'not_requested');assert.equal(row(j,'system_permissions').status,'not_required');
});
test('joining an existing Gateway requires account connection and final chat tests on its owner only',()=>{
 const deployment=ready();deployment.mode='join-existing';deployment.roles.gateway='external';deployment.steps=deployment.steps.filter(s=>s.id.startsWith('host.'));
 const j=projectOnboardingJourney({deployment});
 for(const id of ['external_entry','chat_connection','chat_request_proof','target_chat_confirmation']){assert.equal(row(j,id).status,'not_required');assert.equal(row(j,id).nextAction,'return_to_gateway_owner')}
 assert.equal(j.externalAccount.requiresPluginSetup,false);assert.equal(j.account.status,'not_verified');assert.equal(j.acceptance.complete,false);
});
test('missing GUI session is blocked; disabled desktop requires no desktop permission',()=>{
 let deployment=ready();let j=projectOnboardingJourney({deployment,background:{observation:'current',desktop:'session_unavailable'}});assert.equal(j.readiness.desktop.status,'session_unavailable');assert.equal(row(j,'system_permissions').status,'blocked');
 j=projectOnboardingJourney({deployment,acceptance:accepted(),background:{observation:'current',desktop:'session_unavailable'}});assert.equal(j.readiness.desktop.status,'session_unavailable');assert.equal(row(j,'system_permissions').status,'blocked');assert.equal(j.acceptance.complete,true);
 j=projectOnboardingJourney({deployment,acceptance:accepted(),foreground:{status:'connected',execConnection:'connected',desktopConnection:'session_unavailable_or_unobserved'}});assert.equal(j.readiness.desktop.status,'session_unavailable');assert.equal(row(j,'system_permissions').status,'blocked');
 deployment.roles.computer='disabled';j=projectOnboardingJourney({deployment});assert.equal(row(j,'system_permissions').status,'not_required');assert.equal(j.readiness.desktop.status,'not_requested');assert.ok(j.permissions.every(p=>p.status==='not_required'));
});
test('only current native preflight can complete system permission step, and it does not complete desktop acceptance',()=>{
 const deployment=ready(),permissionObservation={source:'not_observed',accessibility:'granted',screenRecording:'granted',automation:'not_required'};
 let j=projectOnboardingJourney({deployment,permissionObservation});assert.equal(row(j,'system_permissions').status,'pending');assert.equal(j.permissions[0].status,'not_observed');
 permissionObservation.source='current_native_app_preflight';j=projectOnboardingJourney({deployment,permissionObservation});assert.equal(row(j,'system_permissions').status,'completed');assert.equal(j.readiness.desktop.status,'not_verified');assert.equal(j.acceptance.complete,false);assert.equal(j.account.status,'not_verified');
 permissionObservation.screenRecording='denied';j=projectOnboardingJourney({deployment,permissionObservation});assert.equal(row(j,'system_permissions').status,'pending');assert.equal(j.permissions[1].status,'denied');
});
test('journey/diagnostics are whitelisted, read only and fail closed on unavailable observations',async t=>{
 const root=temp(t),stateDir=path.join(root,'state');ensurePrivateDirectory(stateDir);writePrivateFile(path.join(stateDir,'sentinel'),'private');
 const before=snapshot(root),options={core:{readDeployment:()=>ready(),readDeploymentAcceptance:()=>({...accepted(),challenge:{prompt:'SECRET'},modelCredential:'SECRET'}),readDeploymentConnectionHandoff:()=>({status:'available',credentialAvailable:true,authentication:{modelCredential:'SECRET'}}),readDeploymentOnboardingPreference:()=>({background:'foreground',configurationBound:true,config:'SECRET'})},backgroundRead:()=>{throw Error('SECRET_COOKIE /private/config')},tunnelRead:()=>({status:'running',transport:'ready',apiKey:'SECRET'})};
 const j=await readOnboardingJourney(stateDir,options),d=await readOnboardingDiagnostics(stateDir,options);
 assert.equal(j.connectionHandoff.status,'available');assert.equal(j.background.status,'not_observed');assert.equal(d.readOnly,true);assert.doesNotMatch(JSON.stringify({j,d}),/SECRET|COOKIE|\/private|modelCredential|"challenge"/);assert.deepEqual(snapshot(root),before);
 assert.equal(fs.existsSync(path.join(stateDir,'tunnel')),false);
});
test('no deployment produces a create action without running probes or creating directories',async t=>{
 const root=temp(t),stateDir=path.join(root,'new');let probed=false;
 const j=await readOnboardingJourney(stateDir,{core:{readDeployment(){throw Error('SECRET')}},backgroundRead(){probed=true},tunnelRead(){probed=true}});
 assert.equal(j.currentStep,'local_setup');assert.equal(row(j,'local_setup').nextAction,'create_local_setup');assert.equal(j.status,'awaiting_user');assert.equal(probed,false);assert.equal(fs.existsSync(stateDir),false);
});
test('CLI tunnel inspection reads configuration only and neither lock nor autoStart implies running',t=>{
 const root=temp(t);assert.equal(readOnboardingTunnel(root).status,'not_configured');assert.equal(fs.existsSync(path.join(root,'tunnel')),false);
 const tunnel=path.join(root,'tunnel');ensurePrivateDirectory(tunnel);writePrivateFile(path.join(tunnel,'connection.json'),JSON.stringify({schema:1,tunnelId:'tunnel_abcdefgh',keyFile:'key-'+'a'.repeat(32),autoStart:true}));writePrivateFile(path.join(tunnel,'key-'+'a'.repeat(32)),'sk-SECRET');writePrivateFile(path.join(tunnel,'owner.lock'),'123');
 const before=snapshot(root),value=readOnboardingTunnel(root);assert.deepEqual(value,{status:'configured',transport:'not_observed',observation:'configuration_only'});assert.deepEqual(snapshot(root),before);assert.doesNotMatch(JSON.stringify(value),/SECRET|123/);
});
test('acceptance public challenge contains only Core challenge fields, diagnostics projection excludes challenge',()=>{
 const value={...accepted(),challenge:{id:'a'.repeat(32),expiresAt:Date.now()+5000,prompt:'fixed prompt',command:'fixed command',environmentId:'device_123',desktopValue:'STYX_GUI_'+'b'.repeat(32),token:'SECRET'},rawConfig:'SECRET'};
 assert.equal(publicAcceptance(value,{includeChallenge:true}).challenge.desktopValue,value.challenge.desktopValue);assert.equal(publicAcceptance(value).challenge,undefined);assert.doesNotMatch(JSON.stringify(publicAcceptance(value,{includeChallenge:true})),/SECRET/);
});
test('actual CLI and Core share configuration and authoritative background preference without installing roles',{skip:process.platform!=='linux'},async t=>{
 const root=temp(t),stateDir=path.join(root,'state'),input=path.join(root,'input.json');
 writePrivateFile(input,JSON.stringify({schema:1,mode:'join-existing',gateway:{url:'https://owner.invalid'},host:{bundle:path.join(root,'unused-bundle'),publisherKeyFile:path.join(root,'unused-key'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'unused-host'),label:'Joined',computer:false}}));
 createDeployment(input,{stateDir});const originalConfig=fs.readFileSync(path.join(stateDir,'deployment.json'));
 const before=snapshot(root);const journey=await main(['journey',stateDir]);const diagnostics=await main(['diagnostics',stateDir]);assert.deepEqual(snapshot(root),before);
 assert.equal(row(journey,'external_entry').status,'not_required');assert.equal(diagnostics.account.status,'not_verified');assert.equal(readDeployment(stateDir).steps.some(s=>s.id.startsWith('gateway.')),false);
 await assert.rejects(main(['onboarding-background-choice',stateDir,'foreground']),/usage_/);
 await main(['onboarding-background-choice',stateDir,'foreground','--authorize']);assert.equal((await main(['journey',stateDir])).background.preference,'foreground');assert.deepEqual(fs.readFileSync(path.join(stateDir,'deployment.json')),originalConfig);assert.equal(fs.existsSync(path.join(root,'unused-host')),false);assert.equal(fs.existsSync(path.join(stateDir,'gateway')),false);
});
test('actual CLI handoff writes credentials only to a fresh private file and stdout is a redacted receipt',{skip:process.platform!=='linux'},async t=>{
 const root=temp(t),stateDir=path.join(root,'state'),input=path.join(root,'input.json'),baseDir=path.join(root,'host');
 writePrivateFile(input,JSON.stringify({schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:18791',openssl:'/usr/bin/openssl'},host:{bundle:path.join(root,'unused-bundle'),publisherKeyFile:path.join(root,'unused-key'),publisherSha256:'a'.repeat(64),baseDir,label:'Owned',computer:false}}));createDeployment(input,{stateDir});
 for(const d of [baseDir,path.join(baseDir,'device'),path.join(stateDir,'gateway'),path.join(stateDir,'gateway/enrollment'),path.join(stateDir,'tunnel')])ensurePrivateDirectory(d);
 const put=(f,value)=>writePrivateFile(f,JSON.stringify(value));put(path.join(baseDir,'device/identity.json'),{device_id:'device',fingerprint:'fp'});put(path.join(baseDir,'device/host.json'),{host_id:'host'});put(path.join(stateDir,'gateway/enrollment/state.json'),{devices:[{id:'device',fingerprint:'fp',status:'approved',target:{id:'host',allowed:true,generation:'gen'}}]});writePrivateFile(path.join(stateDir,'gateway/certificate.pem'),'test fixture certificate');const secret='SECRET_MODEL_CREDENTIAL_'+'a'.repeat(40);writePrivateFile(path.join(stateDir,'gateway/model.token'),secret);writePrivateFile(path.join(stateDir,'gateway/admin.token'),'ADMIN_ONLY_'+ 'b'.repeat(48));put(path.join(stateDir,'tunnel/connection.json'),{schema:1,tunnelId:'tunnel_abcdefgh',keyFile:'key-'+'a'.repeat(32),autoStart:false});writePrivateFile(path.join(stateDir,'tunnel','key-'+'a'.repeat(32)),'sk-private-fixture');
 const output=path.join(root,'handoff.json'),result=spawnSync(process.execPath,[new URL('../cli.mjs',import.meta.url).pathname,'handoff',stateDir,output,'--authorize'],{encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);assert.doesNotMatch(result.stdout+result.stderr,/SECRET_MODEL_CREDENTIAL/);assert.equal(JSON.parse(result.stdout).privateHandoffFile,output);assert.equal(JSON.parse(fs.readFileSync(output)).authentication.modelCredential,secret);assert.equal(requirePrivateFile(output).mode&0o077,0);
 await assert.rejects(main(['handoff',stateDir,output,'--authorize']),/fresh_private_output_required/);assert.equal(JSON.parse(fs.readFileSync(output)).authentication.modelCredential,secret);
});


test('Browser process readiness cannot complete its independent acceptance or the combined chat gate',()=>{
 const deployment=ready();deployment.roles.browser='requested';deployment.roles.computer='disabled';
 const proof={...accepted(),desktop:{status:'not_required'},browser:{status:'pending',required:true,source:'not_observed'}};
 let j=projectOnboardingJourney({deployment,acceptance:proof,foreground:{status:'connected',execConnection:'connected',browserConnection:'connected'},background:{observation:'current',browser:{readiness:'ready_observed'}}});
 assert.equal(j.acceptance.browser.status,'pending');assert.equal(j.acceptance.complete,false);assert.equal(row(j,'chat_request_proof').status,'pending');assert.equal(row(j,'target_chat_confirmation').nextAction,'run_acceptance_in_target_chat');assert.equal(j.readiness.browser.status,'not_verified');assert.equal(j.permissions[0].status,'not_required');
 proof.browser={status:'verified',required:true,source:'authenticated_mcp_browser_result'};j=projectOnboardingJourney({deployment,acceptance:proof});
 assert.equal(j.acceptance.browser.status,'verified');assert.equal(j.acceptance.requestProof.source,'authenticated_mcp_exec_result');assert.equal(j.acceptance.complete,true);assert.equal(j.account.providerIdentity,'not_verified');assert.equal(j.acceptance.targetChatConfirmation.source,'user_attested');assert.equal(row(j,'chat_request_proof').status,'completed');assert.equal(j.readiness.browser.reason,'historical_browser_proof_not_current_readiness');
 const browserOnly=projectOnboardingJourney({deployment,acceptance:{...proof,requestProof:{status:'pending'},complete:false}});assert.equal(row(browserOnly,'chat_connection').status,'completed');assert.equal(row(browserOnly,'chat_request_proof').status,'pending');assert.equal(browserOnly.account.status,'not_verified');
 const missing=projectOnboardingJourney({deployment,acceptance:accepted()});assert.equal(missing.acceptance.browser.status,'pending');assert.equal(missing.acceptance.complete,false);
});
test('Browser challenge projection accepts only the exact credential-free generated data URL',()=>{
 const browser=browserAcceptanceChallenge('c'.repeat(32)),value={...accepted(),browser:{status:'verified',required:true,source:'authenticated_mcp_browser_result',ownerHash:'PRIVATE_OWNER_HASH'},challenge:{id:'a'.repeat(32),expiresAt:Date.now()+5000,prompt:'fixed prompt',command:'fixed command',environmentId:'device_123',browser}};
 assert.deepEqual(publicAcceptance(value,{includeChallenge:true}).challenge.browser,browser);
 const diagnostics=publicAcceptance(value);assert.equal(diagnostics.challenge,undefined);assert.equal(diagnostics.browser.source,'authenticated_mcp_browser_result');assert.doesNotMatch(JSON.stringify(diagnostics),/STYX_BROWSER_|PRIVATE_OWNER_HASH/);
 for(const url of ['https://example.invalid/private','data:text/html,<script>secret</script>'])assert.equal(publicAcceptance({...value,challenge:{...value.challenge,browser:{...browser,url}}},{includeChallenge:true}).challenge.browser,undefined);
 assert.equal(publicAcceptance({...value,browser:{status:'verified',required:true,source:'process_ready'}}).browser.status,'pending');
});

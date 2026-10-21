import {createHmac} from 'node:crypto';

// Use only after authenticating the dedicated local Tunnel capability AND
// the normal MCP bearer. Untrusted clients retain transport-session ownership.
export class ConversationOwners {
 constructor({key,gateway,principal,clock=()=>Date.now()}) {
  this.key=key;this.gateway=gateway;this.principal=principal;this.clock=clock;this.states=new Map();
 }
 async run(meta,operation) {
  const valid=x=>typeof x==='string'&&x.length>0&&x.length<=512&&!/[\x00-\x1f]/.test(x);
  if(!valid(meta?.['openai/subject'])||!valid(meta?.['openai/session'])||
    (meta?.['openai/organization']!==undefined&&!valid(meta['openai/organization']))) {
   return {isError:true,content:[{type:'text',text:'trusted_conversation_metadata_required'}],
    structuredContent:{error:'trusted_conversation_metadata_required'}};
  }
  const scope=JSON.stringify([this.principal,meta['openai/organization']??null,meta['openai/subject'],meta['openai/session']]);
  const owner='tunnel-conversation:'+createHmac('sha256',this.key).update(scope).digest('hex');
  let state=this.states.get(owner);
  if(!state){state={active:0,last:this.clock()};this.states.set(owner,state);}
  state.active++;state.last=this.clock();
  const profile=createHmac('sha256',this.key).update('browser-profile\0'+JSON.stringify([this.principal,meta['openai/organization']??null,meta['openai/subject']])).digest('hex');
  this.gateway.browser?.bindPrincipal?.(owner,profile);
  try{return await operation(owner);}finally{state.active--;state.last=this.clock();}
 }
 async reap(timeout) {
  if(!timeout)return;
  for(const [owner,state]of this.states) {
   if(state.active||state.last>this.clock()-timeout||this.gateway.hasOwnerWork?.(owner))continue;
   this.states.delete(owner);await this.gateway.closeOwner?.(owner);
  }
 }
}

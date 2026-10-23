// The added device transport has its own lifecycle. It cannot change the
// existing Host execution or chat proof scope. Full deployment bytes remain
// bound by state.configSha256; only this narrow projection excludes the entry.
import {createHash} from 'node:crypto';
export function deploymentConnectionHash(bytes){
 const config=JSON.parse(bytes);
 if(config.gateway?.deviceIngress!==undefined){delete config.gateway.deviceIngress;bytes=Buffer.from(JSON.stringify(config,null,2)+'\n');}
 return createHash('sha256').update(bytes).digest('hex');
}

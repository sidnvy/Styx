import fs from 'node:fs';
export const BROWSER_CONTRACT=JSON.parse(fs.readFileSync(new URL('./playwright-contract-0.0.83.json',import.meta.url),'utf8'));
export const BROWSER_VERSION=BROWSER_CONTRACT.version;
export const BROWSER_META_PROFILE_OWNER='app.styx/browser-profile-owner';
export const BROWSER_META_OWNER='app.styx/browser-owner';
export const BROWSER_OWNER_CLOSED='notifications/styx/browser-owner-closed';
export const BROWSER_STATE_CHANGED='notifications/styx/browser-state';
export const browserTools=BROWSER_CONTRACT.tools;
export const browserFailure=(error,uncertain=false)=>({isError:true,structuredContent:{error,...(uncertain?{uncertain:true}:{})},content:[{type:'text',text:JSON.stringify({error,...(uncertain?{uncertain:true}:{})})}]});

import path from 'node:path';
const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
export function normalizeBrowserConfig(browser){
  if(browser===undefined||browser?.enabled===false)return null;
  if(!plain(browser)||browser.enabled!==true||Object.keys(browser).some(k=>!['enabled','headless','profileRoot','executablePath'].includes(k)))throw Error('invalid_browser_config');
  if(typeof browser.profileRoot!=='string'||!path.isAbsolute(browser.profileRoot)||path.normalize(browser.profileRoot)!==browser.profileRoot)throw Error('private_browser_profile_root_required');
  if(browser.headless!==undefined&&typeof browser.headless!=='boolean')throw Error('invalid_browser_headless');
  if(browser.executablePath!==undefined&&(typeof browser.executablePath!=='string'||!path.isAbsolute(browser.executablePath)))throw Error('invalid_browser_executable');
  return {...browser,headless:browser.headless??true};
}

import fs from 'node:fs';
import path from 'node:path';

// Resolve program files only. No daily profile discovery, CDP attachment or
// cookie import belongs in installed-browser detection.
export function installedBrowserCandidates({platform=process.platform,env=process.env}={}){
  if(platform==='linux')return [
    ['chrome','/opt/google/chrome/chrome'],['chrome','/usr/bin/google-chrome-stable'],['chrome','/usr/bin/google-chrome'],
    ['msedge','/opt/microsoft/msedge/msedge'],['msedge','/usr/bin/microsoft-edge-stable'],['msedge','/usr/bin/microsoft-edge']
  ];
  if(platform==='darwin')return [['chrome','/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'],['msedge','/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge']];
  if(platform==='win32'){
    const result=[];
    for(const [channel,relative] of [['chrome','Google/Chrome/Application/chrome.exe'],['msedge','Microsoft/Edge/Application/msedge.exe']])
      for(const root of [env.PROGRAMFILES,env['PROGRAMFILES(X86)'],env.LOCALAPPDATA].filter(Boolean))
        if(path.win32.isAbsolute(root))result.push([channel,path.win32.join(root,...relative.split('/'))]);
    return result;
  }
  return [];
}
const executable=file=>{try{if(!fs.statSync(file).isFile())return false;fs.accessSync(file,process.platform==='win32'?fs.constants.F_OK:fs.constants.X_OK);return true;}catch{return false;}};
export function resolveInstalledBrowser(browser,{platform=process.platform,env=process.env,isExecutable=executable}={}){
  if(browser.executablePath){if(!isExecutable(browser.executablePath))throw Error('browser_executable_unavailable');return {executablePath:browser.executablePath,channel:browser.channel??'custom',source:'configured_executable'};}
  if(!browser.channel)return null;
  if(!['auto','chrome','msedge'].includes(browser.channel))throw Error('invalid_browser_channel');
  const match=installedBrowserCandidates({platform,env}).find(([channel,file])=>(browser.channel==='auto'||browser.channel===channel)&&isExecutable(file));
  if(!match)throw Error('installed_browser_not_found');
  return {channel:match[0],executablePath:match[1],source:'installed_browser'};
}

import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const assert=(ok,message)=>{if(!ok)throw Error(message)};
export const SPARKLE_PIN=Object.freeze({version:'2.10.0',sha256:'c2bf58aa8387266ac179357b1415d6f2635f044da8be41042af32425dae6da0c'});
const links=Object.freeze(Object.fromEntries(['Sparkle','Autoupdate','Updater.app','XPCServices','Resources','Modules','Headers','PrivateHeaders'].map(n=>[n,'Versions/Current/'+n]).concat([['Versions/Current','B']])));
export function normalizeMacPlatformUpdate(value,{app,updateRelease=false}={}){
 if(value===undefined)return null;
 assert(value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).every(k=>['feedUrl','publicEdKey','sparkleArchive','isolatedProbe'].includes(k)),'invalid_platform_update_configuration');
 assert(updateRelease===true,'platform_update_requires_numbered_release');
 assert(typeof value.publicEdKey==='string'&&Buffer.from(value.publicEdKey,'base64').length===32&&Buffer.from(value.publicEdKey,'base64').toString('base64')===value.publicEdKey,'platform_update_public_key_required');
 assert(typeof value.sparkleArchive==='string'&&path.isAbsolute(value.sparkleArchive)&&path.normalize(value.sparkleArchive)===value.sparkleArchive&&!/[\x00-\x1f\x7f]/.test(value.sparkleArchive),'platform_update_absolute_archive_required');
 assert(value.isolatedProbe===undefined||typeof value.isolatedProbe==='boolean','invalid_platform_update_probe');
 let url;try{url=new URL(value.feedUrl)}catch{assert(false,'platform_update_feed_url_required')}
 const probe=value.isolatedProbe===true;
 assert(!url.username&&!url.password&&!url.hash&&!url.search&&url.href===value.feedUrl,'platform_update_feed_url_required');
 if(probe)assert(typeof app==='string'&&app.startsWith('/private/tmp/styx-platform-update-')&&path.normalize(app)===app&&path.basename(app)==='Styx.app','isolated_platform_update_app_required');
 assert(url.protocol==='https:'||(probe&&url.protocol==='http:'&&url.hostname==='127.0.0.1'&&url.port),'platform_update_https_required');
 return {...value,isolatedProbe:probe};
}
export function isSparkleFrameworkLink(app,file){
 const root=path.join(app,'Contents/Frameworks/Sparkle.framework'),rel=path.relative(root,file);
 if(!Object.hasOwn(links,rel)||!fs.lstatSync(file).isSymbolicLink())return false;
 assert(fs.readlinkSync(file)===links[rel],'sparkle_framework_link_changed');
 const resolved=fs.realpathSync(file);assert(resolved.startsWith(root+'/Versions/B/')||resolved===root+'/Versions/B','sparkle_framework_link_escape');return true;
}
export function stageMacSparkle(config,{app,buildRoot,run=execFileSync}){
 const archiveStat=fs.lstatSync(config.sparkleArchive);assert(archiveStat.isFile()&&!archiveStat.isSymbolicLink(),'regular_sparkle_archive_required');
 const bytes=fs.readFileSync(config.sparkleArchive);assert(createHash('sha256').update(bytes).digest('hex')===SPARKLE_PIN.sha256,'sparkle_archive_checksum_mismatch');
 const source=path.join(buildRoot,'sparkle');fs.mkdirSync(source,{mode:0o700});const archive=path.join(source,'pinned.tar.xz');fs.writeFileSync(archive,bytes,{flag:'wx',mode:0o600});
 run('/usr/bin/tar',['-xf',archive,'-C',source,'./Sparkle.framework','./LICENSE'],{stdio:'pipe'});
 const framework=path.join(app,'Contents/Frameworks/Sparkle.framework');fs.mkdirSync(path.dirname(framework),{recursive:true});
 run('/usr/bin/codesign',['--verify','--deep','--strict',path.join(source,'Sparkle.framework')],{stdio:'pipe'});
 run('/usr/bin/ditto',[path.join(source,'Sparkle.framework'),framework],{stdio:'pipe'});
 for(const name of Object.keys(links))assert(isSparkleFrameworkLink(app,path.join(framework,name)),'sparkle_framework_links_required');
 fs.copyFileSync(path.join(source,'LICENSE'),path.join(app,'Contents/Resources/licenses/Sparkle-LICENSE'));
 return {framework,frameworkSearchPath:path.dirname(framework),version:SPARKLE_PIN.version,archiveSha256:SPARKLE_PIN.sha256};
}
// Follow Sparkle's documented inside-out signing; retain its XPC entitlements.
// Local non-hardened previews retain the official framework's valid signature.
export function sparkleDistributionSigningPlan({app,identity,signingMode='distribution'}={}){
 if(!identity)return [];
 const root=path.join(app,'Contents/Frameworks/Sparkle.framework');
 const units=['Versions/B/XPCServices/Downloader.xpc','Versions/B/XPCServices/Installer.xpc','Versions/B/Autoupdate','Versions/B/Updater.app',''];
 return units.map(unit=>['/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',signingMode==='local-development'?'--timestamp=none':'--timestamp','--preserve-metadata=entitlements',path.join(root,unit)]]);
}

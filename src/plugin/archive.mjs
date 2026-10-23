// A deterministic, stored ZIP of one freshly validated plugin. This API takes
// configuration and proof, never filesystem roots, arbitrary members or secrets.
import {buildPackageFiles,crc32,PACKAGED_SKILLS} from './package.mjs';

const ALLOWED=new Set(['plugin.json','mcp.json',...PACKAGED_SKILLS.map(name=>`skills/${name}/SKILL.md`),'assets/icon.png']);
const MAX_ARCHIVE_BYTES=2*1024*1024;
export function buildPackageArchive(config,receipt,options={}){
 const built=buildPackageFiles(config,receipt,options),local=[],central=[],entries=[];
 let offset=0,centralSize=0;
 if(built.files.length<2+PACKAGED_SKILLS.length||built.files.length>3+PACKAGED_SKILLS.length)throw Error('invalid_plugin_archive_members');
 for(const file of built.files){
  if(!ALLOWED.has(file.path)||entries.includes('styx-native/'+file.path)||!Buffer.isBuffer(file.data))throw Error('invalid_plugin_archive_members');
  const member='styx-native/'+file.path,name=Buffer.from(member,'utf8'),size=file.data.length,checksum=crc32(file.data);
  if(size>MAX_ARCHIVE_BYTES||offset+30+name.length+size>MAX_ARCHIVE_BYTES)throw Error('plugin_archive_size_limit');
  const header=Buffer.alloc(30);header.writeUInt32LE(0x04034b50,0);header.writeUInt16LE(20,4);header.writeUInt16LE(0x0800,6);
  header.writeUInt16LE(0x0021,12); // 1980-01-01, fixed timestamps for reproducibility.
  header.writeUInt32LE(checksum,14);header.writeUInt32LE(size,18);header.writeUInt32LE(size,22);header.writeUInt16LE(name.length,26);
  local.push(header,name,file.data);
  const index=Buffer.alloc(46);index.writeUInt32LE(0x02014b50,0);index.writeUInt16LE((3<<8)|20,4);index.writeUInt16LE(20,6);index.writeUInt16LE(0x0800,8);
  index.writeUInt16LE(0x0021,14);index.writeUInt32LE(checksum,16);index.writeUInt32LE(size,20);index.writeUInt32LE(size,24);index.writeUInt16LE(name.length,28);
  index.writeUInt32LE((0o100600*65536)>>>0,38);index.writeUInt32LE(offset,42);
  central.push(index,name);entries.push(member);offset+=header.length+name.length+size;centralSize+=index.length+name.length;
 }
 const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(centralSize,12);end.writeUInt32LE(offset,16);
 const total=offset+centralSize+end.length;if(total>MAX_ARCHIVE_BYTES)throw Error('plugin_archive_size_limit');
 return {archive:Buffer.concat([...local,...central,end],total),fileName:'styx-native.zip',contentType:'application/zip',connection:built.connection,verificationScope:built.verificationScope,entries,status:'archive_created_not_installed'};
}

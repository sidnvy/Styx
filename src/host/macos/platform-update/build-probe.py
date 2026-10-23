from pathlib import Path
import subprocess,plistlib,shutil,os,json,hashlib,socket,sys
root=Path(sys.argv[1]).resolve()
assert str(root).startswith('/private/tmp/styx-sparkle-'), 'isolated private fixture root required'
assert root.exists() and root.stat().st_uid==os.getuid()
def run(a):return subprocess.check_output(a,stderr=subprocess.STDOUT,text=True)
probe=root/'probe';probe.mkdir(mode=0o700)
feed=probe/'feed';feed.mkdir();installed=probe/'installed';installed.mkdir();new=probe/'new';new.mkdir();events=probe/'observations';events.mkdir()
s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
key=probe/'fixture-ed25519-seed';public=run(['swift',str(root/'FixtureKey.swift'),str(key)]).strip();assert key.stat().st_mode&0o777==0o600
run(['swiftc','-target','arm64-apple-macosx13.0','-F',str(root),'-framework','Sparkle','-Xlinker','-rpath','-Xlinker','@executable_path/../Frameworks',str(root/'Probe.swift'),'-o',str(probe/'Probe')])
for version,parent in [('1',installed),('2',new)]:
 app=parent/'StyxSparkleProbe.app';contents=app/'Contents';(contents/'MacOS').mkdir(parents=True);(contents/'Frameworks').mkdir()
 shutil.copy2(probe/'Probe',contents/'MacOS'/'Probe');run(['ditto',str(root/'Sparkle.framework'),str(contents/'Frameworks'/'Sparkle.framework')])
 info={'CFBundleIdentifier':'app.styx.platform-update-probe.20261022','CFBundleName':'Styx Sparkle Probe','CFBundleExecutable':'Probe','CFBundlePackageType':'APPL','CFBundleVersion':version,'CFBundleShortVersionString':version+'.0','LSMinimumSystemVersion':'13.0','SUFeedURL':f'http://127.0.0.1:{port}/appcast.xml','SUPublicEDKey':public,'SUEnableAutomaticChecks':False,'SUAutomaticallyUpdate':False,'SUSendProfileInfo':False,'SUShowReleaseNotes':False,'SUVerifyUpdateBeforeExtraction':True,'StyxProbeOutput':str(events),'NSAppTransportSecurity':{'NSAllowsLocalNetworking':True}}
 (contents/'Info.plist').write_bytes(plistlib.dumps(info))
 # Ad-hoc code identity for the isolated fixture only. No trust/keychain changes.
 run(['codesign','--force','--deep','--sign','-',str(app)]);run(['codesign','--verify','--deep','--strict',str(app)])
zipfile=feed/'StyxSparkleProbe-2.zip';run(['ditto','-c','-k','--sequesterRsrc','--keepParent',str(new/'StyxSparkleProbe.app'),str(zipfile)])
# Official feed generator uses the explicit fixture seed; no Keychain access.
run([str(root/'bin/generate_appcast'),'--ed-key-file',str(key),'--download-url-prefix',f'http://127.0.0.1:{port}/',str(feed)])
log=open(probe/'feed-server.log','w');server=subprocess.Popen(['/usr/bin/python3','-m','http.server',str(port),'--bind','127.0.0.1','--directory',str(feed)],stdout=log,stderr=log,start_new_session=True)
receipt={'sparkleVersion':'2.10.0','appPath':str(installed/'StyxSparkleProbe.app'),'publicEdKey':public,'feedUrl':f'http://127.0.0.1:{port}/appcast.xml','serverPid':server.pid,'archiveSha256':hashlib.sha256(zipfile.read_bytes()).hexdigest(),'signing':'ad-hoc fixture App; archive Ed25519 with ephemeral private seed stored outside served directory','productionStyx':'UNCHANGED'}
(probe/'build-receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt))

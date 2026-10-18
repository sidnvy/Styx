"""Build an isolated, ad-hoc signed test host; never overwrites an existing app."""
from pathlib import Path
import sys,plistlib,subprocess,os,stat
root=Path(sys.argv[1])
assert root.is_absolute() and str(root).startswith('/private/tmp/styx-gb-')
if not root.exists(): root.mkdir(mode=0o700)
assert not root.is_symlink() and root.resolve()==root and root.stat().st_uid==os.geteuid()
assert stat.S_IMODE(root.stat().st_mode)&0o077==0
app=root/'Styx.app'
assert not app.exists(),'Refusing to overwrite an existing test app'
binary=app/'Contents/MacOS/Styx'
binary.parent.mkdir(parents=True)
(app/'Contents/Info.plist').write_bytes(plistlib.dumps({
 'CFBundleIdentifier':'com.styx.prototype.guibroker20261017',
 'CFBundleName':'Styx GUI Broker Prototype','CFBundleExecutable':'Styx',
 'CFBundlePackageType':'APPL','LSUIElement':True}))
subprocess.run(['/usr/bin/swiftc',str(Path(__file__).with_name('Styx.swift')),'-o',str(binary),'-framework','AppKit'],check=True)
subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(app)],check=True)
print(app)

"""Download a pinned official executor into prototype-owned .runtime only."""
import hashlib,json,pathlib,tarfile,urllib.request,shutil,tempfile,platform
if platform.system()!='Linux' or platform.machine()!='x86_64': raise SystemExit('This pinned pilot runtime requires Linux x86_64')
root=pathlib.Path(__file__).resolve().parent / '.runtime'
root.mkdir(exist_ok=True)
destination=root/'codex'
if destination.exists(): raise SystemExit('Refusing to overwrite existing runtime; inspect or remove it explicitly')
scratch=pathlib.Path(tempfile.mkdtemp(prefix='download-',dir=root))
try:
 archive=scratch/'codex.tar.gz'
 with urllib.request.urlopen('https://github.com/openai/codex/releases/download/rust-v0.163.0/codex-x86_64-unknown-linux-musl.tar.gz',timeout=60) as src,archive.open('wb') as dst:
  shutil.copyfileobj(src,dst)
 expected='beb339e8ecd9ba057a6bb2dc81ad8ca474812edfbf0fc5056ca818797648dde4'
 assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected,'Archive digest mismatch'
 with tarfile.open(archive) as tar:
  members=[m for m in tar.getmembers() if m.isfile() and '/' not in m.name and m.name.startswith('codex')]
  assert len(members)==1,'Unexpected archive structure'
  content=tar.extractfile(members[0]).read()
 with destination.open('xb') as dst: dst.write(content)
 destination.chmod(0o700)
 manifest={'release':'rust-v0.163.0','archive_sha256':expected,'binary_sha256':hashlib.sha256(content).hexdigest(),'platform':'linux-x86_64'}
 (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps(manifest),flush=True)
finally:
 shutil.rmtree(scratch)

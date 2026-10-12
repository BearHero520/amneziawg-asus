"""Deterministic dual architecture packages, core assets and update manifest."""
import re,gzip,hashlib,io,json,pathlib,struct,tarfile
root=pathlib.Path(__file__).resolve().parents[1];plugin=root/'plugin';version='0.5.0'
html=(plugin/'webs/Module_amneziawg.asp').read_text(encoding='utf-8')
for url in re.findall(r'(?:href|src)="(/res/[^\"]+)"',html):
 if url=='/res/softcenter.css':continue
 if '.css' in url:assert '?' not in url
 assert (plugin/url.split('?')[0].lstrip('/')).is_file(),url
out=root/'dist';out.mkdir(exist_ok=True);checks=[];assets={}
def emit(target,data):
 target.write_bytes(data);digest=hashlib.sha256(data).hexdigest();checks.append(digest+'  '+target.name)
 print(json.dumps({'file':str(target),'bytes':len(data),'sha256':digest},ensure_ascii=False));return digest
for arch,cls,machine in [('arm64',2,183),('armv7',1,40)]:
 binary=(root/'work/cores'/arch).read_bytes()
 assert binary[:4]==b'\x7fELF' and binary[4]==cls and struct.unpack_from('<H',binary,18)[0]==machine,arch
 core=out/f'amneziawg-core_{version}_{arch}';digest=emit(core,binary)
 assets[arch]={'url':f'https://github.com/BearHero520/amneziawg-asus/releases/download/v{version}/{core.name}','sha256':digest,'size':len(binary)}
 files={p.relative_to(plugin).as_posix():p.read_bytes() for p in plugin.rglob('*') if p.is_file() and 'bin' not in p.relative_to(plugin).parts}
 files['bin/amneziawg-go']=binary;files['package-arch']=(arch+'\n').encode();files['.valid']=b'hnd\n' if arch=='arm64' else b'hnd arm384\n'
 buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tf:
  for rel,data in sorted(files.items()):
   if pathlib.Path(rel).suffix in ('.sh','.asp','.js','.txt'):
    data=data.replace(b'\r\n',b'\n');assert not data.startswith(b'\xef\xbb\xbf'),rel
   ti=tarfile.TarInfo('amneziawg/'+rel);ti.size=len(data);ti.mode=0o755 if rel.endswith('.sh') or rel.startswith('bin/') else 0o644;ti.mtime=0;ti.uid=ti.gid=0;tf.addfile(ti,io.BytesIO(data))
 target=out/f'amneziawg_{version}_{arch}.tar.gz';emit(target,gzip.compress(buf.getvalue(),compresslevel=9,mtime=0))
 with tarfile.open(target,'r:gz') as tf:
  assert tf.extractfile('amneziawg/package-arch').read().decode().strip()==arch
  assert tf.extractfile('amneziawg/bin/amneziawg-go').read()==binary
  assert tf.getmember('amneziawg/install.sh').mode==0o755
  for m in tf.getmembers():assert m.name.startswith('amneziawg/') and '..' not in m.name
manifest=json.dumps({'version':version,'series':'0.5','abi':1,'assets':assets},indent=2)+'\n'
(root/'updates').mkdir(exist_ok=True);(root/'updates/preview.json').write_text(manifest,encoding='utf-8')
emit(out/f'amneziawg-core_{version}.json',manifest.encode());(out/'SHA256SUMS.txt').write_text('\n'.join(checks)+'\n',encoding='utf-8')

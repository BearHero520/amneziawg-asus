"""Deterministic Softcenter package, including executable POSIX modes."""
import re, gzip, hashlib, io, json, pathlib, struct, tarfile
root=pathlib.Path(__file__).resolve().parents[1]
plugin=root/'plugin'
binary=(plugin/'bin/amneziawg-go').read_bytes()
assert binary[:4]==b'\x7fELF' and binary[4]==2 and struct.unpack_from('<H',binary,18)[0]==183, 'not ARM64 ELF'
required=['.valid','install.sh','uninstall.sh','webs/Module_amneziawg.asp','res/amneziawg.js','res/amneziawg-ui.js','res/amneziawg-0.4.0.css','res/amneziawg-icons/home.svg','licenses/TABLER-MIT.txt','res/icon-amneziawg.png','licenses/AMNEZIAWG-MIT.txt']
for name in required: assert (plugin/name).is_file(), name
assert (plugin/'.valid').read_text().strip()=='hnd'
html=(plugin/'webs/Module_amneziawg.asp').read_text(encoding='utf-8')
for url in re.findall(r'(?:href|src)="(/res/[^\"]+)"',html):
    if url=='/res/softcenter.css': continue # firmware-owned stylesheet
    if '.css' in url: assert '?' not in url, 'CSS query strings unsupported by ASUS httpd'
    assert (plugin/url.split('?')[0].lstrip('/')).is_file(), 'missing page asset: '+url

out=root/'dist';out.mkdir(exist_ok=True)
tarbuffer=io.BytesIO()
with tarfile.open(fileobj=tarbuffer,mode='w',format=tarfile.USTAR_FORMAT) as tf:
    for file in sorted(plugin.rglob('*')):
        if not file.is_file():continue
        rel=file.relative_to(plugin).as_posix();data=file.read_bytes()
        if file.suffix in ('.sh','.asp','.js','.txt'):data=data.replace(b'\r\n',b'\n');assert not data.startswith(b'\xef\xbb\xbf'),rel
        ti=tarfile.TarInfo('amneziawg/'+rel);ti.size=len(data);ti.mode=0o755 if file.suffix=='.sh' or rel.startswith('bin/') else 0o644;ti.mtime=0;ti.uid=ti.gid=0
        tf.addfile(ti,io.BytesIO(data))
target=out/'amneziawg_0.4.0_arm64.tar.gz'
target.write_bytes(gzip.compress(tarbuffer.getvalue(),compresslevel=9,mtime=0))
digest=hashlib.sha256(target.read_bytes()).hexdigest()
(out/'SHA256SUMS.txt').write_text(digest+'  '+target.name+'\n',encoding='utf-8')
with tarfile.open(target,'r:gz') as tf:
    names=tf.getnames();assert 'amneziawg/install.sh' in names
    for member in tf.getmembers():assert member.name.startswith('amneziawg/') and '..' not in member.name
print(json.dumps({'package':str(target),'bytes':target.stat().st_size,'unpacked_bytes':sum(p.stat().st_size for p in plugin.rglob('*') if p.is_file()),'sha256':digest},ensure_ascii=False,indent=2))

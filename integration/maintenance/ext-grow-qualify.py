#!/usr/bin/env python3
"""Offline classic ext2 same-final-group growth; no mount or crash qualification."""
import argparse, hashlib, json, os, pathlib, struct, subprocess

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def u32(b,at):return struct.unpack_from('<I',b,at)[0]
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('binary','source-root','corpus','out'):p.add_argument('--'+n,type=pathlib.Path,required=True)
 a=p.parse_args()
 if not __debug__:p.error('optimized Python unsupported')
 if not all(x.is_absolute() for x in (a.binary,a.source_root,a.corpus,a.out)):p.error('absolute paths required')
 a.out.mkdir();receipt={'complete':False,'scope':__doc__,'runs':[]};dest=a.out/'qualification.json'
 def save():dest.write_text(json.dumps(receipt,indent=2)+'\n')
 save()
 try:
  assert sha(pathlib.Path(__file__).resolve())==sha(a.source_root/'integration/maintenance/ext-grow-qualify.py')
  original=json.loads((a.corpus/'receipt.json').read_text());assert original['complete']
  assert sha(a.corpus/'receipt.json')=='ff88372ea8bfcd8e2a070587e4a31ce4331ff12478aa49f8b0a02520abe68ca9'
  toolroot=pathlib.Path('/nix/store/k79ra63k4vr2srkwvjrqcppm5pamac5n-e2fsprogs-1.47.4-bin/bin');tools={n:toolroot/n for n in ('e2fsck','debugfs')}
  sources=sorted((a.source_root/'src').rglob('*.rs'))+[a.source_root/x for x in ('Cargo.toml','Cargo.lock','tests/fs_ext_geometry_grow_native.rs','integration/maintenance/ext-grow-qualify.py')]
  inputs=[a.corpus/'receipt.json']+[a.corpus/x for x in original['artifacts_sha256']]
  for name,h in original['artifacts_sha256'].items():assert sha(a.corpus/name)==h,name
  def source_paths():return sorted((a.source_root/'src').rglob('*.rs'))+[a.source_root/x for x in ('Cargo.toml','Cargo.lock','tests/fs_ext_geometry_grow_native.rs','integration/maintenance/ext-grow-qualify.py')]
  def snapshot():return {str(x):sha(x) for x in [a.binary,*source_paths(),*inputs,*tools.values()]}
  before=snapshot();receipt['bindings_before']=before;save()
  env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800')
  def run(name,argv,extra=None):
   e=dict(env);e.update(extra or {});r=subprocess.run(list(map(str,argv)),env=e,capture_output=True)
   for stream in ('stdout','stderr'):(a.out/(name+'.'+stream)).write_bytes(getattr(r,stream))
   receipt['runs'].append({'name':name,'argv':list(map(str,argv)),'environment_overrides':{k:e[k] for k in ('LC_ALL','TZ','E2FSCK_TIME')},'exit':r.returncode,'stdout_sha256':sha(a.out/(name+'.stdout')),'stderr_sha256':sha(a.out/(name+'.stderr'))});save()
   assert r.returncode==0,(name,r.returncode);return r.stdout
  gate=a.out/'rust';run('rust',[a.binary,'--ignored','--exact','native_same_final_group_ext2_grow','--nocapture'],{'PARTMGR_GATE_SOURCE_ROOT':str(a.source_root),'PARTMGR_EXT_GROW_CORPUS':str(a.corpus),'PARTMGR_EXT_GROW_EVIDENCE':str(gate)})
  report=json.loads((gate/'report.json').read_text());assert report['complete'] and len(report['profiles'])==3
  assert sha(gate/'gate-binary')==before[str(a.binary)]
  assert (gate/'source-start.sha256').read_bytes()==(gate/'source-end.sha256').read_bytes()
  expected={str(x.relative_to(a.source_root)):sha(x) for x in sources}
  captured={str(x.relative_to(gate/'compiled-source')):sha(x) for x in (gate/'compiled-source').rglob('*') if x.is_file()};assert captured==expected
  for m,row in zip(original['models'],report['profiles']):
   bs=m['block_bytes'];assert row['block_bytes']==bs
   image=gate/f'ext2-b{bs}.raw';assert sha(image)==row['sha256'];initial=(a.corpus/m['extended_before_resize']['path']).read_bytes();actual=image.read_bytes();native=(a.corpus/m['grown']['path']).read_bytes();old=m['before']['geometry']['blocks'];new=m['native_resize_target_blocks'];first=m['before']['geometry']['first'];assert row['blocks']==new
   # Independently reconstruct every permitted changed byte from original native metadata.
   wanted=bytearray(initial);gdt=(first+1)*bs;lastgd=gdt+32;bitmap=u32(initial,lastgd)*bs
   for bit in range(old-first-1024,new-first-1024):wanted[bitmap+bit//8]&=~(1<<(bit%8))
   for sb,gd in ((1024,gdt),((first+1024)*bs,(first+1025)*bs)):
    struct.pack_into('<I',wanted,sb+4,new);struct.pack_into('<I',wanted,sb+12,u32(initial,1024+12)+new-old)
    free=struct.unpack_from('<H',initial,gdt+32+12)[0];struct.pack_into('<H',wanted,gd+32+12,free+new-old)
    assert actual[sb+4:sb+8]==native[sb+4:sb+8]
    assert actual[sb+12:sb+16]==native[sb+12:sb+16]
    assert actual[gd+32+12:gd+32+14]==native[gd+32+12:gd+32+14]
   assert actual==wanted,'unexpected write or incorrect geometry/bitmap/canary'
   assert actual[bitmap:bitmap+bs]==native[bitmap:bitmap+bs],'native bitmap mismatch'
   run(f'b{bs}-fsck',[tools['e2fsck'],'-f','-n',image])
   for index,path in enumerate(m['unchanged_metadata_paths']):
    baseline=run(f'b{bs}-stat-before-{index}',[tools['debugfs'],'-R','stat '+path,a.corpus/m['before']['path']]);after=run(f'b{bs}-stat-after-{index}',[tools['debugfs'],'-R','stat '+path,image]);assert baseline==after,('changed inode metadata',path)
   for index,(path,key) in enumerate((('/alpha','alpha.bin'),('/alias','alpha.bin'),('/sub/nested','nested.bin'))):
    dump=a.out/f'b{bs}-dump-{index}.bin';run(f'b{bs}-dump-{index}',[tools['debugfs'],'-R',f'dump {path} {dump}',image]);assert sha(dump)==m['payload_sha256'][key]
   assert sha(image)==row['sha256'],'read-only native verification changed image'
  after=snapshot();assert before==after,'source/input/tool changed';receipt['bindings_after']=after;receipt['profiles']=report['profiles'];receipt['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};receipt['complete']=True;save()
 except BaseException as e:receipt['error']=repr(e);save();raise
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Qualify native_fresh_ext2_adapter_images and fail-closed source/tool bindings.
Uses actual fresh-file adapter, never a builder-only substitute. No mount/crash claim.
"""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 if not __debug__:p.error('Python assertion optimization is unsupported')
 for n in ('binary','source-root','out'): p.add_argument('--'+n,type=pathlib.Path,required=True)
 a=p.parse_args()
 if not all(x.is_absolute() for x in (a.binary,a.source_root,a.out)):p.error('absolute paths required')
 a.out.mkdir();receipt={'complete':False,'scope':'fresh classic ext2 adapter images and independent e2fsprogs; no mount, kernel-write, crash or hardware qualification','runs':[]};dest=a.out/'qualification.json'
 def save():dest.write_text(json.dumps(receipt,indent=2)+'\n')
 save()
 try:
  assert sha(pathlib.Path(__file__).resolve())==sha(a.source_root/'integration/maintenance/ext-format-qualify.py'),'executing verifier differs from bound source'
  tools={n:pathlib.Path(os.environ.get('PARTMGR_EXT_FORMAT_'+n.upper()) or shutil.which(n) or '/intentionally-missing/'+n).resolve() for n in ('e2fsck','debugfs')}
  for n,t in tools.items():
   if not t.is_file():raise ValueError('missing native tool '+n)
  def source_inventory():return sorted(x for base in ('src','tests') for x in (a.source_root/base).rglob('*.rs'))+[a.source_root/'Cargo.toml',a.source_root/'Cargo.lock',a.source_root/'integration/maintenance/ext-format-qualify.py']
  source_paths=source_inventory()
  def snapshot():return {str(x):sha(x) for x in [a.binary,*source_inventory(),*tools.values()]}
  before=snapshot();receipt['bindings_before']=before;shutil.copyfile(__file__,a.out/'runner-source.py');save()
  receipt['timing_scope']='single host run per block size: fresh-file creation, sizing, zero scan, full emission, file flush, byte verification and audit; cache state uncontrolled; debug_assertions recorded, optimization level not asserted; no cold-cache or hardware durability claim'
  env=dict(os.environ,E2FSCK_TIME='946684800',LC_ALL='C',TZ='UTC')
  def run(name,argv,expected=0,changes=None):
   e=dict(env);e.update(changes or {});r=subprocess.run([str(x) for x in argv],env=e,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   (a.out/(name+'.stdout')).write_bytes(r.stdout);(a.out/(name+'.stderr')).write_bytes(r.stderr)
   receipt['runs'].append({'name':name,'argv':[str(x) for x in argv],'exit':r.returncode});save()
   if expected is not None and r.returncode!=expected:raise ValueError(name+' unexpected exit '+str(r.returncode))
   return r
  for n,t in tools.items():run(n+'-version',[t,'-V'])
  gate=a.out/'positive';cmd=[a.binary,'--ignored','--exact','native_fresh_ext2_adapter_images','--nocapture']
  base={'PARTMGR_EXT_FORMAT_EVIDENCE':str(gate),'PARTMGR_GATE_SOURCE_ROOT':str(a.source_root)}
  run('positive',cmd,changes=base)
  report=json.loads((gate/'report.json').read_text());assert report['complete'] is True and sorted(x['block_size'] for x in report['profiles'])==[1024,2048,4096]
  receipt['profiles']=report['profiles']
  receipt['debug_assertions']=report['debug_assertions']
  assert sha(gate/'gate-binary')==before[str(a.binary)]
  assert (gate/'source-start.sha256').read_bytes()==(gate/'source-end.sha256').read_bytes()
  expected={str(x.relative_to(a.source_root)):sha(x) for x in source_paths}
  captured={str(x.relative_to(gate/'compiled-source')):sha(x) for x in (gate/'compiled-source').rglob('*') if x.is_file()}
  assert captured==expected,'compiled source inventory/hash mismatch'
  for item in report['profiles']:
   bs=item['block_size'];image=gate/f'ext2-b{bs}.raw';original=sha(image);assert original==item['sha256'] and image.stat().st_size==16<<20
   run(f'b{bs}-e2fsck',[tools['e2fsck'],'-f','-n',image])
   stats=run(f'b{bs}-stats',[tools['debugfs'],'-R','stats',image]).stdout.decode()
   fields={'Block count':'blocks','Free blocks':'free_blocks','Inode count':'inodes','Free inodes':'free_inodes'}
   for native,key in fields.items():assert int(re.search(r'^'+native+r':\s*(\d+)',stats,re.M)[1])==item[key],native
   assert int(re.search(r'^Block size:\s*(\d+)',stats,re.M)[1])==bs
   assert re.search(r'^Filesystem UUID:\s*39393939-3939-3939-3939-393939393939\s*$',stats,re.M)
   features=re.search(r'^Filesystem features:\s*(.*)$',stats,re.M)[1].split();assert set(features)=={'filetype','sparse_super'},features
   root=run(f'b{bs}-root-stat',[tools['debugfs'],'-R','stat <2>',image]).stdout.decode()
   for pattern in [r'Type:\s*directory',r'Mode:\s*0755',r'User:\s*0\s+Group:\s*0',r'Links:\s*2',rf'Size:\s*{bs}\b',rf'Blockcount:\s*{bs//512}\b',r'Flags:\s*0x0\b',r'Generation:\s*0\b']:
    assert re.search(pattern,root),pattern
   for field in ['ctime','atime','mtime']:assert re.search(field+r':\s*0x386d4380\b',root),field
   listing=run(f'b{bs}-root-ls',[tools['debugfs'],'-R','ls -p /',image]).stdout.decode()
   names=[line.split('/')[5] for line in listing.splitlines() if line.startswith('/')];assert sorted(names)==['.','..'],names
   assert sha(image)==original,'read-only native commands modified image'
  # Each exact gate must reject missing source and an existing evidence directory.
  for name,changed in [('missing-source',{'PARTMGR_GATE_SOURCE_ROOT':str(a.out/'absent'),'PARTMGR_EXT_FORMAT_EVIDENCE':str(a.out/'missing-source')}),('reused-evidence',{})]:
   changes=dict(base);changes.update(changed);assert run(name,cmd,expected=None,changes=changes).returncode!=0
  stale=a.out/'stale-source-clone';stale.mkdir()
  for source in source_paths:
   target=stale/source.relative_to(a.source_root);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
  with (stale/'src/fs_ext_builder.rs').open('ab') as changed:changed.write(b'\n// deliberate stale-compiled-source control\n')
  stale_out=a.out/'stale-source-evidence'
  assert run('stale-source',cmd,expected=None,changes={**base,'PARTMGR_GATE_SOURCE_ROOT':str(stale),'PARTMGR_EXT_FORMAT_EVIDENCE':str(stale_out)}).returncode!=0
  assert not list(stale_out.glob('*.raw')),'source failure created output images'
  missing=a.out/'missing-tool-control'
  child=run('missing-tool',[__import__('sys').executable,pathlib.Path(__file__).resolve(),'--binary',a.binary,'--source-root',a.source_root,'--out',missing],expected=None,changes={'PARTMGR_EXT_FORMAT_E2FSCK':str(a.out/'absent-e2fsck')})
  assert child.returncode!=0 and json.loads((missing/'qualification.json').read_text())['complete'] is False
  altered_runner=a.out/'altered-verifier.py'
  altered_runner.write_bytes(pathlib.Path(__file__).read_bytes()+b'\n# deliberate verifier-binding control\n')
  altered_out=a.out/'altered-verifier-control'
  altered=run('altered-verifier',[__import__('sys').executable,altered_runner,'--binary',a.binary,'--source-root',a.source_root,'--out',altered_out],expected=None)
  assert altered.returncode!=0 and json.loads((altered_out/'qualification.json').read_text())['complete'] is False
  for item in report['profiles']:
   assert sha(gate/f"ext2-b{item['block_size']}.raw")==item['sha256'],'negative controls changed verified output'
  assert snapshot()==before;receipt['bindings_after']=snapshot()
  receipt['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in a.out.rglob('*') if x.is_file() and x!=dest}
  receipt['complete']=True;save();return 0
 except (OSError,ValueError,KeyError,AssertionError,TypeError) as e:
  receipt['error']=repr(e);save();return 1
if __name__=='__main__':raise SystemExit(main())

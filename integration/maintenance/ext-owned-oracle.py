#!/usr/bin/env python3
"""Independently author classic ext3 owned-extension inputs; no partmgr execution."""
import argparse, hashlib, json, os, pathlib, re, shutil, struct, subprocess, sys

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('out',type=pathlib.Path);a=p.parse_args()
 if not __debug__:p.error('optimized Python unsupported')
 if not a.out.is_absolute():p.error('absolute fresh output required')
 a.out.mkdir();receipt={'complete':False,'scope':__doc__,'invocation':[sys.executable,*sys.argv],'commands':[],'models':[]};dest=a.out/'receipt.json'
 def save():dest.write_text(json.dumps(receipt,indent=2)+'\n')
 save()
 try:
  source=pathlib.Path(__file__).resolve();shutil.copyfile(source,a.out/'generator-source.py');receipt['source_sha256']=sha(source)
  prior=pathlib.Path('/data/cache/partmgr-ext-foreign-preflight-oracle-20261011-v3/receipt.json');old=json.loads(prior.read_text());receipt['prior_receipt']={'path':str(prior),'sha256':sha(prior)}
  toolroot=pathlib.Path('/nix/store/k79ra63k4vr2srkwvjrqcppm5pamac5n-e2fsprogs-1.47.4-bin/bin');tools={n:toolroot/n for n in ('mke2fs','debugfs','e2fsck','dumpe2fs')}
  receipt['tools']={n:{'path':str(t),'sha256':sha(t)} for n,t in tools.items()}
  for n in tools:
   if n in old['tools']:assert receipt['tools'][n]['sha256']==old['tools'][n]['sha256'],n
  env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800',E2FSPROGS_FAKE_TIME='946684800')
  def run(tool,args):
   i=len(receipt['commands']);argv=list(map(str,[tools[tool],*args]));r=subprocess.run(argv,env=env,capture_output=True)
   row={'argv':argv,'environment_overrides':{k:env[k] for k in ('LC_ALL','TZ','E2FSCK_TIME','E2FSPROGS_FAKE_TIME')},'exit':r.returncode}
   for name in ('stdout','stderr'):
    path=a.out/f'command-{i:03}.{name}';path.write_bytes(getattr(r,name));row[name]={'path':path.name,'sha256':sha(path)}
   receipt['commands'].append(row);save();assert r.returncode==0,(i,argv,r.returncode);return r.stdout,row
  def artifact(path):return {'path':path.name,'sha256':sha(path),'bytes':path.stat().st_size}
  for n in ('mke2fs','debugfs','e2fsck'):run(n,['-V'])
  for bs in (1024,2048,4096):
   image=a.out/f'ext3-b{bs}-before.raw'
   with image.open('xb') as f:f.truncate(16<<20)
   run('mke2fs',['-F','-t','ext3','-b',bs,'-I',128,'-m',0,'-O','none,has_journal,filetype,sparse_super','-U','22334455-6677-8899-aabb-ccddeeff0011','-E','lazy_itable_init=0,lazy_journal_init=0',image])
   raw=image.read_bytes();sb=raw[1024:2048];u=lambda at:struct.unpack_from('<I',sb,at)[0]
   geometry={'block_bytes':1024<<u(24),'blocks':u(4),'first':u(20),'blocks_per_group':u(32),'inodes_per_group':u(40),'inode_bytes':struct.unpack_from('<H',sb,88)[0],'features':[u(92),u(96),u(100)],'journal_inode':u(224)}
   assert geometry['block_bytes']==bs and geometry['inode_bytes']==128 and geometry['features']==[4,2,1] and geometry['journal_inode']==8,geometry
   run('e2fsck',['-f','-n',image])
   payload=a.out/f'payload-b{bs}.bin';append=a.out/f'append-b{bs}.bin';expected=a.out/f'expected-extended-b{bs}.bin';unrelated=a.out/f'unrelated-b{bs}.bin'
   payload.write_bytes(bytes((i*47+i//113)%255+1 for i in range(bs*11+37)))
   append.write_bytes(bytes((i*29+i//43+71)%255+1 for i in range(bs*3+71)))
   expected.write_bytes(payload.read_bytes()+append.read_bytes());unrelated.write_bytes(bytes((i*17+i//89+19)%255+1 for i in range(131089)))
   commands=[f'write "{payload}" /payload',f'write "{unrelated}" /unrelated','ln /unrelated /alias','set_inode_field /unrelated links_count 2','mkdir /sub']
   for native,mode,uid,gid in (('/payload','0100640',1234,2345),('/unrelated','0100600',3456,4567),('/sub','040750',5678,6789)):
    for field,value in (('mode',mode),('uid',uid),('gid',gid),('atime',946684800),('mtime',946684801),('ctime',946684802)):commands.append(f'set_inode_field {native} {field} {value}')
   commandfile=a.out/f'populate-b{bs}.cmd';commandfile.write_text('\n'.join(commands)+'\n');run('debugfs',['-w','-f',commandfile,image]);run('e2fsck',['-f','-n',image])
   raw=image.read_bytes();assert struct.unpack_from('<I',raw,1072)[0]==struct.unpack_from('<I',raw,1088)[0]==946684800,'native fake-time not honored';immutable=sha(image);metadata={}
   for native in ('/','/payload','/unrelated','/alias','/sub'):
    stdout,row=run('debugfs',['-R','stat '+native,image]);text=stdout.decode();inode=int(re.search(r'^Inode:\s*(\d+)',text,re.M)[1]);group=(inode-1)//geometry['inodes_per_group'];slot=(inode-1)%geometry['inodes_per_group'];gdt=(geometry['first']+1)*bs;table=struct.unpack_from('<I',raw,gdt+group*32+8)[0];at=table*bs+slot*128
    metadata[native]={'inode':inode,'raw_inode_hex':raw[at:at+128].hex(),'stat_path':row['stdout']['path']}
   assert metadata['/unrelated']['inode']==metadata['/alias']['inode']
   for native,wanted in (('/payload',payload),('/unrelated',unrelated),('/alias',unrelated)):
    output=a.out/f'extracted-b{bs}-{native[1:]}.bin';run('debugfs',['-R',f'dump {native} {output}',image]);assert output.read_bytes()==wanted.read_bytes()
   _,journal=run('debugfs',['-R','stat <8>',image]);run('dumpe2fs',['-h',image]);assert sha(image)==immutable
   receipt['models'].append({'block_bytes':bs,'image':artifact(image),'geometry':geometry,'payload':artifact(payload),'append':artifact(append),'expected_extended':artifact(expected),'unrelated':artifact(unrelated),'metadata_paths':list(metadata),'metadata':metadata,'journal_stat_path':journal['stdout']['path'],'expectation_policy':'expected extension is original payload concatenated with independently authored append; no native rm/write substitution or inode mutation is used'});save()
  assert sha(source)==receipt['source_sha256'];assert sha(prior)==receipt['prior_receipt']['sha256']
  for n,t in tools.items():assert sha(t)==receipt['tools'][n]['sha256']
  rows=[]
  for m in receipt['models']:
   fields=[str(m['block_bytes'])]
   for key in ('image','payload','append','expected_extended','unrelated'):fields.extend((m[key]['path'],m[key]['sha256']))
   fields.append(str(m['metadata']['/payload']['inode']));rows.append('\t'.join(fields))
  (a.out/'models.tsv').write_text('\n'.join(rows)+'\n')
  receipt['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};receipt['complete']=True;save();print(json.dumps({'complete':True,'models':len(receipt['models']),'commands':len(receipt['commands']),'receipt_sha256':sha(dest)}))
 except BaseException as e:receipt['error']=repr(e);save();raise
if __name__=='__main__':main()

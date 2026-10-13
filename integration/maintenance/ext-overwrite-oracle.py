#!/usr/bin/env python3
"""Native-authored classic EXT3 overwrite inputs; expected logical overlays, no allocation oracle."""
import argparse,hashlib,importlib.util,json,os,pathlib,shutil,struct,subprocess,sys
PRIOR='368ce6dae4ad3a375818de3e21e861e3a6596c15f115fb2fee117c4ea6351ec5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('out',type=pathlib.Path);p.add_argument('--prior',type=pathlib.Path,default=pathlib.Path('/data/cache/partmgr-ext-truncate-oracle-20261011-v2'));a=p.parse_args();assert __debug__ and a.out.is_absolute() and a.prior.is_absolute();a.out.mkdir();dest=a.out/'receipt.json';r={'complete':False,'schema_version':1,'scope':__doc__,'commands':[],'models':[],'cases':[],'invocation':sys.argv}
 def save():dest.write_text(json.dumps(r,indent=2)+'\n')
 def artifact(p):return {'path':p.name,'sha256':sha(p),'bytes':p.stat().st_size}
 save()
 try:
  source=pathlib.Path(__file__).resolve();shutil.copyfile(source,a.out/'generator-source.py');r['source_sha256']=sha(source);assert sha(a.prior/'receipt.json')==PRIOR;old=json.loads((a.prior/'receipt.json').read_text());assert old['complete'];r['prior_receipt']={'path':str(a.prior/'receipt.json'),'sha256':PRIOR}
  for n,h in old['artifacts_sha256'].items():assert pathlib.Path(n).name==n and sha(a.prior/n)==h
  dependency=source.with_name('ext-truncate-oracle.py');shutil.copyfile(dependency,a.out/'mapping-source.py');r['mapping_source_sha256']=sha(dependency);spec=importlib.util.spec_from_file_location('mapping',dependency);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
  tools={n:pathlib.Path(old['tools'][n]['path']) for n in ('debugfs','e2fsck')};r['tools']={n:{'path':str(t),'sha256':sha(t)} for n,t in tools.items()};assert all(r['tools'][n]==old['tools'][n] for n in tools);env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800',E2FSPROGS_FAKE_TIME='946684800')
  def run(tool,args):
   argv=list(map(str,[tools[tool],*args]));proc=subprocess.run(argv,env=env,capture_output=True);i=len(r['commands']);row={'argv':argv,'exit':proc.returncode,'environment_overrides':{k:env[k] for k in ('LC_ALL','TZ','E2FSCK_TIME','E2FSPROGS_FAKE_TIME')}}
   for stream in ('stdout','stderr'):
    out=a.out/f'command-{i:03}.{stream}';out.write_bytes(getattr(proc,stream));row[stream]=artifact(out)
   r['commands'].append(row);save();assert proc.returncode==0,(argv,proc.returncode)
  for prior in old['models']:
   bs=prior['block_bytes'];image=a.out/f'overwrite-b{bs}-before.raw';shutil.copyfile(a.prior/prior['image']['path'],image);run('debugfs',['-w','-R','punch /truncate-hole 1 1',image]);run('e2fsck',['-f','-n',image]);raw=image.read_bytes();sources={}
   for tag,src in prior['sources'].items():
    info=helper.mapping(raw,src['inode']);physical=b''.join(raw[x*bs:(x+1)*bs] if x else bytes(bs) for x in info['data_blocks']);payload=physical[:info['length']];body=a.out/f'payload-b{bs}-{tag}.bin';body.write_bytes(payload);full=a.out/f'physical-b{bs}-{tag}.bin';full.write_bytes(physical);sources[tag]={'path':src['path'],'alias':src['alias'],'inode':src['inode'],'raw_inode_hex':helper.raw_inode(raw,src['inode']).hex(),'mapping':info,'payload':artifact(body),'physical_payload':artifact(full)}
    dump=a.out/f'native-dump-b{bs}-{tag}.bin';run('debugfs',['-R',f'dump {src["path"]} {dump}',image]);assert dump.read_bytes()==payload
   assert sources['hole']['mapping']['data_blocks'][1]==0 and sources['hole']['mapping']['data_blocks'][0] and sources['hole']['mapping']['data_blocks'][2]
   r['models'].append({'block_bytes':bs,'image':artifact(image),'sources':sources,'journal_mapping':helper.mapping(raw,8)})
   cases=[('first-byte','direct',0,1),('aligned-full-block','direct',2*bs,bs),('unaligned-cross-block','direct',bs-17,bs+39),('cross-direct-indirect','indirect',11*bs+17,2*bs+23),('partial-eof','indirect',15*bs+11,62),('mapped-hole-mapped','hole',bs-17,bs+39)]
   for name,tag,offset,count in cases:
    src=sources[tag];payload=(a.out/src['payload']['path']).read_bytes();data=bytes(((i*79+bs//1024+len(name)*11)%251)+1 for i in range(count));assert offset+count<=len(payload);inp=a.out/f'input-b{bs}-{name}.bin';inp.write_bytes(data);expected=a.out/f'expected-b{bs}-{name}.bin';expected.write_bytes(payload[:offset]+data+payload[offset+count:]);r['cases'].append({'block_bytes':bs,'case':name,'image':artifact(image),'source_path':src['path'],'alias_path':src['alias'],'inode':src['inode'],'length':len(payload),'offset':offset,'input':artifact(inp),'payload':src['payload'],'expected_payload':artifact(expected)})
   prior_enospc=next(x for x in old['cases'] if x['block_bytes']==bs and x['case']=='enospc');full=a.out/f'overwrite-b{bs}-no-free.raw';shutil.copyfile(a.prior/prior_enospc['image']['path'],full);run('e2fsck',['-f','-n',full]);assert struct.unpack_from('<I',full.read_bytes(),1036)[0]==0;src=sources['direct'];inp=a.out/f'input-b{bs}-enospc.bin';inp.write_bytes(b'overwrite-no-original-free');r['cases'].append({'block_bytes':bs,'case':'enospc','image':artifact(full),'source_path':src['path'],'alias_path':src['alias'],'inode':src['inode'],'length':src['mapping']['length'],'offset':17,'input':artifact(inp),'payload':src['payload']})
  columns='bs case imagepath imagesha sourcepath inode length offset inputpath inputsha aliaspath'.split();lines=['\t'.join(columns)]
  for c in r['cases']:lines.append('\t'.join(map(str,[c['block_bytes'],c['case'],c['image']['path'],c['image']['sha256'],c['source_path'],c['inode'],c['length'],c['offset'],c['input']['path'],c['input']['sha256'],c['alias_path']])))
  (a.out/'cases.tsv').write_text('\n'.join(lines)+'\n');r['tsv_columns']=columns;r['artifacts_sha256']={x.name:sha(x) for x in sorted(a.out.iterdir()) if x.is_file() and x!=dest};r['complete']=True;save()
 except BaseException as e:r['error']=repr(e);save();raise
if __name__=='__main__':main()

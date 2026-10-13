#!/usr/bin/env python3
"""Native-authored classic EXT3 sparse-extension inputs; expected zero-filled sparse growth, no allocation oracle."""
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
  dependency=pathlib.Path('/home/rick/projects-caddy/partmgr/integration/maintenance/ext-truncate-oracle.py');shutil.copyfile(dependency,a.out/'mapping-source.py');r['mapping_source_sha256']=sha(dependency);spec=importlib.util.spec_from_file_location('mapping',dependency);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
  tools={n:pathlib.Path(old['tools'][n]['path']) for n in ('debugfs','e2fsck')};r['tools']={n:{'path':str(t),'sha256':sha(t)} for n,t in tools.items()};assert all(r['tools'][n]==old['tools'][n] for n in tools);env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800',E2FSPROGS_FAKE_TIME='946684800')
  def run(tool,args):
   argv=list(map(str,[tools[tool],*args]));proc=subprocess.run(argv,env=env,capture_output=True);i=len(r['commands']);row={'argv':argv,'exit':proc.returncode,'environment_overrides':{k:env[k] for k in ('LC_ALL','TZ','E2FSCK_TIME','E2FSPROGS_FAKE_TIME')}}
   for stream in ('stdout','stderr'):
    out=a.out/f'command-{i:03}.{stream}';out.write_bytes(getattr(proc,stream));row[stream]=artifact(out)
   r['commands'].append(row);save();assert proc.returncode==0,(argv,proc.returncode);return proc.stdout
  for prior in old['models']:
   bs=prior['block_bytes'];image=a.out/f'sparse-extension-b{bs}-before.raw';shutil.copyfile(a.prior/prior['image']['path'],image);additional={}
   for tag,data in (('empty',b''),('aligned',bytes(((i*67+bs//1024)%251)+1 for i in range(12*bs)))):
    body=a.out/f'native-input-b{bs}-{tag}.bin';body.write_bytes(data);native='/sparse-'+tag;run('debugfs',['-w','-R',f'write {body} {native}',image]);run('debugfs',['-w','-R',f'ln {native} {native}-alias',image]);run('debugfs',['-w','-R',f'set_inode_field {native} links_count 2',image])
    for field,value in (('mode','0100640'),('uid','123'),('gid','456'),('atime','946684800'),('ctime','946684800'),('mtime','946684800'),('generation','97')):run('debugfs',['-w','-R',f'set_inode_field {native} {field} {value}',image])
    text=run('debugfs',['-R',f'stat {native}',image]);import re;number=int(re.search(rb'^Inode: *([0-9]+)',text,re.M)[1]);additional[tag]={'path':native,'alias':native+'-alias','inode':number}
   run('e2fsck',['-f','-n',image]);raw=image.read_bytes();sources={}

   for tag,src in {**prior['sources'],**additional}.items():
    info=helper.mapping(raw,src['inode']);physical=b''.join(raw[x*bs:(x+1)*bs] if x else bytes(bs) for x in info['data_blocks']);payload=physical[:info['length']];body=a.out/f'payload-b{bs}-{tag}.bin';body.write_bytes(payload);full=a.out/f'physical-b{bs}-{tag}.bin';full.write_bytes(physical);sources[tag]={'path':src['path'],'alias':src['alias'],'inode':src['inode'],'raw_inode_hex':helper.raw_inode(raw,src['inode']).hex(),'mapping':info,'payload':artifact(body),'physical_payload':artifact(full)}
    dump=a.out/f'native-dump-b{bs}-{tag}.bin';run('debugfs',['-R',f'dump {src["path"]} {dump}',image]);assert dump.read_bytes()==payload
   assert sources['hole']['mapping']['data_blocks'][-1]==0
   for tag in ('direct','indirect'):
    info=sources[tag];physical=(a.out/info['physical_payload']['path']).read_bytes();length=info['mapping']['length'];assert all(physical[length:]),'independently authored hidden tail must be nonzero'
   r['models'].append({'block_bytes':bs,'image':artifact(image),'sources':sources,'journal_mapping':helper.mapping(raw,8)})
   def add_case(name,tag,new_length,chosen_image,refusal=False):
    src=sources[tag];payload=(a.out/src['payload']['path']).read_bytes();assert new_length>len(payload);expected=a.out/f'expected-b{bs}-{name}.bin';expected.write_bytes(payload+bytes(new_length-len(payload)));entry={'block_bytes':bs,'case':name,'image':artifact(chosen_image),'source_tag':tag,'source_path':src['path'],'alias_path':src['alias'],'inode':src['inode'],'old_length':len(payload),'new_length':new_length,'payload':src['payload'],'expected_payload':artifact(expected),'refusal':refusal};r['cases'].append(entry)
   for name,tag,new_length in (('empty-same','empty',17),('empty-cross-direct','empty',13*bs+19),('aligned-cross-single','aligned',(12+bs//4+1)*bs+23),('mapped-direct-same','direct',11*bs+73),('mapped-direct-cross','direct',13*bs+19),('mapped-indirect-cross-single','indirect',(12+bs//4+1)*bs+23),('hole-same','hole',3*bs+73),('hole-cross-single','hole',(12+bs//4+1)*bs+23)):add_case(name,tag,new_length,image)
   fullimage=a.out/f'sparse-extension-b{bs}-no-free.raw';shutil.copyfile(image,fullimage);fillpaths=[]
   def nodes(n):
    if n<=12:return 0
    n-=12;fan=bs//4;total=1;n-=min(n,fan)
    if n:total+=1+(n+fan-1)//fan
    return total
   for attempt in range(8):
    before=fullimage.read_bytes();free=struct.unpack_from('<I',before,1036)[0]
    if free==0:break
    low,high=1,free
    while low<high:
     middle=(low+high+1)//2
     if middle+nodes(middle)<=free:low=middle
     else:high=middle-1
    count=low;assert count+nodes(count)<=free;fill=a.out/f'fill-b{bs}-{attempt}.bin';fill.write_bytes(bytes([113+attempt])*(count*bs));native=f'/fill-{attempt}';run('debugfs',['-w','-R',f'write {fill} {native}',fullimage]);fillpaths.append(native)
    after=fullimage.read_bytes();assert struct.unpack_from('<I',after,1036)[0]==free-count-nodes(count),'native fill allocation differs'
   filled=fullimage.read_bytes();assert struct.unpack_from('<I',filled,1036)[0]==0;run('e2fsck',['-f','-n',fullimage]);assert fullimage.read_bytes()==filled
   for tag,info in sources.items():assert helper.raw_inode(filled,info['inode']).hex()==info['raw_inode_hex']
   add_case('no-free-aligned','aligned',13*bs+19,fullimage)
   add_case('no-free-hole','hole',13*bs+19,fullimage)
   add_case('enospc','direct',11*bs+73,fullimage,True)
  columns='bs case imagepath imagesha sourcepath inode oldlength newlength payloadpath payloadsha aliaspath'.split();lines=[]
  for c in r['cases']:lines.append('\t'.join(map(str,[c['block_bytes'],c['case'],c['image']['path'],c['image']['sha256'],c['source_path'],c['inode'],c['old_length'],c['new_length'],c['payload']['path'],c['payload']['sha256'],c['alias_path']])))
  assert sha(source)==r['source_sha256'] and sha(dependency)==r['mapping_source_sha256'] and sha(a.prior/'receipt.json')==PRIOR
  for n,h in old['artifacts_sha256'].items():assert sha(a.prior/n)==h
  for n,t in tools.items():assert sha(t)==r['tools'][n]['sha256']
  (a.out/'cases.tsv').write_text('\n'.join(lines)+'\n');r['tsv_columns']=columns;r['artifacts_sha256']={x.name:sha(x) for x in sorted(a.out.iterdir()) if x.is_file() and x!=dest};r['complete']=True;save()
 except BaseException as e:r['error']=repr(e);save();raise
if __name__=='__main__':main()

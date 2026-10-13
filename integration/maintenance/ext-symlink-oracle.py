#!/usr/bin/env python3
"""Native classic EXT3 symlink input corpus draft; never follows symlink targets."""
import argparse,hashlib,importlib.util,json,os,pathlib,re,shutil,struct,subprocess,sys
BASE_SHA='99698f8c91d1bd6215104a7d235b0ba38ff6eb7803ac895330cf46b1d6ebc98c'
GROW_SHA='4270bb2d4a715fe39ff9836d8938bc26558ca5ef5facac30eed6801000519a75'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('out',type=pathlib.Path);p.add_argument('--base',type=pathlib.Path,default=pathlib.Path('/data/cache/partmgr-ext-namespace-oracle-20261011-v1'));p.add_argument('--growth',type=pathlib.Path,default=pathlib.Path('/data/cache/partmgr-ext-directory-growth-oracle-20261011-v1'));a=p.parse_args();assert __debug__ and all(x.is_absolute() for x in (a.out,a.base,a.growth));assert re.fullmatch(r'/[A-Za-z0-9_./-]+',str(a.out)), 'debugfs output path must be command-token-safe';a.out.mkdir();dest=a.out/'receipt.json';r={'complete':False,'schema_version':1,'scope':__doc__,'invocation':sys.argv,'commands':[],'models':[],'cases':[]}
 def save():dest.write_text(json.dumps(r,indent=2)+'\n')
 def artifact(p):return {'path':p.name,'sha256':sha(p),'bytes':p.stat().st_size}
 save()
 try:
  source=pathlib.Path(__file__).resolve();shutil.copyfile(source,a.out/'generator-source.py');r['source_sha256']=sha(source);receipts={}
  for directory,expected in ((a.base,BASE_SHA),(a.growth,GROW_SHA)):
   assert sha(directory/'receipt.json')==expected;receipt=json.loads((directory/'receipt.json').read_text());assert receipt['complete'];receipts[directory]=receipt
   for n,h in receipt['artifacts_sha256'].items():assert pathlib.Path(n).name==n and sha(directory/n)==h
  r['priors']={str(d/'receipt.json'):sha(d/'receipt.json') for d in receipts};dependency=pathlib.Path('/home/rick/projects-caddy/partmgr/integration/maintenance/ext-truncate-oracle.py');shutil.copyfile(dependency,a.out/'mapping-source.py');r['mapping_source_sha256']=sha(dependency);spec=importlib.util.spec_from_file_location('mapping',dependency);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
  tools={n:pathlib.Path(receipts[a.base]['tools'][n]['path']) for n in ('debugfs','e2fsck')};r['tools']={n:{'path':str(t),'sha256':sha(t)} for n,t in tools.items()};assert all(r['tools'][n]==receipts[a.base]['tools'][n] for n in tools);env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800',E2FSPROGS_FAKE_TIME='946684800')
  def run(tool,args):
   argv=list(map(str,[tools[tool],*args]));proc=subprocess.run(argv,env=env,capture_output=True);i=len(r['commands']);row={'argv':argv,'exit':proc.returncode,'environment_overrides':{k:env[k] for k in ('LC_ALL','TZ','E2FSCK_TIME','E2FSPROGS_FAKE_TIME')}}
   for stream in ('stdout','stderr'):
    out=a.out/f'command-{i:04}.{stream}';out.write_bytes(getattr(proc,stream));row[stream]=artifact(out)
   r['commands'].append(row);save();assert proc.returncode==0,(argv,proc.returncode);return proc.stdout
  def counters(raw,require_full=False):
   bs=1024<<struct.unpack_from('<I',raw,1048)[0];first=struct.unpack_from('<I',raw,1044)[0];total=struct.unpack_from('<I',raw,1028)[0];bpg=struct.unpack_from('<I',raw,1056)[0];groups=(total-first+bpg-1)//bpg;gdt=(first+1)*bs;rows=[];total_inodes=struct.unpack_from('<I',raw,1024)[0];ipg=struct.unpack_from('<I',raw,1064)[0]
   for group in range(groups):
    at=gdt+group*32;bitmap=struct.unpack_from('<I',raw,at)[0];valid=min(bpg,total-first-group*bpg);bits=raw[bitmap*bs:(bitmap+1)*bs];free=sum(not(bits[i//8]&(1<<(i%8))) for i in range(valid));assert free==struct.unpack_from('<H',raw,at+12)[0]
    if require_full:assert free==0
    inode_bitmap=struct.unpack_from('<I',raw,at+4)[0];inode_valid=min(ipg,total_inodes-group*ipg);inode_bits=raw[inode_bitmap*bs:(inode_bitmap+1)*bs];free_inode_numbers=[group*ipg+i+1 for i in range(inode_valid) if not(inode_bits[i//8]&(1<<(i%8)))];assert len(free_inode_numbers)==struct.unpack_from('<H',raw,at+14)[0]
    rows.append({'group':group,'valid_blocks':valid,'bitmap':bitmap,'free_blocks':free,'bitmap_hex':bits.hex(),'inode_bitmap':inode_bitmap,'valid_inodes':inode_valid,'inode_bitmap_hex':inode_bits.hex(),'free_inode_numbers':free_inode_numbers})
   free=struct.unpack_from('<I',raw,1036)[0];assert free==sum(x['free_blocks'] for x in rows)
   free_inodes=struct.unpack_from('<I',raw,1040)[0];assert free_inodes==sum(len(x['free_inode_numbers']) for x in rows)
   return {'free_blocks':free,'free_inodes':free_inodes,'groups':rows}
  def insertion(raw,inode,name):
   bs=1024<<struct.unpack_from('<I',raw,1048)[0];need=(8+len(name)+3)&~3;slots=[]
   for block in helper.mapping(raw,inode)['data_blocks']:
    at=0
    while at<bs:
     number,size,nlen,kind=struct.unpack_from('<IHBB',raw,block*bs+at);assert size>=8 and size%4==0 and at+size<=bs
     available=size-((8+nlen+3)&~3) if number else size
     if available>=need:slots.append({'block':block,'offset':at,'available':available})
     at+=size
   return {'name_hex':name.hex(),'required':need,'slots':slots}
  inputs=[(a.base,m,'plain') for m in receipts[a.base]['models']]+[(a.growth,m,'grow-'+m['variant']) for m in receipts[a.growth]['models']]
  for directory,prior,variant in inputs:
   bs=prior['block_bytes'];image=a.out/f'symlink-b{bs}-{variant}-before.raw';shutil.copyfile(directory/prior['image']['path'],image);links={}
   for tag,length in (('fast1',1),('fast59',59),('slow60',60),('slowmax',bs-1)):
    # Exact command-safe ASCII bytes; no interpretation, target lookup or normalization.
    target=(b'relative/../dangling-'+bytes([97+length%20])*bs)[:length];native='/symlink-'+tag;run('debugfs',['-w','-R',f'symlink {native} {target.decode("ascii")}',image]);run('debugfs',['-w','-R',f'ln {native} {native}-alias',image]);run('debugfs',['-w','-R',f'set_inode_field {native} links_count 2',image])
    for field,value in (('uid','123'),('gid','456'),('atime','946684800'),('ctime','946684800'),('mtime','946684800'),('generation','101')):run('debugfs',['-w','-R',f'set_inode_field {native} {field} {value}',image])
    text=run('debugfs',['-R',f'stat {native}',image]);number=int(re.search(rb'^Inode: *([0-9]+)',text,re.M)[1]);raw=image.read_bytes();inode=helper.raw_inode(raw,number);assert struct.unpack_from('<H',inode)[0]&0xf000==0xa000 and struct.unpack_from('<I',inode,4)[0]==length and struct.unpack_from('<H',inode,26)[0]==2;sectors=struct.unpack_from('<I',inode,28)[0];pointers=list(struct.unpack_from('<15I',inode,40));block=None
    if length<60:
     assert sectors==0 and inode[40:40+length]==target and inode[40+length]==0;stored=inode[40:100]
    else:
     assert sectors==bs//512 and pointers[0] and all(x==0 for x in pointers[1:]);block=pointers[0];stored=raw[block*bs:(block+1)*bs];assert stored[:length]==target and stored[length]==0
    body=a.out/f'target-b{bs}-{variant}-{tag}.bin';body.write_bytes(target);storage=a.out/f'storage-b{bs}-{variant}-{tag}.bin';storage.write_bytes(stored);links[tag]={'path':native,'alias':native+'-alias','inode':number,'target':artifact(body),'storage':artifact(storage),'raw_inode_hex':inode.hex(),'sectors':sectors,'pointers':pointers,'physical_block':block,'storage_kind':'fast' if length<60 else 'slow'}
   raw=image.read_bytes();root_entries=helper.directory(raw,helper.mapping(raw,2))
   for info in links.values():
    for path in (info['path'],info['alias']):assert any(x['name_hex']==path[1:].encode().hex() and x['inode']==info['inode'] and x['kind']==7 for x in root_entries),'native symlink dirent/refcount mismatch'
   run('e2fsck',['-f','-n',image]);assert image.read_bytes()==raw;model={'block_bytes':bs,'variant':variant,'image':artifact(image),'symlinks':links,'root_directory_entries':root_entries,'journal_mapping':helper.mapping(raw,8)};r['models'].append(model)
   cases=(('create-fast1',None,'fast1'),('create-fast59',None,'fast59'),('create-slow60',None,'slow60'),('create-slowmax',None,'slowmax'),('replace-fast-fast','fast59','fast1'),('replace-fast-slow','fast1','slow60'),('replace-slow-fast','slow60','fast59'),('replace-slow-slow','slowmax','slow60'),('rename-fast','fast59',None),('rename-slow','slow60',None),('unlink-alias-fast','fast59',None),('unlink-alias-slow','slow60',None))
   for name,oldtag,newtag in cases:r['cases'].append({'block_bytes':bs,'variant':variant,'case':name,'image':model['image'],'source_tag':oldtag,'source':links.get(oldtag),'target':links[newtag]['target'] if newtag else None,'destination_parent':'/' if variant=='plain' else '/crowded','destination_name_hex':(b'new-symlink' if variant=='plain' else b'target-'+b'z'*248).hex()})
   # Each final-unlink case starts with a genuinely single-reference source.
   for tag in ('fast59','slow60'):
    final=a.out/f'symlink-b{bs}-{variant}-final-{tag}.raw';shutil.copyfile(image,final);info=links[tag];run('debugfs',['-w','-R',f"unlink {info['alias']}",final]);run('debugfs',['-w','-R',f"set_inode_field {info['path']} links_count 1",final]);single=final.read_bytes();entries=helper.directory(single,helper.mapping(single,2));assert sum(x['inode']==info['inode'] for x in entries)==1 and struct.unpack_from('<H',helper.raw_inode(single,info['inode']),26)[0]==1
    run('e2fsck',['-f','-n',final]);assert final.read_bytes()==single;single_info=dict(info,alias=None,raw_inode_hex=helper.raw_inode(single,info['inode']).hex());r['cases'].append({'block_bytes':bs,'variant':variant,'case':'unlink-final-'+tag,'image':artifact(final),'source_tag':tag,'source':single_info,'target':None,'expected_outcome':'success','counters':counters(single)})
   # Full images use native regular writes; no raw allocation-bit fabrication.
   full=a.out/f'symlink-b{bs}-{variant}-no-free.raw';shutil.copyfile(image,full);fills=[]
   def nodes(n):
    if n<=12:return 0
    n-=12;fan=bs//4;total=1;n-=min(n,fan)
    if n:total+=1+(n+fan-1)//fan
    return total
   for attempt in range(8):
    free=counters(full.read_bytes())['free_blocks']
    if not free:break
    lo,hi=1,free
    while lo<hi:
     mid=(lo+hi+1)//2
     if mid+nodes(mid)<=free:lo=mid
     else:hi=mid-1
    assert lo+nodes(lo)<=free and lo<=12+(bs//4)+(bs//4)**2
    fill=a.out/f'fill-b{bs}-{variant}-{attempt}.bin';fill.write_bytes(bytes([113+attempt])*(lo*bs));name=f'/fill-{attempt}';run('debugfs',['-w','-R',f'write {fill} {name}',full]);assert counters(full.read_bytes())['free_blocks']==free-lo-nodes(lo);fills.append({'native_path':name,'input':artifact(fill)})
   filled=full.read_bytes();allocation=counters(filled,True);assert allocation['free_blocks']==0 and allocation['free_inodes']>0
   for info in links.values():assert helper.raw_inode(filled,info['inode']).hex()==info['raw_inode_hex']
   parent=2 if variant=='plain' else next(x['inode'] for x in helper.directory(filled,helper.mapping(filled,2)) if x['name_hex']==b'crowded'.hex());name=b'new-symlink' if variant=='plain' else b'target-'+b'z'*248;slack=insertion(filled,parent,name);assert bool(slack['slots'])==(variant=='plain'),'no-free creation precondition changed'
   run('e2fsck',['-f','-n',full]);assert full.read_bytes()==filled
   for case,oldtag,newtag,success in (('replace-fast-fast','fast59','fast1',True),('replace-slow-fast','slow60','fast59',True),('replace-fast-slow','fast1','slow60',False),('replace-slow-slow','slowmax','slow60',False),('create-fast1',None,'fast1',variant=='plain'),('create-slow60',None,'slow60',False)):
    r['cases'].append({'block_bytes':bs,'variant':variant+'-no-free','case':case,'image':artifact(full),'source_tag':oldtag,'source':links.get(oldtag),'target':links[newtag]['target'],'destination_parent':'/' if variant=='plain' else '/crowded','destination_name_hex':name.hex(),'expected_outcome':'success' if success else 'zero-write-no-audited-free-blocks','counters':allocation,'insertion':slack,'fill_inputs':fills})
   # Command-safe unusual bytes are authored by native symlink, never resolved.
   unusual=a.out/f'symlink-b{bs}-{variant}-unusual.raw';shutil.copyfile(image,unusual);targets={ 'dangling':b'absent/path','dots':b'./.././absent//child','absolute':b'/absent/../target','self':b'/odd-self','cycle-a':b'/odd-cycle-b','cycle-b':b'/odd-cycle-a'};odd=[]
   for tag,target in targets.items():
    name='/odd-'+tag;run('debugfs',['-w','-R',f'symlink {name} {target.decode("ascii")}',unusual]);text=run('debugfs',['-R',f'stat {name}',unusual]);number=int(re.search(rb'^Inode: *([0-9]+)',text,re.M)[1]);inode=helper.raw_inode(unusual.read_bytes(),number);assert struct.unpack_from('<H',inode)[0]&0xf000==0xa000 and struct.unpack_from('<I',inode,4)[0]==len(target) and struct.unpack_from('<I',inode,28)[0]==0 and inode[40:40+len(target)]==target and inode[40+len(target)]==0;body=a.out/f'unusual-b{bs}-{variant}-{tag}.bin';body.write_bytes(target);odd.append({'path':name,'inode':number,'target':artifact(body),'raw_inode_hex':inode.hex()})
   unusual_raw=unusual.read_bytes();entries=helper.directory(unusual_raw,helper.mapping(unusual_raw,2))
   for info in odd:assert any(x['name_hex']==info['path'][1:].encode().hex() and x['inode']==info['inode'] and x['kind']==7 for x in entries)
   run('e2fsck',['-f','-n',unusual]);assert unusual.read_bytes()==unusual_raw;r.setdefault('unusual_models',[]).append({'block_bytes':bs,'variant':variant,'image':artifact(unusual),'symlinks':odd,'coverage':'ASCII command-safe targets only; nonUTF8 and embedded whitespace unqualified'})
  assert sha(source)==r['source_sha256'] and sha(dependency)==r['mapping_source_sha256']
  for directory,receipt in receipts.items():
   assert sha(directory/'receipt.json')==r['priors'][str(directory/'receipt.json')]
   for n,h in receipt['artifacts_sha256'].items():assert sha(directory/n)==h
  for n,t in tools.items():assert sha(t)==r['tools'][n]['sha256']
  r['artifacts_sha256']={x.name:sha(x) for x in sorted(a.out.iterdir()) if x.is_file() and x!=dest};r['complete']=True;save()
 except BaseException as e:r['error']=repr(e);save();raise
if __name__=='__main__':main()

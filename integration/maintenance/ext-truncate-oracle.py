#!/usr/bin/env python3
"""Native-authored ordered-truncate input corpus; no partmgr qualification."""
import argparse,hashlib,json,os,pathlib,re,shutil,struct,subprocess,sys
PRIOR='99698f8c91d1bd6215104a7d235b0ba38ff6eb7803ac895330cf46b1d6ebc98c'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def raw_inode(raw,number):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];ipg=struct.unpack_from('<I',raw,1064)[0];first=struct.unpack_from('<I',raw,1044)[0];group,slot=divmod(number-1,ipg);table=struct.unpack_from('<I',raw,(first+1)*bs+group*32+8)[0];return raw[table*bs+slot*128:table*bs+(slot+1)*128]
def mapping(raw,number):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];inode=raw_inode(raw,number);length=struct.unpack_from('<I',inode,4)[0];count=(length+bs-1)//bs;data=[];indirect=[];seen=set();work=0
 def walk(block,depth,slots):
  nonlocal work
  work+=1;assert work<=65536,'mapping work exhausted'
  if not block:data.extend([0]*min(slots,max(0,count-len(data))));return
  assert block not in seen and (block+1)*bs<=len(raw);seen.add(block)
  if not depth:data.append(block);return
  indirect.append(block)
  for child in struct.unpack('<'+'I'*(bs//4),raw[block*bs:(block+1)*bs]):walk(child,depth-1,(bs//4)**(depth-1))
 pointers=struct.unpack_from('<15I',inode,40)
 for block in pointers[:12]:walk(block,0,1)
 for block,depth in zip(pointers[12:],(1,2,3)):
  if len(data)>=count:assert block==0;continue
  walk(block,depth,(bs//4)**depth)
 assert all(block==0 for block in data[count:]);data=data[:count];assert len(data)==count
 return {'length':length,'data_blocks':data,'indirect_blocks':indirect}
def directory(raw,info):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];entries=[]
 for block in info['data_blocks']:
  data=raw[block*bs:(block+1)*bs];at=0
  while at<bs:
   inode,n,nlen,kind=struct.unpack_from('<IHBB',data,at);assert n>=8 and n%4==0 and at+n<=bs and nlen<=n-8
   if inode:entries.append({'name_hex':data[at+8:at+8+nlen].hex(),'inode':inode,'kind':kind,'physical_block':block,'offset':at})
   at+=n
 return entries

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('out',type=pathlib.Path);parser.add_argument('--prior',type=pathlib.Path,default=pathlib.Path('/data/cache/partmgr-ext-namespace-oracle-20261011-v1'));a=parser.parse_args()
 if not __debug__ or not a.out.is_absolute() or not a.prior.is_absolute():parser.error('nonoptimized Python and absolute paths required')
 a.out.mkdir();dest=a.out/'receipt.json';receipt={'schema_version':1,'complete':False,'scope':__doc__,'invocation':[sys.executable,*sys.argv],'commands':[],'models':[],'cases':[]}
 def save():dest.write_text(json.dumps(receipt,indent=2)+'\n')
 save()
 try:
  source=pathlib.Path(__file__).resolve();shutil.copyfile(source,a.out/'generator-source.py');receipt['source_sha256']=sha(source);prior=a.prior/'receipt.json';assert sha(prior)==PRIOR;old=json.loads(prior.read_text());assert old['complete'];receipt['prior_receipt']={'path':str(prior),'sha256':PRIOR}
  for name,h in old['artifacts_sha256'].items():assert pathlib.Path(name).name==name and sha(a.prior/name)==h
  tools={n:pathlib.Path(old['tools'][n]['path']) for n in ('debugfs','e2fsck','dumpe2fs')};receipt['tools']={n:{'path':str(t),'sha256':sha(t)} for n,t in tools.items()};assert receipt['tools']==old['tools'];env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800',E2FSPROGS_FAKE_TIME='946684800')
  def run(tool,args):
   i=len(receipt['commands']);argv=list(map(str,[tools[tool],*args]));r=subprocess.run(argv,env=env,capture_output=True);row={'argv':argv,'exit':r.returncode,'environment_overrides':{k:env[k] for k in ('LC_ALL','TZ','E2FSCK_TIME','E2FSPROGS_FAKE_TIME')}}
   for stream in ('stdout','stderr'):
    path=a.out/f'command-{i:03}.{stream}';path.write_bytes(getattr(r,stream));row[stream]={'path':path.name,'sha256':sha(path)}
   receipt['commands'].append(row);save();assert r.returncode==0,(argv,r.returncode);return r.stdout,row
  def artifact(path):return {'path':path.name,'sha256':sha(path),'bytes':path.stat().st_size}
  def number(image,native):
   text,row=run('debugfs',['-R','stat '+native,image]);match=re.search(rb'^Inode: *([0-9]+)',text,re.M);assert match,(native,text);return int(match[1]),row
  def counters(raw):
   bs=1024<<struct.unpack_from('<I',raw,1048)[0];first=struct.unpack_from('<I',raw,1044)[0];blocks=struct.unpack_from('<I',raw,1028)[0];bpg=struct.unpack_from('<I',raw,1056)[0];groups=(blocks-first+bpg-1)//bpg;gdt=(first+1)*bs;result={'free_blocks':struct.unpack_from('<I',raw,1036)[0],'free_inodes':struct.unpack_from('<I',raw,1040)[0],'groups':[]}
   for group in range(groups):
    at=gdt+group*32;bb,ib,it=struct.unpack_from('<III',raw,at);fb,fi,dirs=struct.unpack_from('<HHH',raw,at+12);result['groups'].append({'group':group,'block_bitmap':bb,'inode_bitmap':ib,'inode_table':it,'free_blocks':fb,'free_inodes':fi,'directories':dirs,'block_bitmap_hex':raw[bb*bs:(bb+1)*bs].hex(),'inode_bitmap_hex':raw[ib*bs:(ib+1)*bs].hex()})
   return result
  for prior_model in old['models']:
   bs=prior_model['block_bytes'];image=a.out/f'truncate-b{bs}-before.raw';shutil.copyfile(a.prior/prior_model['image']['path'],image);assert sha(image)==prior_model['image']['sha256'];run('e2fsck',['-f','-n',image]);commands=[];sources={}
   for tag,blocks,length in (('direct',12,11*bs+37),('indirect',16,15*bs+73),('hole',4,3*bs+37)):
    native='/truncate-'+tag;full=a.out/f'truncate-b{bs}-{tag}-full.bin';full.write_bytes(bytes((i*43+i//59+len(tag)*11)%255+1 for i in range(blocks*bs)));commands.extend([f'write "{full}" {native}',f'set_inode_field {native} size {length}']);sources[tag]={'path':native,'alias':native+'-alias','old_length':length,'full_input':artifact(full)}
    if tag=='hole':commands.append(f'punch {native} 3 3')
    commands.extend([f'ln {native} {native}-alias',f'set_inode_field {native} links_count 2'])
    for field,value in (('mode','0100640'),('uid',1234),('gid',2345),('atime',946684800),('mtime',946684801),('ctime',946684802)):commands.append(f'set_inode_field {native} {field} {value}')
   cmd=a.out/f'populate-truncate-b{bs}.cmd';cmd.write_text('\n'.join(commands)+'\n');run('debugfs',['-w','-f',cmd,image]);run('e2fsck',['-f','-n',image]);raw=image.read_bytes();immutable=sha(image);assert [struct.unpack_from('<I',raw,1024+n)[0] for n in (92,96,100)]==[4,2,1];metadata={}
   for native in prior_model['metadata_paths']:
    ino,row=number(image,native);node=raw_inode(raw,ino);item={'inode':ino,'raw_inode_hex':node.hex(),'mapping':mapping(raw,ino),'stat_path':row['stdout']['path']}
    if struct.unpack_from('<H',node)[0]&0xf000==0x4000:item['directory_entries']=directory(raw,item['mapping'])
    metadata[native]=item
    if native!='/':assert node.hex()==prior_model['metadata'][native]['raw_inode_hex'],'prior unrelated metadata changed'
   for tag,info in sources.items():
    ino,row=number(image,info['path']);alias,_=number(image,info['alias']);assert alias==ino;node=raw_inode(raw,ino);info.update({'inode':ino,'raw_inode_hex':node.hex(),'mapping':mapping(raw,ino),'stat_path':row['stdout']['path']});assert struct.unpack_from('<H',node,26)[0]==2 and info['mapping']['length']==info['old_length'];assert len(info['mapping']['indirect_blocks'])==int(tag=='indirect')
    full=(a.out/info['full_input']['path']).read_bytes();expected=full[:info['old_length']]
    if tag=='hole':assert info['mapping']['data_blocks']==info['mapping']['data_blocks'][:3]+[0];expected=expected[:3*bs]+bytes(37)
    else:
     block=info['mapping']['data_blocks'][-1];assert raw[block*bs+info['old_length']%bs:(block+1)*bs]==full[-bs+info['old_length']%bs:];assert all(raw[block*bs+info['old_length']%bs:(block+1)*bs]),'invisible tail not nonzero'
    payload=a.out/f'truncate-b{bs}-{tag}-payload.bin';payload.write_bytes(expected);info['payload']=artifact(payload);physical=a.out/f'truncate-b{bs}-{tag}-physical.bin';physical.write_bytes(b''.join(raw[b*bs:(b+1)*bs] for b in info['mapping']['data_blocks'] if b));info['physical_payload']=artifact(physical)
    for suffix,native in (('source',info['path']),('alias',info['alias'])):
     dump=a.out/f'truncate-b{bs}-{tag}-{suffix}-dump.bin';run('debugfs',['-R',f'dump {native} {dump}',image]);assert dump.read_bytes()==expected
   journal=mapping(raw,8);assert all(journal['data_blocks']);control=raw[journal['data_blocks'][0]*bs:journal['data_blocks'][0]*bs+1024];assert struct.unpack_from('>II',control,24)[1]==0
   payloads={}
   for native,key in (('/payload','payload'),('/unrelated','unrelated'),('/alias','unrelated'),('/left/tree/leaf','leaf'),('/indirect','indirect_file')):
    dump=a.out/f'truncate-b{bs}-prior-{native.strip("/").replace("/","-")}.bin';run('debugfs',['-R',f'dump {native} {dump}',image]);assert sha(dump)==prior_model[key]['sha256'];payloads[native]=artifact(dump)
   run('dumpe2fs',['-h',image]);assert sha(image)==immutable;model={'block_bytes':bs,'image':artifact(image),'sources':sources,'metadata':metadata,'prior_payloads':payloads,'counters':counters(raw),'journal_mapping':journal};receipt['models'].append(model)
   for case,tag,length in (('zero','direct',0),('boundary-direct','direct',5*bs),('boundary-indirect-drop','indirect',12*bs),('partial-direct','direct',5*bs+17),('partial-indirect','indirect',13*bs+19),('partial-hole','hole',3*bs+17)):
    sourceinfo=sources[tag];expected=a.out/f'expected-b{bs}-{case}.bin';expected.write_bytes((a.out/sourceinfo['payload']['path']).read_bytes()[:length]);receipt['cases'].append({'block_bytes':bs,'case':case,'image':model['image'],'source_tag':tag,'source_path':sourceinfo['path'],'alias_path':sourceinfo['alias'],'inode':sourceinfo['inode'],'old_length':sourceinfo['old_length'],'new_length':length,'payload':sourceinfo['payload'],'expected_payload':artifact(expected),'expected_outcome':'truncate original inode through both hardlinks; no name/link-count change'})
   save()
   # Independently fill a COPY with native regular data until no originally-free
   # block remains. Account classic pointer blocks before each native write.
   fullimage=a.out/f'truncate-b{bs}-no-free.raw';shutil.copyfile(image,fullimage);fillpaths=[]
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
   for tag,info in sources.items():assert raw_inode(filled,info['inode']).hex()==info['raw_inode_hex']
   receipt['cases'].append({'block_bytes':bs,'case':'enospc','image':artifact(fullimage),'source_tag':'direct','source_path':sources['direct']['path'],'alias_path':sources['direct']['alias'],'inode':sources['direct']['inode'],'old_length':sources['direct']['old_length'],'new_length':5*bs+17,'payload':sources['direct']['payload'],'expected_outcome':'mapped partial truncate COW refuses before writes; no original free blocks','free_blocks':0,'fill_paths':fillpaths,'counters':counters(filled)});save()
  columns='block_bytes case image_path image_sha256 source_path inode old_length new_length payload_path payload_sha256 alias_path'.split();receipt['tsv_columns']=columns;rows=[]
  for case in receipt['cases']:rows.append('	'.join(map(str,[case['block_bytes'],case['case'],case['image']['path'],case['image']['sha256'],case['source_path'],case['inode'],case['old_length'],case['new_length'],case['payload']['path'],case['payload']['sha256'],case['alias_path']])))
  (a.out/'cases.tsv').write_text('\n'.join(rows)+'\n');assert sha(source)==receipt['source_sha256'] and sha(prior)==PRIOR
  for name,h in old['artifacts_sha256'].items():assert sha(a.prior/name)==h
  for n,t in tools.items():assert sha(t)==receipt['tools'][n]['sha256']
  receipt['artifacts_sha256']={str(p.relative_to(a.out)):sha(p) for p in sorted(a.out.rglob('*')) if p.is_file() and p!=dest};receipt['complete']=True;save();print(json.dumps({'receipt':str(dest),'receipt_sha256':sha(dest),'cases_sha256':sha(a.out/'cases.tsv'),'models':len(receipt['models']),'cases':len(receipt['cases']),'commands':len(receipt['commands'])}))
 except BaseException as error:receipt['error']=repr(error);save();raise
if __name__=='__main__':main()

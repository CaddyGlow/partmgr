#!/usr/bin/env python3
"""Author immutable namespace-v4 EXT3 inputs with pinned native tools, without partmgr."""
import argparse,hashlib,json,os,pathlib,re,shutil,struct,subprocess,sys
PRIOR='1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf'
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
 assert all(block==0 for block in data[count:]);data=data[:count];assert len(data)==count and all(data)
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
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('out',type=pathlib.Path);parser.add_argument('--prior',type=pathlib.Path,default=pathlib.Path('/data/cache/partmgr-ext-owned-oracle-20261011-v3'));a=parser.parse_args()
 if not __debug__ or not a.out.is_absolute() or not a.prior.is_absolute():parser.error('nonoptimized Python and absolute paths required')
 a.out.mkdir();dest=a.out/'receipt.json';receipt={'schema_version':4,'complete':False,'scope':__doc__,'invocation':[sys.executable,*sys.argv],'commands':[],'models':[]}
 def save():dest.write_text(json.dumps(receipt,indent=2)+'\n')
 save()
 try:
  source=pathlib.Path(__file__).resolve();shutil.copyfile(source,a.out/'generator-source.py');receipt['source_sha256']=sha(source);prior=a.prior/'receipt.json';assert sha(prior)==PRIOR;old=json.loads(prior.read_text());assert old['complete'];receipt['prior_receipt']={'path':str(prior),'sha256':PRIOR}
  for name,h in old['artifacts_sha256'].items():assert pathlib.Path(name).name==name and sha(a.prior/name)==h
  tools={n:pathlib.Path(old['tools'][n]['path']) for n in ('debugfs','e2fsck','dumpe2fs')};receipt['tools']={n:{'path':str(t),'sha256':sha(t)} for n,t in tools.items()}
  for n in tools:assert receipt['tools'][n]==old['tools'][n]
  env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800',E2FSPROGS_FAKE_TIME='946684800')
  def run(tool,args):
   i=len(receipt['commands']);argv=list(map(str,[tools[tool],*args]));r=subprocess.run(argv,env=env,capture_output=True);row={'argv':argv,'exit':r.returncode,'environment_overrides':{k:env[k] for k in ('LC_ALL','TZ','E2FSCK_TIME','E2FSPROGS_FAKE_TIME')}}
   for stream in ('stdout','stderr'):
    path=a.out/f'command-{i:03}.{stream}';path.write_bytes(getattr(r,stream));row[stream]={'path':path.name,'sha256':sha(path)}
   receipt['commands'].append(row);save();assert r.returncode==0,(argv,r.returncode);return r.stdout,row
  def artifact(path):return {'path':path.name,'sha256':sha(path),'bytes':path.stat().st_size}
  for model in old['models']:
   bs=model['block_bytes'];image=a.out/f'ext3-namespace-b{bs}-before.raw';shutil.copyfile(a.prior/model['image']['path'],image);assert sha(image)==model['image']['sha256'];run('e2fsck',['-f','-n',image]);m={k:v for k,v in model.items() if k not in ('metadata','metadata_paths','image','journal_stat_path')}
   for key in ('payload','append','expected_extended','unrelated'):
    path=a.out/model[key]['path'];shutil.copyfile(a.prior/model[key]['path'],path);assert sha(path)==model[key]['sha256'];m[key]=artifact(path)
   leaf=a.out/f'leaf-b{bs}.bin';leaf.write_bytes(bytes((i*61+i//71+31)%255+1 for i in range(2*bs+19)));indirect=a.out/f'indirect-b{bs}.bin';indirect.write_bytes(bytes((i*37+i//97+11)%255+1 for i in range(15*bs+73)))
   commands=['mkdir /left','mkdir /right','mkdir /left/tree',f'write "{leaf}" /left/tree/leaf','mkdir /left/tree/child',f'write "{indirect}" /indirect']
   for native in ('/left','/right','/left/tree','/left/tree/leaf','/left/tree/child','/indirect'):
    for field,value in (('atime',946684800),('mtime',946684801),('ctime',946684802)):commands.append(f'set_inode_field {native} {field} {value}')
   commandfile=a.out/f'populate-namespace-b{bs}.cmd';commandfile.write_text('\n'.join(commands)+'\n');run('debugfs',['-w','-f',commandfile,image]);run('e2fsck',['-f','-n',image]);raw=image.read_bytes();immutable=sha(image);assert [struct.unpack_from('<I',raw,1024+n)[0] for n in (92,96,100)]==[4,2,1]
   metadata={}
   for native in ('/','/payload','/unrelated','/alias','/sub','/left','/right','/left/tree','/left/tree/leaf','/left/tree/child','/indirect'):
    stdout,row=run('debugfs',['-R','stat '+native,image]);match=re.search(rb'^Inode:\s*(\d+)',stdout,re.M);assert match;number=int(match[1]);inode=raw_inode(raw,number);info=mapping(raw,number);item={'inode':number,'raw_inode_hex':inode.hex(),'stat_path':row['stdout']['path'],'mapping':info}
    if struct.unpack_from('<H',inode)[0]&0xf000==0x4000:item['directory_entries']=directory(raw,info)
    metadata[native]=item
   for native,key in (('/payload','payload'),('/unrelated','unrelated'),('/alias','unrelated'),('/left/tree/leaf','leaf'),('/indirect','indirect')):
    wanted={'leaf':leaf,'indirect':indirect}.get(key,a.out/m.get(key,{}).get('path','unused'));output=a.out/f'extracted-b{bs}-{native.strip("/").replace("/","-")}.bin';run('debugfs',['-R',f'dump {native} {output}',image]);assert output.read_bytes()==wanted.read_bytes()
   for native in ('/left','/right','/left/tree','/left/tree/child'):
    entries={bytes.fromhex(x['name_hex']):x['inode'] for x in metadata[native]['directory_entries']};assert entries[b'.']==metadata[native]['inode'];parent=native.rsplit('/',1)[0] or '/';assert entries[b'..']==metadata[parent]['inode']
   assert metadata['/indirect']['mapping']['indirect_blocks'] and len(metadata['/indirect']['mapping']['data_blocks'])==16
   assert metadata['/unrelated']['inode']==metadata['/alias']['inode']
   for native in ('/payload','/unrelated','/alias','/sub'):assert metadata[native]['raw_inode_hex']==model['metadata'][native]['raw_inode_hex'],'prior unrelated metadata changed'
   _,row=run('debugfs',['-R','stat <8>',image]);run('dumpe2fs',['-h',image]);assert sha(image)==immutable;m.update({'block_bytes':bs,'image':artifact(image),'leaf':artifact(leaf),'indirect_file':artifact(indirect),'metadata':metadata,'metadata_paths':list(metadata),'journal_stat_path':row['stdout']['path'],'journal_mapping':mapping(raw,8)});receipt['models'].append(m);save()
  columns=['block_bytes','image_path','image_sha256','payload_path','payload_sha256','append_path','append_sha256','expected_extended_path','expected_extended_sha256','unrelated_path','unrelated_sha256','payload_inode','leaf_path','leaf_sha256','indirect_path','indirect_sha256','tree_inode','indirect_inode'];receipt['tsv_columns']=columns;rows=[]
  for m in receipt['models']:
   fields=[str(m['block_bytes'])]
   for key in ('image','payload','append','expected_extended','unrelated'):fields.extend([m[key]['path'],m[key]['sha256']])
   fields.append(str(m['metadata']['/payload']['inode']))
   for key in ('leaf','indirect_file'):fields.extend([m[key]['path'],m[key]['sha256']])
   fields.extend([str(m['metadata']['/left/tree']['inode']),str(m['metadata']['/indirect']['inode'])]);assert len(fields)==18;rows.append('\t'.join(fields))
  (a.out/'models.tsv').write_text('\n'.join(rows)+'\n');assert sha(source)==receipt['source_sha256'] and sha(prior)==PRIOR
  for name,h in old['artifacts_sha256'].items():assert sha(a.prior/name)==h
  for n,t in tools.items():assert sha(t)==receipt['tools'][n]['sha256']
  receipt['artifacts_sha256']={str(p.relative_to(a.out)):sha(p) for p in sorted(a.out.rglob('*')) if p.is_file() and p!=dest};receipt['complete']=True;save();print(json.dumps({'receipt':str(dest),'receipt_sha256':sha(dest),'models_sha256':sha(a.out/'models.tsv'),'models':len(receipt['models']),'commands':len(receipt['commands'])}))
 except BaseException as error:receipt['error']=repr(error);save();raise
if __name__=='__main__':main()

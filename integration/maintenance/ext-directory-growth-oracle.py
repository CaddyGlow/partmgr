#!/usr/bin/env python3
"""Native-authored packed directory inputs; preparation only, no partmgr qualification."""
import argparse,hashlib,json,os,pathlib,re,shutil,struct,subprocess,sys
PRIOR='99698f8c91d1bd6215104a7d235b0ba38ff6eb7803ac895330cf46b1d6ebc98c'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def inode(raw,number):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];first=struct.unpack_from('<I',raw,1044)[0];ipg=struct.unpack_from('<I',raw,1064)[0];group,slot=divmod(number-1,ipg);table=struct.unpack_from('<I',raw,(first+1)*bs+group*32+8)[0];return raw[table*bs+slot*128:table*bs+(slot+1)*128]
def mapping(raw,number):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];native=inode(raw,number);length=struct.unpack_from('<I',native,4)[0];count=(length+bs-1)//bs;assert count<=65536;data=[];metadata=[];seen=set();work=0
 def walk(block,depth,slots):
  nonlocal work
  work+=1;assert work<=65536
  if not block:data.extend([0]*min(slots,max(0,count-len(data))));return
  assert block not in seen and (block+1)*bs<=len(raw);seen.add(block)
  if not depth:data.append(block);return
  metadata.append(block)
  for child in struct.unpack('<'+'I'*(bs//4),raw[block*bs:(block+1)*bs]):walk(child,depth-1,(bs//4)**(depth-1))
 ptr=struct.unpack_from('<15I',native,40)
 for block in ptr[:12]:walk(block,0,1)
 for block,depth in zip(ptr[12:],(1,2,3)):
  if len(data)>=count:assert block==0;continue
  walk(block,depth,(bs//4)**depth)
 assert len(data)>=count and all(n==0 for n in data[count:]);data=data[:count];assert all(data)
 return {'length':length,'data_blocks':data,'indirect_blocks':metadata}
def records(raw,info):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];rows=[]
 for logical,block in enumerate(info['data_blocks']):
  data=raw[block*bs:(block+1)*bs];at=0
  while at<bs:
   number,n,nlen,kind=struct.unpack_from('<IHBB',data,at);assert n>=8 and n%4==0 and at+n<=bs and nlen<=n-8;minimum=((8+nlen+3)//4)*4;rows.append({'logical':logical,'physical_block':block,'offset':at,'inode':number,'record_bytes':n,'name_hex':data[at+8:at+8+nlen].hex(),'kind':kind,'minimum':minimum,'available':n-minimum if number else n});at+=n
 return rows

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('out',type=pathlib.Path);p.add_argument('--prior',type=pathlib.Path,default=pathlib.Path('/data/cache/partmgr-ext-namespace-oracle-20261011-v1'));a=p.parse_args()
 if not __debug__ or not a.out.is_absolute() or not a.prior.is_absolute():p.error('nonoptimized Python and absolute paths required')
 a.out.mkdir();dest=a.out/'receipt.json';receipt={'complete':False,'schema_version':1,'scope':__doc__,'invocation':[sys.executable,*sys.argv],'commands':[],'models':[]}
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
  empty=a.out/'empty.bin';empty.write_bytes(b'');target='target-'+('z'*248);assert len(target)==255;receipt['target_name_hex']=target.encode().hex();receipt['target_record_minimum']=264
  for m in old['models']:
   bs=m['block_bytes']
   for blocks,variant in ((1,'direct'),(12,'indirect')):
    image=a.out/f'packed-b{bs}-{variant}-before.raw';shutil.copyfile(a.prior/m['image']['path'],image);assert sha(image)==m['image']['sha256'];run('e2fsck',['-f','-n',image]);count=(bs-24)//264+(blocks-1)*(bs//264);names=[f'f{i:06}-'+('a'*247) for i in range(count)];assert all(len(n)==255 for n in names)
    commands=['mkdir /crowded']+[f'write "{empty}" /crowded/{name}' for name in names];cmd=a.out/f'populate-b{bs}-{variant}.cmd';cmd.write_text('\n'.join(commands)+'\n');run('debugfs',['-w','-f',cmd,image]);run('e2fsck',['-f','-n',image]);raw=image.read_bytes();immutable=sha(image);stdout,row=run('debugfs',['-R','stat /crowded',image]);number=int(re.search(rb'^Inode:\s*(\d+)',stdout,re.M)[1]);info=mapping(raw,number);assert info['length']==blocks*bs and len(info['data_blocks'])==blocks and not info['indirect_blocks'],(bs,variant,info)
    proof=records(raw,info);assert all(r['available']<264 for r in proof),'original directory has a usable slot';assert {bytes.fromhex(r['name_hex']).decode() for r in proof if r['inode']}==set(names)|{'.','..'};assert len([r for r in proof if r['inode']])==len(names)+2
    proofpath=a.out/f'packing-b{bs}-{variant}.json';proofpath.write_text(json.dumps({'source_image_sha256':immutable,'directory_inode':number,'original_directory_sha256':hashlib.sha256(b''.join(raw[n*bs:(n+1)*bs] for n in info['data_blocks'])).hexdigest(),'target_name_hex':target.encode().hex(),'target_minimum':264,'records':proof},indent=2)+'\n')
    metadata={}
    for native in m['metadata_paths']+['/crowded']:
     text,stat=run('debugfs',['-R','stat '+native,image]);ino=int(re.search(rb'^Inode:\s*(\d+)',text,re.M)[1]);native_inode=inode(raw,ino);item={'inode':ino,'raw_inode_hex':native_inode.hex(),'stat_path':stat['stdout']['path'],'mapping':mapping(raw,ino)}
     if struct.unpack_from('<H',native_inode)[0]&0xf000==0x4000:item['directory_records']=records(raw,item['mapping'])
     metadata[native]=item
    # Verify every filler is a genuine allocated empty native regular inode.
    for r in proof:
     if not r['inode'] or bytes.fromhex(r['name_hex']) in (b'.',b'..'):continue
     native=inode(raw,r['inode']);assert struct.unpack_from('<H',native)[0]&0xf000==0x8000 and struct.unpack_from('<I',native,4)[0]==0 and struct.unpack_from('<I',native,28)[0]==0
    payloads={}
    for native,key in (('/payload','payload'),('/unrelated','unrelated'),('/alias','unrelated'),('/left/tree/leaf','leaf'),('/indirect','indirect_file')):
     output=a.out/f'dump-b{bs}-{variant}-{native.strip("/").replace("/","-")}.bin';run('debugfs',['-R',f'dump {native} {output}',image]);assert sha(output)==m[key]['sha256'];payloads[native]=artifact(output)
    for native in m['metadata_paths']:
     if native!='/':assert metadata[native]['raw_inode_hex']==m['metadata'][native]['raw_inode_hex'],'unrelated metadata changed'
    run('dumpe2fs',['-h',image]);assert sha(image)==immutable
    # Separate native-authored expanded oracle, using explicit expansion then
    # directory link/unlink. This is not a native atomic rename operation claim.
    expected=a.out/f'packed-b{bs}-{variant}-native-expanded.raw';shutil.copyfile(image,expected);expectcmd=a.out/f'expand-b{bs}-{variant}.cmd';expectcmd.write_text(f'expand_dir /crowded\nln /payload /crowded/{target}\nunlink /payload\n');run('debugfs',['-w','-f',expectcmd,expected]);run('e2fsck',['-f','-n',expected]);expanded=expected.read_bytes();newinfo=mapping(expanded,number);assert newinfo['length']==(blocks+1)*bs and newinfo['data_blocks'][:blocks]==info['data_blocks'];assert len(newinfo['indirect_blocks'])==int(blocks==12)
    payloadinode=m['metadata']['/payload']['inode'];assert inode(expanded,payloadinode)==inode(raw,payloadinode);newrecords=records(expanded,newinfo);assert [r['inode'] for r in newrecords if bytes.fromhex(r['name_hex'])==target.encode()]==[payloadinode]
    receipt['models'].append({'block_bytes':bs,'variant':variant,'original_blocks':blocks,'filler_count':count,'image':artifact(image),'native_expanded_image':artifact(expected),'metadata':metadata,'payloads':payloads,'crowded_inode':number,'original_map':info,'expanded_map':newinfo,'packing_proof':artifact(proofpath),'prior_model_image':m['image'],'target_name_hex':target.encode().hex(),'oracle_policy':'expanded image native expand_dir then ln/unlink; no atomic native rename or production qualification claim'});save()
  assert sha(source)==receipt['source_sha256'] and sha(prior)==PRIOR
  for name,h in old['artifacts_sha256'].items():assert sha(a.prior/name)==h
  for n,t in tools.items():assert sha(t)==receipt['tools'][n]['sha256']
  rows=['\t'.join([str(m['block_bytes']),m['variant'],m['image']['path'],m['image']['sha256'],str(m['crowded_inode']),m['packing_proof']['path'],m['packing_proof']['sha256'],m['native_expanded_image']['path'],m['native_expanded_image']['sha256']]) for m in receipt['models']];(a.out/'models.tsv').write_text('\n'.join(rows)+'\n');receipt['tsv_columns']='block_bytes variant image_path image_sha256 crowded_inode packing_path packing_sha256 native_expanded_path native_expanded_sha256'.split();receipt['artifacts_sha256']={str(p.relative_to(a.out)):sha(p) for p in sorted(a.out.rglob('*')) if p.is_file() and p!=dest};receipt['complete']=True;save();print(json.dumps({'receipt':str(dest),'receipt_sha256':sha(dest),'models_sha256':sha(a.out/'models.tsv'),'models':len(receipt['models']),'commands':len(receipt['commands'])}))
 except BaseException as error:receipt['error']=repr(error);save();raise
if __name__=='__main__':main()

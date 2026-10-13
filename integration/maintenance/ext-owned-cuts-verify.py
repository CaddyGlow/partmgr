#!/usr/bin/env python3
"""Independent native replay of modeled private owned classic-ext3 transaction cuts."""
from collections import Counter
import argparse,re,csv,hashlib,json,os,pathlib,shutil,struct,subprocess
RECEIPT='1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def native_inode(data,inode):
 bs=1024<<struct.unpack_from('<I',data,1048)[0];first=struct.unpack_from('<I',data,1044)[0];ipg=struct.unpack_from('<I',data,1064)[0];size=struct.unpack_from('<H',data,1112)[0];group,slot=divmod(inode-1,ipg);gdt=(first+1)*bs;table=struct.unpack_from('<I',data,gdt+group*32+8)[0];return data[table*bs+slot*size:table*bs+(slot+1)*size]
def journal_blocks(data):
 bs=1024<<struct.unpack_from('<I',data,1048)[0];inode=native_inode(data,8);blocks=set();visited=set()
 def add(n,depth):
  if n==0:return
  assert n not in visited and (n+1)*bs<=len(data),'invalid journal mapping';visited.add(n)
  if not depth:blocks.add(n)
  if depth:
   for child in struct.unpack('<'+'I'*(bs//4),data[n*bs:(n+1)*bs]):add(child,depth-1)
 ptr=struct.unpack_from('<15I',inode,40)
 for n in ptr[:12]:add(n,0)
 for n,depth in zip(ptr[12:],(1,2,3)):add(n,depth)
 return bs,blocks
def classic_map(raw,number):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];inode=native_inode(raw,number);length=struct.unpack_from('<I',inode,4)[0];assert struct.unpack_from('<H',inode)[0]&0xf000 in (0x8000,0x4000)
 count=(length+bs-1)//bs;values=[];seen=set();metadata=set()
 def walk(block,depth,slots):
  if not block:values.extend([0]*slots);return
  assert block not in seen and (block+1)*bs<=len(raw),'aliased/outside classic map';seen.add(block)
  if not depth:values.append(block);return
  metadata.add(block)
  for child in struct.unpack('<'+'I'*(bs//4),raw[block*bs:(block+1)*bs]):walk(child,depth-1,(bs//4)**(depth-1))
 pointers=struct.unpack_from('<15I',inode,40)
 for block in pointers[:12]:walk(block,0,1)
 for block,depth in zip(pointers[12:],(1,2,3)):
  if len(values)>=count:
   assert block==0,'preallocation beyond EOF';continue
  walk(block,depth,(bs//4)**depth)
 assert all(x==0 for x in values[count:]),'preallocation beyond EOF'
 return length,values[:count],metadata

def root_names(raw):
 bs=1024<<struct.unpack_from('<I',raw,1048)[0];length,blocks,_=classic_map(raw,2);names={}
 for block in blocks:
  assert block;data=raw[block*bs:(block+1)*bs];at=0
  while at<bs:
   ino,n,nlen=struct.unpack_from('<IHB',data,at);assert n>=8 and n%4==0 and at+n<=bs and nlen<=n-8
   if ino:
    name=data[at+8:at+8+nlen];assert name not in names;names[name]=ino
   at+=n
 return names

def ordered_redo_proof(base,final,bs,data_blocks,indirect):
 # Parse only the admitted legacy checksumless native framing; owned footer
 # padding is opaque to this independent native descriptor interpretation.
 _,journal,journal_meta=classic_map(base,8);assert journal and all(journal)
 assert classic_map(final,8)[1:]==(journal,journal_meta)
 def block(raw,logical):
  assert 0<=logical<len(journal);return raw[journal[logical]*bs:(journal[logical]+1)*bs]
 original=block(base,0);clean=block(final,0)
 magic,kind,_=struct.unpack_from('>III',original);assert magic==0xc03b3998 and kind==4
 blocksize,maximum,first,sequence,start=struct.unpack_from('>IIIII',original,12)
 assert blocksize==bs and 1<=first<maximum<=len(journal) and start==0
 assert struct.unpack_from('>III',original,36)==(0,0,0),'unqualified journal features'
 assert original[48:64]==base[1128:1144]
 assert clean[:24]==original[:24] and clean[32:64]==original[32:64]
 assert struct.unpack_from('>II',clean,24)==((sequence+2)&0xffffffff,0),'unexpected final journal controls'
 uuid=original[48:64];logical=first;visited=set();transcript=[]
 def consume():
  nonlocal logical
  assert logical not in visited and len(visited)<maximum-first,'journal ring traversal repeated/exhausted'
  visited.add(logical);at=logical;raw=block(final,at);logical=first if logical+1==maximum else logical+1;return at,raw
 def transaction(seq):
  destinations={};descriptors=0
  while True:
   at,raw=consume();header=struct.unpack_from('>III',raw)
   if header==(0xc03b3998,2,seq):
    assert descriptors and destinations,'empty mutation transaction';transcript.append({'kind':'commit','sequence':seq,'logical':at,'raw_sha256':hashlib.sha256(raw).hexdigest()});return destinations
   assert header==(0xc03b3998,1,seq),'unexpected descriptor sequence/type'
   descriptors+=1;position=12;tags=[];tag_destinations=set();last=False;tag_uuid=None
   while not last:
    assert position+8<=bs,'missing LAST_TAG';destination,flags=struct.unpack_from('>II',raw,position);position+=8
    assert flags&~11==0,'unsupported/deleted tag flags'
    if not flags&2:
     assert position+16<=bs;tag_uuid=raw[position:position+16];position+=16;assert tag_uuid==uuid,'foreign tag UUID'
    else:assert tag_uuid==uuid,'SAME_UUID before explicit UUID'
    assert destination not in destinations and destination not in tag_destinations and destination not in journal and destination not in journal_meta and (destination+1)*bs<=len(final),'invalid/duplicate redo destination'
    tag_destinations.add(destination);tags.append((destination,flags));last=bool(flags&8)
   transcript.append({'kind':'descriptor','sequence':seq,'logical':at,'raw_sha256':hashlib.sha256(raw).hexdigest(),'tags':[{'destination':n,'flags':f} for n,f in tags]})
   for destination,flags in tags:
    payload_at,payload=consume()
    if flags&1:assert payload[:4]==bytes(4);payload=struct.pack('>I',0xc03b3998)+payload[4:]
    destinations[destination]=payload;transcript.append({'kind':'data','sequence':seq,'logical':payload_at,'destination':destination,'flags':flags,'decoded_sha256':hashlib.sha256(payload).hexdigest()})
 preparation=transaction(sequence);primary=int(bs==1024);assert set(preparation)=={primary}
 expected=bytearray(base[primary*bs:(primary+1)*bs]);inside=1024%bs;features=struct.unpack_from('<I',expected,inside+96)[0];assert features&4==0;struct.pack_into('<I',expected,inside+96,features|4);assert preparation[primary]==expected,'preparation changes more than recovery flag'
 mutation=transaction((sequence+1)&0xffffffff)
 assert not set(mutation)&set(data_blocks),'regular-file data was journaled'
 assert set(indirect)<=set(mutation),'new indirect metadata missing from redo'
 for destination,payload in mutation.items():
  expected=bytearray(final[destination*bs:(destination+1)*bs])
  if destination==primary:
   features=struct.unpack_from('<I',expected,inside+96)[0];assert features&4==0;struct.pack_into('<I',expected,inside+96,features|4)
  assert payload==expected,'mutation redo differs from final home beyond exact RECOVER bit'
 return {'original_sequence':sequence,'first':first,'maximum':maximum,'journal_map':journal,'mutation_destinations':sorted(mutation),'regular_data_destinations':data_blocks,'new_indirect_destinations':sorted(indirect),'records':transcript}

def ordered_verify(a,gate,models,run,tools,result,save,artifact):
 columns='bs operation case event model fault_kind prefix pre_sha256 pre_path retried_sha256 retried_path result'.split()
 with (gate/'cuts.tsv').open(newline='') as f:
  reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames==columns;rows=list(reader)
 gate_before={str(x.relative_to(gate)):sha(x) for x in sorted(gate.rglob('*')) if x.is_file()}
 profiles={}
 for line in (gate/'observations.txt').read_text().splitlines():
  match=re.fullmatch(r'bs=(\d+) operation=(extend|create) events=(\d+) baseline=(images/([0-9a-f]{64})\.raw)',line)
  if match:profiles[(int(match[1]),match[2])]=(int(match[3]),match[4],match[5])
 assert set(profiles)=={(bs,op) for bs in (1024,2048,4096) for op in ('extend','create')}
 bases={};success={};masks={};journals={};coverage=Counter();expected=Counter();unique={};retries={};cases=set();intermediate=set()
 for (bs,op),(events,path,h) in profiles.items():
  m=models[bs];base=(a.corpus/m['image']['path']).read_bytes();final=artifact(path,h).read_bytes();assert len(base)==len(final);bases[bs]=base;success[bs,op]=final;_,journals[bs]=journal_blocks(base)
  wtime=struct.unpack_from('<I',base,1072)[0];lastcheck=struct.unpack_from('<I',base,1088)[0];assert wtime==lastcheck and wtime>0,'source checker timestamps disagree';result.setdefault('checker_times',{})[str(bs)]=str(wtime)
  assert native_inode(base,8)==native_inode(final,8);oldnames=root_names(base);newnames=root_names(final);name=b'payload' if op=='extend' else b'new-ordered';assert name in newnames
  if op=='create':assert name not in oldnames and set(newnames)==set(oldnames)|{name}
  else:assert newnames==oldnames
  inode=newnames[name];newlen,newmap,indirect=classic_map(final,inode);oldlen,oldmap,oldindirect=classic_map(base,inode) if op=='extend' else (0,[],set());wanted=(a.corpus/m['expected_extended' if op=='extend' else 'append']['path']).read_bytes();assert newlen==len(wanted)
  assert newmap[:len(oldmap)]==oldmap,'existing map replaced';ranges=[];first=struct.unpack_from('<I',base,1044)[0];bpg=struct.unpack_from('<I',base,1056)[0];gdt=(first+1)*bs
  for logical,block in enumerate(newmap):
   assert block and block not in journals[bs] and block not in indirect
   if logical<len(oldmap):
    if logical==oldlen//bs and oldlen%bs:ranges.append((block*bs+oldlen%bs,bs-oldlen%bs))
    continue
   group,bit=divmod(block-first,bpg);bitmap=struct.unpack_from('<I',base,gdt+group*32)[0];assert base[bitmap*bs+bit//8]&(1<<(bit%8))==0,'new regular data originally allocated';ranges.append((block*bs,bs))
  assert len(set(newmap))==len(newmap);ranges.sort();masks[bs,op]=ranges
  proof=ordered_redo_proof(base,final,bs,newmap,indirect-oldindirect);(a.out/f'ordered-redo-b{bs}-{op}.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
  with (gate/f'mask-b{bs}-{op}.tsv').open(newline='') as f:
   reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames==['offset','bytes'];assert [(int(x['offset']),int(x['bytes'])) for x in reader]==ranges,'reported mask differs from independent bitmap/map proof'
  with (gate/f'events-b{bs}-{op}.tsv').open(newline='') as f:
   reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames==['event','kind','bytes'];spec=list(reader)
  assert [int(x['event']) for x in spec]==list(range(1,events+1))
  for event in spec:
   kind=event['kind'];n=int(event['bytes']);assert kind in ('write','flush') and (n>0 if kind=='write' else n==0)
   selectors=[('write',v) for v in (0,n//2,n) for _ in range(2)] if kind=='write' else [('flush-none',0),('flush-persist',0)]
   expected.update((bs,op,int(event['event']),model,k,v) for model in ('immediate','volatile') for k,v in selectors)
 def equal(x,y,bs,op,old=False):
  if len(x)!=len(y):return False
  ranges=[(block*bs,bs) for block in journals[bs]]+(masks[bs,op] if old else []);at=0
  for start,n in sorted(ranges):
   if start<at:assert start+n<=at;continue
   if x[at:start]!=y[at:start]:return False
   at=start+n
  return x[at:]==y[at:]
 def decision(raw,bs,op):
  old=equal(raw,bases[bs],bs,op,True);new=equal(raw,success[bs,op],bs,op);assert old!=new,'partial/ambiguous ordered home image';return 'old' if old else 'new'
 for row in rows:
  bs=int(row['bs']);op=row['operation'];key=(bs,op);assert key in profiles;case=int(row['case']);assert (key,case) not in cases;cases.add((key,case));coverage[(bs,op,int(row['event']),row['model'],row['fault_kind'],int(row['prefix']))]+=1
  pre=artifact(row['pre_path'],row['pre_sha256']);retry=artifact(row['retried_path'],row['retried_sha256']);raw=retry.read_bytes();assert decision(raw,bs,op)==row['result'];unique[(bs,op,row['pre_sha256'])]=pre;retries.setdefault((bs,op,row['pre_sha256']),[]).append((retry,row['result']))
  persisted=pre.read_bytes()
  for start,n in masks[key]:
   part=persisted[start:start+n]
   if part not in (bases[bs][start:start+n],success[key][start:start+n]):intermediate.add(key)
 assert coverage==expected,'ordered interruption coverage mismatch';assert intermediate==set(profiles),'missing genuine partial ordered data cut'
 def inspect(image,bs,op,label,outcome):
  m=models[bs];raw=image.read_bytes();names=root_names(raw);wanted=(a.corpus/m['expected_extended' if op=='extend' and outcome=='new' else 'payload']['path']).read_bytes();dump=a.out/(label+'-payload.bin');run(label+'-payload',[tools['debugfs'],'-R',f'dump /payload {dump}',image]);assert dump.read_bytes()==wanted
  if op=='create':
   assert (b'new-ordered' in names)==(outcome=='new')
   if outcome=='new':
    dump=a.out/(label+'-created.bin');run(label+'-created',[tools['debugfs'],'-R',f'dump /new-ordered {dump}',image]);assert dump.read_bytes()==(a.corpus/m['append']['path']).read_bytes()
    created=native_inode(raw,names[b'new-ordered']);oldslot=native_inode(bases[bs],names[b'new-ordered']);_,createdmap,createdmeta=classic_map(raw,names[b'new-ordered']);assert struct.unpack_from('<H',created)[0]==0o100644 and struct.unpack_from('<H',created,26)[0]==1
    assert created[2:4]==bytes(2) and created[8:26]==bytes(18) and created[32:40]==bytes(8) and created[104:128]==bytes(24),'creation changed zero native template fields'
    assert struct.unpack_from('<I',created,28)[0]==(len(createdmap)+len(createdmeta))*bs//512 and struct.unpack_from('<I',created,100)[0]==struct.unpack_from('<I',oldslot,100)[0]+1,'creation sector count/generation differs'
  assert native_inode(raw,8)==native_inode(bases[bs],8)
  payload_inode=m['metadata']['/payload']['inode'];before_inode=bytes.fromhex(m['metadata']['/payload']['raw_inode_hex']);after_inode=native_inode(raw,payload_inode)
  if op=='create':assert after_inode==before_inode,'create changed original payload inode'
  else:
   for start,end in ((0,4),(8,28),(32,40),(100,108),(112,128)):assert after_inode[start:end]==before_inode[start:end],'extend changed preserved inode fields'
  (a.out/(label+'-metadata.json')).write_text(json.dumps({'root_names':{k.hex():v for k,v in names.items()},'payload_inode_hex':after_inode.hex(),'created_inode_hex':native_inode(raw,names[b'new-ordered']).hex() if b'new-ordered' in names else None},sort_keys=True)+'\n')
  for name in ('/unrelated','/alias','/sub'):
   meta=m['metadata'][name];assert native_inode(raw,meta['inode'])==bytes.fromhex(meta['raw_inode_hex'])
  for name in ('unrelated','alias'):
   dump=a.out/(label+'-'+name+'.bin');run(label+'-'+name,[tools['debugfs'],'-R',f'dump /{name} {dump}',image]);assert sha(dump)==m['unrelated']['sha256']
 for index,((bs,op,h),pre) in enumerate(sorted(unique.items())):
  label=f'o{index}';image=a.out/(label+'.raw');shutil.copyfile(pre,image);run(label+'-before-fn',[tools['e2fsck'],'-f','-n',pre],(0,4));assert sha(pre)==h
  run(label+'-replay',[tools['e2fsck'],'-f','-y','-E','journal_only',image],(0,1),{'E2FSCK_TIME':str(struct.unpack_from('<I',bases[bs],1072)[0])});nativehash=sha(image);run(label+'-after-fn',[tools['e2fsck'],'-f','-n',image]);assert sha(image)==nativehash;raw=image.read_bytes();outcome=decision(raw,bs,op)
  for retry,expectedoutcome in retries[bs,op,h]:assert outcome==expectedoutcome and equal(raw,retry.read_bytes(),bs,op,outcome=='old')
  inspect(image,bs,op,label,outcome);result['images'].append({'block_bytes':bs,'operation':op,'pre_sha256':h,'native_sha256':nativehash,'outcome':outcome});save()
 for (bs,op),(_,path,h) in profiles.items():
  image=artifact(path,h);run(f'baseline-{bs}-{op}-fn',[tools['e2fsck'],'-f','-n',image]);inspect(image,bs,op,f'baseline-{bs}-{op}','new')
 # These are successful repeated public operations, not a repeated-operation cut matrix.
 result['public_repeated_snapshots']=[]
 for bs,m in models.items():
  manifest=gate/f'public-repeat-b{bs}.tsv'
  with manifest.open(newline='') as f:
   reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames=='step image_sha256 image_path payload_path created_payload_path'.split();steps=list(reader)
  assert [x['step'] for x in steps]==['append','create','append-created']
  extended=(a.corpus/m['expected_extended']['path']).read_bytes();append=(a.corpus/m['append']['path']).read_bytes();original_names=root_names(bases[bs]);payload_inode=None;created_inode=None;created_number=None
  _,journal_map,_=classic_map(bases[bs],8);original_control=bases[bs][journal_map[0]*bs:journal_map[0]*bs+bs];original_sequence=struct.unpack_from('>I',original_control,24)[0]
  for index,step in enumerate(steps):
   label=f'public-repeat-b{bs}-{step["step"]}';image=artifact(step['image_path'],step['image_sha256']);raw=image.read_bytes();assert len(raw)==len(bases[bs]);run(label+'-fn',[tools['e2fsck'],'-f','-n',image]);assert sha(image)==step['image_sha256']
   def expected_artifact(relative,wanted):
    path=pathlib.Path(relative);assert path.name==relative and relative!='-';assert (gate/path).read_bytes()==wanted
   expected_artifact(step['payload_path'],extended);dump=a.out/(label+'-payload.bin');run(label+'-payload',[tools['debugfs'],'-R',f'dump /payload {dump}',image]);assert dump.read_bytes()==extended
   names=root_names(raw);assert names.get(b'payload')==original_names[b'payload'];assert set(names)==set(original_names)|({b'new-ordered'} if index else set())
   for name,number in original_names.items():assert names[name]==number,'public repeat changed existing namespace identity'
   observed=native_inode(raw,original_names[b'payload'])
   if payload_inode is None:
    before_inode=bytes.fromhex(m['metadata']['/payload']['raw_inode_hex'])
    for start,end in ((0,4),(8,28),(32,40),(100,108),(112,128)):assert observed[start:end]==before_inode[start:end],'public repeat changed preserved payload metadata'
    payload_inode=observed
   else:assert observed==payload_inode,'create/append-created changed existing payload inode'
   if index==0:assert step['created_payload_path']=='-' and b'new-ordered' not in names
   else:
    wanted=append*(1 if index==1 else 2);expected_artifact(step['created_payload_path'],wanted);dump=a.out/(label+'-created.bin');run(label+'-created',[tools['debugfs'],'-R',f'dump /new-ordered {dump}',image]);assert dump.read_bytes()==wanted
    number=names[b'new-ordered'];inode=native_inode(raw,number);length,mapping,metadata=classic_map(raw,number);assert length==len(wanted);assert struct.unpack_from('<H',inode)[0]==0o100644 and struct.unpack_from('<H',inode,26)[0]==1
    assert inode[2:4]==bytes(2) and inode[8:26]==bytes(18) and inode[32:40]==bytes(8) and inode[104:128]==bytes(24),'public creation native template fields changed'
    assert struct.unpack_from('<I',inode,28)[0]==(len(mapping)+len(metadata))*bs//512
    if created_inode is None:
     oldslot=native_inode(bases[bs],number);assert struct.unpack_from('<I',inode,100)[0]==struct.unpack_from('<I',oldslot,100)[0]+1;created_inode=inode;created_number=number
    else:
     assert number==created_number
     for start,end in ((0,4),(8,28),(32,40),(100,128)):assert inode[start:end]==created_inode[start:end],'append-created changed preserved native inode metadata'
   assert native_inode(raw,8)==native_inode(bases[bs],8),'public repeat changed journal inode'
   for name in ('/unrelated','/alias','/sub'):
    meta=m['metadata'][name];assert native_inode(raw,meta['inode'])==bytes.fromhex(meta['raw_inode_hex'])
   for name in ('unrelated','alias'):
    dump=a.out/(label+'-'+name+'.bin');run(label+'-'+name,[tools['debugfs'],'-R',f'dump /{name} {dump}',image]);assert sha(dump)==m['unrelated']['sha256']
   control=raw[journal_map[0]*bs:journal_map[0]*bs+bs];assert struct.unpack_from('>II',control,24)==((original_sequence+2*(index+1))&0xffffffff,0),'public repeat journal not inactive at expected generation';assert control[:24]==original_control[:24] and control[32:64]==original_control[32:64]
   assert struct.unpack_from('<I',raw,1120)[0]&4==0,'public repeat filesystem remains recovery-needed'
   (a.out/(label+'-metadata.json')).write_text(json.dumps({'names':{k.hex():v for k,v in names.items()},'payload_inode_hex':observed.hex(),'created_inode_hex':native_inode(raw,names[b'new-ordered']).hex() if index else None,'journal_control_hex':control[:64].hex()},sort_keys=True)+'\n')
   assert sha(image)==step['image_sha256'];result['public_repeated_snapshots'].append({'block_bytes':bs,'step':step['step'],'image_sha256':step['image_sha256'],'scope':'successful public session snapshot; no repeated-operation cut coverage'});save()
 assert gate_before=={str(x.relative_to(gate)):sha(x) for x in sorted(gate.rglob('*')) if x.is_file()},'gate artifacts changed during native verification'
 result['independent_masks']={f'{bs}-{op}':ranges for (bs,op),ranges in masks.items()}
 result['cases']=len(rows);result['unique_preimages']=len(unique);result['policy']='ordered exact metadata/visible OLD with independently bounded unreachable-data mask; NEW exact homes excluding journal'

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('binary','source-root','corpus','out'):p.add_argument('--'+n,type=pathlib.Path,required=True)
 p.add_argument('--ordered',action='store_true')
 a=p.parse_args()
 if not __debug__:p.error('optimized Python unsupported')
 if not all(x.is_absolute() for x in (a.binary,a.source_root,a.corpus,a.out)):p.error('absolute paths required')
 a.out.mkdir();dest=a.out/'qualification.json';result={'complete':False,'scope':__doc__+'; modeled persisted bytes only, no kernel/mount/hardware-crash qualification','commands':[],'images':[]}
 def save():dest.write_text(json.dumps(result,indent=2)+'\n')
 save()
 try:
  script=pathlib.Path(__file__).resolve();assert sha(script)==sha(a.source_root/'integration/maintenance/ext-owned-cuts-verify.py'),'altered executing verifier';shutil.copyfile(script,a.out/'verifier-source.py')
  original=json.loads((a.corpus/'receipt.json').read_text());assert sha(a.corpus/'receipt.json')==RECEIPT and original['complete']
  for name,h in original['artifacts_sha256'].items():assert pathlib.Path(name).name==name and sha(a.corpus/name)==h,name
  tools={n:pathlib.Path(original['tools'][n]['path']) for n in ('debugfs','e2fsck')}
  for n,t in tools.items():assert sha(t)==original['tools'][n]['sha256'],n
  def source_paths():return sorted((a.source_root/'src').rglob('*.rs'))+[a.source_root/x for x in ('Cargo.toml','Cargo.lock','integration/maintenance/ext-owned-cuts-verify.py','integration/maintenance/ext-owned-oracle.py','integration/maintenance/ext-namespace-cuts-verify.py','integration/maintenance/ext-namespace-oracle.py','integration/maintenance/ext-namespace-v4-cuts-verify.py','integration/maintenance/ext-directory-growth-oracle.py','integration/maintenance/ext-directory-growth-cuts-verify.py','integration/maintenance/ext-truncate-oracle.py','integration/maintenance/ext-truncate-cuts-verify.py','integration/maintenance/ext-hardlink-oracle.py','integration/maintenance/ext-hardlink-cuts-verify.py','integration/maintenance/ext-overwrite-oracle.py','integration/maintenance/ext-overwrite-cuts-verify.py','integration/maintenance/ext-sparse-extension-oracle.py','integration/maintenance/ext-sparse-extension-cuts-verify.py','integration/maintenance/ext-symlink-oracle.py','integration/maintenance/ext-symlink-cuts-verify.py','tests/fixtures/ext2_clean.rs','tests/fixtures/ntfs_clean.rs','tests/fixtures/jfs_clean.rs','tests/fixtures/hfsplus_clean.rs','tests/fixtures/jffs2_clean.rs','tests/fs_ext_owned.rs')]
  def snapshot():return {str(x):sha(x) for x in [a.binary,*source_paths(),a.corpus/'receipt.json',*(a.corpus/x for x in original['artifacts_sha256']),*tools.values()]}
  before=snapshot();result['bindings_before']=before;save()
  env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800')
  def run(name,argv,accepted=(0,),extra=None):
   e=dict(env);e.update(extra or {});r=subprocess.run(list(map(str,argv)),env=e,capture_output=True)
   for stream in ('stdout','stderr'):(a.out/(name+'.'+stream)).write_bytes(getattr(r,stream))
   result['commands'].append({'name':name,'argv':list(map(str,argv)),'exit':r.returncode,'environment_overrides':{k:v for k,v in e.items() if k.startswith('PARTMGR_') or k in ('LC_ALL','TZ','E2FSCK_TIME')},'stdout_sha256':sha(a.out/(name+'.stdout')),'stderr_sha256':sha(a.out/(name+'.stderr'))});save()
   assert accepted is None or r.returncode in accepted,(name,r.returncode);return r
  gate=a.out/'rust'
  test='fs_ext::jbd::owned_native_cuts::native_owned_ext3_allocation_cuts'
  if a.ordered:test='fs_ext::jbd::owned_native_cuts::native_owned_ext3_ordered_allocation_cuts'
  gatecmd=[a.binary,'--ignored','--exact',test,'--nocapture']
  def gate_env(root,out):return {'PARTMGR_GATE_SOURCE_ROOT':str(root),'PARTMGR_EXT_OWNED_CORPUS':str(a.corpus),('PARTMGR_EXT_ORDERED_EVIDENCE' if a.ordered else 'PARTMGR_EXT_OWNED_EVIDENCE'):str(out)}
  run('rust',gatecmd,extra=gate_env(a.source_root,gate))
  assert 'complete=true' in (gate/'report.txt').read_text();assert sha(gate/'gate-binary')==before[str(a.binary)]
  assert (gate/'source-start.sha256').read_bytes()==(gate/'source-end.sha256').read_bytes()
  captured={str(x.relative_to(gate/'compiled-source')):sha(x) for x in (gate/'compiled-source').rglob('*') if x.is_file()};expected={str(x.relative_to(a.source_root)):sha(x) for x in source_paths()};assert captured==expected,'compiled source inventory mismatch'
  if a.ordered:
   def ordered_artifact(relative,h):
    assert relative==f'images/{h}.raw' and len(h)==64;bytes.fromhex(h);path=gate/relative;assert sha(path)==h;return path
   ordered_verify(a,gate,{m['block_bytes']:m for m in original['models']},run,tools,result,save,ordered_artifact)
   assert run('missing-source',gatecmd,None,gate_env(a.out/'absent',a.out/'missing-source-output')).returncode!=0
   assert run('reused-evidence',gatecmd,None,gate_env(a.source_root,gate)).returncode!=0
   stale=a.out/'stale-source';shutil.copytree(gate/'compiled-source',stale);changed=stale/'Cargo.toml';changed.write_bytes(changed.read_bytes()+b'\n# stale control\n');assert run('stale-source',gatecmd,None,gate_env(stale,a.out/'stale-output')).returncode!=0
   assert before==snapshot(),'source/input/tool changed';result['bindings_after']=snapshot();result['gate_artifacts_sha256']={str(x.relative_to(gate)):sha(x) for x in sorted(gate.rglob('*')) if x.is_file()};result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};result['complete']=True;save();return
  models={m['block_bytes']:m for m in original['models']};profiles={}
  for line in (gate/'observations.txt').read_text().splitlines():
   match=re.fullmatch(r'bs=(\d+) events=(\d+) baseline=(images/([0-9a-f]{64})\.raw)',line)
   if match:profiles[int(match[1])]={'events':int(match[2]),'success_path':match[3],'success_sha256':match[4]}
  assert set(profiles)==set(models)=={1024,2048,4096}
  columns='bs case event model fault_kind prefix pre_sha256 pre_path retried_sha256 retried_path result'.split()
  with (gate/'cuts.tsv').open(newline='') as f:
   reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames==columns;rows=list(reader)
  def artifact(relative,h):
   assert relative==f'images/{h}.raw' and len(h)==64;bytes.fromhex(h);path=gate/relative;assert sha(path)==h;return path
  coverage=Counter();cases=set();unique={};retry_by_pre={};bound={gate/'cuts.tsv':sha(gate/'cuts.tsv'),gate/'report.txt':sha(gate/'report.txt'),gate/'observations.txt':sha(gate/'observations.txt')}
  success={};bases={};maps={};checker_times={}
  for bs,m in models.items():
   bases[bs]=(a.corpus/m['image']['path']).read_bytes();wtime=struct.unpack_from('<I',bases[bs],1072)[0];lastcheck=struct.unpack_from('<I',bases[bs],1088)[0];assert wtime==lastcheck and wtime!=0,'source checker timestamps disagree';checker_times[bs]=str(wtime);_,maps[bs]=journal_blocks(bases[bs]);profile=profiles[bs];success[bs]=artifact(profile['success_path'],profile['success_sha256']).read_bytes();assert len(success[bs])==len(bases[bs]);assert native_inode(success[bs],8)==native_inode(bases[bs],8)
  def homes_equal(x,y,bs):return len(x)==len(y) and all(x[at:at+bs]==y[at:at+bs] for at in range(0,len(x),bs) if at//bs not in maps[bs])
  event_specs={}
  for bs in models:
   eventpath=gate/f'events-b{bs}.tsv';bound[eventpath]=sha(eventpath)
   with eventpath.open(newline='') as f:
    reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames==['event','kind','bytes'];events=list(reader)
   assert [int(x['event']) for x in events]==list(range(1,profiles[bs]['events']+1))
   for event in events:
    kind=event['kind'];size=int(event['bytes']);assert kind in ('write','flush') and (size>0 if kind=='write' else size==0);event_specs[(bs,int(event['event']))]=(kind,size)
  for row in rows:
   assert set(row)==set(columns) and None not in row.values();bs=int(row['bs']);event=int(row['event']);case=int(row['case']);assert bs in models and 1<=event<=profiles[bs]['events'];assert (bs,case) not in cases;cases.add((bs,case));model=row['model'];kind=row['fault_kind'];prefix=int(row['prefix']);assert model in ('immediate','volatile');key=(bs,event,model,kind,prefix);coverage[key]+=1
   pre=artifact(row['pre_path'],row['pre_sha256']);retry=artifact(row['retried_path'],row['retried_sha256']);bound[pre]=row['pre_sha256'];bound[retry]=row['retried_sha256'];data=retry.read_bytes();old=homes_equal(data,bases[bs],bs);new=homes_equal(data,success[bs],bs);assert old != new,'own cold recovery partial or ambiguous home image';assert row['result']==('old' if old else 'new'),'incorrect reported outcome';unique[(bs,row['pre_sha256'])]=pre;retry_by_pre.setdefault((bs,row['pre_sha256']),set()).add((row['retried_sha256'],row['retried_path'],row['result']))
  expectedcoverage=Counter()
  for (bs,event),(kind,size) in event_specs.items():
   selectors=[('write',n) for n in (0,size//2,size) for _ in range(2)] if kind=='write' else [('flush-none',0),('flush-persist',0)]
   expectedcoverage.update((bs,event,model,fault,prefix) for model in ('immediate','volatile') for fault,prefix in selectors)
  assert coverage==expectedcoverage,'missing or unexpected interruption case'
  result['checker_times']=checker_times;result['cases']=len(rows);result['unique_preimages']=len(unique);save()
  for index,((bs,h),pre) in enumerate(sorted(unique.items())):
   env['E2FSCK_TIME']=checker_times[bs]
   m=models[bs];image=a.out/f'native-{index:04}.raw';shutil.copyfile(pre,image)
   # Dirty images may fail this read-only check; replay must subsequently succeed.
   run(f'n{index}-before-fn',[tools['e2fsck'],'-f','-n',pre],(0,4));assert sha(pre)==h
   run(f'n{index}-replay',[tools['e2fsck'],'-f','-y','-E','journal_only',image],(0,1))
   nativehash=sha(image);run(f'n{index}-after-fn',[tools['e2fsck'],'-f','-n',image]);assert sha(image)==nativehash
   payload=a.out/f'native-{index:04}-payload.bin';run(f'n{index}-payload',[tools['debugfs'],'-R',f'dump /payload {payload}',image]);actual=payload.read_bytes();old=(a.corpus/m['payload']['path']).read_bytes();new=(a.corpus/m['expected_extended']['path']).read_bytes();assert actual in (old,new),'native partial payload'
   raw=image.read_bytes()
   native_old=homes_equal(raw,bases[bs],bs);native_new=homes_equal(raw,success[bs],bs)
   assert native_old != native_new,('native recovery partial or ambiguous home image',bs,h)
   decision='old' if native_old else 'new'
   for retryhash,retrypath,retrydecision in retry_by_pre[(bs,h)]:
    retried=artifact(retrypath,retryhash).read_bytes()
    assert homes_equal(raw,retried,bs),('native and owned recovery home bytes differ',bs,h,retryhash)
    assert decision==retrydecision,('native and owned recovery decisions differ',bs,h)
   assert ('old' if actual==old else 'new')==decision,'native payload and complete-home decisions disagree'
   assert native_inode(raw,8)==native_inode(bases[bs],8),'journal inode changed'
   # Existing payload metadata remains fixed except size, sectors and map bytes.
   inode=m['metadata']['/payload']['inode'];beforeinode=bytes.fromhex(m['metadata']['/payload']['raw_inode_hex']);afterinode=native_inode(raw,inode)
   for start,end in ((0,4),(8,28),(32,40),(100,108),(112,128)):assert afterinode[start:end]==beforeinode[start:end],('payload metadata changed',start,end)
   for which in ('/unrelated','/alias','/sub','/'):
    meta=m['metadata'][which];assert native_inode(raw,meta['inode'])==bytes.fromhex(meta['raw_inode_hex']),('unrelated inode metadata changed',which)
   for j,path in enumerate(('/unrelated','/alias')):
    dump=a.out/f'native-{index:04}-unrelated-{j}.bin';run(f'n{index}-unrelated-{j}',[tools['debugfs'],'-R',f'dump {path} {dump}',image]);assert sha(dump)==m['unrelated']['sha256']
   assert sha(image)==nativehash;result['images'].append({'block_bytes':bs,'pre_sha256':h,'native_sha256':nativehash,'payload_outcome':'old' if actual==old else 'new'});save()
  # Independently check the successful allocation and repeated-session images too.
  repeated={}
  for line in (gate/'observations.txt').read_text().splitlines():
   match=re.fullmatch(r'bs=(\d+) repeated=(images/([0-9a-f]{64})\.raw) operations=extend,replace,rename,truncate,create,delete',line)
   if match:repeated[int(match[1])]=(match[2],match[3])
  assert set(repeated)==set(models),'missing repeated-session baseline'
  for bs,m in models.items():
   env['E2FSCK_TIME']=checker_times[bs]
   for label,path,wanted,name in (
    ('baseline',artifact(profiles[bs]['success_path'],profiles[bs]['success_sha256']),(a.corpus/m['expected_extended']['path']).read_bytes(),'/payload'),
    ('repeated',artifact(*repeated[bs]),b'owned-repeated'+(a.corpus/m['payload']['path']).read_bytes()[len(b'owned-repeated'):],'/renamed')):
    imagehash=sha(path);bound[path]=imagehash;run(f'b{bs}-{label}-fn',[tools['e2fsck'],'-f','-n',path])
    dump=a.out/f'b{bs}-{label}-payload.bin';run(f'b{bs}-{label}-payload',[tools['debugfs'],'-R',f'dump {name} {dump}',path]);assert dump.read_bytes()==wanted
    raw=path.read_bytes();assert native_inode(raw,8)==native_inode(bases[bs],8)
    for native in ('/unrelated','/alias'):
     meta=m['metadata'][native];assert native_inode(raw,meta['inode'])==bytes.fromhex(meta['raw_inode_hex'])
     dump=a.out/f'b{bs}-{label}-{native[1:]}.bin';run(f'b{bs}-{label}-{native[1:]}',[tools['debugfs'],'-R',f'dump {native} {dump}',path]);assert sha(dump)==m['unrelated']['sha256']
    if label=='repeated':
     rootinode=native_inode(raw,2);names=[];size=struct.unpack_from('<I',rootinode,4)[0];assert size<=12*bs,'unexpected root mapping'
     for block in struct.unpack_from('<12I',rootinode,40)[:(size+bs-1)//bs]:
      data=raw[block*bs:(block+1)*bs];at=0
      while at<bs:
       ino,length,nlen=struct.unpack_from('<IHB',data,at);assert length>=8 and length%4==0 and at+length<=bs and nlen<=length-8
       if ino:names.append(data[at+8:at+8+nlen])
       at+=length
     assert b'renamed' in names and b'payload' not in names and b'temporary' not in names,'repeated namespace mismatch'
    assert sha(path)==imagehash
  for bs,m in models.items():
   env['E2FSCK_TIME']=checker_times[bs]
   stepfile=gate/f'repeat-steps-b{bs}.tsv';bound[stepfile]=sha(stepfile)
   with stepfile.open(newline='') as f:
    reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames=='step image_sha256 image_path main_name main_payload_path temporary_payload_path'.split();steps=list(reader)
   assert [x['step'] for x in steps]==['replace','rename','truncate','create','delete']
   initial=(a.corpus/m['payload']['path']).read_bytes();extended=(a.corpus/m['expected_extended']['path']).read_bytes();changed=b'owned-repeated'+extended[len(b'owned-repeated'):]
   for index,step in enumerate(steps):
    label=f'b{bs}-step-{index}';path=artifact(step['image_path'],step['image_sha256']);bound[path]=step['image_sha256'];name='payload' if index==0 else 'renamed';wanted=changed if index<2 else changed[:len(initial)];assert step['main_name']==name
    expectedpath=pathlib.Path(step['main_payload_path']);assert expectedpath.name==str(expectedpath);assert (gate/expectedpath).read_bytes()==wanted;bound[gate/expectedpath]=sha(gate/expectedpath)
    run(label+'-fn',[tools['e2fsck'],'-f','-n',path]);dump=a.out/(label+'-payload.bin');run(label+'-payload',[tools['debugfs'],'-R',f'dump /{name} {dump}',path]);assert dump.read_bytes()==wanted
    if index==3:
     assert step['temporary_payload_path']!='-';temporary=pathlib.Path(step['temporary_payload_path']);assert temporary.name==str(temporary) and (gate/temporary).read_bytes()==b'temporary-owned';bound[gate/temporary]=sha(gate/temporary);dump=a.out/(label+'-temporary.bin');run(label+'-temporary',[tools['debugfs'],'-R',f'dump /temporary {dump}',path]);assert dump.read_bytes()==b'temporary-owned'
    else:assert step['temporary_payload_path']=='-'
    raw=path.read_bytes();assert native_inode(raw,8)==native_inode(bases[bs],8)
    for native in ('/unrelated','/alias','/sub'):
     meta=m['metadata'][native];assert native_inode(raw,meta['inode'])==bytes.fromhex(meta['raw_inode_hex'])
    for alias in ('unrelated','alias'):
     dump=a.out/(label+'-'+alias+'.bin');run(label+'-'+alias,[tools['debugfs'],'-R',f'dump /{alias} {dump}',path]);assert sha(dump)==m['unrelated']['sha256']
    rootinode=native_inode(raw,2);names=[];size=struct.unpack_from('<I',rootinode,4)[0];assert size<=12*bs
    for block in struct.unpack_from('<12I',rootinode,40)[:(size+bs-1)//bs]:
     data=raw[block*bs:(block+1)*bs];at=0
     while at<bs:
      ino,length,nlen=struct.unpack_from('<IHB',data,at);assert length>=8 and length%4==0 and at+length<=bs and nlen<=length-8
      if ino:names.append(data[at+8:at+8+nlen])
      at+=length
    assert (b'temporary' in names)==(index==3);assert (b'payload' in names)==(index==0);assert (b'renamed' in names)==(index>0)
    assert sha(path)==step['image_sha256']
  # Enabled gates reject missing/stale source and reused evidence.
  assert run('missing-source',gatecmd,None,gate_env(a.out/'absent',a.out/'missing-source-output')).returncode!=0
  assert run('reused-evidence',gatecmd,None,gate_env(a.source_root,gate)).returncode!=0
  stale=a.out/'stale-source';shutil.copytree(gate/'compiled-source',stale);changed=stale/'Cargo.toml';changed.write_bytes(changed.read_bytes()+b'\n# stale control\n');assert run('stale-source',gatecmd,None,gate_env(stale,a.out/'stale-output')).returncode!=0
  assert before==snapshot(),'source/input/tool changed'
  for path,h in bound.items():assert sha(path)==h,'gate artifact changed'
  result['bindings_after']=snapshot();result['gate_artifacts_sha256']={str(x.relative_to(gate)):sha(x) for x in sorted(gate.rglob('*')) if x.is_file()};result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};result['complete']=True;save()
 except BaseException as e:result['error']=repr(e);save();raise
if __name__=='__main__':main()

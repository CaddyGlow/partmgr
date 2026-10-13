#!/usr/bin/env python3
"""Staged verifier core, NOT a qualification runner. No complete receipt emitted."""
from collections import Counter
import struct

def le(raw,at,n=4):
 assert 0<=at<=len(raw)-n
 return int.from_bytes(raw[at:at+n],'little')

def allocated(raw,number,inode=False):
 bs=1024<<le(raw,1048);first=le(raw,1044);total=le(raw,1024 if inode else 1028)
 assert (1 if inode else first)<=number<=(total if inode else total-1)
 per=le(raw,1064 if inode else 1056);group,bit=divmod(number-1 if inode else number-first,per)
 bitmap=le(raw,(first+1)*bs+group*32+(4 if inode else 0))
 return bool(raw[bitmap*bs+bit//8]&(1<<(bit%8)))

def storage(raw,number,helper):
 """Never call classic_map on a fast symlink's opaque inline bytes."""
 inode=helper.native_inode(raw,number);bs=1024<<le(raw,1048);mode=le(inode,0,2)&0xf000
 if mode!=0xa000:
  length,data,metadata=helper.classic_map(raw,number)
  return {'kind':'directory' if mode==0x4000 else 'regular' if mode==0x8000 else 'other','length':length,'data':data,'metadata':set(metadata),'target':None}
 length=le(inode,4);sectors=le(inode,28);assert 0<length<bs
 if sectors==0:
  assert length<60 and inode[40+length]==0
  target=inode[40:40+length];data=[];kind='fast'
 else:
  assert 60<=length<bs and sectors==bs//512
  pointers=struct.unpack_from('<15I',inode,40);assert pointers[0] and not any(pointers[1:])
  data=[pointers[0]];assert allocated(raw,data[0]);body=raw[data[0]*bs:(data[0]+1)*bs]
  assert len(body)==bs and body[length]==0;target=body[:length];kind='slow'
 assert len(target)==length and b'\0' not in target
 return {'kind':kind,'length':length,'data':data,'metadata':set(),'target':target}

def graph(raw,helper):
 """Byte names; no decoding or target traversal. Records include type7."""
 bs=1024<<le(raw,1048);pending=[2];directories={};references=Counter()
 while pending:
  number=pending.pop();assert number not in directories,'directory cycle/alias'
  info=storage(raw,number,helper);assert info['kind']=='directory';entries={}
  for block in info['data']:
   assert block;body=raw[block*bs:(block+1)*bs];at=0
   while at<bs:
    child,size,n,kind=struct.unpack_from('<IHBB',body,at)
    assert size>=8 and size%4==0 and at+size<=bs and n<=size-8
    if child:
     name=bytes(body[at+8:at+8+n]);assert name not in entries;entries[name]=(child,kind)
     if name not in (b'.',b'..'):
      assert allocated(raw,child,True);mode=le(helper.native_inode(raw,child),0,2)&0xf000
      assert kind=={0x8000:1,0x4000:2,0xa000:7}[mode]
      references[child]+=1
      if mode==0x4000:pending.append(child)
    at+=size
  assert entries[b'.']==(number,2);directories[number]=entries
 for number,count in references.items():
  if le(helper.native_inode(raw,number),0,2)&0xf000!=0x4000:
   assert le(helper.native_inode(raw,number),26,2)==count,'alias/link mismatch'
 return directories,references

def exact_except(before,after,ranges):
 allowed={i for lo,hi in ranges for i in range(lo,hi)}
 assert len(before)==len(after) and all(x==y or i in allowed for i,(x,y) in enumerate(zip(before,after)))

def regular_blocks(raw,helper):
 result=set()
 for number in range(11,le(raw,1024)+1):
  if allocated(raw,number,True) and le(helper.native_inode(raw,number),0,2)&0xf000==0x8000:
   result.update(x for x in storage(raw,number,helper)['data'] if x)
 return result

def check_replace(base,final,number,target,helper):
 bs=1024<<le(base,1048);old=storage(base,number,helper);new=storage(final,number,helper)
 assert old['kind'] in ('fast','slow') and new['target']==target
 assert new['kind']==('fast' if len(target)<60 else 'slow')
 exact_except(helper.native_inode(base,number),helper.native_inode(final,number),[(4,8),(28,32),(40,100)])
 assert graph(base,helper)==graph(final,helper)
 if new['kind']=='fast':assert helper.native_inode(final,number)[40:100]==target+b'\0'+bytes(59-len(target))
 else:
  fresh=new['data'][0];assert not allocated(base,fresh),'slow target must use originally free COW metadata'
  assert final[fresh*bs:(fresh+1)*bs]==target+b'\0'+bytes(bs-len(target)-1)
 for block in old['data']:
  assert base[block*bs:(block+1)*bs]==final[block*bs:(block+1)*bs],'old slow physical bytes changed'
 return set(new['data'])

def accounting(raw):
 """Independent valid block/inode bitmap recount, including all group counters."""
 bs=1024<<le(raw,1048);first=le(raw,1044);total=le(raw,1028);bpg=le(raw,1056);ipg=le(raw,1064);inodes=le(raw,1024)
 freeblocks=freeinodes=0
 for group in range((total-first+bpg-1)//bpg):
  at=(first+1)*bs+group*32;blocks=min(bpg,total-first-group*bpg);count=min(ipg,inodes-group*ipg)
  fb=sum(not allocated(raw,first+group*bpg+i) for i in range(blocks))
  fi=sum(not allocated(raw,group*ipg+i+1,True) for i in range(count))
  assert fb==le(raw,at+12,2) and fi==le(raw,at+14,2)
  freeblocks+=fb;freeinodes+=fi
 assert freeblocks==le(raw,1036) and freeinodes==le(raw,1040)

def redo(base,final,helper,required):
 bs=1024<<le(base,1048);regular=regular_blocks(base,helper)
 for block in regular:assert base[block*bs:(block+1)*bs]==final[block*bs:(block+1)*bs],'original regular bytes/slack changed'
 proof=helper.ordered_redo_proof(base,final,bs,sorted(regular),set())
 destinations=set(proof['mutation_destinations']);assert set(required)<=destinations
 _,journal=helper.journal_blocks(base)
 for block in range(len(base)//bs):
  assert block in journal or block in destinations or base[block*bs:(block+1)*bs]==final[block*bs:(block+1)*bs],'changed home omitted from redo'
 accounting(base);accounting(final)
 return proof

def homes_equal(left,right,journal,bs):
 """Only actual journal DATA blocks masked: no fresh slow metadata mask."""
 return len(left)==len(right) and all(i in journal or left[i*bs:(i+1)*bs]==right[i*bs:(i+1)*bs] for i in range(len(left)//bs))

def classify_replayed(native,retry,base,final,helper):
 bs=1024<<le(base,1048);_,journal=helper.journal_blocks(base)
 old=homes_equal(native,base,journal,bs);new=homes_equal(native,final,journal,bs)
 assert old!=new,'partial or ambiguous OLD/NEW state'
 assert homes_equal(native,retry,journal,bs),'Rust cold/native replay disagree'
 graph(native,helper);accounting(native)
 return 'old' if old else 'new'

def matrix(events_by_profile,rows):
 """Profile key includes block size AND corpus variant to prevent collisions."""
 expected=Counter();actual=Counter();seen=set()
 for profile,events in events_by_profile.items():
  assert [int(x['event']) for x in events]==list(range(1,len(events)+1))
  for row in events:
   event=int(row['event']);n=int(row['bytes']);assert row['kind'] in ('write','flush')
   for model in ('immediate','volatile'):
    if row['kind']=='write':
     assert n>0
     for prefix in (0,n//2,n):expected[profile,event,model,'write',prefix]+=2
    else:
     assert n==0
     for fault in ('flush-persist','flush-none'):expected[profile,event,model,fault,0]+=1
 for row in rows:
  profile=(int(row['bs']),row['operation']);assert profile in events_by_profile
  identity=(profile,int(row['case']));assert identity not in seen;seen.add(identity)
  actual[profile,int(row['event']),row['model'],row['fault_kind'],int(row['prefix'])]+=1
 assert actual==expected,'incomplete or extra actual cut matrix'


import argparse, collections, csv, hashlib, importlib.util, json, os, pathlib, shutil, struct, subprocess
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def resolve(directories,path):
 number=2
 for component in path.encode('ascii').split(b'/'):
  if component:number=directories[number][component][0]
 return number

def owned(raw,number,helper):
 info=storage(raw,number,helper)
 return {x for x in info['data'] if x}|info['metadata']

def semantics(base,final,case,helper,corpus,dtime):
 bs=1024<<le(base,1048);op=case['case'];oldgraph,_=graph(base,helper);newgraph,_=graph(final,helper);expected={n:dict(v) for n,v in oldgraph.items()};changed=set();added=set();released=set();newinode=None;deadinode=None;target_number=case['source']['inode'] if case['source'] else None
 destination=bytes.fromhex(case.get('destination_name_hex',''));parent=resolve(oldgraph,case.get('destination_parent','/'))
 target=(corpus/case['target']['path']).read_bytes() if case['target'] else None
 if op.startswith('create-'):
  assert destination not in oldgraph[parent] and destination in newgraph[parent]
  newinode=newgraph[parent][destination][0];assert not allocated(base,newinode,True) and allocated(final,newinode,True)
  expected[parent][destination]=(newinode,7);changed.add(parent)
  raw=helper.native_inode(final,newinode);oldraw=helper.native_inode(base,newinode);info=storage(final,newinode,helper)
  # Gate creation contract: explicit zeroed metadata mode0xa1ff; assigned native generation=old+1.
  want=bytearray(128);want[:2]=(0xa1ff).to_bytes(2,'little');want[4:8]=len(target).to_bytes(4,'little');want[26:28]=(1).to_bytes(2,'little');want[100:104]=(le(oldraw,100)+1).to_bytes(4,'little')
  assert info['target']==target and info['kind']==('fast' if len(target)<60 else 'slow')
  if info['kind']=='fast':want[40:40+len(target)]=target
  else:
   block=info['data'][0];want[28:32]=(bs//512).to_bytes(4,'little');want[40:44]=block.to_bytes(4,'little')
   assert final[block*bs:(block+1)*bs]==target+b'\0'+bytes(bs-len(target)-1)
  assert raw==want,'created raw inode differs from explicit zeroed metadata contract'
  added|=owned(final,newinode,helper)
 elif op.startswith('replace-'):
  added|=check_replace(base,final,target_number,target,helper)
  released|=owned(base,target_number,helper)-owned(final,target_number,helper)
 elif op.startswith('rename-'):
  source=case['source']['path'];source_parent=resolve(oldgraph,source.rsplit('/',1)[0]);name=source.rsplit('/',1)[1].encode()
  assert destination not in oldgraph[parent]
  del expected[source_parent][name];expected[parent][destination]=(target_number,7);changed|={source_parent,parent}
  assert helper.native_inode(base,target_number)==helper.native_inode(final,target_number)
 elif op.startswith('unlink-'):
  source=case['source']['alias'] if op.startswith('unlink-alias-') else case['source']['path'];source_parent=resolve(oldgraph,source.rsplit('/',1)[0]);name=source.rsplit('/',1)[1].encode();assert expected[source_parent].pop(name)==(target_number,7);changed.add(source_parent)
  before=helper.native_inode(base,target_number);after=helper.native_inode(final,target_number)
  if op.startswith('unlink-final-'):
   assert le(before,26,2)==1 and not allocated(final,target_number,True);deadinode=target_number;released|=owned(base,target_number,helper)
   want=bytearray(before)
   for lo,hi in ((4,8),(26,32),(40,100)):want[lo:hi]=bytes(hi-lo)
   want[20:24]=dtime.to_bytes(4,'little');assert after==want
  else:
   assert le(before,26,2)>1 and allocated(final,target_number,True)
   want=bytearray(before);want[26:28]=(le(before,26,2)-1).to_bytes(2,'little');assert after==want
 else:raise AssertionError('unknown symlink operation')
 assert newgraph==expected,'namespace differs from exact operation graph'
 # Parent maps permit append-only admitted directory growth; no old node relocation.
 for number in changed:
  old=storage(base,number,helper);new=storage(final,number,helper);before=helper.native_inode(base,number);after=helper.native_inode(final,number)
  assert new['data'][:len(old['data'])]==old['data'] and old['metadata']<=new['metadata']
  growth=len(new['data'])-len(old['data']);assert growth in (0,1)
  assert new['length']==old['length']+growth*bs
  if growth:assert len(old['data']) in (1,12),'unqualified parent growth boundary'
  assert len(new['metadata'])==len(old['metadata'])+int(bool(growth) and len(old['data'])==12),'unexpected parent indirect topology'
  if not growth:assert owned(base,number,helper)==owned(final,number,helper)
  exact_except(before,after,[(4,8),(28,32),(40,100)])
  assert le(after,28)==(len(new['data'])+len(new['metadata']))*bs//512
  added|=owned(final,number,helper)-owned(base,number,helper)
  assert not owned(base,number,helper)-owned(final,number,helper)
 # Every other inode remains exact including unused slots; no hidden alias rewrites.
 for number in range(1,le(base,1024)+1):
  assert allocated(final,number,True)==(True if number==newinode else False if number==deadinode else allocated(base,number,True))
  if number not in changed|{target_number,newinode}:assert helper.native_inode(base,number)==helper.native_inode(final,number)
  if allocated(base,number,True) and le(helper.native_inode(base,number),0,2)&0xf000==0xa000:
   for block in storage(base,number,helper)['data']:assert base[block*bs:(block+1)*bs]==final[block*bs:(block+1)*bs],'original slow target bytes changed'
 assert not added&released and all(not allocated(base,x) for x in added)
 first=le(base,1044);total=le(base,1028);bpg=le(base,1056);ipg=le(base,1064)
 for block in range(first,total):assert allocated(final,block)==(True if block in added else False if block in released else allocated(base,block)),'unexpected block bitmap delta'
 assert le(final,1036)-le(base,1036)==len(released)-len(added)
 assert le(final,1040)-le(base,1040)==int(deadinode is not None)-int(newinode is not None)
 for group in range((total-first+bpg-1)//bpg):
  at=(first+1)*bs+group*32;bd=sum((x-first)//bpg==group for x in released)-sum((x-first)//bpg==group for x in added);idelta=int(deadinode is not None and (deadinode-1)//ipg==group)-int(newinode is not None and (newinode-1)//ipg==group)
  assert le(final,at+12,2)-le(base,at+12,2)==bd and le(final,at+14,2)-le(base,at+14,2)==idelta
  exact_except(base[at:at+32],final[at:at+32],[(12,16)])
  # Compare complete bitmap bodies, preserving padding bits outside valid objects.
  for is_inode in (False,True):
   bitmap=le(base,at+(4 if is_inode else 0));want=bytearray(base[bitmap*bs:(bitmap+1)*bs])
   transitions=([(newinode,True)] if newinode is not None else [])+([(deadinode,False)] if deadinode is not None else []) if is_inode else [(x,True) for x in added]+[(x,False) for x in released]
   per=ipg if is_inode else bpg
   for number,value in transitions:
    index=number-1 if is_inode else number-first
    if index//per!=group:continue
    bit=index%per
    if value:want[bit//8]|=1<<(bit%8)
    else:want[bit//8]&=~(1<<(bit%8))
   assert final[bitmap*bs:(bitmap+1)*bs]==want,'unexpected full bitmap/padding change'

 exact_except(base[1024:2048],final[1024:2048],[(12,20)])
 return added

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('gate','corpus','source-root','out'):p.add_argument('--'+name,type=pathlib.Path,required=True)
 p.add_argument('--deletion-time',type=int,default=946684800);a=p.parse_args();assert __debug__ and all(x.is_absolute() for x in (a.gate,a.corpus,a.source_root,a.out));assert __import__('re').fullmatch(r'/[A-Za-z0-9_./-]+',str(a.out));a.out.mkdir()
 helperpath=a.source_root/'integration/maintenance/ext-owned-cuts-verify.py';spec=importlib.util.spec_from_file_location('owned_verify',helperpath);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
 result={'complete':False,'commands':[],'images':[],'inputs_sha256':{},'helper_sha256':sha(helperpath)};dest=a.out/'qualification.json'
 def save():dest.write_text(json.dumps(result,indent=2)+'\n')
 save()
 try:
  assert sha(pathlib.Path(__file__).resolve())==sha(a.source_root/'integration/maintenance/ext-symlink-cuts-verify.py'),'altered executing verifier'
  # Bind the already executed Rust gate to its archived compilation sources and live source root.
  assert (a.gate/'source-start.sha256').read_bytes()==(a.gate/'source-end.sha256').read_bytes()
  # Exact source inventory independently derived from the live source tree;
  # no empty/truncated/self-listed source manifest can establish provenance.
  fixed_sources = ('Cargo.toml', 'Cargo.lock', 'integration/maintenance/ext-owned-cuts-verify.py', 'integration/maintenance/ext-owned-oracle.py', 'integration/maintenance/ext-namespace-cuts-verify.py', 'integration/maintenance/ext-namespace-oracle.py', 'integration/maintenance/ext-namespace-v4-cuts-verify.py', 'integration/maintenance/ext-directory-growth-oracle.py', 'integration/maintenance/ext-directory-growth-cuts-verify.py', 'integration/maintenance/ext-truncate-oracle.py', 'integration/maintenance/ext-truncate-cuts-verify.py', 'integration/maintenance/ext-hardlink-oracle.py', 'integration/maintenance/ext-hardlink-cuts-verify.py', 'integration/maintenance/ext-overwrite-oracle.py', 'integration/maintenance/ext-overwrite-cuts-verify.py', 'integration/maintenance/ext-sparse-extension-oracle.py', 'integration/maintenance/ext-sparse-extension-cuts-verify.py', 'tests/fixtures/ext2_clean.rs', 'tests/fixtures/ntfs_clean.rs', 'tests/fixtures/jfs_clean.rs', 'tests/fixtures/hfsplus_clean.rs', 'tests/fixtures/jffs2_clean.rs', 'tests/fs_ext_owned.rs', 'integration/maintenance/ext-symlink-oracle.py', 'integration/maintenance/ext-symlink-cuts-verify.py')
  expected_paths = sorted((a.source_root/'src').rglob('*.rs')) + [a.source_root/name for name in fixed_sources]
  expected_sources = {str(path.relative_to(a.source_root)): sha(path) for path in expected_paths}
  assert len(expected_sources)==len(expected_paths), 'duplicate expected source inventory entry'
  captured_sources = {str(path.relative_to(a.gate/'compiled-source')): sha(path) for path in (a.gate/'compiled-source').rglob('*') if path.is_file()}
  assert captured_sources==expected_sources, 'compiled source inventory mismatch'
  manifest_sources = {}
  for line in (a.gate/'source-start.sha256').read_text().splitlines():
   digest,relative=line.split('  ',1);path=pathlib.Path(relative)
   assert __import__('re').fullmatch('[0-9a-f]{64}',digest) and not path.is_absolute() and '..' not in path.parts
   assert relative==path.as_posix() and relative not in manifest_sources, 'duplicate/noncanonical source manifest path'
   manifest_sources[relative]=digest
  assert manifest_sources==expected_sources, 'source manifest inventory mismatch'
  result['gate_binary_sha256']=sha(a.gate/'gate-binary');result['verifier_sha256']=sha(pathlib.Path(__file__));shutil.copyfile(__file__,a.out/'verifier-source.py')
  receipt=json.loads((a.corpus/'receipt.json').read_text());assert receipt['complete'] and sha(a.corpus/'receipt.json')=='661553227d2108ed7d10adc22213f76053d314f1c3754bb70d6297275fe66ee5'
  for name,h in receipt['artifacts_sha256'].items():assert pathlib.Path(name).name==name and sha(a.corpus/name)==h
  tools={n:pathlib.Path(receipt['tools'][n]['path']) for n in ('debugfs','e2fsck')}
  for n,t in tools.items():assert sha(t)==receipt['tools'][n]['sha256']
  assert 'complete=true' in (a.gate/'report.txt').read_text().splitlines()
  before={str(x):sha(x) for x in [pathlib.Path(__file__).resolve(),*(a.source_root/line.split('  ',1)[1] for line in (a.gate/'source-start.sha256').read_text().splitlines()),helperpath,a.corpus/'receipt.json',*(a.corpus/name for name in receipt['artifacts_sha256']),*tools.values(),*(x for x in a.gate.rglob('*') if x.is_file())]};result['inputs_sha256']=before
  verified_artifacts=set()
  def artifact(path,h):
   relative=pathlib.Path(path);assert not relative.is_absolute() and '..' not in relative.parts;image=a.gate/relative
   if (path,h) not in verified_artifacts:assert sha(image)==h;verified_artifacts.add((path,h))
   return image
  def run(label,args,time,allowed=(0,),precheck=False):
   env=os.environ.copy();env['E2FSCK_TIME']=str(time);command=[str(x) for x in args];proc=subprocess.run(command,env=env,capture_output=True);(a.out/(label+'.stdout')).write_bytes(proc.stdout);(a.out/(label+'.stderr')).write_bytes(proc.stderr);result['commands'].append({'argv':command,'exit':proc.returncode,'environment':{'E2FSCK_TIME':str(time)}});save()
   if proc.returncode not in allowed:
    assert precheck and proc.returncode==12 and b'directory corrupted' in proc.stdout.lower() and b'e2fsck: aborted' in proc.stderr.lower(),(label,proc.returncode)
    original=args[-1].read_bytes();bs=1024<<le(original,1048);_,mapping,_=helper.classic_map(original,8);assert mapping and mapping[0]
    active=int.from_bytes(original[mapping[0]*bs+28:mapping[0]*bs+32],'big')!=0
    assert le(original,1120)&4 or active,'aborted precheck lacks recovery obligation'
    result['commands'][-1]['accepted_pre_replay_diagnostic']='directory corruption with explicit recovery obligation; strict replay and final check required';save()
  cases_by_key={(m['block_bytes'],'symlink-'+m['variant']+'-'+m['case']):m for m in receipt['cases']}
  assert len(cases_by_key)==len(receipt['cases'])
  models={key:m for key,m in cases_by_key.items() if m.get('expected_outcome','success')=='success'}
  refusals={key:m for key,m in cases_by_key.items() if m.get('expected_outcome','success')!='success'}
  baselines={};journals={};profiles={}
  import re
  for line in (a.gate/'observations.txt').read_text().splitlines():
   m=re.fullmatch(r'bs=(\d+) operation=([a-z0-9-]+) events=(\d+) baseline=(images/([0-9a-f]{64})\.raw)',line);assert m;key=int(m[1]),m[2];assert key not in profiles;profiles[key]=(int(m[3]),m[4],m[5])
  assert set(profiles)==set(models),'missing/extra successful corpus cases'
  with (a.gate/'enospc.tsv').open() as f:
   reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames=='bs operation source_sha256 after_sha256 writes flushes error'.split();refusal_rows=list(reader)
  assert len(refusal_rows)==len(refusals);seen_refusals=set()
  for row in refusal_rows:
   key=int(row['bs']),row['operation'];assert key in refusals and key not in seen_refusals;seen_refusals.add(key);case=refusals[key]
   assert row['source_sha256']==row['after_sha256']==case['image']['sha256'] and row['writes']==row['flushes']=='0' and row['error']=='InvalidOperation:no-audited-free-blocks'
   image=a.corpus/case['image']['path'];raw=image.read_bytes();accounting(raw);assert le(raw,1036)==0 and le(raw,1040)>0
   run('refusal-'+str(key[0])+'-'+key[1],[tools['e2fsck'],'-f','-n',image],le(raw,1072));assert sha(image)==case['image']['sha256']
  result['refusal_cases']=len(refusal_rows)
  expected=collections.Counter();actual=collections.Counter();unique={}
  for (bs,op),(count,path,h) in profiles.items():
   model=models[bs,op];base=(a.corpus/model['image']['path']).read_bytes();final=artifact(path,h).read_bytes();assert len(base)==len(final);baselines[bs,op]=(base,final);_,journal=helper.journal_blocks(base);journals[bs,op]=journal;time=le(base,1072);assert time!=0 and time==le(base,1088)
   required=semantics(base,final,model,helper,a.corpus,a.deletion_time)
   proof=redo(base,final,helper,required);(a.out/f'redo-b{bs}-{op}.json').write_text(json.dumps(proof,indent=2)+'\n')
   # Successful native consistency is mandatory separately from replay of cuts.
   baseline=artifact(path,h);run(f'baseline-b{bs}-{op}',[tools['e2fsck'],'-f','-n',baseline],time);assert sha(baseline)==h
   with (a.gate/f'events-b{bs}-{op}.tsv').open() as f:events=list(csv.DictReader(f,delimiter='\t'))
   assert count>0 and len(events)==count and [int(x['event']) for x in events]==list(range(1,count+1))
   assert any(x['kind']=='write' for x in events) and any(x['kind']=='flush' for x in events),'missing actual write/flush events'
   for row in events:
    event=int(row['event']);n=int(row['bytes']);assert row['kind'] in ('write','flush')
    for mode in ('immediate','volatile'):
     if row['kind']=='write':
      assert n>0,'empty actual write event'
      for prefix in (0,n//2,n):expected[bs,op,event,mode,'write',prefix]+=2
     else:
      assert n==0
      for fault in ('flush-persist','flush-none'):expected[bs,op,event,mode,fault,0]+=1
  with (a.gate/'namespace-cuts.tsv').open() as f:
   reader=csv.DictReader(f,delimiter='\t');assert reader.fieldnames=='bs operation case event model fault_kind prefix pre_sha256 pre_path retried_sha256 retried_path result'.split();rows=list(reader)
  cases=set()
  for row in rows:
   bs=int(row['bs']);op=row['operation'];case=int(row['case']);assert (bs,op,case) not in cases;cases.add((bs,op,case));actual[bs,op,int(row['event']),row['model'],row['fault_kind'],int(row['prefix'])]+=1;pre=artifact(row['pre_path'],row['pre_sha256']);retry=artifact(row['retried_path'],row['retried_sha256']);key=bs,op,row['pre_sha256'];unique.setdefault(key,[]).append((row,pre,retry))
  assert actual==expected,'incomplete fault matrix'
  for index,((bs,op,h),references) in enumerate(sorted(unique.items())):
   row,pre,_=references[0];base,final=baselines[bs,op];time=le(base,1072);image=a.out/f'native-{index:04d}.raw';shutil.copyfile(pre,image);run(f'native-{index:04d}-precheck',[tools['e2fsck'],'-f','-n',image],time,(0,4),precheck=True);assert sha(image)==h;run(f'native-{index:04d}-replay',[tools['e2fsck'],'-y','-E','journal_only',image],time,(0,1));run(f'native-{index:04d}-fn',[tools['e2fsck'],'-f','-n',image],time);native=image.read_bytes()
   decision=classify_replayed(native,references[0][2].read_bytes(),base,final,helper)
   for reference,_,retry in references:
    assert reference['result']==decision
    assert classify_replayed(native,retry.read_bytes(),base,final,helper)==decision
   # Native target and complete raw inode equality follows from journal-only full-home equality;
   # independently re-decode targets, actual alias counts and allocation counters.
   expected_image=base if decision=='old' else final
   for number in range(11,le(native,1024)+1):
    if allocated(native,number,True) and le(helper.native_inode(native,number),0,2)&0xf000==0xa000:
     assert storage(native,number,helper)==storage(expected_image,number,helper)
     assert helper.native_inode(native,number)==helper.native_inode(expected_image,number)
   # Extract actual regular files only. Never ask debugfs dump to follow a symlink.
   directories,_=graph(native,helper);pending=[(2,'')];ordinal=0
   while pending:
    directory,path=pending.pop()
    for name,(number,kind) in directories[directory].items():
     if name in (b'.',b'..'):continue
     native_path=path+'/'+name.decode('ascii')
     if kind==2:pending.append((number,native_path))
     elif kind==1:
      info=storage(expected_image,number,helper);wanted=b''.join(expected_image[b*bs:(b+1)*bs] if b else bytes(bs) for b in info['data'])[:info['length']]
      if not wanted:assert info['length']==0 and not info['data'] and not info['metadata'];continue
      output=a.out/f'dump-{index:04d}-{ordinal}.bin';ordinal+=1
      run(f'dump-{index:04d}-{ordinal}',[tools['debugfs'],'-R',f'dump {native_path} {output}',image],time);assert output.read_bytes()==wanted
   result['images'].append({'block_bytes':bs,'operation':op,'pre_sha256':h,'result':decision,'native_sha256':sha(image)});save()
  assert before=={path:sha(pathlib.Path(path)) for path in before},'bound input changed';result['bindings_after']={path:sha(pathlib.Path(path)) for path in before};result['cases']=len(rows);result['unique_preimages']=len(unique);result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};result['complete']=True;save()
 except BaseException as error:
  result['error']=repr(error);result['complete']=False;result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};save();raise

if __name__=='__main__':main()

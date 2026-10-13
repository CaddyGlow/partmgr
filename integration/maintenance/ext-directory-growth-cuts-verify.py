#!/usr/bin/env python3
"""Independent classic-ext3 forced directory growth cut verifier; offline modeled persisted bytes only."""
import argparse, collections, csv, hashlib, importlib.util, json, os, pathlib, shutil, struct, subprocess
OPS=('move-grow-direct','move-grow-indirect')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def le(raw,offset,width=4):return int.from_bytes(raw[offset:offset+width],'little')
def names_at(raw,number,helper):
 bs=1024<<le(raw,1048);_,blocks,_=helper.classic_map(raw,number);result={}
 for block in blocks:
  assert block;body=raw[block*bs:(block+1)*bs];at=0
  while at<bs:
   inode,length,n=struct.unpack_from('<IHB',body,at);assert length>=8 and length%4==0 and at+length<=bs and n<=length-8
   if inode:
    name=body[at+8:at+8+n];assert name not in result;result[name]=inode
   at+=length
 return result
def allocated(raw,number,inode=False):
 bs=1024<<le(raw,1048);first=le(raw,1044);per=le(raw,1064 if inode else 1056);index=number-1 if inode else number-first;group,bit=divmod(index,per);bitmap=le(raw,(first+1)*bs+group*32+(4 if inode else 0));return bool(raw[bitmap*bs+bit//8]&(1<<(bit%8)))
def preserved_inode(before,after,except_ranges):
 allowed={n for start,end in except_ranges for n in range(start,end)}
 assert len(before)==len(after) and all(a==b or n in allowed for n,(a,b) in enumerate(zip(before,after))),'unrelated inode field changed'
def graph(raw,helper):
 result={};paths={};pending=[(2,'')]
 while pending:
  number,path=pending.pop();assert number not in result,'directory cycle/alias';entries=names_at(raw,number,helper);result[number]=entries
  for name,child in entries.items():
   if name in (b'.',b'..'):continue
   childpath=path+'/'+name.decode('ascii');paths[childpath]=child
   if le(helper.native_inode(raw,child),0,2)&0xf000==0x4000:pending.append((child,childpath))
 return result,paths
def inode_payload(raw,number,helper):
 bs=1024<<le(raw,1048);length,blocks,_=helper.classic_map(raw,number);return b''.join(raw[block*bs:(block+1)*bs] if block else bytes(bs) for block in blocks)[:length]
def semantics(base,final,op,helper,dtime):
 assert op in OPS;bs=1024<<le(base,1048);old,paths=graph(base,helper);new,newpaths=graph(final,helper);crowded=paths['/crowded'];payload=paths['/payload'];target=b'target-'+b'z'*248;assert len(target)==255
 expected={number:dict(entries) for number,entries in old.items()};assert target not in expected[crowded];del expected[2][b'payload'];expected[crowded][target]=payload;assert new==expected,'unexpected directory graph or moved inode'
 oldlength,oldblocks,oldmeta=helper.classic_map(base,crowded);length,blocks,metadata=helper.classic_map(final,crowded);original_count=1 if op=='move-grow-direct' else 12
 assert oldlength==original_count*bs and len(oldblocks)==original_count and not oldmeta
 assert length==(original_count+1)*bs and len(blocks)==original_count+1 and blocks[:-1]==oldblocks
 assert len(metadata)==(0 if original_count==1 else 1);fresh={blocks[-1]}|metadata;assert len(fresh)==(1 if original_count==1 else 2)
 packing=[]
 for logical,block in enumerate(oldblocks):
  body=base[block*bs:(block+1)*bs];at=0
  while at<bs:
   number,record,n=struct.unpack_from('<IHB',body,at);assert record>=8 and record%4==0 and at+record<=bs and n<=record-8;minimum=(8+n+3)//4*4 if number else 0;available=record-minimum;assert available<264,'original directory had insertion slack';packing.append({'logical':logical,'physical_block':block,'offset':at,'record_bytes':record,'minimum':minimum,'available':available});at+=record
  assert body==final[block*bs:(block+1)*bs],'growth changed existing packed directory block'
 count=le(base,1024);assert count==le(final,1024)
 for number in range(1,count+1):
  assert allocated(base,number,True)==allocated(final,number,True),'growth changed inode allocation';before=helper.native_inode(base,number);after=helper.native_inode(final,number)
  if number==crowded:
   assert le(after,4)==length and le(after,28)==le(before,28)+len(fresh)*bs//512;preserved_inode(before,after,[(4,8),(28,32),(40,100)])
  else:assert before==after,'growth changed preserved inode field'
  if number>=11 and allocated(base,number,True) and le(before,0,2)&0xf000==0x8000:
   _,regular,_=helper.classic_map(base,number)
   for block in regular:
    if block:assert base[block*bs:(block+1)*bs]==final[block*bs:(block+1)*bs],'growth changed original regular payload/slack'
 total=le(base,1028);first=le(base,1044);bpg=le(base,1056)
 for block in range(first,total):assert allocated(final,block)==(True if block in fresh else allocated(base,block)),'growth bitmap changes differ from final directory map'
 assert all(not allocated(base,block) for block in fresh);assert le(base,1036)-le(final,1036)==len(fresh) and le(base,1040)==le(final,1040)
 for group in range((total-first+bpg-1)//bpg):
  at=(first+1)*bs+group*32;delta=sum((block-first)//bpg==group for block in fresh);assert le(base,at+12,2)-le(final,at+12,2)==delta;preserved_inode(base[at:at+32],final[at:at+32],[(12,14)])
 preserved_inode(base[1024:2048],final[1024:2048],[(12,16)])
 required=set(fresh)
 for number in new:
  _,directory,indirect=helper.classic_map(final,number);required.update(block for block in directory+list(indirect) if base[block*bs:(block+1)*bs]!=final[block*bs:(block+1)*bs])
 return required,packing

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('gate','corpus','source-root','out'):p.add_argument('--'+name,type=pathlib.Path,required=True)
 p.add_argument('--deletion-time',type=int,default=946684800);a=p.parse_args();assert __debug__ and all(x.is_absolute() for x in (a.gate,a.corpus,a.source_root,a.out));a.out.mkdir()
 helperpath=a.source_root/'integration/maintenance/ext-owned-cuts-verify.py';spec=importlib.util.spec_from_file_location('owned_verify',helperpath);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
 result={'complete':False,'commands':[],'images':[],'inputs_sha256':{},'helper_sha256':sha(helperpath)};dest=a.out/'qualification.json'
 def save():dest.write_text(json.dumps(result,indent=2)+'\n')
 save()
 try:
  assert sha(pathlib.Path(__file__).resolve())==sha(a.source_root/'integration/maintenance/ext-directory-growth-cuts-verify.py'),'altered executing verifier'
  # Bind the already executed Rust gate to its archived compilation sources and live source root.
  assert (a.gate/'source-start.sha256').read_bytes()==(a.gate/'source-end.sha256').read_bytes()
  for line in (a.gate/'source-start.sha256').read_text().splitlines():
   digest,relative=line.split('  ',1);path=pathlib.Path(relative);assert not path.is_absolute() and '..' not in path.parts
   assert sha(a.gate/'compiled-source'/path)==digest and sha(a.source_root/path)==digest
  result['gate_binary_sha256']=sha(a.gate/'gate-binary');result['verifier_sha256']=sha(pathlib.Path(__file__));shutil.copyfile(__file__,a.out/'verifier-source.py')
  receipt=json.loads((a.corpus/'receipt.json').read_text());assert receipt['complete'] and sha(a.corpus/'receipt.json')=='4270bb2d4a715fe39ff9836d8938bc26558ca5ef5facac30eed6801000519a75'
  assert sha(a.corpus/'models.tsv')=='19eca16c3b1c28c6e8d4ddeafa04b09249bd653e5bf05487c0fc12cbb9f8d5b9'
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
  models={(m['block_bytes'],'move-grow-'+m['variant']):m for m in receipt['models']};baselines={};journals={};profiles={}
  # Rust artifact agreement: observations bs=... operation=... events=... baseline=images/HASH.raw
  import re
  for line in (a.gate/'observations.txt').read_text().splitlines():
   m=re.fullmatch(r'bs=(\d+) operation=([a-z-]+) events=(\d+) baseline=(images/([0-9a-f]{64})\.raw)',line);assert m;bs=int(m[1]);op=m[2];assert (bs,op) not in profiles;profiles[bs,op]=(int(m[3]),m[4],m[5])
  assert set(profiles)=={(bs,op) for bs in (1024,2048,4096) for op in OPS}
  expected=collections.Counter();actual=collections.Counter();unique={}
  for (bs,op),(count,path,h) in profiles.items():
   model=models[bs,op];base=(a.corpus/model['image']['path']).read_bytes();final=artifact(path,h).read_bytes();assert len(base)==len(final);baselines[bs,op]=(base,final);_,journal=helper.journal_blocks(base);journals[bs,op]=journal;time=le(base,1072);assert time!=0 and time==le(base,1088)
   required,packing=semantics(base,final,op,helper,a.deletion_time);regular=set();proof_path=a.corpus/model['packing_proof']['path'];captured=json.loads(proof_path.read_text());assert captured['source_image_sha256']==model['image']['sha256'] and captured['directory_inode']==model['crowded_inode'] and captured['target_minimum']==264 and captured['target_name_hex']==(b'target-'+b'z'*248).hex();assert packing==[{k:entry[k] for k in packing[0]} for entry in captured['records']];assert (a.gate/f"packing-b{bs}-{model['variant']}.json").read_bytes()==proof_path.read_bytes();
   for payload_path,bound in model['payloads'].items():
    assert inode_payload(base,graph(base,helper)[1][payload_path],helper)==(a.corpus/bound['path']).read_bytes()
   (a.out/f'packing-b{bs}-{op}.json').write_text(json.dumps(packing,indent=2)+'\n')
   for number in range(11,le(base,1024)+1):
    if allocated(base,number,True) and le(helper.native_inode(base,number),0,2)&0xf000==0x8000:regular.update(helper.classic_map(base,number)[1])
   proof=helper.ordered_redo_proof(base,final,bs,sorted(regular),set());assert required<=set(proof['mutation_destinations']),'new directory data/indirect metadata absent from redo';(a.out/f'redo-b{bs}-{op}.json').write_text(json.dumps(proof,indent=2)+'\n')
   for block in range(len(final)//bs):assert block in journal or block in proof['mutation_destinations'] or base[block*bs:(block+1)*bs]==final[block*bs:(block+1)*bs],'baseline home change outside redo'
   # Successful native consistency is mandatory separately from replay of cuts.
   baseline=artifact(path,h);run(f'baseline-b{bs}-{op}',[tools['e2fsck'],'-f','-n',baseline],time);assert sha(baseline)==h
   with (a.gate/f'events-b{bs}-{op}.tsv').open() as f:events=list(csv.DictReader(f,delimiter='\t'))
   assert len(events)==count and [int(x['event']) for x in events]==list(range(1,count+1))
   for row in events:
    event=int(row['event']);n=int(row['bytes']);assert row['kind'] in ('write','flush')
    for mode in ('immediate','volatile'):
     if row['kind']=='write':
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
   def homes_equal(left,right):return len(left)==len(right) and all(i in journals[bs,op] or left[i*bs:(i+1)*bs]==right[i*bs:(i+1)*bs] for i in range(len(left)//bs))
   old=homes_equal(native,base);new=homes_equal(native,final);assert old!=new,'partial/ambiguous namespace homes';decision='old' if old else 'new'
   for reference,_,retry in references:assert reference['result']==decision and homes_equal(native,retry.read_bytes()),'native/retry disagreement'
   _,visible=graph(native,helper);_,original_paths=graph(base,helper)
   original_payloads={number:inode_payload(base,number,helper) for number in original_paths.values() if le(helper.native_inode(base,number),0,2)&0xf000==0x8000}
   for ordinal,(path,number) in enumerate(visible.items()):
    if number not in original_payloads:continue
    if not original_payloads[number]:
     empty_length,empty_data,empty_metadata=helper.classic_map(base,number);assert empty_length==0 and not empty_data and not empty_metadata;assert helper.native_inode(native,number)==helper.native_inode(base,number) and helper.classic_map(native,number)==helper.classic_map(base,number);continue
    output=a.out/f'dump-{index:04d}-{ordinal}.bin';run(f'dump-{index:04d}-{ordinal}',[tools['debugfs'],'-R',f'dump {path} {output}',image],time);assert output.read_bytes()==original_payloads[number]
   result['images'].append({'block_bytes':bs,'operation':op,'pre_sha256':h,'result':decision,'native_sha256':sha(image)});save()
  assert before=={path:sha(pathlib.Path(path)) for path in before},'bound input changed';result['bindings_after']={path:sha(pathlib.Path(path)) for path in before};result['cases']=len(rows);result['unique_preimages']=len(unique);result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};result['complete']=True;save()
 except BaseException as error:
  result['error']=repr(error);result['complete']=False;result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};save();raise

if __name__=='__main__':main()

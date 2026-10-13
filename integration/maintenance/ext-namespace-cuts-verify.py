#!/usr/bin/env python3
"""Independent classic-ext3 namespace cut verifier; offline modeled persisted bytes only."""
import argparse, collections, csv, hashlib, importlib.util, json, os, pathlib, shutil, struct, subprocess
OPS=('mkdir','rename','move','unlinkalias','unlinkpayload','rmdirsub')
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
def semantics(base,final,op,helper,dtime):
 old=helper.root_names(base);new=helper.root_names(final);bs=1024<<le(base,1048);payload=old[b'payload'];alias=old[b'alias'];assert alias==old[b'unrelated'];sub=old[b'sub'];target=payload if op in ('rename','move','unlinkpayload') else alias if op=='unlinkalias' else sub
 expected=dict(old)
 if op=='mkdir':
  assert b'new-dir' not in old and b'new-dir' in new;expected[b'new-dir']=new[b'new-dir'];inode=expected[b'new-dir'];assert not allocated(base,inode,True) and allocated(final,inode,True);raw=helper.native_inode(final,inode);assert le(raw,0,2)==0o40755 and le(raw,26,2)==2;assert names_at(final,inode,helper)=={b'.':inode,b'..':2};assert le(helper.native_inode(final,2),26,2)==le(helper.native_inode(base,2),26,2)+1
  _,blocks,meta=helper.classic_map(final,inode);assert all(not allocated(base,b) and allocated(final,b) for b in blocks+list(meta));required=set(blocks)|meta
 elif op=='rename':del expected[b'payload'];expected[b'renamed']=payload;required=set()
 elif op=='move':
  del expected[b'payload'];subold=names_at(base,sub,helper);subnew=names_at(final,sub,helper);assert b'moved' not in subold;assert subnew==subold|{b'moved':payload};required=set()
 elif op=='unlinkalias':
  del expected[b'alias'];before=helper.native_inode(base,alias);after=helper.native_inode(final,alias);assert le(after,26,2)==le(before,26,2)-1;preserved_inode(before,after,[(26,28)]);assert allocated(final,alias,True);required=set()
 else:
  del expected[b'payload' if op=='unlinkpayload' else b'sub'];before=helper.native_inode(base,target);after=helper.native_inode(final,target);assert not allocated(final,target,True);assert le(after,26,2)==0 and le(after,4)==0 and le(after,20)==dtime;assert le(after,100)==le(before,100);preserved_inode(before,after,[(4,8),(20,24),(26,32),(40,100)]);_,blocks,meta=helper.classic_map(base,target);assert all(not allocated(final,b) for b in blocks+list(meta) if b);required=set()
  if op=='rmdirsub':assert names_at(base,sub,helper)=={b'.':sub,b'..':2};assert le(helper.native_inode(final,2),26,2)==le(helper.native_inode(base,2),26,2)-1
 assert new==expected,'unexpected root namespace'
 if op in ('rename','move'):assert helper.native_inode(final,payload)==helper.native_inode(base,payload),'rename changed regular inode'
 for name in (b'payload',b'unrelated',b'sub'):
  number=old[name]
  if name==b'payload' and op in ('unlinkpayload',):continue
  if name==b'unrelated' and op=='unlinkalias':continue
  if name==b'sub' and op in ('move','rmdirsub'):continue
  assert helper.native_inode(final,number)==helper.native_inode(base,number),'unrelated raw inode changed'
 # Every changed surviving directory data block is metadata and must be journaled.
 for number in {2,sub}|({new[b'new-dir']} if op=='mkdir' else set()):
  if not allocated(final,number,True):continue
  _,blocks,meta=helper.classic_map(final,number)
  required.update(block for block in blocks+list(meta) if base[block*bs:(block+1)*bs]!=final[block*bs:(block+1)*bs])
 return required

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('gate','corpus','source-root','out'):p.add_argument('--'+name,type=pathlib.Path,required=True)
 p.add_argument('--deletion-time',type=int,default=946684800);a=p.parse_args();assert __debug__ and all(x.is_absolute() for x in (a.gate,a.corpus,a.source_root,a.out));a.out.mkdir()
 helperpath=a.source_root/'integration/maintenance/ext-owned-cuts-verify.py';spec=importlib.util.spec_from_file_location('owned_verify',helperpath);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
 result={'complete':False,'commands':[],'images':[],'inputs_sha256':{},'helper_sha256':sha(helperpath)};dest=a.out/'qualification.json'
 def save():dest.write_text(json.dumps(result,indent=2)+'\n')
 save()
 try:
  assert sha(pathlib.Path(__file__).resolve())==sha(a.source_root/'integration/maintenance/ext-namespace-cuts-verify.py'),'altered executing verifier'
  # Bind the already executed Rust gate to its archived compilation sources and live source root.
  assert (a.gate/'source-start.sha256').read_bytes()==(a.gate/'source-end.sha256').read_bytes()
  for line in (a.gate/'source-start.sha256').read_text().splitlines():
   digest,relative=line.split('  ',1);path=pathlib.Path(relative);assert not path.is_absolute() and '..' not in path.parts
   assert sha(a.gate/'compiled-source'/path)==digest and sha(a.source_root/path)==digest
  result['gate_binary_sha256']=sha(a.gate/'gate-binary');result['verifier_sha256']=sha(pathlib.Path(__file__));shutil.copyfile(__file__,a.out/'verifier-source.py')
  receipt=json.loads((a.corpus/'receipt.json').read_text());assert receipt['complete'] and sha(a.corpus/'receipt.json')==helper.RECEIPT
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
  models={m['block_bytes']:m for m in receipt['models']};baselines={};journals={};profiles={}
  # Rust artifact agreement: observations bs=... operation=... events=... baseline=images/HASH.raw
  import re
  for line in (a.gate/'observations.txt').read_text().splitlines():
   m=re.fullmatch(r'bs=(\d+) operation=(\w+) events=(\d+) baseline=(images/([0-9a-f]{64})\.raw)',line);assert m;bs=int(m[1]);op=m[2];assert (bs,op) not in profiles;profiles[bs,op]=(int(m[3]),m[4],m[5])
  assert set(profiles)=={(bs,op) for bs in (1024,2048,4096) for op in OPS}
  expected=collections.Counter();actual=collections.Counter();unique={}
  for (bs,op),(count,path,h) in profiles.items():
   model=models[bs];base=(a.corpus/model['image']['path']).read_bytes();final=artifact(path,h).read_bytes();assert len(base)==len(final);baselines[bs,op]=(base,final);_,journal=helper.journal_blocks(base);journals[bs]=journal;time=le(base,1072);assert time!=0 and time==le(base,1088)
   required=semantics(base,final,op,helper,a.deletion_time);regular=set()
   for name in (b'payload',b'unrelated'):regular.update(helper.classic_map(base,helper.root_names(base)[name])[1])
   proof=helper.ordered_redo_proof(base,final,bs,sorted(regular),set());assert required<=set(proof['mutation_destinations']),'new directory metadata absent from redo';(a.out/f'redo-b{bs}-{op}.json').write_text(json.dumps(proof,indent=2)+'\n')
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
   def homes_equal(left,right):return len(left)==len(right) and all(i in journals[bs] or left[i*bs:(i+1)*bs]==right[i*bs:(i+1)*bs] for i in range(len(left)//bs))
   old=homes_equal(native,base);new=homes_equal(native,final);assert old!=new,'partial/ambiguous namespace homes';decision='old' if old else 'new'
   for reference,_,retry in references:assert reference['result']==decision and homes_equal(native,retry.read_bytes()),'native/retry disagreement'
   names=helper.root_names(native);original=helper.root_names(base)
   # Native payload extraction, including renamed/moved paths and surviving aliases.
   paths={'/unrelated':(a.corpus/models[bs]['unrelated']['path']).read_bytes()}
   if b'alias' in names:paths['/alias']=paths['/unrelated']
   if old or op!='unlinkpayload':paths['/payload' if old or op not in ('rename','move') else '/renamed' if op=='rename' else '/sub/moved']=(a.corpus/models[bs]['payload']['path']).read_bytes()
   for ordinal,(path,wanted) in enumerate(paths.items()):
    output=a.out/f'dump-{index:04d}-{ordinal}.bin';run(f'dump-{index:04d}-{ordinal}',[tools['debugfs'],'-R',f'dump {path} {output}',image],time);assert output.read_bytes()==wanted
   result['images'].append({'block_bytes':bs,'operation':op,'pre_sha256':h,'result':decision,'native_sha256':sha(image)});save()
  assert before=={path:sha(pathlib.Path(path)) for path in before},'bound input changed';result['bindings_after']={path:sha(pathlib.Path(path)) for path in before};result['cases']=len(rows);result['unique_preimages']=len(unique);result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};result['complete']=True;save()
 except BaseException as error:
  result['error']=repr(error);result['complete']=False;result['artifacts_sha256']={str(x.relative_to(a.out)):sha(x) for x in sorted(a.out.rglob('*')) if x.is_file() and x!=dest};save();raise

if __name__=='__main__':main()

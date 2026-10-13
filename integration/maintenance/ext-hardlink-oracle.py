#!/usr/bin/env python3
"""Independent native hardlink fixtures; no production qualification."""
import argparse,hashlib,json,os,pathlib,re,shutil,struct,subprocess,sys
PINS={'namespace':('partmgr-ext-namespace-oracle-20261011-v1','99698f8c91d1bd6215104a7d235b0ba38ff6eb7803ac895330cf46b1d6ebc98c'),'growth':('partmgr-ext-directory-growth-oracle-20261011-v1','4270bb2d4a715fe39ff9836d8938bc26558ca5ef5facac30eed6801000519a75')}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('out',type=pathlib.Path);a=p.parse_args();assert __debug__ and a.out.is_absolute();a.out.mkdir();receipt={'complete':False,'schema_version':1,'scope':__doc__,'invocation':sys.argv,'commands':[],'models':[],'priors':{}};dest=a.out/'receipt.json'
 def save():dest.write_text(json.dumps(receipt,indent=2)+'\n')
 def artifact(path):return {'path':path.name,'sha256':sha(path),'bytes':path.stat().st_size}
 save()
 try:
  source=pathlib.Path(__file__).resolve();shutil.copyfile(source,a.out/'generator-source.py');sourcehash=sha(source);receipt['source_sha256']=sourcehash;priors={}
  for key,(dirname,pin) in PINS.items():
   directory=pathlib.Path('/data/cache')/dirname;r=directory/'receipt.json';assert sha(r)==pin;data=json.loads(r.read_text());assert data['complete'];
   for name,h in data['artifacts_sha256'].items():assert sha(directory/name)==h
   receipt['priors'][key]={'path':str(r),'sha256':pin};priors[key]=(directory,data)
  helper=priors['growth'][0]/'generator-source.py';shutil.copyfile(helper,a.out/'mapping-helper-source.py');namespace={};exec(compile(helper.read_text(),str(helper),'exec'),namespace);inode=namespace['inode'];mapping=namespace['mapping'];records=namespace['records'];tools=priors['namespace'][1]['tools'];receipt['tools']=tools
  for item in tools.values():assert sha(pathlib.Path(item['path']))==item['sha256']
  env=dict(os.environ,LC_ALL='C',TZ='UTC',E2FSCK_TIME='946684800',E2FSPROGS_FAKE_TIME='946684800')
  def run(tool,args):
   argv=[tools[tool]['path'],*map(str,args)];r=subprocess.run(argv,env=env,capture_output=True);i=len(receipt['commands']);row={'argv':argv,'exit':r.returncode,'environment':{k:env[k] for k in ('LC_ALL','TZ','E2FSCK_TIME','E2FSPROGS_FAKE_TIME')}}
   for stream in ('stdout','stderr'):
    path=a.out/f'command-{i:03}.{stream}';path.write_bytes(getattr(r,stream));row[stream]=artifact(path)
   receipt['commands'].append(row);save();assert r.returncode==0,(argv,r.returncode);return r.stdout
  def graph(raw):
   bs=1024<<struct.unpack_from('<I',raw,1048)[0];first=struct.unpack_from('<I',raw,1044)[0];bpg=struct.unpack_from('<I',raw,1056)[0];ipg=struct.unpack_from('<I',raw,1064)[0];blocks=struct.unpack_from('<I',raw,1028)[0];ninodes=struct.unpack_from('<I',raw,1024)[0];groups=[];entries={}
   for g in range((blocks-first+bpg-1)//bpg):
    at=(first+1)*bs+g*32;bb,ib=struct.unpack_from('<II',raw,at);bitmap=raw[ib*bs:(ib+1)*bs];groups.append({'descriptor_hex':raw[at:at+32].hex(),'block_bitmap_hex':raw[bb*bs:(bb+1)*bs].hex(),'inode_bitmap_hex':bitmap.hex()})
    for slot in range(min(ipg,ninodes-g*ipg)):
     if bitmap[slot//8]&(1<<(slot%8)):
      n=g*ipg+slot+1;native=inode(raw,n);item={'raw_inode_hex':native.hex()};kind=struct.unpack_from('<H',native)[0]&0xf000
      if kind in (0x8000,0x4000) and struct.unpack_from('<I',native,4)[0]:
       info=mapping(raw,n);item['mapping']=info;item['physical_payload_sha256']=hashlib.sha256(b''.join(raw[b*bs:(b+1)*bs] for b in info['data_blocks'])).hexdigest()
       if kind==0x4000:item['directory_records']=records(raw,info)
      entries[str(n)]=item
   return {'superblock_hex':raw[1024:2048].hex(),'groups':groups,'inodes':entries}
  for base in priors['namespace'][1]['models']:
   bs=base['block_bytes']
   for case in ('same','cross','grow-direct','grow-indirect'):
    if case.startswith('grow'):
     variant=case.split('-')[1];m=next(x for x in priors['growth'][1]['models'] if x['block_bytes']==bs and x['variant']==variant);directory=priors['growth'][0];parent='/crowded';name=bytes.fromhex(m['target_name_hex']).decode();packing=m['packing_proof'];shutil.copyfile(directory/packing['path'],a.out/f'packing-b{bs}-{case}.json')
    else:m=base;directory=priors['namespace'][0];parent='/' if case=='same' else '/right';name='hardlink-new'
    sourcepath='/indirect' if case in ('cross','grow-indirect') else '/payload';image=a.out/f'hardlink-b{bs}-{case}-before.raw';shutil.copyfile(directory/m['image']['path'],image);assert sha(image)==m['image']['sha256'];run('e2fsck',['-f','-n',image]);before=image.read_bytes();beforehash=sha(image);text=run('debugfs',['-R','stat '+sourcepath,image]);number=int(re.search(rb'^Inode:\s*(\d+)',text,re.M)[1]);native=inode(before,number);links=struct.unpack_from('<H',native,26)[0];assert 0<links<32000;target=parent.rstrip('/')+'/'+name;expected=a.out/f'hardlink-b{bs}-{case}-native.raw';shutil.copyfile(image,expected);cmd=a.out/f'hardlink-b{bs}-{case}.cmd';commands=[]
    if case.startswith('grow'):commands.append('expand_dir /crowded')
    commands.extend([f'ln {sourcepath} {target}',f'set_inode_field {sourcepath} links_count {links+1}']);cmd.write_text('\n'.join(commands)+'\n');run('debugfs',['-w','-f',cmd,expected]);run('e2fsck',['-f','-n',expected]);after=expected.read_bytes();wanted=bytearray(native);struct.pack_into('<H',wanted,26,links+1);assert inode(after,number)==wanted
    oldmap=mapping(before,number);assert mapping(after,number)==oldmap
    for block in oldmap['data_blocks']+oldmap['indirect_blocks']:assert before[block*bs:(block+1)*bs]==after[block*bs:(block+1)*bs]
    payload=a.out/f'payload-b{bs}-{case}.bin';alias=a.out/f'alias-b{bs}-{case}.bin';run('debugfs',['-R',f'dump {sourcepath} {payload}',expected]);run('debugfs',['-R',f'dump {target} {alias}',expected]);assert payload.read_bytes()==alias.read_bytes();assert len(payload.read_bytes())==oldmap['length']
    pregraph=a.out/f'graph-b{bs}-{case}-before.json';postgraph=a.out/f'graph-b{bs}-{case}-native.json';pregraph.write_text(json.dumps(graph(before),sort_keys=True)+'\n');postgraph.write_text(json.dumps(graph(after),sort_keys=True)+'\n');assert sha(image)==beforehash
    receipt['models'].append({'block_bytes':bs,'case':'hardlink-'+case,'image':artifact(image),'native_image':artifact(expected),'source_path':sourcepath,'destination_parent':parent,'destination_name_hex':name.encode().hex(),'destination_path':target,'inode':number,'old_links':links,'new_links':links+1,'payload':artifact(payload),'native_alias_payload':artifact(alias),'before_graph':artifact(pregraph),'native_graph':artifact(postgraph),'original_map':oldmap,'packing_proof':artifact(a.out/f'packing-b{bs}-{case}.json') if case.startswith('grow') else None});save()
  for key,(directory,data) in priors.items():
   assert sha(directory/'receipt.json')==PINS[key][1]
   for name,h in data['artifacts_sha256'].items():assert sha(directory/name)==h
  for item in tools.values():assert sha(pathlib.Path(item['path']))==item['sha256']
  assert sha(source)==sourcehash
  cols='block_bytes case image_path image_sha256 source_path destination_parent destination_name_hex inode native_image_path native_image_sha256 payload_path payload_sha256'.split();receipt['tsv_columns']=cols;(a.out/'models.tsv').write_text(''.join('\t'.join(map(str,[m['block_bytes'],m['case'],m['image']['path'],m['image']['sha256'],m['source_path'],m['destination_parent'],m['destination_name_hex'],m['inode'],m['native_image']['path'],m['native_image']['sha256'],m['payload']['path'],m['payload']['sha256']]))+'\n' for m in receipt['models']));receipt['artifacts_sha256']={x.name:sha(x) for x in sorted(a.out.iterdir()) if x.is_file() and x!=dest};receipt['complete']=True;save();print(json.dumps({'receipt':str(dest),'sha256':sha(dest),'models_sha256':sha(a.out/'models.tsv'),'models':len(receipt['models']),'commands':len(receipt['commands'])}))
 except BaseException as e:receipt['error']=repr(e);save();raise
if __name__=='__main__':main()

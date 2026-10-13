"""Check source-order and sorted USN CLI output against one frozen native image."""
import argparse,hashlib,json,pathlib,subprocess
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image',type=pathlib.Path,required=True)
parser.add_argument('--binary',type=pathlib.Path,required=True)
parser.add_argument('--evidence-dir',type=pathlib.Path,required=True)
args=parser.parse_args()
image=args.image.resolve(strict=True)
binary=args.binary.resolve(strict=True)
evidence=args.evidence_dir.resolve()
evidence.mkdir()
temporary=evidence/'temporary';temporary.mkdir()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
 return h.hexdigest()
before=digest(image)
common=[str(binary),'timeline-usn',str(image),'--format','raw','--sector-size','512','--assert-stable','--acquisition-id','native-windows-frozen-b','--stability-provider','closed-native-capture','--records','1000000','--read-bytes','1073741824','--memory-bytes','67108864','--output-bytes','1073741824']
commands=[]
def run(label,args):
 with (evidence/(label+'.jsonl')).open('wb') as out, (evidence/(label+'.stderr')).open('wb') as err:
  result=subprocess.run(args,stdout=out,stderr=err)
 commands.append({'argv':args,'exit_status':result.returncode})
 assert result.returncode==0,(label,result.returncode,(evidence/(label+'.stderr')).read_text())
 rows=[json.loads(line) for line in (evidence/(label+'.jsonl')).read_text().splitlines()]
 assert rows[-1]['type']=='terminal' and rows[-1]['complete']
 return rows
plain=run('source-order',common)
sorted_rows=run('chronological',common+['--sort','--temporary-dir',str(temporary)])
a=[r for r in plain if r['type']=='usn_record'];b=[r for r in sorted_rows if r['type']=='usn_record']
assert a and len(a)==len(b)
assert [int(r['timestamp_ticks']) for r in b]==sorted(int(r['timestamp_ticks']) for r in a)
assert sorted(json.dumps(r,sort_keys=True) for r in a)==sorted(json.dumps(r,sort_keys=True) for r in b)
meta=('usn_namespace','usn_max','usn_gap','usn_retention','usn_offset_disagreement')
assert [r for r in plain if r['type'] in meta]==[r for r in sorted_rows if r['type'] in meta]
assert sorted_rows[-1]['coordinate_space']=='record_ordinals'
assert not list(temporary.iterdir())
assert digest(image)==before
receipt={'result':'passed','image_sha256_before_after':before,'binary_sha256':digest(binary),'script_sha256':digest(pathlib.Path(__file__)),'record_count':len(a),'raw_records_and_provenance_preserved':True,'structural_observations_preserved':True,'commands':commands,'source_sha256':{str(p):digest(p) for p in map(pathlib.Path,['src/forensics_journal.rs','src/forensics_sort.rs','src/forensics_timeline_spool.rs','examples/filesystem-forensics.rs'])}}
(evidence/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(evidence/'receipt.json')

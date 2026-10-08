#!/usr/bin/env python3
"""Independent raw MS-FSCC layout assembly; does not call the Rust decoder."""
import hashlib,json,struct
from pathlib import Path
root=Path(__file__).resolve().parent
payload=bytearray(); models=[]
for i in range(1024):
    major=2 if i%2==0 else 3
    prefix=60 if major==2 else 76
    common=24 if major==2 else 40
    extension=8 if i%3==0 else 0
    units=[0x0061,0xd800,i%65536,0,0xffff]
    offset=prefix+extension
    length=(offset+2*len(units)+7)//8*8
    record=bytearray([0xa5]*length)
    struct.pack_into('<IHH',record,0,length,major,9 if extension else 0)
    if major==2:
        struct.pack_into('<QQ',record,8,((i+1)<<48)|i,(17<<48)|5)
    else:
        record[8:24]=i.to_bytes(16,'little');record[24:40]=(5).to_bytes(16,'little')
    struct.pack_into('<qqIIIIHH',record,common,i*4096,132537600123456789+i,0x81002100,0x80000009,42,0x80000020,len(units)*2,offset)
    struct.pack_into('<'+'H'*len(units),record,offset,*units)
    models.append({'offset':len(payload),'length':length,'major':major,'usn':i*4096,'ticks':132537600123456789+i,'name_units':units})
    payload.extend(record)
(root/'ntfs_usn_mixed.bin').write_bytes(payload)
(root/'ntfs_usn_model.json').write_text(json.dumps({'provenance':'Independent Python struct.pack little-endian MS-FSCC V2/V3 documented field offsets; synthetic evidence, not native Windows capture.','records':models,'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)},indent=2)+'\n')
print(f'{len(models)} records {len(payload)} bytes {hashlib.sha256(payload).hexdigest()}')

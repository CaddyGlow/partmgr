#!/usr/bin/env python3
"""Boot partmgr GPT/MBR images with independently prepared FAT and OVMF.

Missing dependencies fail explicitly. Records prove firmware executed our EFI
application; they do not establish Windows servicing or arbitrary bootloader support.
"""
import argparse, hashlib, json, os, shutil, struct, subprocess
from pathlib import Path


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def efi_application():
    """Independent minimal x86-64 PE32+ EFI app, no firmware API dependencies."""
    code = bytearray(b'\x66\xba\xe9\x00')  # mov dx, 0xe9
    for value in b'PARTMGR_FIRMWARE_OK\n':
        code += bytes([0xb0, value, 0xee])  # mov al, value; out dx, al
    code += b'\x66\xba\xf4\x00\xb8\x10\x00\x00\x00\xef\xf4\xeb\xfd'
    b = bytearray(1536)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 60, 64)
    b[64:68] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', b, 68, 0x8664, 2, 0, 0, 0, 240, 0x2022)
    o = 88
    struct.pack_into('<HBBIIIIIQ', b, o, 0x20b, 0, 0, 512, 512, 0, 4096, 4096, 0x400000)
    struct.pack_into('<IIHHHHHHIIIIHHQQQQII', b, o+32,
                     4096,512,0,0,0,0,0,0,0,12288,512,0,10,0,
                     0x100000,0x1000,0x100000,0x1000,0,16)
    struct.pack_into('<II', b, o+112+5*8, 8192, 12)
    s = o+240
    struct.pack_into('<8sIIIIIIHHI', b,s,b'.text\0\0\0',len(code),4096,512,512,0,0,0,0,0x60000020)
    struct.pack_into('<8sIIIIIIHHI', b,s+40,b'.reloc\0\0',12,8192,512,1024,0,0,0,0,0x42000040)
    b[512:512+len(code)] = code
    struct.pack_into('<IIHH', b,1024,4096,12,0,0)
    return b


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ovmf-code',type=Path,required=True)
    parser.add_argument('--ovmf-vars',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    for tool in ['cargo','qemu-system-x86_64','mkfs.fat','mmd','mcopy','sfdisk']:
        if shutil.which(tool) is None: parser.error(f'required tool unavailable: {tool}')
    for firmware in [args.ovmf_code,args.ovmf_vars]:
        if not firmware.is_file(): parser.error(f'firmware unavailable: {firmware}')
    args.output.mkdir(parents=True,exist_ok=False)
    output=args.output.resolve()
    app=output/'BOOTX64.EFI';app.write_bytes(efi_application())
    fat=output/'esp.fat'
    with fat.open('wb') as f:f.truncate(96*1024*1024)
    run(['mkfs.fat','-F','32',str(fat)])
    run(['mmd','-i',str(fat),'::/EFI','::/EFI/BOOT'])
    run(['mcopy','-i',str(fat),str(app),'::/EFI/BOOT/BOOTX64.EFI'])
    results={'scope':'x86-64 fallback EFI execution, 512-byte GPT and MBR ESPs','firmware_sha256':hashlib.sha256(args.ovmf_code.read_bytes()).hexdigest(),'efi_sha256':hashlib.sha256(app.read_bytes()).hexdigest(),'images':{}}
    for scheme in ['gpt','mbr']:
        image=output/f'{scheme}.img'
        run(['cargo','run','--locked','--example','firmware-image','--',scheme,str(image)])
        with image.open('r+b') as destination,fat.open('rb') as source:
            destination.seek(2048*512)
            shutil.copyfileobj(source,destination,1024*1024)
            destination.flush();os.fsync(destination.fileno())
        table=json.loads(subprocess.check_output(['sfdisk','--json',str(image)],text=True))
        vars_file=output/f'{scheme}-vars.fd';shutil.copyfile(args.ovmf_vars,vars_file)
        log=output/f'{scheme}-debug.log'
        command=['qemu-system-x86_64','-machine','q35','-accel','tcg','-m','128','-display','none','-serial','none','-monitor','none','-no-reboot',
                 '-drive',f'if=pflash,format=raw,readonly=on,file={args.ovmf_code}',
                 '-drive',f'if=pflash,format=raw,file={vars_file}',
                 '-drive',f'format=raw,file={image}',
                 '-device','isa-debug-exit,iobase=0xf4,iosize=0x04',
                 '-debugcon',f'file:{log}','-global','isa-debugcon.iobase=0xe9']
        with (output/f'{scheme}-qemu.log').open('w') as qlog:
            result=subprocess.run(command,stdout=qlog,stderr=subprocess.STDOUT,timeout=90)
        marker=log.is_file() and b'PARTMGR_FIRMWARE_OK' in log.read_bytes()
        results['images'][scheme]={'qemu_exit':result.returncode,'efi_marker':marker,'table':table,'command':command}
        (output/'receipt.json').write_text(json.dumps(results,indent=2)+'\n')
        if result.returncode!=33 or not marker:raise SystemExit(f'{scheme} firmware execution failed; evidence: {output}')
    print(output/'receipt.json')

if __name__=='__main__':main()

#!/usr/bin/env python3
"""Boot partmgr GPT/MBR images with native or framework FAT and OVMF.

Missing dependencies fail explicitly. Records prove firmware executed our EFI
application; they do not establish Windows servicing or arbitrary bootloader support.
"""
import argparse, hashlib, json, os, shutil, struct, subprocess
from pathlib import Path


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


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ovmf-code', type=Path, required=True)
    parser.add_argument('--ovmf-vars', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fat-source', choices=['native', 'framework'], default='native')
    parser.add_argument('--target-dir', type=Path)
    args = parser.parse_args()
    tools = ['cargo', 'rustc', 'qemu-system-x86_64', 'sfdisk', 'fsck.fat']
    if args.fat_source == 'native':
        tools += ['mkfs.fat', 'mmd', 'mcopy']
    for tool in tools:
        if shutil.which(tool) is None:
            parser.error(f'required tool unavailable: {tool}')
    for firmware in [args.ovmf_code, args.ovmf_vars]:
        if not firmware.is_file():
            parser.error(f'firmware unavailable: {firmware}')
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    root = Path(__file__).resolve().parent.parent
    env = dict(os.environ, LC_ALL='C')
    if args.target_dir:
        env['CARGO_TARGET_DIR'] = str(args.target_dir.resolve())
    target = Path(env.get('CARGO_TARGET_DIR', root / 'target'))
    if not target.is_absolute():
        target = root / target
    sources = sorted([root / 'Cargo.toml', root / 'Cargo.lock', Path(__file__).resolve(),
                      root / 'examples/firmware-image.rs',
                      root / 'examples/filesystem-fat-build-tree.rs', *root.glob('src/**/*.rs')])
    results = {'schema_version': 2, 'profile': 'fallback-efi-' + args.fat_source + '-fat-v1',
               'status': 'running', 'fat_origin': args.fat_source,
               'scope': 'observed generated x86-64 fallback EFI application execution on 512-byte GPT and MBR ESPs',
               'firmware_sha256': digest(args.ovmf_code), 'firmware_vars_sha256': digest(args.ovmf_vars),
               'sources': {str(p.relative_to(root)): digest(p) for p in sources},
               'tools': {}, 'commands': [], 'binaries': {}, 'images': {}}

    def save():
        (output / 'receipt.json').write_text(json.dumps(results, indent=2) + '\n')

    def command(label, arguments, acceptable=(0,), timeout=None):
        log = output / (label + '.log')
        timed_out = False
        with log.open('wb') as stream:
            try:
                result = subprocess.run([str(a) for a in arguments], cwd=root, env=env,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=timeout,
                                        check=False)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = None
                timed_out = True
        results['commands'].append({'label': label, 'argv': [str(a) for a in arguments],
                                    'cwd': str(root), 'exit_code': code, 'timeout': timed_out,
                                    'log': str(log), 'log_sha256': digest(log)})
        save()
        if timed_out or (acceptable is not None and code not in acceptable):
            raise RuntimeError(f'{label} failed with exit {code}; timeout={timed_out}; see {log}')
        return log.read_text(errors='replace'), code

    try:
        for tool in tools:
            path = Path(shutil.which(tool))
            flags = ['-V'] if tool in ('mmd', 'mcopy') else ['--version']
            if tool in ('fsck.fat', 'mkfs.fat'):
                flags = ['--help']
            results['tools'][tool] = {'path': str(path), 'sha256': digest(path)}
            text, _ = command('version-' + tool, [path, *flags], acceptable=(0, 1))
            results['tools'][tool]['version_output'] = text
        examples = ['firmware-image']
        if args.fat_source == 'framework':
            examples.append('filesystem-fat-build-tree')
        arguments = ['cargo', 'build', '--locked']
        for example in examples:
            arguments += ['--example', example]
        command('cargo-build', arguments)
        for example in examples:
            binary = target / 'debug/examples' / example
            results['binaries'][example] = {'path': str(binary), 'sha256': digest(binary)}
        app = output / 'BOOTX64.EFI'
        app.write_bytes(efi_application())
        results['efi_sha256'] = digest(app)
        fat = output / 'esp.fat'
        if args.fat_source == 'framework':
            command('framework-fat-build', [results['binaries']['filesystem-fat-build-tree']['path'],
                                           fat, 32, app, 'forward'])
            expected_size = 64 * 1024 * 1024
            results['fat_profile'] = 'framework nested FAT32 builder; deterministic defaults; real generated EFI test app at EFI/BOOT/BOOTX64.EFI plus fixture names'
        else:
            with fat.open('xb') as stream:
                stream.truncate(96 * 1024 * 1024)
            command('native-fat-mkfs', ['mkfs.fat', '-F', '32', fat])
            command('native-fat-mmd', ['mmd', '-i', fat, '::/EFI', '::/EFI/BOOT'])
            command('native-fat-install', ['mcopy', '-i', fat, app, '::/EFI/BOOT/BOOTX64.EFI'])
            expected_size = 96 * 1024 * 1024
            results['fat_profile'] = 'independent mkfs.fat FAT32 with mtools EFI installation'
        if fat.stat().st_size != expected_size:
            raise RuntimeError('unexpected FAT profile size')
        fat_hash = digest(fat)
        command('fat-fsck', ['fsck.fat', '-n', '-v', fat])
        if digest(fat) != fat_hash:
            raise RuntimeError('read-only fsck modified prepared FAT')
        results['fat_image'] = {'path': str(fat), 'sha256': fat_hash,
                                'filesystem_bytes': expected_size, 'partition_bytes': 96 * 1024 * 1024,
                                'partition_tail_zero_bytes': 96 * 1024 * 1024 - expected_size,
                                'native_fsck': 'passed; hash unchanged'}
        for scheme in ['gpt', 'mbr']:
            image = output / f'{scheme}.img'
            command(scheme + '-table-build', [results['binaries']['firmware-image']['path'], scheme, image])
            text, _ = command(scheme + '-table-check', ['sfdisk', '--json', image])
            table = json.loads(text)
            partition = table['partitiontable']['partitions'][0]
            if partition['start'] != 2048 or partition['size'] != 196608:
                raise RuntimeError('unexpected ESP bounds')
            expected_type = 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B' if scheme == 'gpt' else 'ef'
            if partition['type'].upper() != expected_type.upper():
                raise RuntimeError('unexpected ESP partition type')
            with image.open('r+b') as destination, fat.open('rb') as source:
                destination.seek(2048 * 512)
                shutil.copyfileobj(source, destination, 1024 * 1024)
                destination.flush()
                os.fsync(destination.fileno())
            before = digest(image)
            vars_file = output / f'{scheme}-vars.fd'
            shutil.copyfile(args.ovmf_vars, vars_file)
            debug = output / f'{scheme}-debug.log'
            argv = ['qemu-system-x86_64', '-machine', 'q35', '-accel', 'tcg', '-m', '128',
                    '-display', 'none', '-serial', 'none', '-monitor', 'none', '-no-reboot',
                    '-drive', f'if=pflash,format=raw,readonly=on,file={args.ovmf_code.resolve()}',
                    '-drive', f'if=pflash,format=raw,file={vars_file}',
                    '-drive', f'format=raw,file={image}',
                    '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                    '-debugcon', f'file:{debug}', '-global', 'isa-debugcon.iobase=0xe9']
            results['images'][scheme] = {'status': 'running', 'table': table, 'command': argv,
                                         'image_sha256_before_boot': before}
            save()
            _, code = command(scheme + '-qemu', argv, acceptable=None, timeout=90)
            marker = debug.is_file() and b'PARTMGR_FIRMWARE_OK\n' in debug.read_bytes()
            results['images'][scheme].update(qemu_exit=code, efi_marker=marker,
                                             debug_log_sha256=digest(debug) if debug.is_file() else None,
                                             image_sha256_after_boot=digest(image),
                                             firmware_vars_sha256_after_boot=digest(vars_file),
                                             status='passed' if marker and code == 33 else 'failed')
            save()
            if not marker or code != 33:
                raise RuntimeError(f'{scheme} firmware execution failed: exit={code}, marker={marker}')
        results['sources_after'] = {str(p.relative_to(root)): digest(p) for p in sources}
        if results['sources_after'] != results['sources']:
            raise RuntimeError('implementation sources changed during gate; rerun required')
        results['status'] = 'passed'
        save()
        print(output / 'receipt.json')
    except Exception as error:
        results['status'] = 'failed'
        for image in results['images'].values():
            if image['status'] == 'running':
                image['status'] = 'failed'
        results['reason'] = str(error)
        save()
        raise SystemExit(f'{error}; evidence: {output}')


if __name__ == '__main__':
    main()

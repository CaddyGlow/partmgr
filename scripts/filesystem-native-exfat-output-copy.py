#!/usr/bin/env python3
"""Explicit native FAT/ext2/exFAT bounded-region capture into direct-authored exFAT."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            value.update(data)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path,
                        default=Path('/data/cache/partmgr-exfat-output-copy-target'))
    parser.add_argument('--tool', action='append', default=[], metavar='NAME=PATH')
    args = parser.parse_args()
    overrides = dict(value.split('=', 1) for value in args.tool)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = args.output.resolve() / f'{stamp}-{os.getpid()}'
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema_version': 1, 'profile': 'common-region-to-exfat-content-only-v1',
               'status': 'running', 'python_version': sys.version,
               'source_stability': 'caller-guaranteed immutable sources; final hashes detect final changes, not transient mutations',
               'metadata_policy': 'explicit content-only deterministic defaults; no metadata preservation',
               'capture_uses_host_extraction': False, 'commands': [], 'tools': {},
               'profiles': [], 'layers': {'source_audit': 'pending', 'filesystem': 'pending',
               'publication': 'pending', 'publication_directory_flush': 'pending',
               'partition': 'standalone filesystem', 'container': 'raw', 'firmware_boot': 'unverified'}}
    env = dict(os.environ, LC_ALL='C.UTF-8', CARGO_TARGET_DIR=str(args.target_dir.resolve()))

    def save():
        with (output / 'evidence.json').open('w') as stream:
            json.dump(receipt, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())

    def command(label, argv, codes=(0,), reject=False, binary_output=False):
        argv = [str(value) for value in argv]
        result = subprocess.run(argv, cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log = output / (label + '.log')
        log.write_bytes(result.stderr if binary_output else result.stdout + result.stderr)
        receipt['commands'].append({'label': label, 'argv': argv, 'cwd': str(ROOT),
                                    'exit_code': result.returncode, 'log': str(log),
                                    'log_sha256': digest(log)})
        save()
        if (reject and result.returncode == 0) or (not reject and result.returncode not in codes):
            raise RuntimeError(f'{label}: unexpected exit {result.returncode}; see {log}')
        return result.stdout if binary_output else (result.stdout + result.stderr).decode('utf-8', errors='replace')

    try:
        versions = {'cargo': ['--version'], 'rustc': ['--version'], 'mkfs.fat': ['--help'],
                    'fsck.fat': ['--help'], 'mcopy': ['-V'], 'mmd': ['-V'],
                    'mke2fs': ['-V'], 'debugfs': ['-V'], 'e2fsck': ['-V'],
                    'fsck.exfat': ['-V'], 'fls': ['-V'], 'icat': ['-V']}
        tools = {}
        for name, flags in versions.items():
            path = overrides.get(name) or shutil.which(name)
            if path is None or not Path(path).is_file():
                raise RuntimeError(f'enabled native gate requires {name}')
            tools[name] = str(Path(path).absolute())
            receipt['tools'][name] = {'path': tools[name], 'sha256': digest(Path(path)),
                                     'version': command('version-' + name, [path, *flags], (0, 1, 16))}
        command('build', [tools['cargo'], 'build', '--locked', '--example', 'filesystem-exfat-copy'])
        executable = args.target_dir.resolve() / 'debug/examples/filesystem-exfat-copy'
        receipt['binary'] = {'path': str(executable), 'sha256': digest(executable)}
        payload = bytes((n * 19 + 11) % 251 for n in range(262161))
        host = output / 'independent-input.bin'
        host.write_bytes(payload)
        sources = []
        fat = output / 'native-source.fat16'
        with fat.open('xb') as stream:
            stream.truncate(16 << 20)
        command('fat-mkfs', [tools['mkfs.fat'], '--invariant', '-F', '16', '-s', '1', fat])
        command('fat-mkdir', [tools['mmd'], '-i', fat, '::EFI', '::EFI/BOOT'])
        command('fat-write', [tools['mcopy'], '-i', fat, host, '::EFI/BOOT/BOOTX64.EFI'])
        command('fat-long', [tools['mcopy'], '-i', fat, host, '::Long root payload.txt'])
        command('fat-source-fsck', [tools['fsck.fat'], '-n', fat])
        sources.append(('fat', fat, {'EFI/BOOT/BOOTX64.EFI': payload, 'Long root payload.txt': payload}))
        ext = output / 'native-source.ext2'
        with ext.open('xb') as stream:
            stream.truncate(16 << 20)
        command('ext-mkfs', [tools['mke2fs'], '-q', '-F', '-t', 'ext2', '-b', '1024', '-I', '128',
                           '-O', 'filetype,sparse_super,^resize_inode,^dir_index,^ext_attr', ext])
        for index, operation in enumerate(['mkdir /EFI', 'mkdir /EFI/BOOT',
                f'write {host} /EFI/BOOT/BOOTX64.EFI', f'write {host} "/Long ä payload.txt"',
                'set_inode_field /EFI/BOOT/BOOTX64.EFI mode 0100640',
                'set_inode_field /EFI/BOOT/BOOTX64.EFI uid 123']):
            command('ext-debugfs-' + str(index), [tools['debugfs'], '-w', '-R', operation, ext])
        command('ext-source-fsck', [tools['e2fsck'], '-fn', ext])
        sources.append(('ext2', ext, {'EFI/BOOT/BOOTX64.EFI': payload, 'Long ä payload.txt': payload}))
        # Versioned independent specification constructor and native-accepted bytes.
        fixture = ROOT / 'fuzz/fixtures'
        manifest_path = fixture / 'exfat-basic-prefix.json'
        manifest = json.loads(manifest_path.read_text())
        prefix = fixture / 'exfat-basic-prefix.bin'
        generator = fixture / Path(manifest['generator_archive']).name
        if digest(prefix) != manifest['prefix_sha256'] or digest(generator) != manifest['generator_sha256']:
            raise RuntimeError('independent exFAT fixture provenance mismatch')
        exfat = output / 'independent-source.exfat'
        exfat.write_bytes(prefix.read_bytes() + bytes(manifest['logical_bytes'] - manifest['prefix_bytes']))
        if digest(exfat) != manifest['source_sha256']:
            raise RuntimeError('independent exFAT source hash mismatch')
        receipt['independent_exfat_fixture'] = manifest
        command('exfat-source-fsck', [tools['fsck.exfat'], '-n', exfat])
        sources.append(('exfat', exfat, {'prefixNoChain.bin': bytes((n * 17 + 3) % 251 for n in range(600)) + bytes(100),
                                      'CHAIN.BIN': bytes((n * 13 + 9) % 251 for n in range(900)),
                                      'nested/inside': b'child'}))
        source_files = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', Path(__file__),
                        ROOT / 'examples/filesystem-exfat-copy.rs', ROOT / 'tests/fs_exfat_copy.rs', manifest_path, prefix, generator,
                        *ROOT.glob('src/**/*.rs')]
        receipt['source_sha256'] = {str(p.relative_to(ROOT)): digest(p) for p in sorted(source_files)}
        for profile, source, expected in sources:
            wrapper = output / f'{profile}-source-framed.img'
            wrapper.write_bytes(bytes([0xa5]) * 8192 + source.read_bytes() + bytes([0x5a]) * 4096)
            unchanged = {str(p): digest(p) for p in (source, wrapper)}
            hashes = []
            for repeat in range(2):
                destination = output / f'{profile}-destination-{repeat}.exfat'
                argv = [executable, '--source-profile', profile, wrapper, '8192', str(source.stat().st_size),
                        destination, '32', '--metadata-policy', 'content-only-deterministic-defaults']
                report = command(f'{profile}-capture-{repeat}', argv)
                for marker in ('source_allocation_audit=complete', 'copy_preflight=complete',
                        'metadata_policy=content_only_deterministic_defaults', 'reopened_audit=complete',
                        'publication=completed', 'publication_directory_flush=complete'):
                    if marker not in report:
                        raise RuntimeError('missing stage report: ' + marker)
                hashes.append(digest(destination))
                command(f'{profile}-fsck-{repeat}', [tools['fsck.exfat'], '-n', destination])
                listing = command(f'{profile}-names-{repeat}', [tools['fls'], '-f', 'exfat', '-r', '-p', destination])
                names = {}
                for line in listing.splitlines():
                    if '\t' not in line:
                        continue
                    header, name = line.split('\t', 1)
                    if 'r/r' in header and not name.startswith('$'):
                        names[name] = header.split(':', 1)[0].split()[-1]
                if set(names) != set(expected):
                    raise RuntimeError(f'exact native payload names differ: {names.keys()} vs {expected.keys()}')
                for index, (name, data) in enumerate(expected.items()):
                    extracted = command(f'{profile}-payload-{repeat}-{index}',
                                        [tools['icat'], '-f', 'exfat', destination, names[name]], binary_output=True)
                    artifact = output / f'{profile}-payload-{repeat}-{index}.bin'
                    artifact.write_bytes(extracted)
                    if extracted != data:
                        raise RuntimeError(f'native payload mismatch: {profile}/{name}')
                    receipt.setdefault('payloads', []).append({'profile': profile, 'name': name,
                        'bytes': len(data), 'expected_sha256': hashlib.sha256(data).hexdigest(),
                        'extracted_sha256': digest(artifact), 'artifact': str(artifact)})
                refusal = command(f'{profile}-existing-destination-{repeat}', argv, reject=True)
                if 'already exists' not in refusal or digest(destination) != hashes[-1]:
                    raise RuntimeError('existing destination refusal changed output')
            if hashes[0] != hashes[1]:
                raise RuntimeError('repeated capture image hashes differ')
            if {str(p): digest(p) for p in (source, wrapper)} != unchanged:
                raise RuntimeError('source or framing changed')
            receipt['profiles'].append({'source_profile': profile, 'source_region_offset': 8192,
                'source_region_bytes': source.stat().st_size, 'unchanged_sha256': unchanged,
                'destination_sha256': hashes, 'repeat_deterministic': True, 'existing_destination_refused': True})
        damaged = bytearray(exfat.read_bytes())
        sector = 1 << damaged[108]
        cluster_bytes = sector << damaged[109]
        bitmap = int.from_bytes(damaged[88:92], 'little') * sector + cluster_bytes
        damaged[bitmap + 1] |= 4  # cluster12: unreferenced allocation in independent fixture.
        bad = output / 'lost-exfat-framed.img'
        bad.write_bytes(bytes([0xa5]) * 8192 + damaged + bytes([0x5a]) * 4096)
        bad_hash = digest(bad)
        destination = output / 'must-not-publish.exfat'
        result = command('lost-allocation-refusal', [executable, '--source-profile', 'exfat', bad, '8192',
            str(len(damaged)), destination, '32', '--metadata-policy', 'content-only-deterministic-defaults'], reject=True)
        if 'ownership/state audit failed' not in result or destination.exists() or digest(bad) != bad_hash:
            raise RuntimeError('lost source allocation not rejected unchanged before output')
        receipt.update(status='passed', lost_source_allocation_refused_before_output=True)
        receipt['layers'].update(source_audit='complete-clean', filesystem='verified-reopened-clean',
            publication='persist_noclobber-complete', publication_directory_flush='complete', native_validation='passed')
        save()
        directory = os.open(output, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        print(output / 'evidence.json')
        return 0
    except Exception as error:
        receipt.update(status='failed', reason=str(error))
        save()
        print(output / 'evidence.json')
        return 1


if __name__ == '__main__':
    sys.exit(main())

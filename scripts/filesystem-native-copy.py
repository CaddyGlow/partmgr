#!/usr/bin/env python3
"""Validate bounded FAT-region capture and staged FAT publication with native tools."""
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
DEFAULT_FIXTURE = Path('/data/cache/partmgr-filesystem-native-evidence/20261007T203552Z-2')
NAMES = ['BOOTX64.EFI', 'Long boot payload sharing prefix alpha.txt',
         'Long boot payload sharing prefix beta.txt',
         'Long boot payload sharing prefix gamma.txt', '123456789.txt']


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument('--output', type=Path,
                        default=Path('/data/cache/partmgr-filesystem-native-copy-evidence'))
    parser.add_argument('--target-dir', type=Path,
                        default=Path('/data/cache/partmgr-native-copy-target'))
    args = parser.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = args.output.resolve() / f'{stamp}-{os.getpid()}'
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema_version': 1, 'evidence_version': 'fat-region-copy-native-v1',
               'status': 'running', 'python_version': sys.version,
               'source_stability': 'caller guarantees immutable inputs throughout inventory and deferred reads; hashes detect final changes, not transient mutation',
               'metadata_policy': 'content-only; deterministic FAT defaults; source native metadata is transformed explicitly',
               'layers': {'filesystem': 'pending', 'image_publication': 'pending',
                          'publication_directory_flush': 'pending',
                          'native_validation': 'pending', 'partition': 'standalone filesystem; no partition commit',
                          'container': 'raw file; no container transaction',
                          'firmware_boot': 'unverified'},
               'capture_uses_host_extraction': False, 'commands': [], 'tools': {},
               'sources': {}, 'binary': {}, 'payloads': []}
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()), LC_ALL='C')

    def save():
        (output / 'evidence.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def command(label, argv, acceptable=(0,)):
        log = output / (label + '.log')
        result = subprocess.run([str(value) for value in argv], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        log.write_bytes(result.stdout)
        receipt['commands'].append({'label': label, 'argv': [str(value) for value in argv],
                                    'cwd': str(ROOT), 'exit_code': result.returncode,
                                    'log': str(log), 'log_sha256': digest(log)})
        save()
        if result.returncode not in acceptable:
            raise RuntimeError(f'{label} exited {result.returncode}; see {log}')
        return result.stdout.decode('utf-8', errors='replace')

    try:
        for name in ('cargo', 'rustc', 'fsck.fat', 'mcopy', 'mdir'):
            path = shutil.which(name)
            if path is None:
                receipt['status'] = 'skipped'
                receipt['reason'] = f'missing executable: {name}'
                save()
                print(output / 'evidence.json')
                return 77
            receipt['tools'][name] = {'path': path, 'sha256': digest(Path(path))}
        source = args.fixture.resolve() / 'tree-fat32.img'
        payload = args.fixture.resolve() / 'PAYLOAD.BIN'
        if not source.is_file() or not payload.is_file():
            raise RuntimeError(f'missing required native fixture in {args.fixture}')
        for name, flags in [('cargo', ['--version']), ('rustc', ['--version']),
                            ('fsck.fat', ['--help']), ('mcopy', ['-V']), ('mdir', ['-V'])]:
            receipt['tools'][name]['version_output'] = command(
                'version-' + name, [receipt['tools'][name]['path'], *flags], acceptable=(0, 1))
        inputs = sorted([ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', Path(__file__).resolve(),
                         ROOT / 'examples/filesystem-fat-copy.rs', *ROOT.glob('src/**/*.rs')])
        receipt['sources'] = {str(path.relative_to(ROOT)): digest(path) for path in inputs}
        command('cargo-build', ['cargo', 'build', '--locked', '--example', 'filesystem-fat-copy'])
        binary = args.target_dir.resolve() / 'debug/examples/filesystem-fat-copy'
        receipt['binary'] = {'path': str(binary), 'sha256': digest(binary)}
        initial = {'native_source': digest(source), 'expected_payload': digest(payload)}
        region_source = output / 'prefixed-source.img'
        with region_source.open('xb') as destination, source.open('rb') as original:
            destination.write(bytes([0xA5]) * 8192)
            shutil.copyfileobj(original, destination, 1024 * 1024)
            destination.write(bytes([0x5A]) * 8192)
            destination.flush()
            os.fsync(destination.fileno())
        length = source.stat().st_size
        initial['region_source'] = digest(region_source)
        receipt['source_region'] = {'path': str(region_source), 'offset': 8192,
                                    'length': length, 'prefix_bytes': 8192, 'suffix_bytes': 8192,
                                    'native_fixture': str(source), 'hashes_before_capture': initial}
        destination = output / 'copied-fat32.img'
        capture = command('capture', [binary, region_source, 8192, length, destination, 32])
        markers = ['copy_preflight=complete content_only=true source_stability=caller_guarantee',
                   'filesystem_flush=complete reopened_audit=complete',
                   'publication=completed destination=', 'publication_directory_flush=complete']
        if not all(marker in capture for marker in markers):
            raise RuntimeError('capture output lacks required completion markers')
        receipt['capture_stdout'] = capture
        receipt['layers'].update(filesystem='flushed and reopened ownership/state audit passed',
                                 image_publication='persist_noclobber completed',
                                 publication_directory_flush='completed')
        if destination.stat().st_size != 64 * 1024 * 1024:
            raise RuntimeError('destination size differs from FAT32 copy profile')
        before = {'native_source': digest(source), 'expected_payload': digest(payload),
                  'region_source': digest(region_source), 'destination': digest(destination)}
        if any(before[key] != value for key, value in initial.items()):
            raise RuntimeError('source changed during capture')
        receipt['hashes_before_native_validation'] = before
        refusal = command('capture-refuse-overwrite',
                          [binary, region_source, 8192, length, destination, 32], acceptable=(1,))
        if 'File exists' not in refusal and 'file exists' not in refusal:
            raise RuntimeError('existing-destination refusal lacks expected file-exists diagnostic')
        if digest(destination) != before['destination']:
            raise RuntimeError('existing destination changed on refused publication')
        receipt['existing_destination_refusal'] = 'passed; existing image hash unchanged'
        command('source-fsck', ['fsck.fat', '-n', '-v', source])
        command('destination-fsck', ['fsck.fat', '-n', '-v', destination])
        command('source-names', ['mdir', '-i', f'{region_source}@@8192', '::/EFI/BOOT'])
        command('destination-names', ['mdir', '-i', destination, '::/EFI/BOOT'])
        command('destination-root', ['mdir', '-i', destination, '::/'])
        for index, name in enumerate(NAMES):
            extracted = output / f'validation-payload-{index}.bin'
            command(f'destination-extract-{index}', ['mcopy', '-n', '-i', destination,
                                                     '::/EFI/BOOT/' + name, extracted])
            actual = digest(extracted)
            matched = actual == initial['expected_payload'] and extracted.stat().st_size == payload.stat().st_size
            receipt['payloads'].append({'native_path': 'EFI/BOOT/' + name,
                                        'extraction_purpose': 'post-publication validation only',
                                        'expected_sha256': initial['expected_payload'], 'actual_sha256': actual,
                                        'expected_bytes': payload.stat().st_size,
                                        'actual_bytes': extracted.stat().st_size, 'matches': matched})
            if not matched:
                raise RuntimeError(f'content mismatch: {name}')
        after = {'native_source': digest(source), 'expected_payload': digest(payload),
                 'region_source': digest(region_source), 'destination': digest(destination)}
        receipt['hashes_after_native_validation'] = after
        if before != after:
            raise RuntimeError('source or destination changed during native validation')
        receipt['sources_after_validation'] = {str(path.relative_to(ROOT)): digest(path) for path in inputs}
        if receipt['sources_after_validation'] != receipt['sources']:
            raise RuntimeError('implementation source changed during build or validation; rerun required')
        if digest(binary) != receipt['binary']['sha256']:
            raise RuntimeError('copy binary changed during validation; rerun required')
        receipt['layers']['native_validation'] = 'passed read-only fsck, native listings, five payload size/hash checks, and unchanged full-image hashes'
        receipt['status'] = 'passed'
        save()
        print(output / 'evidence.json')
        return 0
    except Exception as error:
        receipt['status'] = 'failed'
        receipt['reason'] = str(error)
        save()
        print(f'{error}\n{output / "evidence.json"}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

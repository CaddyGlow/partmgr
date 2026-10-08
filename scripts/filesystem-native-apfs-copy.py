#!/usr/bin/env python3
"""Verify standalone/GPT/MBR APFS copies against supplied independent payload models."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--length', type=int, required=True)
    parser.add_argument('--volume-oid', type=int, required=True)
    parser.add_argument('--output-mib', type=int, required=True)
    parser.add_argument('--expected-data', type=Path, required=True)
    parser.add_argument('--expected-fork', type=Path, required=True)
    parser.add_argument('--data-inode', default='16')
    parser.add_argument('--fork-inode', default='16-4353-1')
    parser.add_argument('--volume-index', default='19')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs = {'binary': args.binary, 'source': args.source,
              'expected-data': args.expected_data, 'expected-fork': args.expected_fork}
    inputs = {name: path.resolve(strict=True) for name, path in inputs.items()}
    for path in inputs.values():
        require(path.is_file(), f'input is not a regular file: {path}')
    require(1 <= args.output_mib <= 128, 'output must be1..128MiB')
    require(0 <= args.offset and 0 < args.length <= inputs['source'].stat().st_size - args.offset,
            'source region is outside supplied image')
    tools = {}
    for name in ('apfsck', 'icat'):
        executable = shutil.which(name)
        require(executable is not None, f'required native tool missing: {name}')
        tools[name] = Path(executable).resolve(strict=True)
    helper = Path(__file__).with_name('filesystem-native-partition-copy.py').resolve(strict=True)
    spec = importlib.util.spec_from_file_location('partition_oracle', helper)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'status': 'failed', 'commands': [], 'cases': {},
               'scope': 'Standalone/GPT/MBR raw copy, independent table checks and complete supplied data/resource-fork models; no complete namespace, macOS, COW, firmware or compiled-source binding claim',
               'scripts': {str(path): digest(path) for path in (Path(__file__).resolve(), helper)},
               'inputs': {name: {'path': str(path), 'sha256': digest(path)} for name, path in inputs.items()},
               'tools': {name: {'path': str(path), 'sha256': digest(path)} for name, path in tools.items()}}

    def save():
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def run(label, argv, success=True):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=600)
        row = {'label': label, 'argv': argv, 'exit_code': result.returncode}
        for name, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
            path = output / (label + '.' + name)
            path.write_bytes(data)
            row[name] = path.name
            row[name + '_sha256'] = digest(path)
        receipt['commands'].append(row)
        save()
        require((result.returncode == 0) if success else (result.returncode != 0),
                f'{label}: unexpected exit {result.returncode}; retained logs')
        return result

    try:
        retained = {}
        for name, path in inputs.items():
            copy = output / name
            shutil.copy2(path, copy)
            require(digest(copy) == receipt['inputs'][name]['sha256'], f'input changed while copying: {name}')
            retained[name] = copy
        expected = {name: retained[name].read_bytes() for name in ('expected-data', 'expected-fork')}
        filesystem_bytes = args.output_mib << 20
        standalone_sha = None
        for scheme in ('standalone', 'gpt', 'mbr'):
            image = output / (scheme + '.raw')
            argv = [retained['binary'], retained['source'], args.offset, args.length,
                    args.volume_oid, image, args.output_mib,
                    '--metadata-policy', 'content-only-deterministic-defaults']
            if scheme != 'standalone':
                argv += ['--partition-table', scheme]
            run(scheme + '-copy', argv)
            if scheme != 'standalone':
                oracle.inspect_table(image, scheme, filesystem_bytes, 0xaf,
                                     '7c3457ef-0000-11aa-aa11-00306543ecac')
            region = output / (scheme + '.apfs')
            with image.open('rb') as src, region.open('wb') as dst:
                src.seek(0 if scheme == 'standalone' else 1 << 20)
                remaining = filesystem_bytes
                while remaining:
                    data = src.read(min(1 << 20, remaining))
                    require(bool(data), 'truncated filesystem region')
                    dst.write(data)
                    remaining -= len(data)
            require(image.stat().st_size == filesystem_bytes + (0 if scheme == 'standalone' else 2 << 20),
                    'unexpected output disk length')
            region_sha = digest(region)
            if standalone_sha is None:
                standalone_sha = region_sha
            require(region_sha == standalone_sha, 'partitioned filesystem differs from standalone output')
            check = run(scheme + '-checker', [tools['apfsck'], '-c', '-u', '-w', region])
            require(not check.stdout and not check.stderr, 'native checker produced diagnostics')
            for kind, inode, model in [('data', args.data_inode, 'expected-data'),
                                       ('fork', args.fork_inode, 'expected-fork')]:
                data = run(scheme + '-' + kind, [tools['icat'], '-P', 'apfs', '-B', args.volume_index,
                                                '-f', 'apfs', region, inode]).stdout
                require(data == expected[model], f'complete independent {kind} model differs')
            before = digest(image)
            run(scheme + '-existing-destination', argv, success=False)
            require(digest(image) == before, 'existing-destination refusal changed output')
            require(digest(region) == region_sha, 'native tools changed filesystem region')
            receipt['cases'][scheme] = {'image_sha256': before, 'region_sha256': region_sha,
                                        'complete_data_bytes': len(expected['expected-data']),
                                        'complete_fork_bytes': len(expected['expected-fork']),
                                        'existing_destination_unchanged': True}
            save()
        for name, path in inputs.items():
            require(digest(path) == receipt['inputs'][name]['sha256'], f'original input changed: {name}')
            require(digest(retained[name]) == receipt['inputs'][name]['sha256'], f'retained input changed: {name}')
        for name, path in tools.items():
            require(digest(path) == receipt['tools'][name]['sha256'], f'native tool changed: {name}')
        for path, checksum in receipt['scripts'].items():
            require(digest(Path(path)) == checksum, 'oracle script changed during gate')
        receipt['status'] = 'passed'
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error)
    finally:
        save()
    print(f"{receipt['status']}: {output / 'receipt.json'}")
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate bounded native ext2 capture, staging and publication with e2fsprogs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for data in iter(lambda: source.read(1 << 20), b''):
            digest.update(data)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, default=Path('/data/cache/partmgr-filesystem-target'))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='ext2-capture-', dir=args.output.resolve()))
    receipt = {'status': 'failed', 'profile': 'native-ext2-region-to-ext2-content-only-v1',
               'scope': 'offline native capture/publication; no metadata preservation, partition commit, container conversion, power-loss or firmware claim',
               'commands': [], 'tools': {}, 'source_stability': 'caller-guaranteed stable during deferred reads; final hashes are not snapshots'}
    env = dict(os.environ, LC_ALL='C.UTF-8')

    def run(label, command, success=True):
        command = [str(part) for part in command]
        started = time.monotonic()
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        log = output / (label + '.log')
        log.write_bytes(result.stdout)
        receipt['commands'].append({'label': label, 'argv': command, 'exit_code': result.returncode, 'elapsed_seconds': time.monotonic()-started, 'log': str(log), 'log_sha256': sha(log)})
        if success and result.returncode != 0:
            raise RuntimeError(f'{label} failed: {log}')
        return result

    try:
        for name in ['mke2fs', 'debugfs', 'e2fsck']:
            tool = args.tools.resolve() / name
            if not tool.is_file():
                raise RuntimeError(f'missing required tool: {tool}')
            receipt['tools'][name] = {'path': str(tool), 'sha256': sha(tool)}
            run(name+'-version', [tool, '-V'])
        run('rustc-version', ['rustc', '--version'])
        run('cargo-version', ['cargo', '--version'])
        inputs = sorted((ROOT/'src').glob('*.rs')) + [ROOT/p for p in ['Cargo.toml', 'Cargo.lock', 'examples/filesystem-ext-copy.rs', 'scripts/filesystem-native-ext-copy.py']]
        receipt['source_sha256'] = {str(p.relative_to(ROOT)): sha(p) for p in inputs}
        native_tree = output/'tree'
        (native_tree/'nested').mkdir(parents=True)
        payload = bytes((i*17+3) % 251 for i in range(350123))
        (native_tree/'nested'/'payload').write_bytes(payload)
        os.link(native_tree/'nested'/'payload', native_tree/'alias')
        byte_name = os.fsdecode(bytes([ord('x'), 255]))
        (native_tree/byte_name).write_bytes(b'native byte name\x00payload')
        source = output/'source.img'
        with source.open('wb') as file:
            file.truncate(16 << 20)
        run('source-create', [args.tools/'mke2fs', '-q', '-F', '-t', 'ext2', '-b', '1024', '-I', '128', '-O', 'none,filetype,sparse_super', '-m', '0', '-E', 'lazy_itable_init=0', '-d', native_tree, source])
        run('source-check', [args.tools/'e2fsck', '-f', '-n', source])
        framed = output/'framed.raw'
        with framed.open('wb') as file:
            file.write(bytes([0xa5])*8192)
            with source.open('rb') as stream:
                shutil.copyfileobj(stream, file)
            file.write(bytes([0x5a])*8192)
        source_hash, framing_hash = sha(source), sha(framed)
        run('build', ['cargo', 'build', '--locked', '--example', 'filesystem-ext-copy', '--target-dir', args.target_dir.resolve()])
        binary = args.target_dir.resolve()/'debug/examples/filesystem-ext-copy'
        receipt['binary_sha256'] = sha(binary)
        destination = output/'destination.img'
        command = [binary, '--source-profile', 'ext2', framed, '8192', str(16 << 20), destination, '32', '--metadata-policy', 'content-only-deterministic-defaults', '--names', 'exact-bytes']
        result = run('capture', command)
        for marker in [b'copy_preflight=complete', b'filesystem_flush=complete reopened_audit=complete', b'publication=completed', b'publication_directory_flush=complete']:
            if marker not in result.stdout:
                raise RuntimeError(f'missing completed stage: {marker!r}')
        destination_hash = sha(destination)
        run('destination-check', [args.tools/'e2fsck', '-f', '-n', destination])
        recovery = output/'recovered'
        recovery.mkdir()
        run('recover', [args.tools/'debugfs', '-R', f'rdump / {recovery}', destination])
        for name, expected in [('nested/payload', payload), ('alias', payload), (byte_name, b'native byte name\x00payload')]:
            if (recovery/name).read_bytes() != expected:
                raise RuntimeError(f'independent recovered payload mismatch: {name!r}')
        stat = run('hardlink-stat', [args.tools/'debugfs', '-R', 'stat /alias', destination])
        if b'Links: 2' not in stat.stdout:
            raise RuntimeError('native hardlink count not preserved')
        rejected = run('existing-destination', command, success=False)
        if rejected.returncode == 0 or b'destination already exists' not in rejected.stdout:
            raise RuntimeError('existing destination was not rejected')
        unsupported = output/'unsupported-source.img'
        shutil.copyfile(source, unsupported)
        run('unsupported-source-author', [args.tools/'debugfs', '-w', '-R', 'symlink /link nested/payload', unsupported])
        run('unsupported-source-check', [args.tools/'e2fsck', '-f', '-n', unsupported])
        unsupported_hash = sha(unsupported)
        refused_output = output/'unsupported-destination.img'
        refused = run('unsupported-symlink', [binary, '--source-profile', 'ext2', unsupported, '0', str(16 << 20), refused_output, '32', '--metadata-policy', 'content-only-deterministic-defaults', '--names', 'exact-bytes'], success=False)
        if refused.returncode == 0 or b'ext2 audit special inode profile unsupported' not in refused.stdout or refused_output.exists() or b'copy_preflight=complete' in refused.stdout:
            raise RuntimeError('unsupported symlink was not rejected before destination creation')
        if sha(unsupported) != unsupported_hash:
            raise RuntimeError('unsupported source changed during rejected capture')
        if (sha(source), sha(framed), sha(destination)) != (source_hash, framing_hash, destination_hash):
            raise RuntimeError('source/framing/destination changed during validators or rejection')
        for path, digest in receipt['source_sha256'].items():
            if sha(ROOT/path) != digest:
                raise RuntimeError(f'source changed during native gate: {path}')
        receipt.update(status='passed', source_image_sha256=source_hash, framed_sha256=framing_hash, destination_sha256=destination_hash,
                       payload_bytes=len(payload), payload_sha256=hashlib.sha256(payload).hexdigest(),
                       layers={'source_audit': 'complete', 'filesystem': 'flushed and reopened audit complete', 'publication': 'completed without overwrite', 'publication_directory_flush': 'complete', 'partition': 'standalone', 'container': 'raw', 'boot': 'unverified'})
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error)
    finally:
        with (output/'evidence.json').open('w') as file:
            json.dump(receipt, file, indent=2)
            file.write('\n')
            file.flush()
            os.fsync(file.fileno())
        print(f"{receipt['status'].upper()}: {output/'evidence.json'}", flush=True)
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

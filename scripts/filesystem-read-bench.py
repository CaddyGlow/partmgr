#!/usr/bin/env python3
"""Record bounded FAT/ext2 raw/container reads against mapped direct logical ReadAt."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('/data/cache/partmgr-read-bench-evidence'))
    parser.add_argument('--target-dir', type=Path, default=Path('/data/cache/partmgr-read-bench-target'))
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--containers', action='store_true', help='Also measure independently converted normal/compressed QCOW2 readers')
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 10:
        parser.error('repetitions must be between 1 and 10')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = args.output.resolve() / f'{stamp}-{os.getpid()}'
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema_version': 2, 'profile': 'immutable-fat32-ext2-direct-logical-read-v2',
               'status': 'running', 'controlled_runner_acceptance': False,
               'cache_policy': 'OS buffered positional reads; no drop-caches; cache state uncontrolled; order alternates by repetition',
               'source_stability': 'new private disposable fixture files; caller must prevent concurrent mutation; full hashes checked after reads',
               'baseline': 'same selected raw/container logical reader and validated file extent map; requests pretranslated into physical ReadAt pieces before timed workload',
               'gates': {'shared_memory_limit_bytes': 256 << 20, 'process_peak_rss_limit_kib_linux': 256 << 10,
                         'map_unit_limit': 65536,
                         'setup_backend_call_limit': 65536 * 16 + 1024,
                         'fixture_setup_backend_call_limits': {'fat': 65537, 'ext2': 256},
                         'operation_limit': 65536, 'segments_per_request_limit': 16,
                         'payload_backend_calls': 'exactly independently counted request pieces in validated map',
                         'payload_backend_bytes': 'exactly requested data pieces; holes zero-filled without backend reads',
                         'content': 'filesystem/direct worker hashes equal; sequential full-file hash equals generated payload',
                         'timing_threshold': None},
               'machine': {'platform': platform.platform(), 'uname': list(platform.uname()),
                           'python': sys.version, 'logical_cpus': os.cpu_count(),
                           'affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None},
               'tools': {}, 'commands': [], 'datasets': {}, 'runs': [], 'comparisons': []}
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()), LC_ALL='C')

    def save():
        (output / 'evidence.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def command(label, argv, acceptable=(0,)):
        log = output / (label + '.log')
        started = time.monotonic_ns()
        with log.open('wb') as stream:
            child = subprocess.Popen([str(a) for a in argv], cwd=ROOT, env=env,
                                     stdout=stream, stderr=subprocess.STDOUT)
            _, status, usage = os.wait4(child.pid, 0)
            code = os.waitstatus_to_exitcode(status)
            child.returncode = code
        record = {'label': label, 'argv': [str(a) for a in argv], 'cwd': str(ROOT),
                  'exit_code': code, 'log': str(log), 'log_sha256': digest(log),
                  'process_wall_ns': time.monotonic_ns() - started,
                  'process_cpu_user_seconds': usage.ru_utime, 'process_cpu_system_seconds': usage.ru_stime,
                  'process_peak_rss_kib_linux': usage.ru_maxrss,
                  'process_block_input_units_512_bytes': usage.ru_inblock,
                  'process_block_output_units_512_bytes': usage.ru_oublock,
                  'process_voluntary_context_switches': usage.ru_nvcsw,
                  'process_involuntary_context_switches': usage.ru_nivcsw}
        receipt['commands'].append(record)
        save()
        if code not in acceptable:
            raise RuntimeError(f'{label} failed with exit {code}; {log}')
        return log.read_text(errors='replace'), record

    try:
        if sys.platform != 'linux' or not hasattr(os, 'wait4'):
            receipt.update(status='skipped', reason='Linux wait4 per-child CPU/RSS/I/O receipt required')
            save()
            return 77
        tools = ['cargo', 'rustc', 'mkfs.fat', 'mcopy', 'fsck.fat', 'mke2fs', 'debugfs', 'e2fsck']
        if args.containers:
            tools.append('qemu-img')
        for tool in tools:
            path = shutil.which(tool)
            if path is None:
                receipt.update(status='skipped', reason='missing executable: ' + tool)
                save()
                return 77
            receipt['tools'][tool] = {'path': path, 'sha256': digest(Path(path))}
            flag = '-V' if tool in ('mcopy', 'mke2fs', 'debugfs', 'e2fsck') else '--version'
            if tool in ('mkfs.fat', 'fsck.fat'):
                flag = '--help'
            text, _ = command('version-' + tool, [path, flag], acceptable=(0, 1))
            receipt['tools'][tool]['version_output'] = text
        for path in (Path('/proc/cpuinfo'), Path('/proc/meminfo'), Path('/proc/self/mountinfo')):
            log = output / (path.name + '.txt')
            log.write_bytes(path.read_bytes())
            receipt['machine'][path.name] = {'path': str(log), 'sha256': digest(log)}
        sources = sorted([ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', Path(__file__).resolve(),
                          ROOT / 'examples/filesystem-read-bench.rs', *ROOT.glob('src/**/*.rs'),
                          *([ROOT / 'scripts/filesystem-container-check.py'] if args.containers else [])])
        receipt['sources'] = {str(p.relative_to(ROOT)): digest(p) for p in sources}
        command('cargo-release-build', ['cargo', 'build', '--release', '--locked', '--example', 'filesystem-read-bench'])
        binary = args.target_dir.resolve() / 'release/examples/filesystem-read-bench'
        receipt['binary'] = {'path': str(binary), 'sha256': digest(binary)}
        payload = output / 'payload.bin'
        # Exactly 16 MiB; independent deterministic byte pattern, no production builder.
        chunk = bytes((i * 37 + i // 17) & 255 for i in range(65536))
        with payload.open('xb') as stream:
            for _ in range(256):
                stream.write(chunk)
        expected = digest(payload)
        length = payload.stat().st_size
        fat = output / 'fat32.img'
        ext = output / 'ext2.img'
        for image in (fat, ext):
            with image.open('xb') as stream:
                stream.truncate(64 << 20)
        command('fat-mkfs', ['mkfs.fat', '--invariant', '-F', '32', '-s', '1', fat])
        command('fat-insert', ['mcopy', '-i', fat, payload, '::/PAYLOAD.BIN'])
        command('fat-fsck', ['fsck.fat', '-n', '-v', fat])
        with fat.open('rb') as stream:
            boot = stream.read(512)
            sector = struct.unpack_from('<H', boot, 11)[0]
            reserved = struct.unpack_from('<H', boot, 14)[0]
            fat_sectors = struct.unpack_from('<I', boot, 36)[0]
            root_cluster = struct.unpack_from('<I', boot, 44)[0]
            root_at = (reserved + boot[16] * fat_sectors + (root_cluster - 2) * boot[13]) * sector
            stream.seek(root_at)
            root = stream.read(boot[13] * sector)
        slots = [root[at:at + 32] for at in range(0, len(root), 32)
                 if root[at:at + 11] == b'PAYLOAD BIN']
        if len(slots) != 1:
            raise RuntimeError('expected exactly one native FAT root payload slot')
        slot = slots[0]
        first = struct.unpack_from('<H', slot, 26)[0] | struct.unpack_from('<H', slot, 20)[0] << 16
        if struct.unpack_from('<I', slot, 28)[0] != length:
            raise RuntimeError('FAT native payload length mismatch')
        command('ext-mkfs', ['mke2fs', '-q', '-F', '-t', 'ext2', '-O', 'none', '-I', '128', '-b', '1024', ext])
        command('ext-insert', ['debugfs', '-w', '-R', 'write ' + json.dumps(str(payload)) + ' /payload.bin', ext])
        text, _ = command('ext-stat', ['debugfs', '-R', 'stat /payload.bin', ext])
        match = re.search(r'Inode:\s*(\d+)', text)
        if not match:
            raise RuntimeError('debugfs did not report payload inode')
        inode = int(match.group(1))
        command('ext-fsck', ['e2fsck', '-fn', ext])
        for family, image, object_id in [('fat', fat, first), ('ext2', ext, inode)]:
            initial = digest(image)
            receipt['datasets'][family] = {'path': str(image), 'image_bytes': image.stat().st_size,
                                           'image_sha256_before': initial, 'object': object_id,
                                           'payload_bytes': length, 'payload_sha256': expected,
                                           'native_profile': 'FAT32/512-byte clusters' if family == 'fat' else 'ext2/features none/1024-byte blocks/128-byte inode'}
            profiles = [('raw', image, 'raw')]
            if args.containers:
                converted = output / (family + '-containers')
                command(family + '-container-oracle', [sys.executable,
                        ROOT / 'scripts/filesystem-container-check.py', image, '--output', converted])
                conversion = json.loads((converted / 'receipt.json').read_text())
                if conversion['status'] != 'passed' or conversion['source_sha256'] != initial:
                    raise RuntimeError('independent full logical container validation failed')
                receipt['datasets'][family]['container_oracle'] = {
                    'receipt': str(converted / 'receipt.json'),
                    'sha256': digest(converted / 'receipt.json')}
                profiles.extend((name, converted / (name + '.qcow2'), 'qcow2')
                                for name in ('normal', 'compressed'))
            receipt['datasets'][family]['backend_profiles'] = {}
            for profile, selected_image, backend in profiles:
                profile_hash = digest(selected_image)
                receipt['datasets'][family]['backend_profiles'][profile] = {
                    'backend': backend, 'path': str(selected_image),
                    'container_bytes': selected_image.stat().st_size,
                    'image_sha256_before': profile_hash}
                for workload in ('sequential', 'random', 'repeated', 'concurrent'):
                    for repetition in range(args.repetitions):
                        modes = ('filesystem', 'direct') if repetition % 2 == 0 else ('direct', 'filesystem')
                        pair = {}
                        for mode in modes:
                            label = f'{family}-{profile}-{workload}-{repetition}-{mode}'
                            text, record = command(label, [binary, family, selected_image, object_id, length, mode, workload, 4096, '--backend', backend])
                            metrics = json.loads(text)
                            if metrics['backend'] != backend:
                                raise RuntimeError('benchmark selected the wrong logical backend')
                            metrics['container_profile'] = profile
                            metrics['payload_mib_per_second'] = metrics['operations'] * metrics['request_bytes'] / (1 << 20) / (metrics['elapsed_ns'] / 1e9)
                            metrics['payload_iops'] = metrics['operations'] / (metrics['elapsed_ns'] / 1e9)
                            if record['process_peak_rss_kib_linux'] > receipt['gates']['process_peak_rss_limit_kib_linux']:
                                raise RuntimeError('process peak RSS budget exceeded')
                            metrics.update(repetition=repetition, command_label=label,
                                           process_resources={k: v for k, v in record.items() if k.startswith('process_')})
                            if metrics['work_memory_gates'] != 'passed':
                                raise RuntimeError('numeric work/memory gates did not pass')
                            setup_limit = receipt['gates']['fixture_setup_backend_call_limits'][family]
                            if metrics['setup_backend_calls'] > setup_limit:
                                raise RuntimeError(f'{family} fixture metadata indexing regression: '
                                                   f'{metrics["setup_backend_calls"]} calls exceeds {setup_limit}')
                            if workload == 'sequential' and metrics['worker_sha256'] != [expected]:
                                raise RuntimeError('sequential full-file hash differs from independent payload')
                            pair[mode] = metrics
                            receipt['runs'].append(metrics)
                        if pair['filesystem']['worker_sha256'] != pair['direct']['worker_sha256']:
                            raise RuntimeError('filesystem/direct workload content mismatch')
                        receipt['comparisons'].append({'family': family, 'container_profile': profile, 'workload': workload, 'repetition': repetition,
                                                       'content_matches': True,
                                                       'filesystem_to_direct_elapsed_ratio': pair['filesystem']['elapsed_ns'] / pair['direct']['elapsed_ns'],
                                                       'timing_acceptance': 'not evaluated; uncontrolled runner'})
                profile_final = digest(selected_image)
                receipt['datasets'][family]['backend_profiles'][profile]['image_sha256_after'] = profile_final
                if profile_final != profile_hash:
                    raise RuntimeError('benchmark changed immutable backend: ' + family + '/' + profile)
            final = digest(image)
            receipt['datasets'][family]['image_sha256_after'] = final
            if final != initial:
                raise RuntimeError('benchmark changed immutable image: ' + family)
        receipt['summary'] = []
        for family in ('fat', 'ext2'):
            for profile in receipt['datasets'][family]['backend_profiles']:
                for workload in ('sequential', 'random', 'repeated', 'concurrent'):
                    group = [r for r in receipt['comparisons'] if r['family'] == family
                             and r['container_profile'] == profile and r['workload'] == workload]
                    receipt['summary'].append({'family': family, 'container_profile': profile,
                                               'workload': workload,
                                               'median_filesystem_to_direct_elapsed_ratio': statistics.median(r['filesystem_to_direct_elapsed_ratio'] for r in group),
                                               'repetitions': len(group)})
        receipt['sources_after'] = {str(p.relative_to(ROOT)): digest(p) for p in sources}
        if receipt['sources_after'] != receipt['sources'] or digest(binary) != receipt['binary']['sha256']:
            raise RuntimeError('implementation changed during benchmark; rerun required')
        if digest(payload) != expected:
            raise RuntimeError('reference payload changed during benchmark')
        receipt['status'] = 'passed'
        save()
        print(output / 'evidence.json')
        return 0
    except Exception as error:
        receipt.update(status='failed', reason=str(error))
        save()
        print(f'{error}; evidence: {output}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

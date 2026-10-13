#!/usr/bin/env python3
"""Qualify closed Windows-created NTFS artifacts against native and TSK facts.

Run on the host after new-windows-ntfs-fixture.ps1 detaches and uploads its private
artifacts. Every command, hash and partial outcome is retained. A failed profile
is a failed receipt, not an implicit downgrade to whichever checks passed.
"""
import argparse
import csv
import calendar
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--creation', required=True)
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--sleuthkit-bin', required=True)
    parser.add_argument('--ntfs-bin', required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    artifacts = Path(args.artifacts)
    # A concurrent development build must not replace the executable between
    # independently qualified backend commands.
    binary = output / 'partmgr-forensics'
    shutil.copyfile(args.cli, binary)
    binary.chmod(0o500)
    creation = json.loads(Path(args.creation).read_text())
    receipt = {'version': 1, 'profile': 'closed-windows-native-ntfs-qualification-v1',
               'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'creation_receipt_sha256': digest(args.creation),
               'binary_sha256': digest(binary), 'commands': [], 'checks': {},
               'native_artifact_hashes': {}, 'passed': False}
    repository = Path(__file__).resolve().parents[2]
    receipt['qualifier_sha256'] = digest(__file__)
    source_paths = sorted((repository / 'src').rglob('*.rs')) + [
        repository / 'Cargo.toml', repository / 'Cargo.lock',
        repository / 'examples/filesystem-forensics.rs']
    receipt['library_source_sha256'] = {
        str(path.relative_to(repository)): digest(path) for path in source_paths}

    def check(name, passed, **evidence):
        receipt['checks'][name] = {'passed': bool(passed), **evidence}

    def run(name, command, timeout=90):
        result = subprocess.run([str(arg) for arg in command], capture_output=True, timeout=timeout)
        stdout = output / (name + '.stdout')
        stderr = output / (name + '.stderr')
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        receipt['commands'].append({'name': name, 'command': [str(arg) for arg in command],
                                    'exit_code': result.returncode,
                                    'stdout_file': stdout.name, 'stdout_sha256': digest(stdout),
                                    'stderr_file': stderr.name, 'stderr_sha256': digest(stderr)})
        return result

    def cli(name, command, image, fmt='raw', extra=()):
        result = run(name, [binary, command, image, '--format', fmt, '--sector-size', '512',
                          '--assert-stable', '--acquisition-id', 'windows-native-' + name,
                          '--stability-provider', 'closed-detached-private-artifact',
                          '--records', '65536', '--read-bytes', str(1 << 30),
                          '--output-bytes', str(64 << 20), '--memory-bytes', str(256 << 20), *extra])
        rows = [json.loads(line) for line in result.stdout.decode().splitlines()]
        terminals = [row for row in rows if row['type'] == 'terminal']
        terminal = terminals[-1] if terminals else None
        return result, rows, terminal

    try:
        check('windows_fixture_creation', creation['creation_passed'],
              os=creation['os'], script_sha256=creation['runner_sha256'],
              consistency=creation['consistency'], stability=creation['stability'])
        paths = {}
        for artifact in creation['artifacts']:
            path = artifacts / artifact['host_name']
            actual = digest(path)
            paths[artifact['name']] = path
            receipt['native_artifact_hashes'][artifact['name']] = {
                'domain': artifact['hash_domain'], 'native_sha256': artifact['sha256'],
                'before_sha256': actual, 'bytes': path.stat().st_size}
            check('native_hash_' + artifact['name'], actual == artifact['sha256']
                  and path.stat().st_size == artifact['length'])
        tsk = Path(args.sleuthkit_bin)
        ntfs = Path(args.ntfs_bin)
        run('tsk-version', [tsk / 'fls', '-V'])
        run('ntfs-version', [ntfs / 'ntfsinfo', '--version'])
        run('ntfs-volume', [ntfs / 'ntfsinfo', '-m', paths['volume.dd']])
        fls = run('tsk-fls', [tsk / 'fls', '-r', '-p', paths['volume.dd']])
        check('independent_namespace_completed', fls.returncode == 0)
        namespace = {}
        for line in fls.stdout.decode().splitlines():
            match = re.search(r'(\d+-128-\d+):\s*\t(.*)$', line)
            if match:
                namespace[match[2]] = match[1]
        inventories = {}
        region = ('--offset', str(creation['partition_offset']), '--length', str(creation['partition_bytes']))
        for name, image, extra in [('volume', paths['volume.dd'], ()), ('disk-region', paths['disk.dd'], region)]:
            result, rows, terminal = cli('inventory-' + name, 'inventory-ntfs', image, extra=extra)
            check('inventory_' + name, result.returncode == 0 and terminal and terminal['complete'], terminal=terminal)
            inventories[name] = [row for row in rows if row['type'] == 'ntfs_slot']
        qcow2 = output / 'disk.qcow2'
        qemu = run('qemu-version', ['qemu-img', '--version'])
        converted = run('qemu-convert', ['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2', paths['disk.dd'], qcow2])
        check('derived_container_created', converted.returncode == 0, qemu_version=qemu.stdout.decode().strip())
        if converted.returncode == 0:
            before = digest(qcow2)
            result, rows, terminal = cli('inventory-qcow2', 'inventory-ntfs', qcow2, fmt='qcow2', extra=region)
            check('inventory_qcow2', result.returncode == 0 and terminal and terminal['complete'],
                  terminal=terminal, container_sha256_before=before, container_sha256_after=digest(qcow2))
            inventories['qcow2'] = [row for row in rows if row['type'] == 'ntfs_slot']
        keys = ('slot', 'raw_hex', 'allocated_bitmap_bit', 'sequence', 'file_in_use', 'base_reference', 'validation')
        facts = {name: [{key: row.get(key) for key in keys} for row in rows] for name, rows in inventories.items()}
        check('backend_independent_inventory', len(facts) == 3 and all(value == facts['volume'] for value in facts.values()),
              backends=list(facts), compared_fields=list(keys), source_identities_preserved_separately=True)
        slots = {row['slot']: row for row in inventories['volume']}
        # Explicit controlled-damage copies preserve the closed native original.
        # Completing traversal of a damaged FILE slot is distinct from validating it.
        damaged = output / 'bad-fixup-volume.dd'
        shutil.copyfile(paths['volume.dd'], damaged)
        target_record = creation['files'][0]['record']
        target = slots[target_record]
        if len(target['volume_ranges']) != 1:
            raise ValueError('negative fixture requires one observed native FILE fragment')
        trailer = target['volume_ranges'][0]['offset'] + 1022
        with damaged.open('r+b') as stream:
            stream.seek(trailer)
            original_byte = stream.read(1)[0]
            stream.seek(trailer)
            stream.write(bytes([original_byte ^ 1]))
        damaged_hash = digest(damaged)
        result, rows, terminal = cli('negative-bad-fixup', 'inventory-ntfs', damaged)
        observed_damage = next(row for row in rows if row.get('type') == 'ntfs_slot' and row['slot'] == target_record)
        check('native_bad_fixup_raw_preservation', result.returncode == 0 and terminal and terminal['complete']
              and observed_damage['validation'] == 'rejected'
              and observed_damage['allocated_bitmap_bit'] is True
              and bytes.fromhex(observed_damage['raw_hex'])[1022] == original_byte ^ 1
              and 'attributes' not in observed_damage and digest(damaged) == damaged_hash,
              derivation='copy native volume; xor1 at selected FILE second USA trailer',
              selected_record=target_record, source_offset=trailer, derived_sha256=damaged_hash,
              raw_validation_error=observed_damage.get('validation_error'), terminal=terminal)
        conflicting = output / 'mirror-conflict-volume.dd'
        shutil.copyfile(paths['volume.dd'], conflicting)
        with conflicting.open('r+b') as stream:
            boot = stream.read(512)
            mirror = int.from_bytes(boot[56:64], 'little') * creation['cluster_bytes']
            stream.seek(mirror + 1000)
            original_byte = stream.read(1)[0]
            stream.seek(mirror + 1000)
            stream.write(bytes([original_byte ^ 1]))
        conflict_hash = digest(conflicting)
        result, rows, terminal = cli('negative-mirror-conflict', 'inventory-ntfs', conflicting)
        primary = next(row for row in rows if row.get('type') == 'ntfs_slot' and row['slot'] == 0)
        check('native_mirror_disagreement', result.returncode == 0 and terminal and terminal['complete']
              and primary['mirror_agrees'] is False and digest(conflicting) == conflict_hash,
              derivation='copy native volume; xor1 in mirror record0 unused bytes, leaving USA valid',
              source_offset=mirror + 1000, derived_sha256=conflict_hash, terminal=terminal)
        truncated = output / 'truncated-volume.dd'
        with paths['volume.dd'].open('rb') as source, truncated.open('xb') as target_stream:
            target_stream.write(source.read(4096))
        truncated_hash = digest(truncated)
        result, rows, terminal = cli('negative-truncated', 'inventory-ntfs', truncated)
        check('native_truncation_before_first_observation', result.returncode != 0 and terminal
              and terminal['complete'] is False and terminal['stop_reason'] == 'invalid_bootstrap'
              and terminal['observations'] == 0 and bool(terminal['causes']) and digest(truncated) == truncated_hash,
              derivation='first4096 bytes of closed native volume; declared geometry retained',
              derived_sha256=truncated_hash, terminal=terminal)
        victim = creation['reuse']['victim']
        current = creation['reuse']['matching_current_record']
        check('native_record_reuse', creation['reuse']['record_reuse_observed'] and current
              and slots[current['record']]['sequence'] == current['sequence']
              and current['sequence'] != victim['sequence'] and slots[current['record']]['allocated_bitmap_bit'] is True,
              native_victim=victim, native_current=current)
        deleted = creation['deleted_preserved']
        if creation.get('mark_dirty_requested'):
            volume_record = slots[3]
            volume_attributes = [bytes.fromhex(attribute['raw_hex']) for attribute in volume_record['attributes'] if attribute['type'] == 0x70]
            flags = [int.from_bytes(attribute[int.from_bytes(attribute[20:22], 'little') + 10:int.from_bytes(attribute[20:22], 'little') + 12], 'little') for attribute in volume_attributes]
            check('native_dirty_volume_readonly_inventory', any(flag & 1 for flag in flags), native_dirty_query=creation['dirty_query'], raw_volume_flags=flags)
        check('native_deleted_record', slots[deleted['record']]['file_in_use'] is False
              and slots[deleted['record']]['allocated_bitmap_bit'] is False,
              record=deleted['record'], raw_evidence_preserved=bool(slots[deleted['record']]['raw_hex']))
        selections = [(fact['relative_name'], fact['record'], [], fact['sha256']) for fact in creation['files']]
        ads = creation['ads']
        ads_record = next(fact['record'] for fact in creation['files'] if fact['relative_name'] == ads['base'])
        selections.append((ads['base'] + ':' + ads['name'], ads_record,
                           ['--stream-name-utf16', ','.join(f'{ord(c):x}' for c in ads['name'])], ads['sha256']))
        for index, (name, record, selection, expected) in enumerate(selections):
            dest = output / ('live-output-' + str(index))
            dest.mkdir()
            extra = ['--record', str(record), '--output-dir', str(dest), *selection]
            if name == 'compressed.bin':
                extra.append('--allow-lznt1')
            result, rows, terminal = cli('extract-' + str(index), 'extract-ntfs', paths['volume.dd'], extra=extra)
            files = [path for path in dest.glob('*.partial') if not path.name.endswith('.jsonl.partial')]
            actual = digest(files[0]) if len(files) == 1 else None
            tsk_result = run('icat-' + str(index), [tsk / 'icat', paths['volume.dd'], namespace[name]])
            tsk_hash = hashlib.sha256(tsk_result.stdout).hexdigest()
            check('live_stream_' + name, result.returncode == 0 and terminal and terminal['complete']
                  and actual == expected and tsk_result.returncode == 0 and tsk_hash == expected,
                  native_sha256=expected, framework_sha256=actual, tsk_sha256=tsk_hash, terminal=terminal)
        result, time_rows, time_terminal = cli('timeline', 'timeline-ntfs', paths['volume.dd'])
        check('timeline_traversal', result.returncode == 0 and time_terminal and time_terminal['complete'], terminal=time_terminal)
        timestamps = {}
        for row in time_rows:
            if row['type'] == 'timestamp':
                record = row['evidence']['offset'] // 1024
                timestamps.setdefault(record, {}).setdefault(row['kind'], []).append(int(row['time']['unix_ticks_100ns']))
        timestamp_labels = {'Created': 'created', 'File Modified': 'modified', 'MFT Modified': 'changed', 'Accessed': 'accessed'}
        for fact in creation['files']:
            native = run('istat-' + str(fact['record']), [tsk / 'istat', '-z', 'UTC', paths['volume.dd'], str(fact['record'])])
            expected = {}
            prefix = None
            for line in native.stdout.decode().splitlines():
                if line.startswith('$STANDARD_INFORMATION Attribute'):
                    prefix = 'ntfs_standard_'
                elif line.startswith('$FILE_NAME Attribute'):
                    prefix = 'ntfs_name_'
                match = re.match(r'^(Created|File Modified|MFT Modified|Accessed):\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d{9}) \(UTC\)', line)
                if prefix and match:
                    seconds = calendar.timegm(datetime.datetime.strptime(match[2], '%Y-%m-%d %H:%M:%S').timetuple())
                    ticks = seconds * 10_000_000 + int(match[3]) // 100
                    expected.setdefault(prefix + timestamp_labels[match[1]], []).append(ticks)
            actual = timestamps.get(fact['record'], {})
            check('both_timestamp_sets_' + fact['relative_name'], native.returncode == 0 and len(expected) == 8
                  and {kind: sorted(values) for kind, values in expected.items()} == {kind: sorted(values) for kind, values in actual.items()},
                  precision_100ns=1, native_tsk_unix_ticks=expected, framework_unix_ticks=actual)
        dest = output / 'deleted-output'
        dest.mkdir()
        result, rows, terminal = cli('recover-deleted', 'recover-ntfs', paths['volume.dd'],
                                    extra=['--record', str(deleted['record']), '--output-dir', str(dest)])
        recovered = [path for path in dest.glob('*.partial') if not path.name.endswith('.jsonl.partial')]
        actual = digest(recovered[0]) if len(recovered) == 1 else None
        tsk_result = run('icat-deleted', [tsk / 'icat', '-r', paths['volume.dd'], namespace['deleted-preserved.bin']])
        tsk_hash = hashlib.sha256(tsk_result.stdout).hexdigest()
        manifests = [json.loads(line) for path in dest.glob('*.jsonl.partial') for line in path.read_text().splitlines()]
        check('deleted_current_bytes_and_qualifications', result.returncode == 0 and terminal and terminal['complete']
              and actual == tsk_hash and tsk_result.returncode == 0
              and any(row.get('verified_original') is False for row in manifests),
              original_native_sha256=deleted['sha256'], current_framework_sha256=actual,
              current_tsk_sha256=tsk_hash, original_content_matches=(actual == deleted['sha256']), terminal=terminal)
        result, rows, terminal = cli('usn', 'inspect-usn', paths['volume.dd'])
        check('usn_traversal', result.returncode == 0 and terminal and terminal['complete'], terminal=terminal)
        if creation.get('rollover_writes'):
            native_first = re.search(r'^First Usn\s*:\s*0x([0-9a-fA-F]+)', creation['usn_query'], re.MULTILINE)
            first = int(native_first[1], 16) if native_first else 0
            sparse_prefixes = [row['range'] for row in rows if row['type'] == 'usn_gap' and row['kind'] == 'sparse' and row['range']['offset'] == 0]
            check('native_rollover_sparse_prefix', first > 0 and bool(sparse_prefixes) and sparse_prefixes[0]['length'] >= first,
                  native_first_usn=first, sparse_prefixes=sparse_prefixes, native_writes=creation['rollover_writes'])
        text = paths['usn-native.csv'].read_text(encoding='utf-8-sig')
        header = text.index('Usn,File name,')
        native_records = list(csv.DictReader(io.StringIO(text[header:])))
        observed = {row['usn']: row for row in rows if row['type'] == 'usn_record'}
        mismatches = []
        for native in native_records:
            usn = int(native['Usn'])
            record = observed.get(usn)
            expected_name = list(native['File name'].encode('utf-16-le'))
            units = [expected_name[n] | expected_name[n + 1] << 8 for n in range(0, len(expected_name), 2)]
            def reference_value(value):
                return int(value['raw']) if value['version'] == 2 else int.from_bytes(bytes.fromhex(value['raw_hex']), 'little')
            reference_match = bool(record) and reference_value(record['file']) == int(native['File ID'], 16) and reference_value(record['parent']) == int(native['Parent file ID'], 16)
            if not record or record['name_utf16'] != units or record['reason'] != int(native['Reason #'], 0) or not reference_match:
                mismatches.append(usn)
        max_rows = [row for row in rows if row['type'] == 'usn_max']
        labels = {'journal_id': 'Usn Journal ID', 'lowest_valid_usn': 'Lowest Valid Usn',
                  'maximum_size': 'Maximum Size', 'allocation_delta': 'Allocation Delta'}
        expected_max = {}
        for field, label in labels.items():
            match = re.search(r'^' + re.escape(label) + r'\s*:\s*0x([0-9a-fA-F]+)', creation['usn_query'], re.MULTILINE)
            if not match:
                raise ValueError('native queryjournal field unavailable: ' + label)
            expected_max[field] = int(match[1], 16)
        check('native_max_retention_metadata', bool(max_rows) and max_rows[0].get('validated') is True
              and all(int(max_rows[0][field]) == value for field, value in expected_max.items()),
              native_fields=expected_max, framework_fields=max_rows)
        check('native_usn_known_operations', not mismatches and bool(native_records),
              native_record_count=len(native_records), framework_record_count=len(observed),
              native_records_not_matching=mismatches,
              additional_close_time_usns=sorted(set(observed) - {int(row['Usn']) for row in native_records}),
              native_readjournal_may_upconvert_v2_to_v3=True,
              compared_fields=['USN', 'native UTF16 name', 'reason bits', 'native file ID', 'native parent ID'],
              timestamp_timezone_not_inferred=True)
        result, rows, terminal = cli('logfile', 'inspect-logfile', paths['volume.dd'])
        reports = [row for row in rows if row['type'] == 'logfile_restart']
        check('logfile_separate_no_replay', result.returncode == 0 and terminal and terminal['complete']
              and bool(reports) and all(row['transaction_analysis_complete'] is False for row in reports), terminal=terminal)
        for artifact in creation['artifacts']:
            after = digest(paths[artifact['name']])
            receipt['native_artifact_hashes'][artifact['name']]['after_sha256'] = after
            check('immutable_' + artifact['name'], after == artifact['sha256'])
        receipt['passed'] = all(check['passed'] for check in receipt['checks'].values())
    except Exception as error:
        receipt['qualification_error'] = {'type': type(error).__name__, 'message': str(error)}
        receipt['passed'] = False
    finally:
        receipt['library_source_sha256_end'] = {
            str(path.relative_to(repository)): digest(path) for path in source_paths}
        receipt['library_sources_unchanged'] = (
            receipt['library_source_sha256'] == receipt['library_source_sha256_end'])
        if not receipt['library_sources_unchanged']:
            receipt['passed'] = False
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'passed': receipt['passed'], 'checks': len(receipt['checks']),
                          'failed_checks': [name for name, value in receipt['checks'].items() if not value['passed']],
                          'error': receipt.get('qualification_error'), 'receipt': str(output / 'receipt.json')}))
    raise SystemExit(0 if receipt['passed'] else 1)


if __name__ == '__main__':
    main()

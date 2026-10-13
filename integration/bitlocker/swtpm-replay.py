#!/usr/bin/env python3
"""Explicit LABORATORY PCR replay for a Windows-created TPM2-only fixture.

This is not a firmware boot or a live VM TPM handoff. A matching source emulator
must be stopped; only copied persistent state is mutated. The native protector
profile is PolicyAuthValue followed by PolicyPCR SHA256 with an empty authValue.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


def find_prefix(decoded_log, selected, expected):
    pcrs = {index: bytes(32) for index in selected}
    events = []
    for block in decoded_log.split('- EventNum: ')[1:]:
        # Consume only the trusted tool's record header, never event payload text.
        header = block.split('  EventSize:', 1)[0]
        index = int(re.search(r'\n  PCRIndex: (\d+)\n', header)[1])
        kind = re.search(r'\n  EventType: (\S+)', header)[1]
        if index not in pcrs or kind == 'EV_NO_ACTION':
            continue
        digest = re.search(r'AlgorithmId: sha256\n\s+Digest: "([0-9a-f]{64})"', header)
        if digest is None:
            continue
        value = bytes.fromhex(digest[1])
        pcrs[index] = hashlib.sha256(pcrs[index] + value).digest()
        events.append({'event': int(header.splitlines()[0]), 'pcr': index, 'digest': value.hex()})
        if hashlib.sha256(b''.join(pcrs[p] for p in sorted(pcrs))).digest() == expected:
            return events
    raise ValueError('no event-log prefix matches the native protector PCR digest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--swtpm', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--source-state', type=Path, required=True)
    parser.add_argument('--event-log', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True, help='native-sealed.pub/.priv and native-pcr.digest')
    parser.add_argument('--parent-handle', required=True, help='independently established persistent storage parent')
    parser.add_argument('--pcrs', required=True, help='explicit SHA256 indices, e.g. 7,11')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER, help='optional engine gate command after --')
    args = parser.parse_args()
    parent = int(args.parent_handle, 0)
    if not 0x81000000 <= parent <= 0x81ffffff:
        parser.error('parent must be an explicit persistent TPM handle')
    selected = [int(index) for index in args.pcrs.split(',')]
    if not selected or selected != sorted(set(selected)) or any(index < 0 or index > 15 for index in selected):
        parser.error('require sorted unique static PCR indices in [0,15]')
    root = args.output.resolve()
    if len(str(root)) > 55 or ',' in str(root):
        parser.error('output path too long for UNIX sockets or contains comma')
    root.mkdir(mode=0o700)
    if args.event_log.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('event log exceeds the laboratory 16 MiB bound')
    decoded = subprocess.run([str(args.tools / 'tpm2_eventlog'), str(args.event_log)],
                             capture_output=True, check=True, timeout=30).stdout.decode()
    (root / 'decoded-events.yaml').write_text(decoded)
    expected = (args.fixture / 'native-pcr.digest').read_bytes()
    if len(expected) != 32:
        raise ValueError('requires a SHA256 native PCR digest')
    events = find_prefix(decoded, selected, expected)
    (root / 'replay.json').write_text(json.dumps({'pcrs': selected, 'events': events}, indent=2))
    spec = importlib.util.spec_from_file_location('swtpm_gate', Path(__file__).with_name('swtpm-gate.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = args.source_state / 'tpm2-00.permall'
    original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    emulator = module.Emulator(args.swtpm, root / 'instance', args.source_state)
    try:
        environment = os.environ.copy()
        environment['TPM2TOOLS_TCTI'] = f'swtpm:path={emulator.command}'
        def tool(name, *arguments):
            result = subprocess.run([str(args.tools / ('tpm2_' + name)), *arguments],
                                    env=environment, cwd=root, capture_output=True, timeout=30)
            with (root / 'tools.log').open('ab') as log:
                log.write(name.encode() + b'\n' + result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f'tpm2_{name} failed; inspect retained tools.log')
        for event in events:
            tool('pcrextend', f"{event['pcr']}:sha256={event['digest']}")
        # This fixture's storage parent was independently established by Load.
        tool('load', '-C', hex(parent), '-u', str((args.fixture / 'native-sealed.pub').resolve()),
             '-r', str((args.fixture / 'native-sealed.priv').resolve()), '-c', 'sealed.ctx')
        tool('startauthsession', '--policy-session', '-S', 'session.ctx')
        tool('policyauthvalue', '-S', 'session.ctx')
        tool('policypcr', '-S', 'session.ctx', '-l', 'sha256:' + args.pcrs)
        secret = root / 'unsealed.secret'
        descriptor = os.open(secret, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        tool('unseal', '-c', 'sealed.ctx', '-p', 'session:session.ctx', '-o', str(secret))
        value = secret.read_bytes()
        if len(value) != 44 or value[:12] not in (bytes.fromhex('2c0000000100000003200000'), bytes.fromhex('2c0005000100000003200000')):
            raise ValueError('unexpected native unsealed key record')
        tool('flushcontext', 'session.ctx')
        tool('flushcontext', '-t')
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        environment['PARTMGR_BITLOCKER_TPM_SOCKET'] = str(emulator.command)
        environment['PARTMGR_BITLOCKER_TPM_PARENT'] = hex(parent)
        if command:
            subprocess.run(command, env=environment, check=True)
        manifest = {'schema': 1, 'kind': 'laboratory-native-policy-replay',
                    'sourceStateSha256': original_hash, 'eventLogSha256': hashlib.sha256(args.event_log.read_bytes()).hexdigest(),
                    'parentHandle': hex(parent), 'pcrs': selected, 'throughEvent': events[-1]['event'], 'extensions': len(events),
                    'nativeToolUnseal': True, 'externalEngineCommandPassed': bool(command),
                    'firmwareBoot': False, 'liveVmHandoff': False}
    finally:
        emulator.close()
    if hashlib.sha256(source.read_bytes()).hexdigest() != original_hash:
        raise RuntimeError('source persistent state changed')
    manifest['sourceStateUnchanged'] = True
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Create an isolated real TPM2 policy-sealed fixture and verify native-tool gates.

Uses explicit swtpm and tpm2-tools paths. Every instance is private; no VM-owned
socket or original state is opened. Output contains sensitive state and secrets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time


class Emulator:
    def __init__(self, binary, directory, imported=None):
        self.directory = directory
        directory.mkdir(mode=0o700)
        state = directory / 'state'
        state.mkdir(mode=0o700)
        if imported is not None:
            shutil.copyfile(imported / 'tpm2-00.permall', state / 'tpm2-00.permall')
            (state / 'tpm2-00.permall').chmod(0o600)
        self.command = directory / 'command.sock'
        self.control = directory / 'command.sock.ctrl'
        self.log = (directory / 'swtpm.log').open('wb')
        self.process = subprocess.Popen([
            str(binary), 'socket', '--tpm2', '--tpmstate', f'dir={state},mode=0600,lock,fsync',
            '--server', f'type=unixio,path={self.command},mode=0600',
            '--ctrl', f'type=unixio,path={self.control},mode=0600',
            '--flags', 'not-need-init,startup-clear',
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.log)
        deadline = time.monotonic() + 10
        while not self.command.exists() or not self.control.exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                self.close()
                raise RuntimeError('swtpm startup failed; inspect retained log')
            time.sleep(0.01)

    def close(self):
        try:
            if self.process.poll() is None:
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.settimeout(2)
                    connection.connect(str(self.control))
                    connection.sendall(struct.pack('>I', 3))
                    if connection.recv(4) != b'\0' * 4:
                        raise RuntimeError('swtpm shutdown rejected')
                self.process.wait(timeout=5)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--swtpm', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True, help='tpm2-tools bin directory')
    parser.add_argument('--output', type=Path, required=True, help='new short absolute directory')
    args = parser.parse_args()
    root = args.output.resolve()
    if len(str(root)) > 55 or ',' in str(root):
        parser.error('output path too long for UNIX sockets or contains comma')
    root.mkdir(mode=0o700)
    secret = struct.pack("<HHHHHH", 44, 5, 1, 0, 0x2003, 0) + os.urandom(32)
    (root / 'secret.bin').write_bytes(secret)
    (root / 'secret.bin').chmod(0o600)
    results = {}

    def tool(emulator, name, *arguments, failure=False):
        env = os.environ.copy()
        env['TPM2TOOLS_TCTI'] = f'swtpm:path={emulator.command}'
        result = subprocess.run([str(args.tools / ('tpm2_' + name)), *arguments], cwd=root,
                                env=env, capture_output=True, timeout=30)
        with (root / 'tool.log').open('ab') as log:
            log.write(name.encode() + b'\n' + result.stdout + result.stderr)
        if bool(result.returncode) != failure:
            raise RuntimeError(f'tpm2_{name} unexpected status {result.returncode}; inspect tool.log')
        return result

    source = Emulator(args.swtpm, root / 'source')
    try:
        tool(source, 'createprimary', '-C', 'o', '-G', 'rsa', '-g', 'sha256', '-c', 'parent.ctx')
        tool(source, 'evictcontrol', '-C', 'o', '-c', 'parent.ctx', '0x81000001')
        tool(source, 'flushcontext', '-t')
        tool(source, 'startauthsession', '-S', 'trial.ctx')
        tool(source, 'policyauthvalue', '-S', 'trial.ctx')
        tool(source, 'policypcr', '-S', 'trial.ctx', '-l', 'sha256:7,11')
        tool(source, 'getpolicydigest', '-S', 'trial.ctx', '-o', 'policy.bin')
        tool(source, 'flushcontext', 'trial.ctx')
        tool(source, 'create', '-C', '0x81000001', '-g', 'sha256',
             '-a', 'fixedtpm|fixedparent|noda', '-i', 'secret.bin', '-L', 'policy.bin',
             '-u', 'sealed.pub', '-r', 'sealed.priv')
        tool(source, 'pcrread', 'sha256:7,11', '-o', 'pcr.bin')
    finally:
        source.close()
    state_hash = hashlib.sha256((root / 'source/state/tpm2-00.permall').read_bytes()).hexdigest()
    imported = Emulator(args.swtpm, root / 'imported', root / 'source/state')
    try:
        tool(imported, 'load', '-C', '0x81000001', '-u', 'sealed.pub', '-r', 'sealed.priv', '-c', 'sealed.ctx')
        tool(imported, 'startauthsession', '--policy-session', '-S', 'session.ctx')
        tool(imported, 'policyauthvalue', '-S', 'session.ctx')
        tool(imported, 'policypcr', '-S', 'session.ctx', '-l', 'sha256:7,11')
        tool(imported, 'unseal', '-c', 'sealed.ctx', '-p', 'session:session.ctx', '-o', 'unsealed.bin')
        if (root / 'unsealed.bin').read_bytes() != secret:
            raise RuntimeError('unseal plaintext mismatch')
        tool(imported, 'flushcontext', 'session.ctx')
        results['matchingCopiedStateAndPolicy'] = True
        tool(imported, 'pcrextend', '7:sha256=' + '01' * 32)
        tool(imported, 'startauthsession', '--policy-session', '-S', 'wrong-session.ctx')
        tool(imported, 'policyauthvalue', '-S', 'wrong-session.ctx')
        tool(imported, 'policypcr', '-S', 'wrong-session.ctx', '-l', 'sha256:7,11')
        tool(imported, 'unseal', '-c', 'sealed.ctx', '-p', 'session:wrong-session.ctx',
             '-o', 'rejected.bin', failure=True)
        tool(imported, 'flushcontext', 'wrong-session.ctx')
        results['changedPcrRejected'] = True
    finally:
        imported.close()
    wrong = Emulator(args.swtpm, root / 'wrong')
    try:
        tool(wrong, 'createprimary', '-C', 'o', '-G', 'rsa', '-g', 'sha256', '-c', 'wrong-parent.ctx')
        tool(wrong, 'evictcontrol', '-C', 'o', '-c', 'wrong-parent.ctx', '0x81000001')
        tool(wrong, 'flushcontext', '-t')
        tool(wrong, 'load', '-C', '0x81000001', '-u', 'sealed.pub', '-r', 'sealed.priv', '-c', 'wrong.ctx', failure=True)
        results['unrelatedTpmRejected'] = True
    finally:
        wrong.close()
    if hashlib.sha256((root / 'source/state/tpm2-00.permall').read_bytes()).hexdigest() != state_hash:
        raise RuntimeError('original source state changed')
    manifest = {'schema': 1, 'kind': 'synthetic-policy-sealed-tpm2',
                'parentHandle': '0x81000001', 'hash': 'sha256', 'pcrs': [7, 11],
                'secretSha256': hashlib.sha256(secret).hexdigest(), 'nativeToolGates': results,
                'windowsProtector': False, 'firmwareBoot': False, 'rustProvider': False}
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()

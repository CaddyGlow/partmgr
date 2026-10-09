#!/usr/bin/env python3
"""Validate a native fixture manifest, then run the portable interoperability gate.

Supply the build command after --, e.g. nix develop ... -c cargo test ... .
Credentials travel via a file path, never command-line plaintext.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    manifest = json.loads((args.fixture / 'manifest.json').read_text(encoding='utf-8-sig'))
    if manifest['schema'] != 1 or manifest['profile'] != 'windows-native-data':
        raise ValueError('unsupported fixture manifest')
    if manifest['conversion'] != 'FullyEncrypted' or manifest['encryptionPercentage'] != 100:
        raise ValueError('fixture encryption did not complete')
    if manifest['cipher'] not in ('XtsAes128', 'XtsAes256'):
        raise ValueError('unsupported cipher')
    if not manifest['evidence']['cleanDetach'] or not manifest['evidence']['nativeEncryptedReadWrite']:
        raise ValueError('fixture lacks native completion evidence')
    if manifest['disk'] != 'disk.vhd' or manifest['container'] != 'fixed-vhd':
        raise ValueError('expected the fixed-VHD provisioning artifact')
    disk = args.fixture / 'disk.vhd'
    offset, length = manifest['partitionOffset'], manifest['partitionLength']
    if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length <= 0 or offset + length > disk.stat().st_size - 512:
        raise ValueError('invalid bounded partition')
    with disk.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != manifest['diskSha256']:
        raise ValueError('ciphertext artifact hash mismatch')
    command = args.command
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        parser.error('an explicit native Rust test command after -- is required')
    environment = os.environ.copy()
    environment.update({
        'PARTMGR_BITLOCKER_DISK': str(disk.resolve()),
        'PARTMGR_BITLOCKER_OFFSET': str(offset),
        'PARTMGR_BITLOCKER_LENGTH': str(length),
        'PARTMGR_BITLOCKER_PASSWORD_FILE': str((args.fixture / 'recovery.secret').resolve()),
        'PARTMGR_BITLOCKER_FILE': manifest['oracle']['path'].removeprefix('/'),
        'PARTMGR_BITLOCKER_SHA256': manifest['oracle']['sha256'],
    })
    if (args.fixture / 'samples' / 'samples.json').is_file():
        environment['PARTMGR_BITLOCKER_SECTORS_DIR'] = str((args.fixture / 'samples').resolve())
    subprocess.run(command, env=environment, check=True)


if __name__ == '__main__':
    main()

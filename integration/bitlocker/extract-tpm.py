#!/usr/bin/env python3
"""Extract one explicitly selected experimental Windows TPM-only protector.

Reads one captured <=64 KiB metadata block, verifies its CRC and the complete
native PolicyAuthValue->PolicyPCR digest, and writes new owner-only artifacts.
It neither contacts a TPM nor reads credentials or infers a storage parent.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import uuid
import zlib


def require(condition, message):
    if not condition:
        raise ValueError(message)


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def entries(data):
    offset = 0
    count = 0
    while offset < len(data):
        if not any(data[offset:]):
            return
        require(len(data) - offset >= 8, 'truncated metadata entry')
        size = u16(data, offset)
        require(8 <= size <= len(data) - offset, 'invalid metadata entry size')
        count += 1
        require(count <= 4096, 'metadata entry count limit')
        yield data[offset:offset + size]
        offset += size


def extract(metadata, protector):
    require(120 <= len(metadata) <= 65536, 'metadata input size outside bounds')
    require(metadata[:8] == b'-FVE-FS-' and u16(metadata, 10) == 2,
            'unsupported metadata block header')
    size = u16(metadata, 8) * 16
    require(112 <= size and size + 8 <= len(metadata), 'metadata block bounds')
    validation_size = u16(metadata, size)
    require(8 <= validation_size <= len(metadata) - size
            and u16(metadata, size + 2) in (1, 2), 'metadata validation header')
    require(zlib.crc32(metadata[:size]) == u32(metadata, size + 4),
            'metadata CRC mismatch')
    dataset_size, version, header_size, size_copy = struct.unpack_from('<IIII', metadata, 64)
    require(version == 1 and header_size == 48, 'unsupported dataset header')
    require(48 <= dataset_size <= size_copy <= size - 64, 'dataset bounds')
    selected = []
    for entry in entries(metadata[112:64 + dataset_size]):
        if u16(entry, 2) == 2 and u16(entry, 4) == 8:
            require(len(entry) >= 36, 'VMK property header bounds')
            if entry[8:24] == protector.bytes_le:
                selected.append(entry)
    require(len(selected) == 1, 'selected protector missing or duplicated')
    vmk = selected[0]
    require(u16(vmk, 6) in (1, 3), 'unsupported VMK entry version')
    require(u16(vmk, 34) == 0x0100, 'selected protector is not TPM-only')
    sealed = None
    auxiliary = False
    for entry in entries(vmk[36:]):
        require(u16(entry, 2) == 0, 'unsupported TPM property kind')
        value = u16(entry, 4)
        if value == 6 and sealed is None:
            sealed = entry
        elif (value == 30 and not auxiliary and len(entry) == 128
              and u16(entry, 6) == 5 and u16(entry, 8) == 1
              and not any(entry[96:])):
            auxiliary = True
        else:
            raise ValueError('unsupported or duplicate TPM property')
    require(sealed is not None, 'TPM sealed property absent')
    require(len(sealed) == 302 and u16(sealed, 6) == 5, 'unsupported TPM datum size/version')
    mask = u32(sealed, 8)
    require(0 < mask <= 0xffffff, 'unsupported PCR mask')
    require(struct.unpack_from('>H', sealed, 12)[0] == 170, 'private TPM2B size')
    private = sealed[12:184]
    require(struct.unpack_from('>H', private, 2)[0] == 32
            and struct.unpack_from('>H', private, 36)[0] == 16,
            'unsupported private TPM object profile')
    require(struct.unpack_from('>H', sealed, 184)[0] == 78, 'public TPM2B size')
    public = sealed[184:264]
    area = public[2:]
    require(area[:10] == bytes.fromhex('0008000b000004120020')
            and area[42:46] == bytes.fromhex('00100020'),
            'unsupported public TPM object profile')
    require(sealed[264:266] == b'\x00\x20', 'unsupported PCR digest size')
    digest = sealed[266:298]
    require(sealed[298:] == b'\x03' + mask.to_bytes(4, 'little')[:3],
            'PCR selection copies disagree')
    selection = bytes.fromhex('00000001000b') + sealed[298:]
    first = hashlib.sha256(bytes(32) + struct.pack('>I', 0x16b)).digest()
    policy = hashlib.sha256(first + struct.pack('>I', 0x17f) + selection + digest).digest()
    require(policy == area[10:42], 'unsupported complete authorization policy')
    return {
        'native-sealed.priv': private,
        'native-sealed.pub': public,
        'native-pcr.digest': digest,
        'native-auth.policy': policy,
        'native-tpm-datum.bin': sealed,
    }, mask, auxiliary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, required=True, help='one captured metadata block, at most 65536 bytes')
    parser.add_argument('--protector', required=True, help='explicit Windows protector GUID')
    parser.add_argument('--output', type=Path, required=True, help='new private output directory; must not exist')
    args = parser.parse_args()
    protector = uuid.UUID(args.protector.strip('{}'))
    with args.metadata.open('rb') as source:
        metadata = source.read(65537)
    files, mask, auxiliary = extract(metadata, protector)
    manifest = {
        'schema': 1,
        'profile': 'windows-tpm-only-version5-sha256-authvalue-pcr',
        'protectorId': str(protector),
        'metadataSha256': hashlib.sha256(metadata).hexdigest(),
        'pcrBank': 'sha256',
        'pcrIndices': [index for index in range(24) if mask & (1 << index)],
        'policySequence': ['PolicyAuthValue', 'PolicyPCR'],
        'parentHandle': None,
        'parentRequirement': 'explicit independently established persistent storage parent',
        'auxiliaryPropertyPresent': auxiliary,
        'evidence': {'boundedParsing': True, 'policyDigestMatches': True, 'tpmUnseal': False},
        'artifacts': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                      for name, data in files.items()},
    }
    files['native-tpm-policy.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    args.output.mkdir(mode=0o700)
    for name, data in files.items():
        # Exclusive creation never overwrites existing artifacts or follows links.
        descriptor = os.open(args.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
    print('Exported bounded TPM artifacts; no credentials, TPM command or parent inference.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        raise SystemExit(f'extraction failed: {error}') from None

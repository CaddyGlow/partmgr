# Experimental Windows TPM-only format

The `bitlocker-tpm` parser accepts one experimentally observed Windows 26200
profile. It is a bounded parser, not proof of successful TPM unsealing or boot.
The sibling host provider executes its validated policy on an explicitly
selected, exclusive TPM command transport.

## Selected profile

The native TPM-only protector (`0x0100`) contains a 302-byte TPM datum, property
kind zero, value six and version five. Its four-byte little-endian PCR mask is
followed by a 170-byte TPM2B_PRIVATE payload and a 78-byte TPMT_PUBLIC payload;
TPM2B lengths are big-endian. The public object is KEYEDHASH, SHA256, attributes
`0x412`, a 32-byte authPolicy, NULL scheme and a 32-byte unique value. A trailing
TPM2B_DIGEST has 32 bytes and is followed by a three-byte PCR selection whose
mask must agree with the prefix. No trailing bytes or alternate algorithms are
accepted.

These observations come from the locally generated Windows system fixture in
`/data/cache/partmgr-bitlocker-native/system/`. They are also structurally
consistent with the [faulTPM authors' Windows TPM artifact](https://github.com/PSPReverse/ftpm_attack#tpm-object-decryption),
which demonstrates the private/public object envelope and a 44-byte unsealed
BitLocker key record. This implementation does not import their hardware attack
or offline secret-extraction procedure.

The complete native authPolicy was independently reproduced as:

```text
first = SHA256(zero32 || BE32(TPM_CC_PolicyAuthValue))
policy = SHA256(first || BE32(TPM_CC_PolicyPCR)
                || TPML_PCR_SELECTION(SHA256, mask) || trailing_digest32)
```

The parser checks that digest before returning the object. This fixes the PCR
bank and command order from the policy itself; it does not try guessed policies.
The digest update follows Microsoft's TPM reference
[PolicyAuthValue](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/EA/PolicyAuthValue.c)
and [PolicyPCR](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/EA/PolicyPCR.c)
implementations. The observed native selection is SHA256 PCRs 7 and 11.

One auxiliary property (value 30, version five, 128-byte datum, observed envelope)
is accepted alongside the TPM property and retained in the original metadata.
Its opaque contents are not executed or substituted for authorization; the
entire sealed public policy must still equal the supported sequence. Other
properties and duplicate TPM/auxiliary records fail explicitly. This is not
support for TPM+PIN, startup keys or arbitrary Windows TPM formats.

## Host and key boundary

The parent handle is not encoded in this parsed object. Callers must supply the
matching persistent storage parent explicitly. Empty parent authorization and
empty (or TPM-trimmed all-zero) object authValue are the experimental host
profile. The encrypted authValue cannot be verified by parsing. The TPM must
validate it through PolicyAuthValue session HMAC authentication; it is never
silently omitted. Session nonces must be fresh and caller supplied.

The unsealed record must have exactly 44 bytes: the twelve-byte header
`2c0000000100000003200000` observed through the Windows 26200 TPM fixture, or
`2c0005000100000003200000` from the authors' older Windows artifact, then a
32-byte VMK. The second little-endian header word has incompletely documented
status/type semantics; only the observed values zero and five are accepted.
The first four bytes must not be interpreted as one 32-bit record length.
All other header fields and the exact total length remain mandatory.
The parser retains that VMK in a
non-clonable zeroizing fixed array with redacted formatting. The public volume
API authenticates the wrapped FVEK before reporting key evidence. It does not
return a decrypted reader for unsupported volume mappings. Response buffers and
keys must not be logged, included in manifests or exposed in debug formatting.

The native metadata acquisition was live and bounded, not a coherent full
volume/TPM snapshot. A successful parser test establishes the recorded shape and
policy equality only. The Rust provider has now unsealed the Windows-created
object through an isolated copied swtpm state and authenticated its wrapped
FVEK. The PCR window was recreated by an explicitly authorized laboratory replay;
this is not evidence of a genuine live boot-time provider handoff. The system
volume's used-space-only mapping remains unsupported. Wrong-state failures and
firmware boot remain distinct evidence gates.

Reproduce the bounded input artifacts without copying keys into a command line:

```sh
python3 integration/bitlocker/extract-tpm.py \
  --metadata /data/cache/partmgr-bitlocker-native/system/metadata-41943040.bin \
  --protector CF72DC49-03AD-4720-A4AA-924C2DD68535 \
  --output /data/cache/partmgr-bitlocker-tpm-extracted-new
```

The directory must not exist. The helper checks metadata CRC, the explicitly
selected protector, all accepted TPM lengths and the complete policy digest
before creating a mode-0700 directory with exclusively created mode-0600 files.
It exports `native-sealed.pub`, `native-sealed.priv`, `native-pcr.digest`,
`native-auth.policy`, the complete bounded TPM datum and a non-secret manifest.
Reproduction matched the SHA-256 hashes of all four original exported public,
private, PCR-digest and authorization-policy artifacts. It makes no TPM call,
infers no parent handle, and records no unsealed VMK or recovery credential.

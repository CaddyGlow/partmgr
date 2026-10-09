# TPM provider feasibility and format audit

Status: no native TPM or swtpm unlock provider is implemented or qualified.
Enumerating a TPM protector and supplying an externally obtained VMK are separate
operations. A successful generic TPM sealing demonstration would not establish
Windows BitLocker compatibility.

## Format evidence checked

The reader/parser audit used libbde commit
`96e3c5dce6143c2702c90f3903018fb8c12a8956` and its
[format specification](https://github.com/libyal/libbde/blob/96e3c5dce6143c2702c90f3903018fb8c12a8956/documentation/BitLocker%20Drive%20Encryption%20%28BDE%29%20format.asciidoc).
The implementation matches the documented version-2 block offsets, dataset
bounds, 28-byte VMK property prefix, recovery stretch inputs, CCM nonce/tag
layout, and volume-relative XTS sector numbering. Boot redirection and zeroed
reserved regions follow the documented Windows 7 mapping. The observed Windows 26200 completed full-volume extended descriptor is now
strictly decoded, with its additional region checked against a native zero-read
oracle. Other extended area profiles remain refused.
The reference still describes some conversion/header fields as uncertain.
Consequently, synthetic state checks do not qualify a Windows profile.

For TPM, that specification identifies value type `0x0006` but explicitly leaves
its body unanalyzed. Protector type `0x0100` identifies TPM and `0x0500` identifies
TPM plus PIN. The [libbde support list](https://github.com/libyal/libbde/tree/96e3c5dce6143c2702c90f3903018fb8c12a8956)
marks TPM protection unsupported. It is therefore unsuitable as the sole TPM
provider format oracle.

The authors' [faulTPM research artifact](https://github.com/PSPReverse/ftpm_attack#tpm-object-decryption)
includes a Windows 11 TPM-only metadata example. Its TPM datum has a 12-byte
header (including the common datum header), followed by a payload containing
length-prefixed TPM object material. The example is useful for locating a
candidate representation. It does not document all Windows blob versions,
parent selection, PCR policies, additional factors, or an ordinary live swtpm
unseal lifecycle. This project does not import its hardware attack or secret
extraction procedures.

## Missing evidence before a parser/provider API

A dedicated Windows-created fixture must establish all of the following:

1. Exact TPM datum version and prefix semantics; byte order, lengths and trailing
   fields; private/public object boundaries; all relevant nested properties.
2. Parent object identity and authorization, object name/hash algorithm, and
   expected unsealed structure. The provider must validate a VMK before using it
   to authenticate the FVEK record.
3. The complete policy sequence, PCR bank and selection, digest inputs, locality,
   session authorization and any additional factors. Reject unsupported policy
   branches or TPM+PIN/startup-key protection explicitly.
4. A coherent disk, firmware-variable and TPM-state generation with a demonstrated
   unseal window. A metadata dump alone does not provide that window.

These are concrete blockers to defining a qualified Windows TPM parser. No
public generic callback or opaque-blob passthrough is added as a substitute.
The first parser should accept only the demonstrated version, bound every
length/count, preserve unknown records for inspection, and decline unlocking
when the policy cannot be fully interpreted.

## Live and imported-state transport requirements

[swtpm's documented interface](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod)
separates command and control channels, offers Unix sockets, supports TPM 2.0
explicitly, and can encrypt persistent state. The provider needs an exclusive
command endpoint, bounded response frames, deadlines, cancellation and guaranteed
session/object cleanup. State encryption requires the corresponding import key.
The provider must never implicitly clear the TPM or reset PCRs.

[QEMU's TPM migration contract](https://www.qemu.org/docs/master/specs/tpm.html)
is the basis for a coherent emulator lifecycle. Import should restore into a
new disposable state directory through supported tooling, preserving original
artifacts. Persistent state alone must not be advertised as preservation of
runtime PCR state; a post-boot snapshot is not proof that boot-time unseal policy
still holds. OVMF variables are boot inputs, never a volume-key credential.

The [Microsoft countermeasures guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures)
explains the measured-boot and additional-authentication context. Qualification
must demonstrate matching-state success and explicit failures for a wrong TPM,
incompatible PCRs, missing factors, post-boot state, mismatched generations,
unsupported state formats, absent state-decryption keys and transport errors.
A generic [`TPM2_Unseal` invocation](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_unseal.1.md)
cannot establish those Windows-specific conditions.

Host parser, crypto, reader and encrypted-write tests provide no TPM or firmware
boot evidence. Record successful live and imported-state gates separately in the
native evidence manifest before changing this status.

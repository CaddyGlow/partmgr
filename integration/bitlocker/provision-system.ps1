# Run elevated inside the intended disposable VM after native Windows deployment.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [Parameter(Mandatory=$true)][switch]$DisposableVm,
    [switch]$UsedSpaceOnly,
    [ValidateSet('XtsAes128','XtsAes256')][string]$Cipher = 'XtsAes128',
    [ValidateRange(60,14400)][int]$TimeoutSeconds = 7200
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$DisposableVm) { throw 'DisposableVm acknowledgement is required' }
if (Test-Path $EvidenceDirectory) { throw 'Evidence directory already exists' }
$mount = $env:SystemDrive
$volume = Get-BitLockerVolume -MountPoint $mount
if ($volume.VolumeStatus -ne 'FullyDecrypted') { throw 'Refuse to change existing encryption/protectors' }
$tpm = Get-Tpm
if (!$tpm.TpmPresent -or !$tpm.TpmReady) { throw 'Intended TPM must already be ready; this script never clears or initializes it' }
$null = New-Item -ItemType Directory $EvidenceDirectory
& icacls $EvidenceDirectory /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict fixture/secret directory ACL' }
& reagentc /enable 2>&1 | Out-File "$EvidenceDirectory\reagentc-enable.log"
if ($LASTEXITCODE -ne 0) { throw 'REAgentC failed' }
& reagentc /info 2>&1 | Out-File "$EvidenceDirectory\reagentc-info.log"
if ($LASTEXITCODE -ne 0) { throw 'REAgentC info failed' }
$null = Add-BitLockerKeyProtector -MountPoint $mount -RecoveryPasswordProtector -WarningAction SilentlyContinue
$recovery = @((Get-BitLockerVolume -MountPoint $mount).KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
if ($recovery.Count -ne 1) { throw 'Expected exactly one recovery protector' }
$recovery[0].RecoveryPassword | Set-Content "$EvidenceDirectory\recovery.secret" -Encoding ASCII
$null = Enable-BitLocker -MountPoint $mount -EncryptionMethod $Cipher -TpmProtector -SkipHardwareTest -UsedSpaceOnly:$UsedSpaceOnly -WarningAction SilentlyContinue
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do {
    $volume = Get-BitLockerVolume -MountPoint $mount
    if ((Get-Date) -gt $deadline) { throw 'Encryption timeout; staging remains incomplete' }
    if ($volume.VolumeStatus -ne 'FullyEncrypted') { Start-Sleep -Seconds 5 }
} while ($volume.VolumeStatus -ne 'FullyEncrypted')
if ($volume.ProtectionStatus -ne 'On') { throw 'Protection is not active' }
$types = @($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
if ($types.Count -ne 2 -or $types -notcontains 'Tpm' -or $types -notcontains 'RecoveryPassword') { throw 'Unexpected protector set' }
@{
    schema = 1; profile = 'windows-native-system-staging'; windowsBuild = [Environment]::OSVersion.Version.ToString()
    cipher = $volume.EncryptionMethod.ToString(); conversion = $volume.VolumeStatus.ToString(); usedSpaceOnly = [bool]$UsedSpaceOnly
    secureBoot = Confirm-SecureBootUEFI; protectorTypes = $types
    protectorIds = @($volume.KeyProtector | ForEach-Object { $_.KeyProtectorId })
    evidence = @{ encrypted = $true; tpmProvisioned = $true; firmwareBootAfterEncryption = $false; winreBoot = $false; hostTpmUnseal = $false }
} | ConvertTo-Json -Depth 5 | Set-Content "$EvidenceDirectory\manifest.json" -Encoding UTF8
# A subsequent reboot + boot/event evidence and WinRE launch are separate gates.

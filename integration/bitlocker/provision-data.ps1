# Run elevated in a disposable Windows guest. Creates a NEW fixed VHD only.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('XtsAes128','XtsAes256')][string]$Cipher = 'XtsAes128',
    [ValidatePattern('^[D-Z]$')][string]$DriveLetter = 'R',
    [ValidateRange(256,4096)][int]$SizeMiB = 256,
    [ValidateRange(30,7200)][int]$TimeoutSeconds = 900
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path $OutputDirectory) { throw 'Output directory must not exist; refuse to reuse fixtures' }
if (Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue) { throw 'Drive letter already in use' }
$null = New-Item -ItemType Directory -Path $OutputDirectory
& icacls $OutputDirectory /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict fixture/secret directory ACL' }
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
$vhd = Join-Path $OutputDirectory 'disk.vhd'
$mount = "${DriveLetter}:"
$attached = $false
try {
    @"
create vdisk file="$vhd" maximum=$SizeMiB type=fixed
select vdisk file="$vhd"
attach vdisk
convert gpt
create partition primary
format fs=ntfs quick label=PARTMGR_NATIVE
assign letter=$DriveLetter
"@ | Set-Content (Join-Path $OutputDirectory 'create.diskpart') -Encoding ASCII
    & diskpart /s (Join-Path $OutputDirectory 'create.diskpart') | Out-File (Join-Path $OutputDirectory 'diskpart.log')
    $attached = $true
    if (!(Test-Path "$mount\")) { throw 'DiskPart failed to mount the new VHD; inspect diskpart.log' }
    $partition = Get-Partition -DriveLetter $DriveLetter
    $disk = Get-Disk -Number $partition.DiskNumber
    if ($disk.PartitionStyle -ne 'GPT') { throw 'Expected GPT' }
    $layout = @(Get-Partition -DiskNumber $partition.DiskNumber)
    if ($layout.Count -ne 2 -or @($layout | Where-Object GptType -eq '{e3c9e316-0b5c-4db8-817d-f92df00215ae}').Count -ne 1) { throw 'Expected one MSR and one data partition' }
    $payload = New-Object byte[] 1048576
    for ($i=0; $i -lt $payload.Length; $i++) { $payload[$i] = [byte](($i * 17 + 31) % 251) }
    [IO.File]::WriteAllBytes("$mount\oracle.bin", $payload)
    $hash = (Get-FileHash "$mount\oracle.bin" -Algorithm SHA256).Hash.ToLowerInvariant()
    # Recovery material is saved separately and never emitted into evidence/logs.
    $null = Enable-BitLocker -MountPoint $mount -EncryptionMethod $Cipher -RecoveryPasswordProtector -SkipHardwareTest -WarningAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $volume = Get-BitLockerVolume -MountPoint $mount
        if ((Get-Date) -gt $deadline) { throw 'Timed out waiting for full encryption' }
        if ($volume.VolumeStatus -ne 'FullyEncrypted') { Start-Sleep -Seconds 2 }
    } while ($volume.VolumeStatus -ne 'FullyEncrypted')
    $recovery = @($volume.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
    if ($recovery.Count -ne 1) { throw 'Expected exactly one recovery protector' }
    if (@($volume.KeyProtector | Where-Object KeyProtectorType -eq 'Clear').Count) { throw 'Unexpected clear protector' }
    $recovery[0].RecoveryPassword | Set-Content (Join-Path $OutputDirectory 'recovery.secret') -Encoding ASCII
    # Native read/write after encryption, then clean detach: independent Windows oracle.
    [IO.File]::WriteAllText("$mount\after-encryption.txt", 'native encrypted write oracle')
    if ((Get-FileHash "$mount\oracle.bin" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw 'Native oracle changed' }
    $manifest = [ordered]@{
        schema = 1; profile = 'windows-native-data'; windowsBuild = [Environment]::OSVersion.Version.ToString()
        cipher = $volume.EncryptionMethod.ToString(); conversion = $volume.VolumeStatus.ToString()
        protection = $volume.ProtectionStatus.ToString(); encryptionPercentage = $volume.EncryptionPercentage
        disk = 'disk.vhd'; container = 'fixed-vhd'; logicalSectorBytes = $disk.LogicalSectorSize
        partitionOffset = $partition.Offset; partitionLength = $partition.Size
        partitions = @($layout | Select-Object PartitionNumber,GptType,Offset,Size)
        protectorId = $recovery[0].KeyProtectorId; protector = 'RecoveryPassword'
        oracle = @{ path = '/oracle.bin'; bytes = $payload.Length; sha256 = $hash }
        evidence = @{ nativeEncryptedReadWrite = $true; cleanDetach = $false; portableRead = $false; firmwareBoot = $false; tpmUnseal = $false }
    }
    @"
select vdisk file="$vhd"
detach vdisk
"@ | Set-Content (Join-Path $OutputDirectory 'detach.diskpart') -Encoding ASCII
    & diskpart /s (Join-Path $OutputDirectory 'detach.diskpart') | Out-File (Join-Path $OutputDirectory 'detach.log')
    if (Test-Path "$mount\") { throw 'VHD remains attached' }
    $attached = $false
    $manifest.evidence.cleanDetach = $true
    $manifest.diskSha256 = (Get-FileHash $vhd -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputDirectory 'manifest.json') -Encoding UTF8
} finally {
    if ($attached) {
        "select vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content (Join-Path $OutputDirectory 'cleanup.diskpart') -Encoding ASCII
        & diskpart /s (Join-Path $OutputDirectory 'cleanup.diskpart') | Out-Null
    }
}

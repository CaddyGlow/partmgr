# Native acceptance of a separately staged data VHD (including host-edited images).
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$DiskImage,
    [Parameter(Mandatory=$true)][string]$RecoverySecretFile,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference='Stop'
if(Test-Path $EvidenceDirectory){throw 'Evidence directory exists'}
$null=New-Item -ItemType Directory $EvidenceDirectory
$DiskImage=(Resolve-Path $DiskImage).Path
$initialHash=(Get-FileHash $DiskImage -Algorithm SHA256).Hash.ToLowerInvariant()
$attached=$false
try {
    "select vdisk file=`"$DiskImage`"`nattach vdisk" | Set-Content "$EvidenceDirectory\attach.diskpart" -Encoding ASCII
    & diskpart /s "$EvidenceDirectory\attach.diskpart" | Out-File "$EvidenceDirectory\attach.log"
    $attached=$true
    $parts=@(Get-DiskImage -ImagePath $DiskImage | Get-Disk | Get-Partition | Where-Object {$_.Type -eq 'Basic'})
    if($parts.Count -ne 1 -or !$parts[0].DriveLetter){throw 'Expected one automatically mounted data partition'}
    $mount="$($parts[0].DriveLetter):"
    $null=Unlock-BitLocker -MountPoint $mount -RecoveryPassword ((Get-Content $RecoverySecretFile -Raw).Trim()) -WarningAction SilentlyContinue
    $actual=(Get-FileHash "$mount\oracle.bin" -Algorithm SHA256).Hash.ToLowerInvariant()
    if($actual -ne $ExpectedSha256.ToLowerInvariant()){throw 'Native file SHA256 mismatch'}
    & fsutil dirty query $mount | Out-File "$EvidenceDirectory\dirty.log"
    if($LASTEXITCODE -ne 0){throw 'Native dirty query failed'}
    & chkdsk $mount /scan | Out-File "$EvidenceDirectory\chkdsk.log"
    if($LASTEXITCODE -ne 0){throw 'Native consistency check failed'}
    & manage-bde -lock $mount -forcedismount | Out-File "$EvidenceDirectory\lock.log"
    if($LASTEXITCODE -ne 0){throw 'Native lock/dismount failed'}
    "select vdisk file=`"$DiskImage`"`ndetach vdisk" | Set-Content "$EvidenceDirectory\detach.diskpart" -Encoding ASCII
    & diskpart /s "$EvidenceDirectory\detach.diskpart" | Out-File "$EvidenceDirectory\detach.log"
    if((Get-DiskImage -ImagePath $DiskImage).Attached){throw 'Native detach failed'}
    $attached=$false
    @{schema=1;profile='native-data-acceptance';inputDiskSha256=$initialHash;oracleSha256=$actual;nativeRecoveryUnlock=$true;nativeFileRead=$true;chkdskScan=$true;cleanDetach=$true;firmwareBoot=$false} | ConvertTo-Json | Set-Content "$EvidenceDirectory\manifest.json" -Encoding UTF8
}finally{
    if($attached){"select vdisk file=`"$DiskImage`"`ndetach vdisk" | Set-Content "$EvidenceDirectory\cleanup.diskpart" -Encoding ASCII;& diskpart /s "$EvidenceDirectory\cleanup.diskpart" | Out-Null}
}

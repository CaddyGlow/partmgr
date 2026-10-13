# Run only in a disposable VM with the dedicated blank 256 MiB fixture disk.
# No disk is selected by number, size alone, or drive-letter coincidence.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^PARTMGR-LOG-[0-9]{8}$')]
    [string]$DiskSerial,
    [ValidatePattern('^[D-Z]$')]
    [string]$DriveLetter = 'S',
    [switch]$ResumePopulating
)
$ErrorActionPreference = 'Stop'
$disks = @(Get-Disk | Where-Object { ([string]$_.SerialNumber).Trim() -eq $DiskSerial })
if ($disks.Count -ne 1) { throw 'Expected exactly one fixture disk with the requested serial' }
$disk = $disks[0]
if ($disk.IsBoot -or $disk.IsSystem -or $disk.Size -ne 268435456) {
    throw 'Fixture disk must be exactly 256 MiB and neither boot nor system'
}
if ($ResumePopulating) {
    $parts = @(Get-Partition -DiskNumber $disk.Number)
    if ($parts.Count -ne 1 -or $parts[0].DriveLetter -ne $DriveLetter) { throw 'Unexpected fixture partition' }
    $partition = $parts[0]
    $volume = $partition | Get-Volume
    if ($volume.FileSystem -ne 'NTFS' -or $volume.FileSystemLabel -ne 'PARTMGR-LOG') { throw 'Unexpected existing fixture volume' }
} else {
    if ($disk.PartitionStyle -ne 'RAW') { throw 'New fixture disk must be blank RAW' }
    if (Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue) { throw 'Requested fixture drive letter is occupied' }
    if ($disk.IsOffline) { $disk | Set-Disk -IsOffline $false }
    if ($disk.IsReadOnly) { $disk | Set-Disk -IsReadOnly $false }
    $disk | Initialize-Disk -PartitionStyle MBR
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter $DriveLetter
    $partition | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel 'PARTMGR-LOG' -Confirm:$false | Out-Null
}
$root = $DriveLetter + ':\'
$directory = Join-Path $root 'fixture'
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$ordinary = Join-Path $directory 'ordinary.bin'
$payload = New-Object byte[] 131072
for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = [byte](($i * 17 + 31) % 251) }
[IO.File]::WriteAllBytes($ordinary, $payload)
& cmd.exe /D /C ('echo partmgr native named stream>"' + $ordinary + ':evidence"')
if ($LASTEXITCODE -ne 0) { throw 'Native named stream creation failed' }
& cmd.exe /D /C ('echo partmgr native directory stream>"' + $directory + ':directory-evidence"')
if ($LASTEXITCODE -ne 0) { throw 'Native directory stream creation failed' }
$compressed = Join-Path $directory 'compressed.bin'
[IO.File]::WriteAllBytes($compressed, (New-Object byte[] 196608))
& compact.exe /C /I /Q $compressed
if ($LASTEXITCODE -ne 0) { throw 'Native compression failed' }
& fsutil.exe hardlink create (Join-Path $directory 'ordinary-link.bin') $ordinary
if ($LASTEXITCODE -ne 0) { throw 'Native hardlink failed' }
# Verify without repair, then dismount before taking host-side image evidence.
& chkdsk.exe ($DriveLetter + ':')
if ($LASTEXITCODE -ne 0) { throw 'Native read-only chkdsk found a problem' }
& fsutil.exe fsinfo ntfsinfo ($DriveLetter + ':')
if ($LASTEXITCODE -ne 0) { throw 'Native NTFS geometry query failed' }
& fsutil.exe dirty query ($DriveLetter + ':')
if ($LASTEXITCODE -ne 0) { throw 'Native dirty query failed' }
$build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[ordered]@{
    WindowsBuild = $build.CurrentBuildNumber
    WindowsRevision = $build.UBR
    DiskSerial = $disk.SerialNumber.Trim()
    DiskNumber = $disk.Number
    PartitionOffset = $partition.Offset
    PartitionBytes = $partition.Size
    OrdinarySHA256 = (Get-FileHash $ordinary -Algorithm SHA256).Hash
    CompressedPlaintextSHA256 = (Get-FileHash $compressed -Algorithm SHA256).Hash
    Streams = @(Get-Item $ordinary -Stream * | Select-Object Stream, Length)
} | ConvertTo-Json -Depth 5
& fsutil.exe volume dismount ($DriveLetter + ':')
if ($LASTEXITCODE -ne 0) { throw 'Native dismount failed' }
$disk | Set-Disk -IsOffline $true

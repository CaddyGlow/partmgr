# Disposable VM only. Power-cut the owned VM externally while this script runs.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^PARTMGR-LOG-[0-9]{8}$')]
    [string]$DiskSerial,
    [ValidatePattern('^[D-Z]$')]
    [string]$DriveLetter = 'S'
)
$ErrorActionPreference = 'Stop'
$disks = @(Get-Disk | Where-Object { ([string]$_.SerialNumber).Trim() -eq $DiskSerial })
if ($disks.Count -ne 1) { throw 'Expected exactly one dedicated fixture disk' }
$disk = $disks[0]
if ($disk.IsBoot -or $disk.IsSystem -or $disk.Size -ne 268435456 -or $disk.PartitionStyle -ne 'MBR') {
    throw 'Unexpected dedicated fixture disk identity or geometry'
}
if ($disk.IsOffline) { $disk | Set-Disk -IsOffline $false }
if ($disk.IsReadOnly) { $disk | Set-Disk -IsReadOnly $false }
$parts = @(Get-Partition -DiskNumber $disk.Number)
if ($parts.Count -ne 1 -or $parts[0].Offset -ne 65536 -or $parts[0].Size -ne 267321344) {
    throw 'Unexpected dedicated fixture partition geometry'
}
$partition = $parts[0]
if ($partition.DriveLetter -ne $DriveLetter) {
    if (Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue) { throw 'Drive letter occupied' }
    $partition | Set-Partition -NewDriveLetter $DriveLetter
}
$volume = Get-Volume -DriveLetter $DriveLetter
if ($volume.FileSystem -ne 'NTFS' -or $volume.FileSystemLabel -ne 'PARTMGR-LOG') { throw 'Unexpected fixture volume' }
$build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$state = [ordered]@{ DiskSerial=$DiskSerial; DiskNumber=$disk.Number; WindowsBuild=$build.CurrentBuildNumber; WindowsRevision=$build.UBR; Iteration=0; Stage='starting'; Utc=[DateTime]::UtcNow.ToString('o') }
$status = 'C:\vm\partmgr-dirty-workload.json'
New-Item -ItemType Directory -Path 'C:\vm' -Force | Out-Null
$root = $DriveLetter + ':\dirty-workload'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$bytes = New-Object byte[] 65536
for ($j=0; $j -lt $bytes.Length; $j++) { $bytes[$j] = [byte](($j*19+7)%251) }
for ($i=1; ; $i++) {
    $slot = $i % 512
    $name = Join-Path $root ('file-{0:D4}.bin' -f $slot)
    $renamed = Join-Path $root ('renamed-{0:D4}.bin' -f $slot)
    if (Test-Path $renamed) { Remove-Item $renamed -Force }
    $stream = New-Object IO.FileStream($name, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    & cmd.exe /D /C ('echo native-transaction-' + $i + '>"' + $name + ':evidence"')
    if ($LASTEXITCODE -ne 0) { throw 'Native ADS write failed' }
    Move-Item $name $renamed -Force
    if (($i % 16) -eq 0) {
        $state.Iteration=$i; $state.Stage='running'; $state.Utc=[DateTime]::UtcNow.ToString('o')
        $state | ConvertTo-Json | Set-Content -Encoding UTF8 $status
    }
}

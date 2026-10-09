# Read-only plaintext samples from a natively unlocked, explicitly selected volume.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Z]:$')][string]$MountPoint,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][UInt64[]]$Offsets,
    [ValidateRange(512,1048576)][int]$Length = 65536
)
$ErrorActionPreference = 'Stop'
if (Test-Path $OutputDirectory) { throw 'Output directory already exists' }
$v=Get-BitLockerVolume -MountPoint $MountPoint
if($v.LockStatus -ne 'Unlocked' -or $v.VolumeStatus -ne 'FullyEncrypted'){throw 'Require completed native unlocked encryption'}
$null=New-Item -ItemType Directory $OutputDirectory
$f=[IO.File]::Open("\\.\$MountPoint",[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
$records=@()
try {
    foreach($offset in $Offsets) {
        if($offset % 512 -ne 0 -or $Length % 512 -ne 0 -or $offset -gt [Int64]::MaxValue){throw 'Unaligned or oversized sample'}
        $b=New-Object byte[] $Length
        $null=$f.Seek([Int64]$offset,[IO.SeekOrigin]::Begin)
        if($f.Read($b,0,$b.Length) -ne $b.Length){throw 'Short native sample read'}
        $name="$offset.bin"
        [IO.File]::WriteAllBytes((Join-Path $OutputDirectory $name),$b)
        $records+=@{offset=$offset;length=$Length;file=$name;sha256=(Get-FileHash (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
} finally {$f.Dispose()}
@{schema=1;kind='native-unlocked-logical-sectors';samples=$records} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputDirectory 'samples.json') -Encoding UTF8

# Offline Windows deployment in WinPE. Target MUST be a blank disposable disk.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][int]$DiskNumber,
    [Parameter(Mandatory=$true)][string]$WindowsImage,
    [Parameter(Mandatory=$true)][string]$WinreImage,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [ValidateRange(1,65535)][int]$ImageIndex = 1,
    [ValidateRange(260,4096)][int]$EspMiB = 300,
    [ValidateRange(1024,16384)][int]$RecoveryMiB = 2048
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Invoke-Native([string]$Program, [string[]]$Arguments, [string]$Log) {
    & $Program @Arguments 2>&1 | Out-File $Log
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE; see $Log" }
}
if (!(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')) { throw 'Run this adapter only in WinPE' }
$disk = Get-Disk -Number $DiskNumber
if ($disk.IsBoot -or $disk.IsSystem -or $disk.PartitionStyle -ne 'RAW') { throw 'Target must be a blank non-system disk; no existing disk is erased' }
if (!(Test-Path $WindowsImage) -or !(Test-Path $WinreImage)) { throw 'Explicit Windows and WinRE images are required' }
if ((Get-Item $WinreImage).Length + 512MB -gt ($RecoveryMiB * 1MB)) { throw 'Recovery partition lacks 512 MiB servicing headroom' }
if ($disk.Size -lt (32GB + ($EspMiB + $RecoveryMiB + 20) * 1MB)) { throw 'Disk is too small for the requested layout' }
if (Test-Path $EvidenceDirectory) { throw 'Evidence directory already exists' }
$null = New-Item -ItemType Directory $EvidenceDirectory
foreach ($letter in @('S','W','T')) {
    if (Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue) { throw "Drive $letter is already in use" }
}
$null = Initialize-Disk -Number $DiskNumber -PartitionStyle GPT
$esp = New-Partition -DiskNumber $DiskNumber -Size ($EspMiB * 1MB) -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -DriveLetter S
$null = $esp | Format-Volume -FileSystem FAT32 -NewFileSystemLabel SYSTEM -Confirm:$false
$null = New-Partition -DiskNumber $DiskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
$available = (Get-Disk -Number $DiskNumber).LargestFreeExtent
$windowsSize = [math]::Floor(($available - $RecoveryMiB * 1MB - 1MB) / 1MB) * 1MB
if ($windowsSize -lt 32GB) { throw 'Target lacks space for a 32 GiB Windows partition' }
$windows = New-Partition -DiskNumber $DiskNumber -Size $windowsSize -DriveLetter W
$null = $windows | Format-Volume -FileSystem NTFS -NewFileSystemLabel Windows -Confirm:$false
$recovery = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -DriveLetter T -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
$null = $recovery | Format-Volume -FileSystem NTFS -NewFileSystemLabel Recovery -Confirm:$false
Invoke-Native dism @('/Apply-Image', "/ImageFile:$WindowsImage", "/Index:$ImageIndex", '/ApplyDir:W:\', '/CheckIntegrity') "$EvidenceDirectory\dism.log"
Invoke-Native bcdboot @('W:\Windows','/s','S:','/f','UEFI') "$EvidenceDirectory\bcdboot.log"
$null = New-Item -ItemType Directory 'T:\Recovery\WindowsRE' -Force
Copy-Item $WinreImage 'T:\Recovery\WindowsRE\winre.wim'
Invoke-Native 'W:\Windows\System32\reagentc.exe' @('/setreimage','/path','T:\Recovery\WindowsRE','/target','W:\Windows') "$EvidenceDirectory\reagentc-set.log"
"select disk $DiskNumber`nselect partition $($recovery.PartitionNumber)`ngpt attributes=0x8000000000000001" | Set-Content "$EvidenceDirectory\recovery.diskpart" -Encoding ASCII
Invoke-Native diskpart @('/s',"$EvidenceDirectory\recovery.diskpart") "$EvidenceDirectory\recovery-attributes.log"
@{
    schema = 1; profile = 'windows-system-staging'; diskNumber = $DiskNumber
    windowsImageSha256 = (Get-FileHash $WindowsImage -Algorithm SHA256).Hash
    winreImageSha256 = (Get-FileHash $WinreImage -Algorithm SHA256).Hash
    imageIndex = $ImageIndex
    evidence = @{ offlineApplied = $true; efiFilesInstalled = $true; winrePathRegistered = $true; encrypted = $false; firmwareBoot = $false; winreBoot = $false; tpmUnseal = $false }
} | ConvertTo-Json -Depth 5 | Set-Content "$EvidenceDirectory\manifest.json" -Encoding UTF8

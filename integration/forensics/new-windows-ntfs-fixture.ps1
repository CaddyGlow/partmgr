param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$UploadBase = '',
    [int]$ReuseAttempts = 256,
    [int]$RolloverWrites = 0,
    [switch]$MarkDirty
)
# Guest-only fixture creation. Every device write is restricted to a newly
# created private fixed VHD resolved through its exact owned image path.
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'fixture output directory already exists' }
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
$image = Join-Path $OutputDirectory 'fixture.vhd'
$commands = Join-Path $OutputDirectory 'diskpart.txt'
$attached = $false
$native = [ordered]@{
    version=1; profile='windows-created-private-ntfs-known-operations-v1'
    started_utc=[DateTime]::UtcNow.ToString('o'); os=[Environment]::OSVersion.VersionString
    powershell=$PSVersionTable.PSVersion.ToString(); runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    operations=@(); files=@(); diskpart=@(); creation_passed=$false; library_qualification_passed=$false
    consistency='private filesystem; all test handles closed and native volume dismounted before VHD detach; no live-media capture claim'
    stability='closed detached private fixed-VHD and copied raw artifacts; keep artifacts immutable during deferred analysis'
}
function Invoke-Diskpart([string[]]$Lines) {
    $Lines | Set-Content -LiteralPath $commands -Encoding ASCII
    $result = & diskpart.exe /s $commands 2>&1
    $code = $LASTEXITCODE
    $native.diskpart += [ordered]@{commands=$Lines; exit_code=$code; output=($result -join "`n")}
    if ($code -ne 0) { throw "owned diskpart command failed: $code" }
}
function Native-Command([string]$Exe,[string[]]$Arguments) {
    $text = & $Exe @Arguments 2>&1
    $code = $LASTEXITCODE
    $native.operations += [ordered]@{command=$Exe; arguments=$Arguments; exit_code=$code; output=($text -join "`n"); utc=[DateTime]::UtcNow.ToString('o')}
    if ($code -ne 0) { throw "native fixture command failed: $Exe $Arguments ($code)" }
    return ($text -join "`n")
}
function File-Fact([string]$Path,[string]$Kind) {
    $id = & fsutil.exe file queryfileid $Path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "native file ID query failed: $Path" }
    $match = [regex]::Match(($id -join "`n"),'0x([0-9a-fA-F]{16,32})')
    if (-not $match.Success) { throw 'native file ID response not recognized' }
    $hex = $match.Groups[1].Value
    $raw = [Convert]::ToUInt64($hex.Substring($hex.Length-16),16)
    return [ordered]@{kind=$Kind; relative_name=$Path.Substring(3); native_id_hex=$hex; record=($raw -band [UInt64]281474976710655); sequence=($raw -shr 48); length=(Get-Item -LiteralPath $Path).Length; sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function Write-Pattern([string]$Path,[int]$Length,[int]$Seed) {
    $bytes = New-Object byte[] $Length
    for ($n=0;$n -lt $Length;$n++) { $bytes[$n]=[byte](($n*17+$Seed)%251) }
    [IO.File]::WriteAllBytes($Path,$bytes)
}
function Copy-Range([string]$InputPath,[string]$OutputPath,[long]$Offset,[long]$Length) {
    $inputStream=[IO.File]::Open($InputPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $outputStream=[IO.File]::Open($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {
        [void]$inputStream.Seek($Offset,[IO.SeekOrigin]::Begin)
        $buffer=New-Object byte[] (1024*1024); $remaining=$Length
        while ($remaining -gt 0) { $take=[int][Math]::Min($remaining,$buffer.Length);$read=$inputStream.Read($buffer,0,$take);if($read -le 0){throw 'short closed artifact copy'};$outputStream.Write($buffer,0,$read);$remaining-=$read }
        $outputStream.Flush($true)
    } finally { $outputStream.Dispose();$inputStream.Dispose() }
}
function Upload([string]$Path,[string]$Name) {
    if (-not $UploadBase) { return }
    $request=[Net.HttpWebRequest]::Create($UploadBase.TrimEnd('/')+'/'+$Name)
    $request.Method='PUT';$request.ContentLength=(Get-Item -LiteralPath $Path).Length
    $request.AllowWriteStreamBuffering=$false;$request.Timeout=600000;$request.ReadWriteTimeout=600000
    $inputStream=[IO.File]::OpenRead($Path)
    try { $outputStream=$request.GetRequestStream();try{$inputStream.CopyTo($outputStream)}finally{$outputStream.Dispose()};$response=$request.GetResponse();$response.Dispose() } finally {$inputStream.Dispose()}
}
try {
    Invoke-Diskpart @("create vdisk file=`"$image`" maximum=64 type=fixed","select vdisk file=`"$image`"",'attach vdisk')
    $disk=Get-DiskImage -ImagePath $image | Get-Disk
    if (-not $disk -or $disk.Size -ne 64MB -or $disk.Number -eq 0) { throw 'new private VHD disk ownership/size was not established' }
    $attached=$true
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop | Out-Null
    $partition=New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
    $volume=Format-Volume -Partition $partition -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel PMFORENSICS -Confirm:$false -ErrorAction Stop
    $drive=([string]$partition.DriveLetter)+':'
    $root=$drive+'\'
    $native.disk_number=$disk.Number;$native.logical_sector_size=$disk.LogicalSectorSize;$native.disk_bytes=$disk.Size
    $native.partition_offset=$partition.Offset;$native.partition_bytes=$partition.Size;$native.cluster_bytes=$volume.AllocationUnitSize
    $null=Native-Command 'fsutil.exe' @('fsinfo','ntfsinfo',$drive)
    $null=Native-Command 'fsutil.exe' @('usn','createjournal','m=8388608','a=1048576',$drive)
    $null=New-Item -ItemType Directory -Path ($root+'reuse')
    Write-Pattern ($root+'live.bin') 131072 7
    [IO.File]::WriteAllBytes(($root+'resident.txt'),[Text.Encoding]::UTF8.GetBytes('native resident forensic payload'))
    Set-Content -LiteralPath ($root+'live.bin') -Stream 'forensic-ads' -Encoding Byte -Value ([Text.Encoding]::UTF8.GetBytes('native ADS exact bytes'))
    $adsBytes=[byte[]](Get-Content -LiteralPath ($root+'live.bin') -Stream 'forensic-ads' -Encoding Byte -Raw)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$adsHash=([BitConverter]::ToString($sha.ComputeHash($adsBytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    $native.ads=[ordered]@{base='live.bin';name='forensic-ads';length=22;sha256=$adsHash}
    $compressible=New-Object byte[] 262144
    for($n=0;$n -lt $compressible.Length;$n++){$compressible[$n]=[byte](65+($n%3))}
    [IO.File]::WriteAllBytes(($root+'compressed.bin'),$compressible)
    $null=Native-Command 'compact.exe' @('/c','/i','/q',($root+'compressed.bin'))
    if (-not ((Get-Item -LiteralPath ($root+'compressed.bin')).Attributes -band [IO.FileAttributes]::Compressed)) {throw 'native NTFS compression flag was not observed'}
    Write-Pattern ($root+'sparse.bin') 32768 19
    $null=Native-Command 'fsutil.exe' @('sparse','setflag',($root+'sparse.bin'))
    $null=Native-Command 'fsutil.exe' @('sparse','setrange',($root+'sparse.bin'),'4096','8192')
    [IO.File]::WriteAllBytes(($root+'created.txt'),[Text.Encoding]::UTF8.GetBytes('created'))
    [IO.File]::AppendAllText(($root+'created.txt'),' then extended',[Text.Encoding]::ASCII)
    Rename-Item -LiteralPath ($root+'created.txt') -NewName 'renamed.txt'
    Write-Pattern ($root+'reuse-victim.bin') 8192 31
    $victim=File-Fact ($root+'reuse-victim.bin') 'deleted-before-record-reuse-search'
    Remove-Item -LiteralPath ($root+'reuse-victim.bin') -Force
    $reused=$null
    for($attempt=0;$attempt -lt $ReuseAttempts;$attempt++){
        $path=$root+('reuse\r{0:D4}.bin' -f $attempt)
        Write-Pattern $path 512 ($attempt%251)
        $fact=File-Fact $path 'record-reuse-search'
        if($fact.record -eq $victim.record -and $fact.sequence -ne $victim.sequence){$reused=$fact;break}
    }
    $native.reuse=[ordered]@{victim=$victim;matching_current_record=$reused;attempts_completed=([Math]::Min($attempt+1,$ReuseAttempts));record_reuse_observed=($null -ne $reused)}
    if($RolloverWrites -gt 0){
        $null=Native-Command 'fsutil.exe' @('usn','createjournal','m=1048576','a=262144',$drive)
        $native.rollover_query_before=Native-Command 'fsutil.exe' @('usn','queryjournal',$drive)
        $rolloverPath=$root+'rollover.bin'
        [IO.File]::WriteAllBytes($rolloverPath,[byte[]]@())
        for($n=0;$n -lt $RolloverWrites;$n++){[IO.File]::AppendAllText($rolloverPath,'x',[Text.Encoding]::ASCII)}
        $native.rollover_writes=$RolloverWrites
        Start-Sleep -Seconds 3
        $native.rollover_query_after=Native-Command 'fsutil.exe' @('usn','queryjournal',$drive)
    }
    Write-Pattern ($root+'deleted-preserved.bin') 8192 47
    $native.deleted_preserved=File-Fact ($root+'deleted-preserved.bin') 'deleted-last-no-further-file-creation'
    Remove-Item -LiteralPath ($root+'deleted-preserved.bin') -Force
    foreach($name in @('live.bin','resident.txt','compressed.bin','sparse.bin','renamed.txt')) {$native.files+=File-Fact ($root+$name) 'live'}
    $native.usn_query=Native-Command 'fsutil.exe' @('usn','queryjournal',$drive)
    $journalText=& fsutil.exe usn readjournal $drive csv 2>&1
    if($LASTEXITCODE -ne 0){throw 'native USN oracle export failed'}
    $journalText | Set-Content -LiteralPath (Join-Path $OutputDirectory 'usn-native.csv') -Encoding UTF8
    $native.mark_dirty_requested=[bool]$MarkDirty
    if($MarkDirty){$null=Native-Command 'fsutil.exe' @('dirty','set',$drive)}
    $native.dirty_query=Native-Command 'fsutil.exe' @('dirty','query',$drive)
    $null=Native-Command 'fsutil.exe' @('volume','dismount',$drive)
    Invoke-Diskpart @("select vdisk file=`"$image`"",'detach vdisk')
    $attached=$false
    if((Get-DiskImage -ImagePath $image).Attached){throw 'fixture remains attached'}
    $native.closed_utc=[DateTime]::UtcNow.ToString('o')
    Copy-Range $image (Join-Path $OutputDirectory 'disk.dd') 0 $disk.Size
    Copy-Range $image (Join-Path $OutputDirectory 'volume.dd') $partition.Offset $partition.Size
    $native.artifacts=@()
    $prefix=Split-Path -Leaf $OutputDirectory
    [IO.File]::Copy($PSCommandPath,(Join-Path $OutputDirectory 'runner.ps1'),$false)
    foreach($name in @('fixture.vhd','disk.dd','volume.dd','usn-native.csv','runner.ps1')){
        $path=Join-Path $OutputDirectory $name
        $native.artifacts += [ordered]@{name=$name;host_name=($prefix+'-'+$name);length=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();hash_domain=$(if($name -eq 'fixture.vhd'){'original_fixed_vhd_container_bytes'}elseif($name -eq 'disk.dd'){'logical_disk_bytes'}elseif($name -eq 'volume.dd'){'selected_ntfs_volume_bytes'}elseif($name -eq 'runner.ps1'){'fixture_creation_script_bytes'}else{'native_fsutil_oracle_export_bytes'})}
        Upload $path ($prefix+'-'+$name)
    }
    $native.creation_passed=$true
} catch {
    $native.creation_error=[ordered]@{type=$_.Exception.GetType().FullName;message=$_.Exception.Message;stack=$_.ScriptStackTrace}
} finally {
    if($attached){try{Invoke-Diskpart @("select vdisk file=`"$image`"",'detach vdisk');$attached=$false}catch{$native.cleanup_error=$_.Exception.Message}}
    $native.finished_utc=[DateTime]::UtcNow.ToString('o')
    $receipt=Join-Path $OutputDirectory 'creation.json'
    $json=$native | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($receipt,$json,(New-Object Text.UTF8Encoding($false)))
    Upload $receipt ((Split-Path -Leaf $OutputDirectory)+'-creation.json')
    $json | Out-Host
}
if(-not $native.creation_passed){exit 1}

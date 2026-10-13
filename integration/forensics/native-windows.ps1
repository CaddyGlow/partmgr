param(
    [Parameter(Mandatory=$true)][string]$TestExe,
    [Parameter(Mandatory=$true)][string]$Fixture,
    [Parameter(Mandatory=$true)][string]$FixtureSha256,
    [Parameter(Mandatory=$true)][string]$BinarySha256,
    [Parameter(Mandatory=$true)][string]$Receipt
)
# Run only in a disposable elevated Windows test guest. Every write targets the
# newly created private VHD, resolved back to its disk through its owned image path.
$ErrorActionPreference = 'Stop'
$directory = Join-Path ([IO.Path]::GetTempPath()) ('partmgr-native-' + [Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
$image = Join-Path $directory 'fat-partition.vhd'
$raw = Join-Path $directory 'fat-partition.dd'
$commands = Join-Path $directory 'diskpart.txt'
$attached = $false
$created = $false
$native = [ordered]@{
    version = 1; profile = 'disposable-windows-partmgr-readonly-vhd'
    started_utc = [DateTime]::UtcNow.ToString('o')
    os = [Environment]::OSVersion.VersionString
    powershell = $PSVersionTable.PSVersion.ToString()
    backend = 'partmgr-raw-native-device-equivalence'
    runner_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    expected_fixture_sha256 = $FixtureSha256.ToLowerInvariant()
    expected_binary_sha256 = $BinarySha256.ToLowerInvariant()
    fixture_hash_domain = 'original_raw_dd_file_bytes'
    container_hash_domain = 'original_fixed_vhd_container_bytes'
    logical_hash_domain = 'logical_disk_bytes_from_native_physical_device'
    fixture_bytes = 8 * 1024 * 1024
    diskpart = @(); passed = $false
}
function Invoke-OwnedDiskpart([string[]]$Lines) {
    $Lines | Set-Content -LiteralPath $commands -Encoding ASCII
    $result = & diskpart.exe /s $commands 2>&1
    $exit = $LASTEXITCODE
    $native.diskpart += [ordered]@{ commands = $Lines; exit_code = $exit; output = ($result -join "`n") }
    if ($exit -ne 0) { throw "diskpart failed with exit $exit" }
}
function Get-LogicalHash([string]$Device, [long]$Length) {
    $stream = [IO.File]::Open($Device, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $digest = [Security.Cryptography.SHA256]::Create()
    try {
        $buffer = New-Object byte[] (64 * 1024)
        [long]$remaining = $Length
        while ($remaining -gt 0) {
            $take = [int][Math]::Min($remaining, $buffer.Length)
            $read = $stream.Read($buffer, 0, $take)
            if ($read -le 0) { throw "short logical device read: $remaining bytes unavailable" }
            [void]$digest.TransformBlock($buffer, 0, $read, $buffer, 0)
            $remaining -= $read
        }
        [void]$digest.TransformFinalBlock([byte[]]@(), 0, 0)
        return ([BitConverter]::ToString($digest.Hash)).Replace('-', '').ToLowerInvariant()
    } finally { $digest.Dispose(); $stream.Dispose() }
}
# Metadata-only native queries avoid depending on MSFT_Disk's optional visibility
# of a very small MBR/FAT VHD. No write is used to establish write protection.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class PartmgrOwnedDiskProbe {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code,
        IntPtr input, uint inputLength, byte[] output, uint outputLength,
        out uint returned, IntPtr overlapped);
    public long Size;
    public uint LogicalSectorSize;
    public bool IsReadOnly;
    public bool WritableQuerySucceeded;
    public int WritableQueryError;
    public bool AttributesQuerySucceeded;
    public ulong Attributes;
    private static byte[] Query(SafeFileHandle handle, uint code, int length) {
        byte[] bytes = new byte[length]; uint returned;
        if (!DeviceIoControl(handle, code, IntPtr.Zero, 0, bytes, (uint)length,
                             out returned, IntPtr.Zero)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        if (returned < length) { throw new IOException("truncated native disk geometry response"); }
        return bytes;
    }
    public static PartmgrOwnedDiskProbe Open(string path) {
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
            PartmgrOwnedDiskProbe probe = new PartmgrOwnedDiskProbe();
            probe.Size = BitConverter.ToInt64(Query(stream.SafeFileHandle, 0x7405c, 8), 0);
            probe.LogicalSectorSize = BitConverter.ToUInt32(Query(stream.SafeFileHandle, 0x70000, 24), 20);
            uint returned;
            probe.WritableQuerySucceeded = DeviceIoControl(stream.SafeFileHandle, 0x70024,
                IntPtr.Zero, 0, new byte[0], 0, out returned, IntPtr.Zero);
            probe.WritableQueryError = probe.WritableQuerySucceeded ? 0 : Marshal.GetLastWin32Error();
            byte[] attributes = new byte[16];
            probe.AttributesQuerySucceeded = DeviceIoControl(stream.SafeFileHandle, 0x700f0,
                IntPtr.Zero, 0, attributes, 16, out returned, IntPtr.Zero);
            if (probe.AttributesQuerySucceeded && returned >= 16) {
                probe.Attributes = BitConverter.ToUInt64(attributes, 8);
            }
            probe.IsReadOnly = (!probe.WritableQuerySucceeded && probe.WritableQueryError == 19)
                || (probe.AttributesQuerySucceeded && (probe.Attributes & 2) != 0);
            return probe;
        }
    }
}
'@
function Resolve-OwnedDisk {
    $ownedImage = Get-DiskImage -ImagePath $image -ErrorAction Stop
    if (-not $ownedImage.Attached) { throw 'owned VHD attachment is not visible' }
    $path = [string]$ownedImage.DevicePath
    $match = [regex]::Match($path, '^\\\\\.\\PhysicalDrive([0-9]+)$')
    if (-not $match.Success) { throw "owned image did not identify an exact physical device path: $path" }
    $number = [int]$match.Groups[1].Value
    $probe = [PartmgrOwnedDiskProbe]::Open($path)
    $provider = $null
    try { $provider = $ownedImage | Get-Disk -ErrorAction Stop }
    catch { $native.storage_provider_discovery_error = $_.Exception.Message }
    $native.device_resolution = [ordered]@{
        owned_image_path = $image; image_attached = $ownedImage.Attached
        image_device_path = $path; disk_number = $number
        native_capacity = $probe.Size; native_logical_sector_size = $probe.LogicalSectorSize
        native_is_read_only = $probe.IsReadOnly
        ioctl_disk_is_writable_succeeded = $probe.WritableQuerySucceeded
        ioctl_disk_is_writable_error = $probe.WritableQueryError
        ioctl_disk_attributes_available = $probe.AttributesQuerySucceeded
        ioctl_disk_attributes = $probe.Attributes
        msft_disk_visible = ($null -ne $provider)
    }
    if ($probe.Size -ne $native.fixture_bytes) { throw 'owned native device capacity differs from fixture profile' }
    return [pscustomobject]@{ Number = $number; Size = $probe.Size; LogicalSectorSize = $probe.LogicalSectorSize; IsReadOnly = $probe.IsReadOnly; DevicePath = $path }
}

try {
    $binaryHash = (Get-FileHash -LiteralPath $TestExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $native.binary_sha256 = $binaryHash
    if ($binaryHash -ne $native.expected_binary_sha256) { throw 'test binary hash differs from host-staged expected hash' }
    [IO.File]::Copy((Resolve-Path -LiteralPath $Fixture).Path, $raw, $false)
    $fixtureBefore = (Get-FileHash -LiteralPath $raw -Algorithm SHA256).Hash.ToLowerInvariant()
    $native.fixture_sha256_before = $fixtureBefore
    if ($fixtureBefore -ne $native.expected_fixture_sha256 -or (Get-Item -LiteralPath $raw).Length -ne $native.fixture_bytes) { throw 'raw fixture hash or length differs from host-staged expected artifact' }
    Invoke-OwnedDiskpart @("create vdisk file=`"$image`" maximum=8 type=fixed", "select vdisk file=`"$image`"", 'attach vdisk')
    $created = Test-Path -LiteralPath $image
    $disk = Resolve-OwnedDisk
    if (-not $created -or -not $disk -or $disk.Size -ne $native.fixture_bytes) { throw 'newly created owned VHD was not resolved to expected disk' }
    $attached = $true
    $device = "\\.\PhysicalDrive$($disk.Number)"
    $bytes = [IO.File]::ReadAllBytes($raw)
    $stream = [IO.File]::Open($device, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
    $bytes = $null
    Invoke-OwnedDiskpart @("select vdisk file=`"$image`"", 'detach vdisk', 'attach vdisk readonly')
    $disk = Resolve-OwnedDisk
    $device = "\\.\PhysicalDrive$($disk.Number)"
    $native.device = $device
    $native.logical_sector_size = $disk.LogicalSectorSize
    $native.disk_read_only = $disk.IsReadOnly
    if ($disk.LogicalSectorSize -ne 512 -or -not $disk.IsReadOnly) { throw 'fixture profile requires queried 512-byte logical sectors and a read-only disk' }
    $native.container_sha256_before = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
    $native.logical_sha256_before = Get-LogicalHash $device $native.fixture_bytes
    if ($native.logical_sha256_before -ne $fixtureBefore) { throw 'native logical disk differs from the closed raw fixture before inspection' }
    $env:PARTMGR_TEST_DEVICE = $device
    $env:PARTMGR_TEST_RAW = $raw
    $env:PARTMGR_TEST_SECTOR_SIZE = [string]$disk.LogicalSectorSize
    $testName = 'native_fat_partition_equivalence_for_disposable_device'
    $testOutput = & $TestExe --ignored --exact $testName --nocapture 2>&1
    $native.exit_code = $LASTEXITCODE
    $text = $testOutput -join "`n"
    $native.stdout = $text
    $text | Out-Host
    $native.selected_test_executed = ($text -match 'running 1 test' -and $text.Contains($testName) -and $text -match 'test result: ok. 1 passed; 0 failed')
    $native.fixture_sha256_after = (Get-FileHash -LiteralPath $raw -Algorithm SHA256).Hash.ToLowerInvariant()
    $native.container_sha256_after = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
    $native.logical_sha256_after = Get-LogicalHash $device $native.fixture_bytes
    $native.immutable_fixture_verified = ($native.fixture_sha256_before -eq $native.fixture_sha256_after -and $native.container_sha256_before -eq $native.container_sha256_after -and $native.logical_sha256_before -eq $native.logical_sha256_after -and $native.logical_sha256_after -eq $native.fixture_sha256_after)
    $native.passed = ($native.exit_code -eq 0 -and $native.selected_test_executed -and $native.immutable_fixture_verified)
} catch {
    $native.runner_error = [ordered]@{ type = $_.Exception.GetType().FullName; message = $_.Exception.Message; stack = $_.ScriptStackTrace }
    $native.passed = $false
} finally {
    Remove-Item Env:PARTMGR_TEST_DEVICE -ErrorAction SilentlyContinue
    Remove-Item Env:PARTMGR_TEST_RAW -ErrorAction SilentlyContinue
    Remove-Item Env:PARTMGR_TEST_SECTOR_SIZE -ErrorAction SilentlyContinue
    if ($attached -or $created -or (Test-Path -LiteralPath $image)) {
        try {
            Invoke-OwnedDiskpart @("select vdisk file=`"$image`"", 'detach vdisk')
            if ((Get-DiskImage -ImagePath $image).Attached) { throw 'owned VHD remains attached after cleanup' }
            $attached = $false
        } catch { $native.cleanup_error = $_.Exception.Message; $native.passed = $false; $attached = $true }
    }
    if (-not $attached) {
        try { Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop; $native.owned_fixture_removed = $true }
        catch { $native.cleanup_error = $_.Exception.Message; $native.passed = $false }
    }
    $native.finished_utc = [DateTime]::UtcNow.ToString('o')
    # Never replace a prior receipt, including one from a failed attempt.
    $receiptStream = [IO.File]::Open($Receipt, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $encoded = [Text.UTF8Encoding]::new($false).GetBytes(($native | ConvertTo-Json -Depth 10) + "`n")
        $receiptStream.Write($encoded, 0, $encoded.Length)
    } finally { $receiptStream.Dispose() }
}
if (-not $native.passed) { throw 'Partmgr native Windows receipt did not qualify; inspect the exclusive receipt' }
Write-Output "Partmgr native Windows qualification passed; receipt=$Receipt"

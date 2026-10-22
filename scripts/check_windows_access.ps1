param([int]$Port, [string]$ResultFile, [int]$TimeoutSeconds = 1200, [switch]$OpenBrowser)
$ErrorActionPreference = 'Stop'
function Read-LocalUrl([string]$Path) {
    $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$Port$Path")
    $request.Proxy = $null
    $request.Timeout = 1500
    $request.ReadWriteTimeout = 1500
    $request.KeepAlive = $false
    $response = $request.GetResponse()
    try {
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $response.Dispose() }
}
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
while ([DateTime]::UtcNow -lt $deadline) {
    try {
        $health = (Read-LocalUrl '/api/v1/health') | ConvertFrom-Json
        if ($health.status -eq 'ok' -and $health.worker_running) {
            $page = Read-LocalUrl '/'
            $asset = Read-LocalUrl '/assets/app.js'
            if ($page.Contains('OHScanner') -and $asset.Length -gt 1000) {
                @{status='passed';url="http://localhost:$Port";worker_running=$true;homepage=$true;static_asset=$true} |
                    ConvertTo-Json | Set-Content -LiteralPath $ResultFile -Encoding UTF8
                Write-Host "Windows browser ready: http://localhost:$Port (Windows health, page and assets verified)" -ForegroundColor Green
                if ($OpenBrowser) { Start-Process "http://localhost:$Port" }
                exit 0
            }
        }
    } catch { }
    Start-Sleep -Milliseconds 300
}
@{status='failed';url="http://localhost:$Port";reason='Windows host readiness timeout; WSL-local health alone is insufficient'} |
    ConvertTo-Json | Set-Content -LiteralPath $ResultFile -Encoding UTF8
Write-Host "Windows cannot access http://localhost:$Port. Check WSL localhost forwarding and port reservations." -ForegroundColor Red
exit 1

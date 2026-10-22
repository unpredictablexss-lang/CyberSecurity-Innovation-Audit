[CmdletBinding()]
param(
    [ValidateRange(1024,65535)][int]$Port = 18765,
    [string]$Distribution = 'Ubuntu',
    [switch]$SetupOnly,
    [switch]$SmokeTest,
    [switch]$StartOnly
)
$ErrorActionPreference = 'Stop'
if (@($SetupOnly, $SmokeTest, $StartOnly).Where({$_}).Count -gt 1) { throw 'Choose SetupOnly, SmokeTest or StartOnly.' }
function Test-LocalPort([int]$Candidate) {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Candidate)
    try { $listener.Start(); return $true } catch { return $false } finally { $listener.Stop() }
}
if (-not $SetupOnly -and -not (Test-LocalPort $Port)) {
    throw "Windows port $Port is occupied or reserved. The script will not change it automatically. Free the port, or explicitly choose another port with -Port."
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL is unavailable. Enable Windows Subsystem for Linux and virtualization, reboot, then rerun.'
}
$distros = @(& wsl.exe --list --quiet 2>$null) | ForEach-Object { ($_ -replace "`0", '').Trim() }
if ($distros -notcontains $Distribution) {
    Write-Host "Installing WSL2 distribution $Distribution. Windows may require administrator access and a restart."
    & wsl.exe --install --distribution $Distribution --no-launch
    if ($LASTEXITCODE -ne 0) { throw 'WSL installation did not finish. Restart Windows if requested, then rerun this script.' }
    $distros = @(& wsl.exe --list --quiet 2>$null) | ForEach-Object { ($_ -replace "`0", '').Trim() }
    if ($distros -notcontains $Distribution) {
        Write-Host 'WSL installation requires a restart. Restart Windows, then run deploy-windows.cmd again.'
        exit 3010
    }
}
if (-not $StartOnly) {
    & (Join-Path $PSScriptRoot 'scripts\prepare_windows_node.ps1') -Distribution $Distribution
}
$deployArgs = @('-d', $Distribution, '--cd', $PSScriptRoot, '--exec', 'bash', './scripts/deploy_windows_wsl.sh', '--port', "$Port")
if ($SetupOnly) { $deployArgs += '--setup-only' }
if ($SmokeTest) { $deployArgs += '--smoke-test' }
if ($StartOnly) { $deployArgs += '--start-only' }
Write-Host "Preparing OHScanner in $Distribution (install/build/start). The browser opens only after http://localhost:$Port is verified. Ctrl+C stops the service."
$monitor = $null
$resultFile = Join-Path ([System.IO.Path]::GetTempPath()) ('ohscanner-windows-ready-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    if (-not $SetupOnly) {
        $monitorScript = (Join-Path $PSScriptRoot 'scripts\check_windows_access.ps1').Replace("'", "''")
        $resultLiteral = $resultFile.Replace("'", "''")
        $monitorCommand = "& '$monitorScript' -Port $Port -ResultFile '$resultLiteral'"
        if (-not $SmokeTest) { $monitorCommand += ' -OpenBrowser' }
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($monitorCommand))
        $monitor = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encodedCommand -WindowStyle Hidden -PassThru
    }
    & wsl.exe @deployArgs
    $deployExit = $LASTEXITCODE
    if ($SmokeTest -and $deployExit -eq 0) {
        if (-not (Test-Path -LiteralPath $resultFile) -or (Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json).status -ne 'passed') {
            throw "WSL self-test finished, but Windows browser access was not verified. See $resultFile"
        }
        Write-Host "Windows host self-test passed: http://localhost:$Port"
    }
} finally {
    if ($monitor -and -not $monitor.HasExited) { Stop-Process -Id $monitor.Id -ErrorAction SilentlyContinue }
}
exit $deployExit

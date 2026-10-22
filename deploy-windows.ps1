[CmdletBinding()]
param(
    [ValidateRange(1024,65535)][int]$Port = 8765,
    [string]$Distribution = 'Ubuntu',
    [switch]$SetupOnly,
    [switch]$SmokeTest
)
$ErrorActionPreference = 'Stop'
if ($SetupOnly -and $SmokeTest) { throw 'Choose SetupOnly or SmokeTest.' }
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
$deployArgs = @('-d', $Distribution, '--cd', $PSScriptRoot, '--exec', 'bash', './scripts/deploy_windows_wsl.sh', '--port', "$Port")
if ($SetupOnly) { $deployArgs += '--setup-only' }
if ($SmokeTest) { $deployArgs += '--smoke-test' }
Write-Host "Starting OHScanner in $Distribution; browse http://localhost:$Port after startup. Ctrl+C stops the service."
& wsl.exe @deployArgs
exit $LASTEXITCODE

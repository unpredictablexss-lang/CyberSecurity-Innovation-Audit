[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RepoDir,

    [Parameter(Mandatory = $true)]
    [string] $Repository,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $Commit,

    [Parameter(Mandatory = $true)]
    [string] $JsonOut,

    [Parameter(Mandatory = $true)]
    [string] $MdOut,

    [string[]] $Include = @()
)

$ErrorActionPreference = 'Stop'
$scannerRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$repoPath = (Resolve-Path $RepoDir).Path

# The CVE-specific rule pack is explicitly selected because it is registered
# but remains disabled in the shared default catalog pending owner admission.
$detectors = @(
    'ohscanner.cpp.bounds',
    'ohscanner.cpp.integer_bounds',
    'ohscanner.cpp.resource_lifetime',
    'ohscanner.known_disclosed_cves'
)
$ohscanArgs = @(
    '-m', 'src.cli', 'ohscan-run',
    '--repo-dir', $repoPath,
    '--repository', $Repository,
    '--commit', $Commit,
    '--json-out', $JsonOut,
    '--md-out', $MdOut
)
foreach ($detector in $detectors) {
    $ohscanArgs += @('--detector', $detector)
}
foreach ($path in $Include) {
    $ohscanArgs += @('--include', $path)
}

Push-Location $scannerRoot
try {
    & python @ohscanArgs
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $exitCode

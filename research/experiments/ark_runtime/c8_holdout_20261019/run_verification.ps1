param(
    [string]$Python = 'C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe',
    [string]$DependencyPath = 'E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps',
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..\..\')).Path
$LogDir = Join-Path $PSScriptRoot 'logs'
$CompileInput = Join-Path $PSScriptRoot 'compile_input'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Quote-Arg([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"') + '"'
}

function Invoke-Measured {
    param(
        [string]$Name,
        [string[]]$ArgumentList,
        [hashtable]$Environment = @{},
        [bool]$CompileAll = $false
    )

    $stdoutPath = Join-Path $LogDir ($Name + '.stdout.txt')
    $stderrPath = Join-Path $LogDir ($Name + '.stderr.txt')
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Python
    $psi.Arguments = (($ArgumentList | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.WorkingDirectory = $Root
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['PYTHONPATH'] = '.;' + $DependencyPath
    $psi.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    if ($CompileAll) {
        $psi.EnvironmentVariables.Remove('PYTHONDONTWRITEBYTECODE') | Out-Null
        $psi.EnvironmentVariables.Remove('PYTHONPYCACHEPREFIX') | Out-Null
    }
    $envOverrides = [ordered]@{
        PYTHONPATH = '.;' + $DependencyPath
    }
    if (-not $CompileAll) { $envOverrides['PYTHONDONTWRITEBYTECODE'] = '1' }
    foreach ($key in $Environment.Keys) {
        $psi.EnvironmentVariables[$key] = [string]$Environment[$key]
        $envOverrides[$key] = [string]$Environment[$key]
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $started = [DateTime]::UtcNow
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $peakBytes = 0L
    $timedOut = $false
    while (-not $process.HasExited) {
        if ($watch.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
            $timedOut = $true
            try { $process.Kill($true) } catch { try { $process.Kill() } catch {} }
            break
        }
        $process.Refresh()
        if ($process.PeakWorkingSet64 -gt $peakBytes) { $peakBytes = $process.PeakWorkingSet64 }
        Start-Sleep -Milliseconds 2
    }
    [void]$process.WaitForExit()
    $watch.Stop()
    $process.Refresh()
    if ($process.PeakWorkingSet64 -gt $peakBytes) { $peakBytes = $process.PeakWorkingSet64 }
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    [IO.File]::WriteAllText($stdoutPath, $stdout, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($stderrPath, $stderr, [Text.UTF8Encoding]::new($false))
    $peakKib = if ($peakBytes -gt 0) { [math]::Round($peakBytes / 1KB, 3) } else { $null }
    return [pscustomobject][ordered]@{
        name = $Name
        argv = @($Python) + $ArgumentList
        cwd = $Root
        environment_overrides = $envOverrides
        started_at_utc = $started.ToString('o')
        finished_at_utc = [DateTime]::UtcNow.ToString('o')
        wall_seconds = [math]::Round($watch.Elapsed.TotalSeconds, 6)
        peak_working_set_kib = $peakKib
        rss_measurement = 'Process.PeakWorkingSet64 sampled every 2 ms and refreshed after exit; Windows working-set high-water, not cross-platform ru_maxrss'
        timeout_seconds = $TimeoutSeconds
        timed_out = $timedOut
        returncode = if ($timedOut) { 124 } else { $process.ExitCode }
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        stdout_sha256 = (Get-FileHash -LiteralPath $stdoutPath -Algorithm SHA256).Hash.ToLowerInvariant()
        stderr_sha256 = (Get-FileHash -LiteralPath $stderrPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

if (-not $CompileInput.StartsWith($PSScriptRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "compile input escaped review directory: $CompileInput"
}
if (Test-Path -LiteralPath $CompileInput) {
    Remove-Item -LiteralPath $CompileInput -Recurse -Force
}
New-Item -ItemType Directory -Path $CompileInput | Out-Null
$compileSources = @()
foreach ($baseRel in @('src','tests','research/experiments/ark_runtime/c8_holdout_20261019','research/methods/ark_runtime/rule_freeze_0.7.0')) {
    $base = Join-Path $Root $baseRel
    if (-not (Test-Path -LiteralPath $base)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $base -Recurse -File -Filter *.py) {
        if ($file.FullName.StartsWith($CompileInput, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $relative = [IO.Path]::GetRelativePath($Root, $file.FullName)
        $destination = Join-Path $CompileInput $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
        New-Item -ItemType Directory -Force -Path (Join-Path (Split-Path -Parent $destination) '__pycache__') | Out-Null
        $compileSources += [ordered]@{
            source = $relative
            source_sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            copy = $relative
            copy_sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}
$compileManifestPath = Join-Path $PSScriptRoot 'compile_input_manifest_20261019.json'
[ordered]@{
    schema = 'compileall-byte-identical-input-v1'
    reason = 'PYTHONPYCACHEPREFIX mirrors absolute paths and exceeded Windows path limits for this non-ASCII checkout; compileall therefore runs on byte-identical copies rooted under the allowed output directory.'
    files = $compileSources
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $compileManifestPath -Encoding utf8

$docsBudgetScript = 'E:\网安\CyberSecurity-Innovation-Audit\scripts\check_docs_context_budget.py'
$commands = @(
    [pscustomobject]@{
        name = 'review_pinned_artifacts'
        args = @('research/experiments/ark_runtime/c8_holdout_20261019/review_pinned_artifacts.py')
        compile = $false
    },
    [pscustomobject]@{
        name = 'ark_runtime_unittest'
        args = @('-m','unittest','discover','-s','tests/detectors/ark_runtime','-t','.','-q')
        compile = $false
    },
    [pscustomobject]@{
        name = 'compileall'
        args = @('-m','compileall','-q','-b','-j','1','research/experiments/ark_runtime/c8_holdout_20261019/compile_input')
        compile = $true
    },
    [pscustomobject]@{
        name = 'docs_context_budget'
        args = @($docsBudgetScript,'--root',$Root)
        compile = $false
    }
)

$results = foreach ($command in $commands) {
    Invoke-Measured -Name $command.name -ArgumentList $command.args -CompileAll $command.compile
}
$pythonVersion = & $Python --version 2>&1
$verification = [ordered]@{
    schema = 'ark-runtime-holdout-review-verification-v1'
    date = '2026-10-19'
    base = [ordered]@{
        commit = (git -C $Root rev-parse HEAD).Trim()
        tree = (git -C $Root rev-parse 'HEAD^{tree}').Trim()
        status = @(git -C $Root status --short)
    }
    reviewed_ref = [ordered]@{
        ref = 'origin/codex/c-line-ark-runtime-replay-20261019'
        commit = (git -C $Root rev-parse 'origin/codex/c-line-ark-runtime-replay-20261019').Trim()
        tree = (git -C $Root rev-parse 'origin/codex/c-line-ark-runtime-replay-20261019^{tree}').Trim()
    }
    python = $pythonVersion
    commands = $results
    compileall = [ordered]@{
        input_manifest = $compileManifestPath
        input_file_count = $compileSources.Count
        byte_identical_copies = ($compileSources | Where-Object { $_.source_sha256 -ne $_.copy_sha256 }).Count -eq 0
        initial_pycacheprefix_probe_error = 'WinError 206 filename or extension is too long; retained under logs/compileall_initial_probe.*'
    }
    docs_budget = [ordered]@{
        script_path = $docsBudgetScript
        script_present_in_base = $false
        root_override = $Root
        note = 'The budget checker is read from the main checkout because this pinned base omits scripts/check_docs_context_budget.py; it validates the worktree root via --root and writes nothing.'
    }
    performance_scope = 'Local static/test/documentation commands only; no repository-scale scan, Worker/API, dynamic Ark runtime or product PoC.'
    token_usage = $null
    token_status = 'not_measured_for_local_subprocess_commands'
    cost_usd = $null
    cost_status = 'not_measured_for_local_subprocess_commands'
    metrics_gate = [ordered]@{
        eligible_for_metrics = $false
        precision = $null
        recall = $null
        zero_fp_fn_claim_allowed = $false
        validated_vulnerability = 0
    }
}
$out = Join-Path $PSScriptRoot 'verification_20261019.json'
$verification | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $out -Encoding utf8
if (Test-Path -LiteralPath $CompileInput) {
    if (-not $CompileInput.StartsWith($PSScriptRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "compile input escaped review directory: $CompileInput"
    }
    Remove-Item -LiteralPath $CompileInput -Recurse -Force
}
Write-Output $out
foreach ($item in $results) {
    Write-Output ("{0}: exit={1} wall={2}s rss={3}KiB" -f $item.name,$item.returncode,$item.wall_seconds,$item.peak_working_set_kib)
}
if ($results | Where-Object { $_.returncode -ne 0 }) { exit 1 }





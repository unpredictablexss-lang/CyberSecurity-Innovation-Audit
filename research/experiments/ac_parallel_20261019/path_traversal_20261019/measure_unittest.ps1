param([Parameter(Mandatory=$true)][string]$Mode)
$ErrorActionPreference = 'Stop'
$root = (Get-Location).Path
$py = 'C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$env:PYTHONPATH = '.;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps'
$common = @('-X','utf8','-m','unittest')
if ($Mode -eq 'final') {
  $argv = $common + @('tests.detectors.test_cpp_path_traversal_detector','-v')
} elseif ($Mode -eq 'legacy7') {
  $argv = $common + @(
    'tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_identity_and_positive_file_operation_controls',
    'tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_fixture_manifest_hashes_and_categories',
    'tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_containment_basename_and_allowlist_controls',
    'tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_no_source_no_sink_and_unrelated_api_are_not_candidates',
    'tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_unresolved_cross_function_and_partial_parse_remain_unknown',
    'tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_candidate_requires_file_sink_not_path_concatenation_alone',
    'tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_budget_and_unexpected_analysis_failures_fail_closed',
    '-v'
  )
} else { throw "unknown mode" }
$dir = Join-Path $root 'research\experiments\ac_parallel_20261019\path_traversal_20261019'
$out = Join-Path $dir ($Mode + '_ps_measured_unittest_stdout.txt')
$err = Join-Path $dir ($Mode + '_ps_measured_unittest_stderr.txt')
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $py -ArgumentList $argv -WorkingDirectory $root -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$p.WaitForExit()
$sw.Stop()
$peak = [int64]$p.PeakWorkingSet64
$manifest = [ordered]@{
  schema_version = 'ohscanner-test-measurement-v1'
  mode = $Mode
  cwd = $root
  python = $py
  argv = $argv
  command = ($py + ' ' + ($argv -join ' '))
  env = @{ PYTHONPATH = $env:PYTHONPATH }
  returncode = $p.ExitCode
  wall_seconds = $sw.Elapsed.TotalSeconds
  max_rss_bytes = $peak
  output_stdout_file = $out
  output_stderr_file = $err
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir ($Mode + '_ps_measured_run_manifest.json')) -Encoding utf8
$manifest | ConvertTo-Json -Depth 5

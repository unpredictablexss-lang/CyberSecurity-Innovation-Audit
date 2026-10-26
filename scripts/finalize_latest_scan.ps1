$ErrorActionPreference='Stop'
$scan='D:\openHarmonyScanner\openharmony-abcd-full-scan-20261018-final'
$out='D:\openHarmonyScanner\openharmony-scan-reports-20261018'
$repo='D:\openHarmonyScanner\CyberSecurity-Innovation-Audit'
while ($true) {
  $s=Get-Content -Raw (Join-Path $scan 'summary.json') | ConvertFrom-Json
  if ($s.processed_count -ge $s.project_count) { break }
  Start-Sleep -Seconds 30
}
python (Join-Path $repo 'scripts\generate_openharmony_scan_reports.py')
$toolRoots=@(
  'C:\Users\DeepSleep\.codex\plugins\cache\openai-primary-runtime\spreadsheets\26.1013.11914\node_modules',
  'C:\Users\DeepSleep\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\node_modules'
)
foreach($root in $toolRoots){ if(Test-Path (Join-Path $root '@oai\artifact-tool')){$env:ARTIFACT_TOOL_ROOT=$root; break} }
node (Join-Path $repo 'scripts\build_openharmony_scan_workbook.mjs') (Join-Path $out 'workbook_data.json') (Join-Path $out '候选结果.xlsx')
if(-not (Test-Path (Join-Path $out '候选结果.xlsx'))){ throw 'workbook missing' }
$dest=Join-Path $repo 'docs\openharmony-full-scan-20261018'
if(Test-Path $dest){ Remove-Item -LiteralPath $dest -Recurse -Force }
New-Item -ItemType Directory -Path $dest | Out-Null
$allowed=@('总览报告.md','漏洞候选分类报告.md','检测器能力与改进报告.md','测试与限制报告.md','分批反思报告.md','交付清单.md','候选结果TOP5000.csv','CWE汇总.csv','检测线汇总.csv','检测器能力.csv','项目结果.csv','失败与受限项目.csv','compact-summary.json','checksums.json','候选结果.xlsx')
foreach($name in $allowed){ Copy-Item -LiteralPath (Join-Path $out $name) -Destination (Join-Path $dest $name) -Force }
$forbidden=git -C $repo status --short --untracked-files=all
$bad=$forbidden | Where-Object { $_ -match '(^|\s|/)(openharmony|\.repo|node_modules)(/|\s|$)|web/dist' }
if($bad){ throw "unsafe staged/untracked paths: $($bad -join '; ')" }
git -C $repo add -- 'scripts/generate_openharmony_scan_reports.py' 'scripts/build_openharmony_scan_workbook.mjs' 'scripts/finalize_latest_scan.ps1' 'docs/openharmony-full-scan-20261018'
git -C $repo commit -m 'test: publish latest OpenHarmony scan reports'
git -C $repo push origin HEAD
Set-Content -LiteralPath (Join-Path $out 'COMPLETE') -Value 'COMPLETE' -Encoding utf8
Set-Content -LiteralPath (Join-Path $out 'READY_FOR_PUSH.json') -Value '{"status":"pushed","branch":"codex/a-line-scanner-regression-20261018","excluded":["openharmony/",".repo/","node_modules","web/dist"]}' -Encoding utf8

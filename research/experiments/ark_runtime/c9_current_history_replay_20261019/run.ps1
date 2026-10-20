param(
    [string]$Python = 'C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe',
    [string]$ArkRepo = 'E:\网安\_oh_targets\arkcompiler_ets_runtime'
)

$ErrorActionPreference = 'Stop'
$env:PYTHONPATH = '.;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONHASHSEED = '0'
$env:PYTHONPYCACHEPREFIX = 'research\experiments\ark_runtime\c9_current_history_replay_20261019\pycache'
$env:GIT_NO_LAZY_FETCH = '1'
$env:GIT_ALLOW_PROTOCOL = ''
$env:GIT_TERMINAL_PROMPT = '0'
$env:GIT_NO_REPLACE_OBJECTS = '1'
$env:OHSCANNER_ARK_REPO = $ArkRepo

& $Python 'research\experiments\ark_runtime\c9_current_history_replay_20261019\measure.py'
exit $LASTEXITCODE

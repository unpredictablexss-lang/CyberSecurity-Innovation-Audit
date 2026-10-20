$ErrorActionPreference = "Stop"
# Run from the exception-guard worktree. These commands do not fetch or mutate Git history.
wsl.exe -e python3 -m unittest tests.detectors.ark_runtime.test_exception_guard.ExceptionGuardSyntheticTests -v
wsl.exe -e python3 -m unittest tests.detectors.ark_runtime.test_exception_guard -v
wsl.exe -e python3 -m unittest discover -s tests/detectors/ark_runtime -t . -p "test_*.py" -v
wsl.exe -e python3 -m compileall -q src tests/detectors/ark_runtime
git diff --check

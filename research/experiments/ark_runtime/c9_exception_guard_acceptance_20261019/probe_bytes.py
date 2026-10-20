from pathlib import Path
paths = [
    Path('/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard/research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/latest09ba_val/src/ohscanner/detectors/ark_runtime/exception_guard.py'),
    Path('/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard/research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/latest_static_09ba5aba_minimal.patch'),
]
for p in paths:
    b = p.read_bytes()
    print(p.name, len(b), repr(b[:80]), 'crlf', b.count(b'\r\n'), 'lf', b.count(b'\n'))

from pathlib import Path
p=Path('/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard/research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/logs/latest_runtime_exception.stdout.txt')
b=p.read_bytes(); print(len(b), repr(b[:80]), b[:4])
for enc in ('utf-8','utf-16','utf-16-le','utf-32'):
    try:
        t=b.decode(enc); print(enc, repr(t[:80]), 'Ran' in t)
    except Exception as e: print(enc, e)

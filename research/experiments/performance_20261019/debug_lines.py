from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
    if i in (50, 106, 204, 214, 284):
        print(i, repr(line))

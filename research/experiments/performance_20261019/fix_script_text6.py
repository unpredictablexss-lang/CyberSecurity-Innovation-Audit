from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
lines = p.read_text(encoding="utf-8").splitlines()
bs = chr(92) + "n"
nl = chr(10)
changed = 0
for i, line in enumerate(lines):
    if line.startswith("def build_context(sources") and bs in line:
        lines[i] = line.replace(bs, nl)
        changed += 1
if changed != 1:
    raise SystemExit(f"expected 1 change, got {changed}")
p.write_text(nl.join(lines) + nl, encoding="utf-8")
print("fixed build_context")

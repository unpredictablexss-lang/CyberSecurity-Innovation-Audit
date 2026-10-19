from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
lines = p.read_text(encoding="utf-8").splitlines()
bs = chr(92) + "n"
nl = chr(10)
prefixes = (
    "    if os.name != \"nt\"",
    "    rows = sorted(rows)",
    "        \"diagnostic_rows\"",
    "                            result[\"source_identity_sha256\"]",
)
changed = 0
for i, line in enumerate(lines):
    if bs in line and line.startswith(prefixes):
        lines[i] = line.replace(bs, nl)
        changed += 1
if changed != 5:
    raise SystemExit(f"expected 5 changed lines, got {changed}")
p.write_text(nl.join(lines) + nl, encoding="utf-8")
print("fixed", changed)

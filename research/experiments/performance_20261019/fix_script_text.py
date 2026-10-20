from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
t = p.read_text(encoding="utf-8")
bs = chr(92)
nl = chr(10)
reps = [
    ("def peak_rss_bytes_for_process(proc) -> int:" + bs + "n    if os.name", "def peak_rss_bytes_for_process(proc) -> int:" + nl + "    if os.name"),
    ("def identity_signature_rows(rows):" + bs + "n    rows", "def identity_signature_rows(rows):" + nl + "    rows"),
    ("def diagnostic_signature_rows(rows):" + bs + "n    rows", "def diagnostic_signature_rows(rows):" + nl + "    rows"),
    ('"diagnostic_signature_sha256": diagnostic_signature(reports)[0],' + bs + 'n        "diagnostic_rows"', '"diagnostic_signature_sha256": diagnostic_signature(reports)[0],' + nl + '        "diagnostic_rows"'),
    ('"invariant": (' + bs + 'n                            result["source_identity_sha256"]', '"invariant": (' + nl + '                            result["source_identity_sha256"]'),
]
for old, new in reps:
    if old not in t:
        raise SystemExit("missing replacement: " + repr(old))
    t = t.replace(old, new)
p.write_text(t, encoding="utf-8")
print("fixed")

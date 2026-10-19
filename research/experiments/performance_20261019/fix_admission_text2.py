from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_admission_audit.py")
t = p.read_text(encoding="utf-8")
t = t.replace('        "- Performance is platform cost on fixed inputs. It is not accuracy, recall or security evidence.",',
'''        "- Performance is platform cost on fixed inputs. It is not accuracy, recall or security evidence.",
        "- Real batch/index cases use the pinned Git commit/tree/blob path. Cache and exact-limit cases use deterministic in-memory fixture identities to isolate frontend/runner behavior; they are not product-source evidence.",''')
old = '''    (DELIVERY / "sustained-goals.md").write_text("\\n".join(goals) + "\\n", encoding="utf-8")
    return 0'''
new = '''    (DELIVERY / "sustained-goals.md").write_text("\\n".join(goals) + "\\n", encoding="utf-8")
    final_paths = [AUDIT_RECORD, AUDIT_IMPORT, C_PLAN, C_README, D49, D50,
                   BASE / "run_performance_admission.py", BASE / "run_admission_audit.py",
                   OUT / "raw-index.json", OUT / "summary.json"]
    final_paths.extend(sorted(p for p in DELIVERY.iterdir()
                              if p.is_file() and p.name != "artifact-hashes.json"))
    final_hashes = [{"path": str(p), "sha256": sha256(p), "bytes": p.stat().st_size}
                    for p in final_paths if p.exists()]
    write(DELIVERY / "artifact-hashes.json", final_hashes)
    return 0'''
if old not in t:
    raise SystemExit("end block not found")
t = t.replace(old, new)
p.write_text(t, encoding="utf-8")
print("patched report and final hashes")

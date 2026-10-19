from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
t = p.read_text(encoding="utf-8")
old = '''            top_paths = []
            for p in sorted((ROOT / "src").iterdir()):
                rel = "src/" + p.name if p.is_dir() else "src/" + p.name
                if p.is_file() and p.suffix in {".py"}:
                    top_paths.append(rel)
                elif p.is_dir() and p.name != "__pycache__":
                    top_paths.append(rel)
            def fn():
                full = run_cli((".",))
                shards = [run_cli((x,)) for x in top_paths]'''
new = '''            def fn():
                full = run_cli((".",))
                top_names = sorted({row[0].split("/", 2)[1] for row in full["source_rows"]})
                top_paths = ["src/" + name for name in top_names]
                shards = [run_cli((x,)) for x in top_paths]'''
if old not in t:
    raise SystemExit("old CLI shard block not found")
t = t.replace(old, new)
p.write_text(t, encoding="utf-8")
print("patched top paths")

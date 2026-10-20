from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
t = p.read_text(encoding="utf-8")
old = '''                top_names = sorted({row[0].split("/", 2)[1] for row in full["source_rows"]})
                top_paths = ["src/" + name for name in top_names]'''
new = '''                tree_paths = subprocess.check_output(
                    ["git", "-C", str(ROOT), "ls-tree", "-r", "--name-only", BASE_COMMIT, "src"],
                    env=GIT_ENV, text=True).splitlines()
                top_names = sorted({path.split("/", 2)[1] for path in tree_paths if "/" in path})
                top_paths = ["src/" + name for name in top_names]'''
if old not in t:
    raise SystemExit("top names block not found")
t = t.replace(old, new)
p.write_text(t, encoding="utf-8")
print("patched tree top paths")

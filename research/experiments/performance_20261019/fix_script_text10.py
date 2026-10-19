from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
t = p.read_text(encoding="utf-8")
old = '                top_paths = ["src/" + name for name in top_names]'
new = '''                top_paths = []
                for name in top_names:
                    candidate = "src/" + name
                    try:
                        load_git_sources(ROOT, BASE_COMMIT, (candidate,))
                    except ValueError:
                        continue
                    top_paths.append(candidate)'''
if old not in t:
    raise SystemExit("top paths line not found")
t = t.replace(old, new)
p.write_text(t, encoding="utf-8")
print("patched supported top paths")

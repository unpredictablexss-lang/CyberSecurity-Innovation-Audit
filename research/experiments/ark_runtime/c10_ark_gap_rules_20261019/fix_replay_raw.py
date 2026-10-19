from pathlib import Path
p=Path("research/experiments/ark_runtime/c10_ark_gap_rules_20261019/replay_real_sources.py")
s=p.read_text(encoding="utf-8")
s=s.replace('return subprocess.check_output(["git", "show", spec], cwd=ARK)', 'return subprocess.check_output(["git", "cat-file", "blob", spec], cwd=ARK)')
s=s.replace('method": "git show pinned commit:path;', 'method": "git cat-file blob pinned commit:path;')
p.write_text(s,encoding="utf-8",newline="")
print("patched raw object read")

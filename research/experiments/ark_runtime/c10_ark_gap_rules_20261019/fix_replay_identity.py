from pathlib import Path
p=Path("research/experiments/ark_runtime/c10_ark_gap_rules_20261019/replay_real_sources.py")
s=p.read_text(encoding="utf-8")
s=s.replace('def git_bytes(spec):\n    return subprocess.check_output(["git", "cat-file", "blob", spec], cwd=ARK)',
'def git_bytes(spec):\n    blob = subprocess.check_output(["git", "rev-parse", spec], cwd=ARK, text=True).strip()\n    return subprocess.check_output(["git", "cat-file", "blob", blob], cwd=ARK)')
p.write_text(s,encoding="utf-8",newline="")

p=Path("src/ohscanner/detectors/ark_runtime/size_overflow.py")
s=p.read_text(encoding="utf-8")
s=s.replace("        if not any(token in body for token in ('ToIndex', 'requestIndex', 'accessIndex')):\n            continue",
"        if (not any(token in body for token in ('ToIndex', 'requestIndex', 'accessIndex'))\n                and not re.search(r'\\bindex\\b', body)):\n            continue")
p.write_text(s,encoding="utf-8",newline="")
print("patched blob resolution and stub applicability")

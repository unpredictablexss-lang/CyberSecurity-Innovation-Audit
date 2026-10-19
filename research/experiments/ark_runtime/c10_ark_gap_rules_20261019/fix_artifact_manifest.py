from pathlib import Path
p=Path("research/experiments/ark_runtime/c10_ark_gap_rules_20261019/build_artifacts.py")
s=p.read_text(encoding="utf-8")
s=s.replace('`check-records-win-final.json`', '`check-records-win-final2.json`')
s=s.replace('artifact_paths = sorted(p for p in OUT.iterdir() if p.is_file() and p.name != "artifact-hashes.json")',
'''artifact_paths = sorted(
    p for p in OUT.rglob("*")
    if p.is_file() and p.name != "artifact-hashes.json" and ".pycache" not in p.parts
)''')
s=s.replace('"files": [{"path": p.name, "bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}',
'"files": [{"path": p.relative_to(OUT).as_posix(), "bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}')
p.write_text(s,encoding="utf-8",newline="")
print("updated final record reference and recursive artifact hashes")

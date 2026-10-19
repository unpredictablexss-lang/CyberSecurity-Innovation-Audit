from pathlib import Path
p=Path("research/experiments/ark_runtime/c10_ark_gap_rules_20261019/build_artifacts.py")
s=p.read_text(encoding="utf-8")
s=s.replace("import subprocess\n\nROOT = Path(__file__).resolve().parents[4]", "import subprocess\nimport sys\n\nROOT = Path(__file__).resolve().parents[4]\nsys.path.insert(0, str(ROOT))")
p.write_text(s,encoding="utf-8",newline="")
print("patched artifact builder imports")

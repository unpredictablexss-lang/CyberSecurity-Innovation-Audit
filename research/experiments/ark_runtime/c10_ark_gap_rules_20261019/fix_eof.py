from pathlib import Path
p=Path("src/ohscanner/detectors/ark_runtime/detector.py")
s=p.read_text(encoding="utf-8")
p.write_text(s.rstrip()+"\n",encoding="utf-8",newline="")
print("trimmed detector EOF")

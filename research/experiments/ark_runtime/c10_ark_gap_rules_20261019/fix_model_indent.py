from pathlib import Path
p=Path("src/ohscanner/detectors/ark_runtime/model.py")
lines=p.read_text(encoding="utf-8").splitlines()
for i,line in enumerate(lines):
    if line.startswith("+ tuple((revision, path, blob)"):
        lines[i]="                " + line
p.write_text("\n".join(lines)+"\n",encoding="utf-8",newline="")
print("aligned model source view indentation")

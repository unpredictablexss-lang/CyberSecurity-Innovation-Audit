from pathlib import Path
p=Path("src/ohscanner/detectors/ark_runtime/detector.py")
lines=p.read_text(encoding="utf-8").splitlines()
for i,line in enumerate(lines):
    if line.strip()=="for _, binding in rule_bindings)),":
        lines[i]="                           for _, binding in rule_bindings))):"
        break
else:
    raise SystemExit("line not found")
p.write_text("\n".join(lines)+"\n",encoding="utf-8",newline="")
print("fixed detector parenthesis")

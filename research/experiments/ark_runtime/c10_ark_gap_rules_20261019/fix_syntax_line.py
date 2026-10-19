from pathlib import Path
p = Path("src/ohscanner/detectors/ark_runtime/size_overflow.py")
lines = p.read_text(encoding="utf-8").splitlines()
for i, line in enumerate(lines):
    if line.startswith("        elif (re.search(r'index"):
        lines[i:i+1] = [
            "        elif (re.search(r'index\\s*>\\s*size\\s*\\|\\|\\s*elementSize\\s*>\\s*size\\s*-\\s*index', body)",
            "              or re.search(r'elementSize\\s*>\\s*size\\s*-\\s*index', body)):",
            "            continue",
            "        elif any(token in body for token in ('DoubleToUInt64', 'Int64UnsignedGreaterThan', 'uint64_t index')):",
        ]
        break
else:
    raise SystemExit("target line not found")
p.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
print("fixed syntax line")

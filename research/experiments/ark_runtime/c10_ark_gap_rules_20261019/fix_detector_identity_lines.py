from pathlib import Path
p=Path("src/ohscanner/detectors/ark_runtime/detector.py")
lines=p.read_text(encoding="utf-8").splitlines()
start=next(i for i,x in enumerate(lines) if x.strip().startswith("if (unit.language not in self.supported_languages"))
end=next(i for i in range(start,len(lines)) if lines[i].strip()=="outcomes.append((unit.path, 'not_analyzed'))")
lines[start:end+1]=[
"            source_hash_mismatch = any(unit.sha256 != binding[3] for _, binding in rule_bindings)",
"            source_blob_mismatch = blob_oids.get(unit.path) not in {binding[2] for _, binding in rule_bindings}",
"            if unit.language not in self.supported_languages or source_hash_mismatch or source_blob_mismatch:",
"                outcomes.append((unit.path, 'not_analyzed'))",
]
p.write_text("\n".join(lines)+"\n",encoding="utf-8",newline="")
print("replaced detector identity block by line")

from pathlib import Path
p=Path("src/ohscanner/detectors/ark_runtime/detector.py")
s=p.read_text(encoding="utf-8")
old="""            if (unit.language not in self.supported_languages
                    or any(unit.sha256 != binding[3] for _, binding in rule_bindings)
                    or any(blob_oids.get(unit.path) != binding[2]
                           for _, binding in rule_bindings))),
                outcomes.append((unit.path, 'not_analyzed'))"""
new="""            source_hash_mismatch = any(unit.sha256 != binding[3] for _, binding in rule_bindings)
            source_blob_mismatch = blob_oids.get(unit.path) not in {binding[2] for _, binding in rule_bindings}
            if unit.language not in self.supported_languages or source_hash_mismatch or source_blob_mismatch:
                outcomes.append((unit.path, 'not_analyzed'))"""
if old not in s:
    old=old.replace("))),", ")),")
    new=new
assert old in s, "target block not found"
s=s.replace(old,new)
p.write_text(s,encoding="utf-8",newline="")
print("simplified target identity block")

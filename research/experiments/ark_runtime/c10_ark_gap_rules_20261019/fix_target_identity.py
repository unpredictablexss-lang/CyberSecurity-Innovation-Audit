from pathlib import Path
p=Path("src/ohscanner/detectors/ark_runtime/detector.py")
s=p.read_text(encoding="utf-8")
s=s.replace('''        raw = dependency.text.encode('utf-8')
        git_blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
        source_digest = sha256(raw).hexdigest()
        ast_entry = ast.get(path)
        if (dependency.language != 'cpp' or dependency.sha256 != source_digest
                or blob_oids.get(path) != expected_blob or git_blob != expected_blob):''',
'''        raw = dependency.text.encode('utf-8')
        source_digest = sha256(raw).hexdigest()
        ast_entry = ast.get(path)
        if (dependency.language != 'cpp' or dependency.sha256 != source_digest
                or blob_oids.get(path) != expected_blob):''')
s=s.replace('''            if (unit.language not in self.supported_languages
                    or any(unit.sha256 != binding[3] or git_blob != binding[2]
                           for _, binding in rule_bindings)
                    or blob_oids.get(unit.path) != rule_bindings[0][1][2]):''',
'''            if (unit.language not in self.supported_languages
                    or any(unit.sha256 != binding[3] for _, binding in rule_bindings)
                    or any(blob_oids.get(unit.path) != binding[2]
                           for _, binding in rule_bindings)),''')
p.write_text(s,encoding="utf-8",newline="")
print("bound target identity through verified shared Git OID plus source SHA-256")

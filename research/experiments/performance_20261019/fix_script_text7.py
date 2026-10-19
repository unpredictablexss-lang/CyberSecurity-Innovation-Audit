from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
t = p.read_text(encoding="utf-8")
t = t.replace('def diagnostic_signature_rows(rows):', '''def compact_result(value):
    if isinstance(value, dict):
        skip = {"diagnostic_rows", "parse_rows", "detector_sidecar", "source_rows"}
        out = {k: compact_result(v) for k, v in value.items() if k not in skip}
        if "shards" in value and isinstance(value["shards"], list):
            out["shards"] = [{
                "source_identity_sha256": x.get("source_identity_sha256"),
                "parse_signature_sha256": x.get("parse_signature_sha256"),
                "diagnostic_signature_sha256": x.get("diagnostic_signature_sha256"),
                "diagnostic_count": x.get("diagnostic_count"),
            } for x in value["shards"]]
        return out
    if isinstance(value, list):
        return [compact_result(x) for x in value]
    return value


def diagnostic_signature_rows(rows):''')
t = t.replace('    payload["result"] = result', '    payload["result"] = compact_result(result)')
t = t.replace('''            rows = [[u["file"], u["language"], u["sha256"], u["parse_status"], u.get("parse_issues", [])]
                    for u in data["source_units"]]
            return {"wall_seconds": wall, "peak_rss_bytes": peak,
                    "source_count": data["scope"]["selected_source_files"],
                    "source_bytes": data["scope"]["selected_source_bytes"], "parse": data["source_parsing"],
                    "source_identity_sha256": identity_signature_rows(rows)[0],
                    "source_rows": rows}''', '''            source_rows = [[u["file"], u["language"], u["sha256"], u.get("blob_oid"), json.dumps(u.get("archive_binding"), sort_keys=True)]
                           for u in data["source_units"]]
            parse_rows = [[u["file"], u["language"], u["sha256"], u["parse_status"], u.get("parse_issues", [])]
                          for u in data["source_units"]]
            return {"wall_seconds": wall, "peak_rss_bytes": peak,
                    "source_count": data["scope"]["selected_source_files"],
                    "source_bytes": data["scope"]["selected_source_bytes"],
                    "parse": data["coverage"],
                    "source_identity_sha256": identity_signature_rows(source_rows)[0],
                    "coverage_signature_sha256": identity_signature_rows(parse_rows)[0],
                    "source_rows": source_rows, "parse_rows": parse_rows}''')
t = t.replace('''                merged_rows = sum((r["source_rows"] for r in shards), [])
                merged_parse = dict(sorted(__import__("collections").Counter(
                    row[3] for row in merged_rows).items()))
                return {
                    "full": full, "shards": shards,
                    "invariant": (
                        full["source_identity_sha256"] == identity_signature_rows(merged_rows)[0]
                        and full["parse"] == {"parsing_status": merged_parse,
                                              "languages": full["parse"]["languages"]}
                    ),
                }''', '''                merged_source_rows = sum((r["source_rows"] for r in shards), [])
                merged_parse_rows = sum((r["parse_rows"] for r in shards), [])
                return {
                    "full": full, "shards": shards,
                    "invariant": (
                        full["source_identity_sha256"] == identity_signature_rows(merged_source_rows)[0]
                        and full["coverage_signature_sha256"] == identity_signature_rows(merged_parse_rows)[0]
                    ),
                }''')
p.write_text(t, encoding="utf-8")
print("patched compact and cli")

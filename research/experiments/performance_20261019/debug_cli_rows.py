import json, pathlib
root=pathlib.Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\out")
for name in ["cli-cli_index_shards-99-full.json","cli-cli_index_shards-99-shard-*.json"]:
    for p in root.glob(name):
        d=json.loads(p.read_text(encoding="utf-8"))
        rows=[(u["file"],u.get("blob_oid"),u.get("archive_binding")) for u in d["source_units"]]
        print(p.name, len(rows), rows[:2], rows[-2:])

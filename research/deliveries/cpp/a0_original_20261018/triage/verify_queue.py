#!/usr/bin/env python3
"""Read-only A0 hash and candidate-key reconciliation; validates generated queue cardinality."""
import collections, hashlib, json, pathlib, sys
HERE=pathlib.Path(__file__).resolve().parent
SOURCE=pathlib.Path(r"D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-sample30\20261018")
manifest=json.loads((SOURCE/"evidence/hashes.json").read_text(encoding="utf-8"))
reviews=json.loads((SOURCE/"evidence/candidate_reviews.json").read_text(encoding="utf-8"))
samples=json.loads((SOURCE/"evidence/sample_manifest.json").read_text(encoding="utf-8"))
missing=[]; bad=[]
for e in manifest["files"]:
 p=SOURCE/e["path"]
 if not p.is_file(): missing.append(e["path"]); continue
 b=p.read_bytes()
 if len(b)!=e["size_bytes"] or hashlib.sha256(b).hexdigest()!=e["sha256"]: bad.append(e["path"])
q=json.loads((HERE/"queue.json").read_text(encoding="utf-8"))
ids={x["candidate_id"]:x for x in q["queue"]}
source_by_id={x["diagnostic_id"]:x for x in reviews["records"]}
sample_by_order={x["sample_order"]:x for x in samples["records"]}
key_mismatches=[]
for cid,x in source_by_id.items():
 y=ids.get(cid)
 if y is None: key_mismatches.append(cid); continue
 expected=(x["review_id"],x["repository"],x["commit"],x["git_tree"],x["file"],x["source_binding"].get("git_blob_oid"),x["source_binding"].get("actual_source_sha256"),x["scanner_provider"],x["detector_version"],x["rule_id"],x["final_status"],sample_by_order[x["sample_order"]].get("profile_id"))
 observed=(y["original_review_id"],y["repository"],y["commit"],y["tree"],y["path"],y["blob"],y["source_sha256"],y["detector"],y["detector_version"],y["rule"],y["original_status"],y["profile"])
 if expected!=observed: key_mismatches.append(cid)
counts=collections.Counter(x["original_status"] for x in q["queue"])
ok=not missing and not bad and not key_mismatches and len(ids)==345 and len(source_by_id)==345 and counts=={"not_reproduced":9,"not_testable":336}
print(json.dumps({"hash_manifest_entries":len(manifest["files"]),"missing":missing,"mismatched":bad,"source_candidate_count":len(source_by_id),"queue_items":len(q["queue"]),"unique_candidate_ids":len(ids),"source_key_mismatches":key_mismatches,"statuses":counts,"hash_ok":not missing and not bad,"count_and_keys_ok":not key_mismatches and len(ids)==345 and len(source_by_id)==345 and counts=={"not_reproduced":9,"not_testable":336},"overall_ok":ok},ensure_ascii=False,indent=2))
sys.exit(0 if ok else 1)

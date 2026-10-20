"""Build source-bound audit, known-CVE coverage and migration ledgers."""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess
from pathlib import Path

W = Path(__file__).resolve().parents[4]
C8 = Path(__file__).resolve().parent
C9 = W / "research/experiments/ark_runtime/c9_partial_owner_acceptance_20261019"
SRC = C9 / "source-audit-original.md"
DETAIL = C9 / "source-audit-entry-reconciliation.json"
REVIEW = ("e4e0761501a83ac25cc67d04c527eefe9f4a1b50", "307ac8237263db793028e0bf34a82a85f60821a5", "dbedea677c8dc70c1b0066c7bc52df27bcff06ea", "732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240")
HEAD = ("7af25f5ced471e5d6acc8cf5efd4c696275ce940", "11f53fe00d79d477c383e7e9b49ad3b1adcae86c")
STATIC = ("09ba5aba03c7c7d6787bace349b8fc0a6b0a5457", "d15b91627c94d9c3043d7d58d47fcf9af7e42454")
MAIN = ("db77164fdc2af0da02e4d3efc056d84694fd68e8", "8c5a296d8304d98193a29a4695aaf61ca0c0996c")
KNOWN_BLOB = "a2ddd5ff2afc2f6fb0f1677ea3ffbbfc580a195b"

RULES = {
 "CVE-2022-45877":"ohknowncve-device-manager-cve-2022-45877", "CVE-2025-25212":"ohknowncve-pasteboard-cve-2025-25212",
 "CVE-2025-27247":"ohknowncve-pasteboard-cve-2025-27247", "CVE-2025-57052":"ohknowncve-cjson-cve-2025-57052",
 "CVE-2025-9900":"ohknowncve-libtiff-cve-2025-9900", "CVE-2026-25850":"ohknowncve-storage-cve-2026-25850",
 "CVE-2026-27648":"ohknowncve-webview-cve-2026-27648", "CVE-2026-28733":"ohknowncve-storage-cve-2026-28733",
 "CVE-2026-28751":"ohknowncve-storage-cve-2026-28751", "CVE-2026-33636":"ohknowncve-libpng-cve-2026-33636",
 "CVE-2026-46675":"ohknowncve-libpng-cve-2026-46675", "CVE-2026-58313":"ohknowncve-appdomainverify-cve-2026-58313",
 "CVE-2026-67215":"ohknowncve-cjson-cve-2026-67215", "CVE-2026-67216":"ohknowncve-cjson-cve-2026-67216",
 "CVE-2026-9079":"ohknowncve-curl-cve-2026-9079", "CVE-2026-92391":"ohknowncve-curl-cve-2026-92391", "CVE-2026-92392":"ohknowncve-curl-cve-2026-92392",
}
UNCOVERED = {"CVE-2025-24304":"alternate Ark type-origin mapping exists", "CVE-2026-33416":"patch-list-only", "CVE-2026-34757":"patch-list-only"}
C9_RESULTS = {
 "CVE-2025-24304":"Map root 1->0; family candidates remain; partial/blocked", "IBS5YG":"TypeOrigin 1->0; partial/blocked",
 "I7KZJ7":"multiplication root 1->0; partial/blocked", "IC7B8Q":"exception candidates 2->0; partial/blocked",
 "IAO7GO":"0->0 because selector matched 0 applicable files", "I7W51D":"0->0; no length-narrowing rule",
 "IB8BCA":"0->0; no DataView/Atomics boundary model", "IAO7E8":"receiver-guard 1->0; detector blocked/partial",
}

def git(*a): return subprocess.check_output(["git",*a],cwd=W,text=True).strip()
def sha(b): return hashlib.sha256(b).hexdigest()
def blob(b): return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def excerpt(lines,start,end):
 text="\n".join(lines[start-1:end]); return {"line_start":start,"line_end":end,"excerpt_sha256":sha(text.encode()),"excerpt":text}
def cov(cve):
 rule=RULES.get(cve); return {"detector_id":"ohscanner.known_disclosed_cves","detector_version":"0.16.0","rule_id":rule,
 "coverage_status":"rule_present_source_signature_only" if rule else "unknown_not_covered_by_known_cves_0.16.0",
 "actual_result":"not_run_in_this_slice" if rule else UNCOVERED.get(cve,"unknown"),"product_status":"unknown"}

def item(lines,ident,start,end,kind,cves):
 rec=excerpt(lines,start,end); text=rec["excerpt"]
 component=next((x for x in ["libpng","libtiff","libcurl","cJSON","web_webview","pasteboard","device_manager","app_domain_verify","storage_service","security_asset","update_update_app","request_request","security_deviceauth"] if x.lower() in text.lower()),"source_audit_row")
 controls={"manual_candidate":["AUDIT-MANUAL-CANDIDATE-UNKNOWN-001"],"negative_control":["AUDIT-NEGATIVE-CONTROL-001"],"patch_list_only":["AUDIT-PATCH-LIST-ONLY-UNKNOWN-001"]}.get(kind,["AUDIT-EXTERNAL-PUBLIC-001","AUDIT-EXTERNAL-LOCAL-001","AUDIT-EXTERNAL-UNKNOWN-001"])
 return {"finding_id":ident,"kind":kind,"title":text.splitlines()[0] if text else ident,"cve_ids":cves,
 "id_mapping":{"finding_to_cve_or_id":cves or [ident],"cwe":"unknown_not_provided_by_original"},
 "source_identity":{"component":component,"repository_paths_from_original":sorted(set(re.findall(r"G:\\[^\\s\\.,;`]+",text))),
 "head_spellings_from_original":sorted(set(re.findall(r"HEAD ([0-9a-f]{12})",text))),"version_mentions":re.findall(r"(?i)(?:version |v)\d+(?:\.\d+)+",text),
 "full_commit":"unknown","tree":"unknown","file_blob":"unknown","source_sha256":"unknown","identity_status":"partial_external_identity_from_original","strict_eligible":False,"audit_record":rec},
 "detector_rule":{"known_cves_0.16.0":[cov(c) for c in cves],"mapping_status":"rule_present" if any(c in RULES for c in cves) else "unknown_or_unmapped"},
 "controls":controls,"actual_result":{"original_text":text,"scanner_result":"not_run_original_manual_review","product_status":"unknown_not_promoted","classification":kind,"cve_claim":"public_disclosure_only" if cves else "not_applicable","cia_claim":"not_asserted"},"evidence_role":"source_audit_original"}

def parse_entries(lines):
 out=[]; heads=[(i+1,re.match(r"^#### (CVE-\d{4}-\d+).+$",line)) for i,line in enumerate(lines)]
 heads=[(n,m) for n,m in heads if m]
 for idx,(start,m) in enumerate(heads):
  end=heads[idx+1][0]-1 if idx+1<len(heads) else 149; out.append(item(lines,"AUDIT-"+m.group(1),start,end,"public_cve",[m.group(1)]))
 patch_cves=sorted(set(re.findall(r"CVE-\d{4}-\d+",lines[37])) - {e["cve_ids"][0] for e in out})
 for cve in patch_cves: out.append(item(lines,"PATCH-ONLY-"+cve,38,38,"patch_list_only",[cve]))
 manual=[(i+1,line) for i,line in enumerate(lines[153:178],153) if line.startswith("### ")]
 for j,(start,line) in enumerate(manual):
  end=manual[j+1][0]-1 if j+1<len(manual) else 178; out.append(item(lines,"MANUAL-"+re.sub(r"\W+","-",line[4:]).strip("-"),start,end,"manual_candidate",[]))
 for n in range(181,186): out.append(item(lines,"NEG-"+re.sub(r"\W+","-",lines[n-1][2:]).strip("-"),n,n,"negative_control",[]))
 detail=json.loads(DETAIL.read_text(encoding="utf-8"))
 for old in detail["entries"]:
  rid=old["row_id"]; cves=[rid] if rid.startswith("CVE-") else []
  out.append({"finding_id":rid,"kind":"c_line_ark_runtime_replay","title":rid,"cve_ids":cves,
  "id_mapping":{"finding_to_cve_or_id":cves or [rid],"cwe":"not_asserted"},"source_identity":old["source_identity"],
  "detector_rule":{**old["finding_to_rule"],"known_cves_0.16.0":[cov(c) for c in cves]},"controls":old["finding_to_rule"].get("control_ids",[]),
  "actual_result":{"scanner_result":C9_RESULTS[rid],"dynamic_evidence":"not_run","product_status":"unknown","classification":{"IAO7GO":"miss_coverage_selector_not_applicable","I7W51D":"miss_rule_length_narrowing_uncovered","IB8BCA":"miss_rule_dataview_boundary_uncovered"}.get(rid,"candidate_static_response"),"cve_claim":"not_asserted" if cves else "not_applicable","cia_claim":"not_asserted"},
  "audit_record_identity":excerpt(lines,old["original_line"],old["original_line"]),"evidence_role":"source_audit_original"})
 out.sort(key=lambda x:(x.get("source_identity",{}).get("audit_record",x.get("audit_record_identity",{})).get("line_start",999),x["finding_id"])); return out

def build():
 raw=SRC.read_bytes(); lines=raw.decode().splitlines(); assert sha(raw)==REVIEW[3] and blob(raw)==REVIEW[2]; entries=parse_entries(lines)
 return {"schema_version":"c8.source-audit.full-entry-map/v1","bindings":{"review_original":{"commit":REVIEW[0],"tree":REVIEW[1],"blob":REVIEW[2],"sha256":REVIEW[3]},"current_head":{"commit":HEAD[0],"tree":HEAD[1]},"latest_static_baseline":{"ref":"origin/codex/c-line-static-20261019","commit":STATIC[0],"tree":STATIC[1]},"known_cves_baseline":{"ref":"origin/main","commit":MAIN[0],"tree":MAIN[1],"path":"src/ohscanner/detectors/known_cves.py","blob":KNOWN_BLOB,"version":"0.16.0"}},"entry_counts":{"all":len(entries)},"claim_boundary":{"substitute_evidence_used_as_input":False,"product_vulnerability":"not_asserted","cia":"not_asserted","metrics":"not_computed"},"entries":entries}

def coverage(mapping):
 cs=sorted({c for e in mapping["entries"] for c in e["cve_ids"]}); rows=[{"cve":c,**cov(c)} for c in cs]
 return {"schema_version":"c8.source-audit.known-cve-coverage/v1","detector":{"id":"ohscanner.known_disclosed_cves","version":"0.16.0","commit":MAIN[0],"tree":MAIN[1],"blob":KNOWN_BLOB},"counts":{"audit_cves":len(rows),"covered_by_rule":sum(r["rule_id"] is not None for r in rows),"unknown_not_covered":sum(r["rule_id"] is None for r in rows)},"interpretation":"Rule presence is source-signature coverage only; no product result is asserted.","entries":rows}

def migration():
 paths=["research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/README.md","research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/audit-schema.json","research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/expected-regressions.json","research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/input-manifest.json","research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/known-source-findings.json","research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/reconcile.py","research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/run-manifest.json","src/ohscanner/detectors/ark_runtime/syntax.py","tests/detectors/ark_runtime/test_parser_owner.py"]
 rows=[]
 for p in paths:
  exists=subprocess.run(["git","cat-file","-e",f"{STATIC[0]}:{p}"],cwd=W,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
  if p.endswith("test_parser_owner.py"): kind,decision="semantic_content_conflict","retain current fail-closed tests; reject 09ba lexical_scope and unclassified read_bytes failure"
  elif p.endswith("syntax.py"): kind,decision="target_missing_required_dependency","carry syntax.py; 09ba tests import it but tree lacks it"
  elif not exists: kind,decision="carry_over_addition","carry dirty evidence without overwriting teammate work"
  else: kind,decision="content_conflict","manual three-way merge"
  rows.append({"path":p,"classification":kind,"target_exists":exists,"target_blob":git("rev-parse",f"{STATIC[0]}:{p}") if exists else None,"decision":decision})
 rows += [{"path":"research/experiments/ark_runtime/c9_partial_owner_acceptance_20261019/","classification":"carry_over_untracked_directory","decision":"carry exact evidence"},{"path":"tests/detectors/ark_runtime/fixtures/ark_runtime/parser_owner/","classification":"carry_over_untracked_fixture","decision":"carry fail-closed fixtures"},{"path":"src/ohscanner/detectors/known_cves.py","classification":"target_only_addition_no_conflict","target_blob":KNOWN_BLOB,"decision":"bind 0.16.0 coverage only"}]
 return {"schema_version":"c8.source-audit.migration-conflicts/v1","from":{"commit":HEAD[0],"tree":HEAD[1]},"to":{"commit":STATIC[0],"tree":STATIC[1]},"review_binding":{"commit":REVIEW[0],"tree":REVIEW[1],"blob":REVIEW[2],"sha256":REVIEW[3]},"entries":rows}

def self_test(m,c,g):
 ids=[e["finding_id"] for e in m["entries"]]; cases={"review_blob":blob(SRC.read_bytes())==REVIEW[2],"review_sha256":sha(SRC.read_bytes())==REVIEW[3],"static_tree":git("rev-parse",f"{STATIC[0]}^{{tree}}")==STATIC[1],"known_blob":git("rev-parse",f"{MAIN[0]}:src/ohscanner/detectors/known_cves.py")==KNOWN_BLOB,"entries_36":len(ids)==36 and len(ids)==len(set(ids)),"known_cves_17_3":c["counts"]=={"audit_cves":20,"covered_by_rule":17,"unknown_not_covered":3},"no_substitute":m["claim_boundary"]["substitute_evidence_used_as_input"] is False,"partial_identity_rejected":all(not e["source_identity"].get("strict_eligible",True) for e in m["entries"] if e["source_identity"].get("identity_status")=="partial_external_identity_from_original"),"migration_conflicts":any(x["classification"]=="semantic_content_conflict" for x in g["entries"]) and any(x["classification"]=="target_missing_required_dependency" for x in g["entries"])}
 return {"schema_version":"c8.source-audit.mapping-self-test/v1","status":"pass" if all(cases.values()) else "fail","cases":[{"case":k,"passed":v} for k,v in cases.items()]}

def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--write",action="store_true"); a=ap.parse_args(); m=build(); c=coverage(m); g=migration(); r=self_test(m,c,g)
 if a.write:
  (C8/"audit-entry-mapping.json").write_text(json.dumps(m,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); (C9/"known-cve-coverage-0.16.0.json").write_text(json.dumps(c,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); (C9/"migration-conflicts-09ba5ab.json").write_text(json.dumps(g,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
  d=json.loads(DETAIL.read_text(encoding="utf-8")); by={e["finding_id"]:e for e in m["entries"]}
  for row in d["entries"]: row["actual_result"]=by[row["row_id"]]["actual_result"]; row["known_cves_0_16_0"]=by[row["row_id"]]["detector_rule"]["known_cves_0.16.0"]
  d["input"]["latest_static_baseline"]={"commit":STATIC[0],"tree":STATIC[1],"ref":"origin/codex/c-line-static-20261019"}; d["input"]["known_cves_baseline"]={"commit":MAIN[0],"tree":MAIN[1],"blob":KNOWN_BLOB,"detector_version":"0.16.0"}; DETAIL.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 print(json.dumps(r,ensure_ascii=False,indent=2)); return 0 if r["status"]=="pass" else 1
if __name__=="__main__": raise SystemExit(main())



#!/usr/bin/env python3
"""Read-only independent checks for T27 Preferences A0 source audit."""
from __future__ import annotations
import collections, csv, hashlib, json, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
OBJECTS=Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
QUEUE_CSV=Path(r"D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-triage\20261018\queue.csv")
QUEUE_JSON=Path(r"D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-triage\20261018\queue.json")
COMMIT="bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE="7761d9e273ae7007046ae115797f255e554523ae"
ROWS={"CR-0020":("frameworks/js/napi/common/include/js_proxy.h",37),"CR-0021":("frameworks/js/napi/common/include/js_proxy.h",42),"CR-0022":("test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp",43),"CR-0023":("test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp",48),"CR-0024":("test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp",50)}
def git(*args,data=None): return subprocess.check_output(["git",f"--git-dir={OBJECTS}",*args],input=data)
def main():
 with QUEUE_CSV.open(encoding="utf-8-sig",newline="") as f: csvrows=list(csv.DictReader(f))
 jsonrows=json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
 assert len(csvrows)==len(jsonrows)==345
 cmap={x["queue_id"]:x for x in csvrows}; jmap={x["queue_id"]:x for x in jsonrows}
 assert len(cmap)==len(jmap)==345 and set(cmap)==set(jmap)
 for qid in cmap:
  for field in ("candidate_id","repository","commit","tree","path","line","blob","source_sha256","original_status","queue_status"):
   assert str(cmap[qid][field])==str(jmap[qid][field]),(qid,field)
 assert git("rev-parse",f"{COMMIT}^{{commit}}").decode().strip()==COMMIT
 assert git("show","-s","--format=%T",COMMIT).decode().strip()==TREE
 raw=json.loads((HERE/"t27_preferences_header_and_fuzzer_20261020.json").read_text(encoding="utf-8"))
 run=raw["detector_runs"][0]
 assert raw["commit"]==COMMIT and raw["git_tree"]==TREE
 assert raw["status"]=="completed" and raw["source_parsing"]["parsing_status"]=={"complete":2}
 assert run["tool"]=="ohscanner.cpp.shared_ptr_race" and run["tool_version"]=="0.5.1" and run["diagnostic_count"]==21
 findings={(x["file"],x["line"],x["symbol"]) for x in run["diagnostics"]}
 assert (ROWS["CR-0020"][0],37,"instance_") in findings
 assert (ROWS["CR-0021"][0],42,"instance_") in findings
 assert sum(1 for x in findings if x[0]==ROWS["CR-0020"][0])==2
 assert sum(1 for x in findings if x[0]==ROWS["CR-0022"][0])==19
 for qid,(path,line) in ROWS.items():
  row=cmap[qid]
  assert (row["commit"],row["tree"],row["path"],int(row["line"]),row["original_status"],row["queue_status"])==(COMMIT,TREE,path,line,"not_testable","paused_pending_evidence")
  blob=git("show",f"{COMMIT}:{path}"); bid=git("hash-object","--stdin",data=blob).decode().strip(); sha=hashlib.sha256(blob).hexdigest()
  assert (row["blob"],row["source_sha256"])==(bid,sha)
  evidence=json.loads((HERE/f"t27_{qid.lower()}_20261020.json").read_text(encoding="utf-8"))
  assert evidence["queue_id"]==qid and evidence["queue_preserved"] and evidence["disposition"]=="PARTIAL"
  assert evidence["source"]["blob"]==bid and evidence["source"]["sha256"]==sha
  assert evidence["original_a0"]["original_status"]=="not_testable" and evidence["original_a0"]["queue_status"]=="paused_pending_evidence"
 counts={k:dict(collections.Counter(x[k] for x in csvrows)) for k in ("original_status","queue_status")}
 assert counts["original_status"]=={"not_testable":336,"not_reproduced":9}
 assert counts["queue_status"]=={"paused_pending_evidence":331,"queued_not_reproduced":9,"queued_first_batch":5}
 print("T27 source commit/tree and five source blobs/SHA: PASS")
 print("Original A0 CSV/JSON 345 IDs and row identity parity: PASS")
 print("CR-0020–0024 source keys and original statuses unchanged: PASS")
 print("Independent CLI identity, complete parsing and finding locations: PASS")
 print("All five per-ID evidence records preserve PARTIAL and A0 state: PASS")
 print("A0 status/queue counts unchanged: PASS")
 return 0
if __name__=="__main__": raise SystemExit(main())

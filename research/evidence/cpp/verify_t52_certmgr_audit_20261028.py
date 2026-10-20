#!/usr/bin/env python3
"""Verify T52 exact source bindings, current CLI replays, and A0 reconciliation."""
from __future__ import annotations
import argparse, csv, hashlib, json, subprocess, collections
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
COMMIT="5fcc0b6379567a70176307c281360be2ba281d6b"
TREE="f3e078b356ac0724d8ab267d73ab85e69b9b44ad"
EXPECTED={
 "CR-0315":("cmdline/certmgr/src/certmgr_command.cpp",364,"46d78a85b7e13b1752201b3f537343d9164f908d","27f61990ff04328955bea8ceae9e5a262706e74fc44118cc7951b2425cdfa530","ohscanner.cpp.shared_ptr_race","0.5.1","complete",0,"t52_certmgr_cr0315_shared_ptr_cli_20261028.json"),
 "CR-0316":("frameworks/cert_manager_standard/main/os_dependency/cm_ipc/src/cm_ipc_dialog_client.cpp",127,"88937de7088f08ee85ac8dfdc70990f3b881ee2b","dbe4abc0c0402ed6c86862649d710939f110bc9fd6d0311b4020a39870373e87","ohscanner.interface.ipc","0.12.12","partial",1,"t52_certmgr_cr0316_ipc_cli_20261028.json"),
}
def git(repo:Path,*args:str)->bytes:
 return subprocess.check_output(["git","-C",str(repo),*args])
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--source-repo",type=Path,required=True); args=ap.parse_args(); repo=args.source_repo.resolve()
 assert git(repo,"rev-parse",f"{COMMIT}^{{commit}}").decode().strip()==COMMIT
 assert git(repo,"rev-parse",f"{COMMIT}^{{tree}}").decode().strip()==TREE
 qcsv_path=ROOT/"research/deliveries/cpp/a0_triage_20261019/queue.csv"
 qjson_path=ROOT/"research/deliveries/cpp/a0_triage_20261019/queue.json"
 with qcsv_path.open(encoding="utf-8-sig",newline="") as f: rows=list(csv.DictReader(f))
 jq=json.loads(qjson_path.read_text(encoding="utf-8"))["queue"]
 assert len(rows)==len(jq)==345 and len({r["queue_id"] for r in rows})==345
 assert {r["queue_id"] for r in rows}=={r["queue_id"] for r in jq}
 assert {r["queue_id"]:r["original_status"] for r in rows}=={r["queue_id"]:r["original_status"] for r in jq}
 for qid,expected in EXPECTED.items():
  path,line,blob,sha,detector,version,parse_status,count,cli_name=expected
  row=next(r for r in rows if r["queue_id"]==qid); jr=next(r for r in jq if r["queue_id"]==qid)
  for key in ("candidate_id","repository","commit","tree","path","line","blob","source_sha256","original_status","queue_status"):
   assert str(row[key])==str(jr[key]),(qid,key)
  assert (row["repository"],row["commit"],row["tree"],row["path"],int(row["line"]),row["blob"],row["source_sha256"],row["original_status"],row["queue_status"]) == ("openharmony/security_certificate_manager",COMMIT,TREE,path,line,blob,sha,"not_testable","paused_pending_evidence")
  data=git(repo,"show",f"{COMMIT}:{path}")
  assert git(repo,"rev-parse",f"{COMMIT}:{path}").decode().strip()==blob
  assert hashlib.sha256(data).hexdigest()==sha
  cli=json.loads((HERE/cli_name).read_text(encoding="utf-8")); run=cli["detector_runs"][0]
  assert cli["commit"]==COMMIT and cli["git_tree"]==TREE
  assert run["tool"]==detector and run["tool_version"]==version and run["diagnostic_count"]==count
  assert cli["source_parsing"]["parsing_status"]=={parse_status:1}
  assert cli["detector_coverage"]["detectors"][detector]["status"]==parse_status
  if qid=="CR-0316":
   d=run["diagnostics"][0]
   assert d["file"]==path and d["line"]==127 and d["rule_id"]=="ipc.relay.descriptor-boundary"
   assert cli["status"]=="completed_with_limitations"
  else: assert not run["diagnostics"] and cli["status"]=="completed"
 audit=json.loads((HERE/"t52_certmgr_audit_20261028.json").read_text(encoding="utf-8"))
 assert audit["source_commit"]==COMMIT and audit["source_tree"]==TREE
 assert audit["a0_reconciliation"]["total_rows"]==345 and audit["a0_reconciliation"]["unique_ids"]==345
 assert audit["a0_reconciliation"]["original_status_counts"]==dict(collections.Counter(r["original_status"] for r in rows))
 identities=json.loads((HERE/"t52_certmgr_context_identity_20261028.json").read_text(encoding="utf-8"))
 for bypath in identities.values():
  for path, binding in bypath.items():
   data=git(repo,"show",f"{COMMIT}:{path}")
   assert git(repo,"rev-parse",f"{COMMIT}:{path}").decode().strip()==binding["blob"]
   assert hashlib.sha256(data).hexdigest()==binding["sha256"]
 assert audit["context_identities"]==identities
 assert all(c["conclusion"]=="PARTIAL/BLOCK" for c in audit["cases"])
 print("PASS T52: exact source commit/tree/blob/SHA bindings for CR-0315–CR-0316")
 print("PASS T52: current shared_ptr_race and IPC CLI outputs match recorded coverage/findings")
 print("PASS T52: A0 CSV/JSON reconcile to 345 unique rows; original selected states preserved")
 print("PASS T52: no fixed-source claim; both cases remain PARTIAL/BLOCK")
if __name__=="__main__": main()

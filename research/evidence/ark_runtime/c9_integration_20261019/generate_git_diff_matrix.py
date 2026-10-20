#!/usr/bin/env python3
from __future__ import annotations
import json, os, subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO=Path("/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-opt-20261019")
OUT=REPO/"research/evidence/ark_runtime/c9_integration_20261019"
ENV=dict(os.environ)
ENV.update({
 "GIT_DIR":"/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/CyberSecurity-Innovation-Audit-c-line-opt-20261019",
 "GIT_WORK_TREE":str(REPO),
 "LC_ALL":"C.UTF-8",
})
COMMITS={
 "local_715":"715e29884a845a2daa80016f332c70b3db84ca45",
 "local_7af":"7af25f5ced471e5d6acc8cf5efd4c696275ce940",
 "remote_e4e":"e4e0761501a83ac25cc67d04c527eefe9f4a1b50",
 "merge_base":"4e6c8d957cce91bfec150faaae7d6ac69b84def4",
}
SCOPES={
 "public_contracts_runner_catalog":["src/ohscanner/contracts.py","src/ohscanner/runner.py","src/ohscanner/detectors/catalog.py"],
 "ark_implementation":["src/ohscanner/detectors/ark_runtime/"],
 "ark_tests":["tests/detectors/ark_runtime/"],
 "ark_and_c_line_evidence":["research/deliveries/c-line/","research/deliveries/ark_runtime/","research/experiments/ark_runtime/","research/evidence/ark_runtime/"],
 "source_audit_reconciliation":["research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/"],
}
PAIRS=[("local_715","local_7af"),("local_715","remote_e4e"),("local_7af","remote_e4e")]

def git(*args, text=False):
    return subprocess.check_output(["/usr/bin/git","-C",str(REPO),*args],env=ENV)

def commit_info(ref):
    raw=git("show","-s","--format=%H%n%T%n%P%n%aI%n%s",ref,text=True).splitlines()
    return {"commit":raw[0],"tree":raw[1],"parents":raw[2].split() if raw[2] else [],"author_date":raw[3],"subject":raw[4]}

def numstat(a,b,paths):
    raw=git("diff","--no-renames","--numstat","-z",a,b,"--",*paths)
    rows=[]
    for record in raw.split(b"\0"):
        if not record:
            continue
        bits=record.decode("utf-8","replace").split("\t",2)
        if len(bits)!=3:
            continue
        add,del_,path=bits
        rows.append({"path":path,"additions":None if add=="-" else int(add),"deletions":None if del_=="-" else int(del_),"binary":add=="-" or del_=="-"})
    return rows

def summarize(rows):
    return {
      "files":len(rows),
      "binary_files":sum(r["binary"] for r in rows),
      "additions":sum(r["additions"] or 0 for r in rows),
      "deletions":sum(r["deletions"] or 0 for r in rows),
      "paths":[r["path"] for r in rows],
    }

identities={name:commit_info(ref) for name,ref in COMMITS.items()}
pairs={}
for left,right in PAIRS:
    key=f"{left}_to_{right}"
    pairs[key]={}
    for scope,paths in SCOPES.items():
        rows=numstat(COMMITS[left],COMMITS[right],paths)
        pairs[key][scope]=summarize(rows)
relations={
 "remote_e4e_descends_from_local_715":False,
 "local_7af_descends_from_local_715":True,
 "local_715_and_remote_e4e_share_merge_base":COMMITS["merge_base"],
}
original_name="OHScanner_G盘源码漏洞审查记录_20261018.md"
tree_raw=git("ls-tree","-r","-z",COMMITS["remote_e4e"])
original=None
for item in tree_raw.split(b"\0"):
    if not item: continue
    meta,path_raw=item.split(b"\t",1)
    path=path_raw.decode("utf-8","replace")
    if path.endswith(original_name):
        mode,typ,oid=meta.decode().split()
        original={"path":path,"mode":mode,"type":typ,"git_blob":oid}
        break
payload={
 "schema":"c9-git-readonly-diff-matrix/v1",
 "generated_at":datetime.now(timezone.utc).isoformat(),
 "checkout":str(REPO),
 "commands":"read-only git show/diff/ls-tree only; no fetch/checkout/reset/push/merge",
 "identities":identities,
 "relations":relations,
 "source_audit_original_in_remote_e4e":original,
 "pair_scopes":pairs,
}
(OUT/"git_readonly_diff_matrix.json").write_text(json.dumps(payload,ensure_ascii=False,indent=2,default=lambda value: value.decode("utf-8","replace") if isinstance(value, bytes) else str(value))+"\n",encoding="utf-8")
print(json.dumps({"pairs":list(pairs),"original":original},ensure_ascii=False,indent=2))



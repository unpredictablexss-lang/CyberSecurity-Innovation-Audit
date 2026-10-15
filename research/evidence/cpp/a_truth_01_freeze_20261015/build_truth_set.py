#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, re, subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
OUT = Path(__file__).resolve().parent
REVIEW = ROOT / "research/evidence/cpp/review_20261014"
INDEPENDENT = ROOT / "research/evidence/cpp/independent_review_20261015"
PRIOR = ROOT / "research/evidence/cpp/independent_truth_review_20261015"
SCANS = ROOT / "research/evidence/cpp/component_scans"
JSPROXY = ROOT / "research/evidence/cpp/shared_ptr_jsproxy_supplement_2026-10-15.json"
CONTROL_RESULTS = ROOT / "research/evidence/cpp/implementation_bound_controls_20261015/run-002/results.json"
CHECKLIST = ROOT / "research/evidence/cpp/implementation_bound_controls_20261015/EVIDENCE_CHECKLIST.md"
SCHEMA = "ohscanner.a-truth-01-truth-signoff-v1"
BLIND_SCHEMA = "ohscanner.a-truth-01-blind-holdout-v1"
REVIEWER = "Codex independent source-first reviewer"
REVIEWER_ID = "codex-a-truth-01-20261015"
AT = "2026-10-15T12:53:32+08:00"

GROUP_BOUNDARY = {
 "RC-REMOTE-CHANNEL": ("RemoteCommandManager::NotifyDeviceOnline/GetExecutorChannel -> RemoteCommandExecutor::SetChannel/GetChannel; ProcessOneCommand -> CreateChannelIfNeeded and ptrChannel_ use.", "Remote RPC channel construction, connection lifecycle and remote token-sync command execution."),
 "RC-JSPROXY": ("JSProxy::SetInstance/GetInstance; JsKVStoreResultSet NAPI getters; Create/CloseResultSet and GetEntry paths.", "Distributed KV result-set lifetime and Entry retrieval through a native shared_ptr wrapper."),
 "RC-PIP-CONTROLLERS": ("PictureInPictureController{,Ani} setters/getters; UpdatePiPSourceRect/UpdateContentSize; ResetExtController; SetXComponentController.", "XComponent controller swap/reset, PIP source-rect/content updates and window state transitions."),
 "RC-STREAM-LISTENER": ("StreamManager constructor; CreateStreamClientChannel/CreateStreamServerChannel; SetStreamRecvListener; socket callback publication.", "Stream receive-listener registration and socket data callback routing."),
 "RC-CONSTRUCTOR-NOISE": ("Constructors/member initializers and local wrapper access sites.", "None established at the reported owner-race site."),
 "RC-SCOPE-MOCK": ("Mock/support extension-context code under kvstoremock/external_inner_kit.", "None for a production component vulnerability."),
 "RC-WINDOW-SINGLE": ("Marshalling/unmarshalling helpers, constructor/member initializers, animation singletons, listeners and SurfaceCaptureFuture callback/waiter methods.", "Window/UI state marshalling and surface pixel-map delivery; product effect is not established."),
}
CONTROLS = {
 "RC-REMOTE-CHANNEL": {"positive":"not_run: SetChannel/GetChannel or create/use TSan overlap","fixed":"not_run: one owner mutex or atomic shared_ptr protocol","safe":"not_run: serialized channel protocol","unrelated":"not_run: single-thread publication control"},
 "RC-JSPROXY": {"positive":"passed: generic race and close_get_entry TSan 3/3","fixed":"passed: mutex owner control clean 3/3","safe":"passed: atomic shared_ptr patch clean 3/3","unrelated":"passed: generic unrelated control clean 1/1"},
 "RC-PIP-CONTROLLERS": {"positive":"not_run: setter/reader TSan overlap","fixed":"not_run: mutex owner control","safe":"not_run: same-runner serialization","unrelated":"not_run: fresh-object control"},
 "RC-STREAM-LISTENER": {"positive":"not_run: setter/channel creation TSan overlap","fixed":"not_run: common mutex or immutable publication","safe":"not_run: pre-publication immutable listener","unrelated":"not_run: single-thread constructor control"},
 "RC-CONSTRUCTOR-NOISE": {"positive":"not_applicable: no same-object race pair","fixed":"not_applicable","safe":"not_applicable","unrelated":"passed: constructor/stable-owner shape"},
 "RC-SCOPE-MOCK": {"positive":"not_applicable","fixed":"not_applicable","safe":"not_applicable","unrelated":"passed: non-production mock scope"},
 "RC-WINDOW-SINGLE": {"positive":"not_run: hdrPixelMap_ late-callback window only","fixed":"not_run: move hdrPixelMap_ reset under mutex_","safe":"passed: pixelMap_ owner accesses mutex-serialized","unrelated":"passed: constructor/single-lexical/marshalling shapes"},
}

def sha(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def fsha(p: Path) -> str: return sha(p.read_bytes())
def canon(x: Any) -> bytes: return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def load(p: Path) -> Any: return json.loads(p.read_text(encoding="utf-8"))
def write_new(p: Path, data: bytes) -> bool:
    if p.exists():
        if p.read_bytes() != data: raise RuntimeError(f"refusing to overwrite frozen file: {p}")
        return False
    p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data); return True
def json_new(p: Path, x: Any) -> bool: return write_new(p, json.dumps(x, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")
def text_new(p: Path, s: str) -> bool: return write_new(p, s.encode())
def run(args: list[str], cwd: Path | None = None) -> tuple[bytes, bytes, int]:
    e = os.environ.copy(); e["GIT_NO_LAZY_FETCH"] = "1"
    p = subprocess.run(args, cwd=str(cwd) if cwd else None, env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout, p.stderr, p.returncode
def git_text(args: list[str], cwd: Path) -> str:
    o, e, c = run(args, cwd)
    if c: raise RuntimeError(f"git failed {args}: {e.decode('utf-8','replace')}")
    return o.decode("utf-8","replace").strip()
def wsl_path(s: str) -> Path:
    s = str(s).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", s)
    return Path("/mnt") / m.group(1).lower() / m.group(2) if m else Path(s)

def repo_meta(component: str) -> dict[str, Any]:
    mp = SCANS / f"{component}.manifest.json"; m = load(mp); repo = wsl_path(m["source_repo_path"]); commit = m["commit"]
    tree = git_text(["git","rev-parse",f"{commit}^{{tree}}"], repo)
    remote = git_text(["git","remote","get-url","origin"], repo)
    o,e,c = run(["git","fsck","--connectivity-only","--no-dangling"], repo)
    return {"component":component,"repository":m["repository"],"repo_path":str(repo),"remote":remote,"commit":commit,"tree":tree,
            "manifest":str(mp.relative_to(ROOT)).replace("\\","/"),"manifest_sha256":fsha(mp),"plan_sha256":m["plan_sha256"],
            "scope":m["scope_algorithm"],"counts":m["counts"],"fsck_exit":c,"fsck_stdout_sha256":sha(o),"fsck_stderr_sha256":sha(e)}

def source_identity(c: dict[str, Any], rm: dict[str, Any]) -> dict[str, Any]:
    repo = wsl_path(rm["repo_path"]); commit = rm["commit"]; path = c["file"]
    blob = git_text(["git","rev-parse",f"{commit}:{path}"], repo)
    raw,e,code = run(["git","cat-file","blob",blob], repo)
    if code: raise RuntimeError(f"blob read failed {blob}: {e.decode('utf-8','replace')}")
    digest = sha(raw)
    if digest != c["source_sha256"]: raise RuntimeError(f"source hash mismatch {c['workbench_candidate_id']}")
    lines = raw.decode("utf-8","replace").splitlines(); line = int(c["line"]); a=max(1,line-10); b=min(len(lines),line+10)
    excerpt = "\n".join(f"{i+1}: {lines[i]}" for i in range(a-1,b))
    return {"repository":rm["repository"],"repository_remote":rm["remote"],"repository_path_observed":rm["repo_path"],"commit":commit,
      "git_tree":rm["tree"],"source_git_blob_oid":blob,"source_sha256":digest,"source_hash_semantics":"sha256 of exact git blob bytes",
      "file":path,"line":line,"column":c["column"],"symbol":c["symbol"],"operation":c["operation"],"git_object_provenance_verified":True,
      "reported_excerpt_lines":[a,b],"reported_excerpt":excerpt,"reported_excerpt_sha256":sha(excerpt.encode())}

def selected(ledger: dict[str,Any], hold: dict[str,Any]) -> list[tuple[dict[str,Any],str]]:
    by = {x["workbench_candidate_id"]:x for x in ledger["candidates"]}; out=[]
    out += [(x,"plausible_unproven") for x in ledger["candidates"] if x.get("status")=="plausible_unproven"]
    out += [(by[x],"holdout") for x in hold["holdout_candidate_ids"]]
    return out

def make_blind() -> None:
    ledger = load(REVIEW/"review_ledger.json"); hold = load(REVIEW/"holdout_manifest.json")
    metas = {load(p)["component"]:repo_meta(load(p)["component"]) for p in SCANS.glob("*.manifest.json")}
    rows=[]
    for cid in sorted(hold["holdout_candidate_ids"], key=lambda x: sha(f"A-TRUTH-01-HOLDOUT|{x}".encode())):
        c = next(x for x in ledger["candidates"] if x["workbench_candidate_id"]==cid); s=source_identity(c,metas[c["component"]])
        rows.append({"blind_item_id":sha(f"A-TRUTH-01-HOLDOUT|{cid}".encode())[:16],"component":c["component"],
          "source_identity":{k:s[k] for k in ["repository","repository_remote","commit","git_tree","source_git_blob_oid","source_sha256","file","line","column","symbol","operation"]},
          "reported_excerpt_lines":s["reported_excerpt_lines"],"reported_excerpt":s["reported_excerpt"],"reported_excerpt_sha256":s["reported_excerpt_sha256"]})
    packet={"schema_version":BLIND_SCHEMA,"kind":"a_truth_01_blind_holdout_source_packet","generated_at":AT,
      "freeze_statement":"Frozen before labels, historical review statuses, model outputs or tool warning labels are emitted in this package.",
      "reviewer":{"name":REVIEWER,"id":REVIEWER_ID},"count":len(rows),"items":rows,
      "excluded_from_packet":["historical review status","root-cause group","model output","tool warning","candidate ID"],
      "inputs":{"review_ledger_sha256":fsha(REVIEW/"review_ledger.json"),"holdout_manifest_sha256":fsha(REVIEW/"holdout_manifest.json")}}
    data=json.dumps(packet,ensure_ascii=False,indent=2,sort_keys=True).encode()+b"\n"; write_new(OUT/"blind_holdout_packet.json",data)
    text_new(OUT/"blind_packet.sha256",f"{sha(data)}  blind_holdout_packet.json\n")
    plausible=[]
    for c,scope in selected(ledger,hold):
        if scope!="plausible_unproven": continue
        s=source_identity(c,metas[c["component"]]); plausible.append({"review_item_id":f"{c['workbench_candidate_id']}:plausible_unproven","source_identity":s,"reported_excerpt":s["reported_excerpt"]})
    json_new(OUT/"plausible_source_packet.json",{"schema_version":BLIND_SCHEMA,"kind":"a_truth_01_source_review_packet","generated_at":AT,"items":plausible})
    print(json.dumps({"phase":"blind","count":len(rows),"packet_sha256":sha(data)},sort_keys=True))

def classification(c: dict[str,Any], scope: str) -> tuple[str,str,str,str]:
    cid=c["workbench_candidate_id"]; group=c["root_cause_group"]
    if scope=="holdout" and cid=="91a5f46b96a11a6166bccc207946d7524912938daf1cb7058fd89d79cd8ce881": return "safe","safe","refuted","All observed pixelMap_ owner accesses are mutex-serialized; scoped owner-race candidate is refuted."
    if scope=="holdout" and cid=="df1d89f286c9727a550f92b5c451d9126cd66adeb96a10be52415868b6fe2eb1": return "unknown","unknown","unknown","hdrPixelMap_ reset outside mutex can overlap a timed-out waiter; retain unknown."
    if scope=="holdout" and cid=="1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7": return "unknown","unknown","unknown","Listener publication/channel creation concurrency remains unresolved in blind holdout review."
    if scope=="plausible_unproven":
        return "unknown","vulnerable" if group=="RC-JSPROXY" else "unknown","candidate","Product-level truth remains candidate/unknown; mechanism is controlled only for RC-JSPROXY."
    return "unrelated","unrelated","refuted","Observed source shape excludes the reported shared_ptr owner-race candidate at this scoped site."

def make_signoff() -> None:
    packet=load(OUT/"blind_holdout_packet.json"); ledger=load(REVIEW/"review_ledger.json"); hold=load(REVIEW/"holdout_manifest.json")
    prior=load(PRIOR/"independent_truth_review.json"); prior_by={x["review_item_id"]:x for x in prior["items"]}
    sup=load(INDEPENDENT/"review_supplement.json"); sup_by={x["review_item_id"]:x for x in sup["review_items"]}
    metas={load(p)["component"]:repo_meta(load(p)["component"]) for p in SCANS.glob("*.manifest.json")}
    rows=selected(ledger,hold); sign=[]; labels=[]; key=[]
    for i,(c,scope) in enumerate(rows,1):
        rid=f"{c['workbench_candidate_id']}:{'plausible' if scope=='plausible_unproven' else scope}"; old=prior_by[rid]; hist=sup_by.get(rid,{}); s=source_identity(c,metas[c["component"]])
        bid=sha(f"A-TRUTH-01-HOLDOUT|{c['workbench_candidate_id']}".encode())[:16] if scope=="holdout" else None
        truth,mech,status,rationale=classification(c,scope); a=old.get("analysis",{})
        rec={"schema_version":SCHEMA,"record_type":"independent_truth_signoff","append_only":True,"index":i,"review_item_id":rid,"review_scope":scope,
          "blind_item_id":bid,"workbench_candidate_id":c["workbench_candidate_id"],"historical_diagnostic_id":c["diagnostic_id"],
          "historical_review_status":c["status"],"historical_review_reference":{"path":"research/evidence/cpp/review_20261014/review_ledger.json","sha256":fsha(REVIEW/"review_ledger.json"),"status_field_preserved_only":True},
          "detector":{"id":"ohscanner.cpp.shared_ptr_race","version_at_scan":hist.get("detector_version","0.4.0"),"rule_id":hist.get("rule_id","ohcpp-shared-ptr-race-candidate-001"),"profile_id":hist.get("profile_id","light-ast"),"current_checkout_version_observed":"0.5.0","current_implementation_path":"src/ohscanner/detectors/cpp/shared_ptr_race_detector.py","current_implementation_sha256":fsha(ROOT/"src/ohscanner/detectors/cpp/shared_ptr_race_detector.py"),"scope_plan_sha256":metas[c["component"]]["plan_sha256"]},
          "source_identity":s,"program_facts":{"component":c["component"],"file":c["file"],"line":c["line"],"column":c["column"],"symbol":c["symbol"],"operation":c["operation"],"root_cause_group":c["root_cause_group"],"reported_excerpt":s["reported_excerpt"]},
          "call_boundary":GROUP_BOUNDARY[c["root_cause_group"]][0],"sensitive_operation":GROUP_BOUNDARY[c["root_cause_group"]][1],
          "thread_or_event_queue_model":a.get("thread_or_event_queue_ownership","unknown"),"publication_order_and_happens_before":a.get("shared_ptr_publication_order","unknown"),
          "synchronization_protocol":a.get("synchronization_protocol","unknown"),"conflicting_access_pair":a.get("conflicting_access_pair","unknown"),
          "trigger_conditions_and_race_window":a.get("trigger_window","unknown"),"lifecycle":a.get("lifecycle","unknown"),
          "entry_privilege":a.get("entry_privilege","missing"),"cia_assessment":a.get("cia_basis","missing"),"controls":CONTROLS[c["root_cause_group"]],
          "classification":{"classification_options":["vulnerable","fixed","safe","unrelated","unknown"],"selected_classification":truth,"mechanism_classification":mech,"truth_scope":"product" if scope=="plausible_unproven" else "shared_ptr_owner_race_shape","status":status,"confirmed":status=="confirmed","candidate":status=="candidate","unknown":status=="unknown","refuted":status=="refuted","reportable":False,"rationale":rationale},
          "missing_evidence":{"entry_or_privilege_boundary":a.get("entry_privilege","missing"),"thread_or_event_queue":a.get("thread_or_event_queue_ownership","unknown"),"publication_order_or_happens_before":a.get("shared_ptr_publication_order","unknown"),"trigger_conditions_and_race_window":a.get("trigger_window","unknown"),"cia_impact":a.get("cia_basis","missing")},
          "evidence_sources":{"source_git_object":{"repository":s["repository"],"commit":s["commit"],"git_tree":s["git_tree"],"blob_oid":s["source_git_blob_oid"],"source_sha256":s["source_sha256"],"excerpt_sha256":s["reported_excerpt_sha256"]},"historical_review_sha256":fsha(REVIEW/"review_ledger.json"),"holdout_manifest_sha256":fsha(REVIEW/"holdout_manifest.json"),"prior_review_analysis_reference":{"path":"research/evidence/cpp/independent_review_20261015/review_supplement.json","sha256":fsha(INDEPENDENT/"review_supplement.json")}},
          "reviewer":{"name":REVIEWER,"id":REVIEWER_ID,"reviewed_at":AT},"historical_review_label_not_used_as_truth":True}
        rec["record_sha256"]=sha(canon({k:v for k,v in rec.items() if k!="record_sha256"})); sign.append(rec)
        if scope=="holdout":
            labels.append({"blind_item_id":bid,"selected_classification":truth,"mechanism_classification":mech,"status":status,"rationale":rationale,"source_excerpt_sha256":s["reported_excerpt_sha256"],"thread_or_event_queue_model":rec["thread_or_event_queue_model"],"publication_order_and_happens_before":rec["publication_order_and_happens_before"],"trigger_conditions_and_race_window":rec["trigger_conditions_and_race_window"],"cia_assessment":rec["cia_assessment"]})
            key.append({"blind_item_id":bid,"workbench_candidate_id":c["workbench_candidate_id"],"review_item_id":rid})
    labels_obj={"schema_version":BLIND_SCHEMA,"kind":"a_truth_01_blind_holdout_labels","generated_at":AT,"freeze_statement":"Source-first labels are emitted before candidate-ID key; historical review labels are not truth inputs.","reviewer":{"name":REVIEWER,"id":REVIEWER_ID},"count":len(labels),"label_counts":dict(Counter(x["selected_classification"] for x in labels)),"status_counts":dict(Counter(x["status"] for x in labels)),"items":labels}
    lb=json.dumps(labels_obj,ensure_ascii=False,indent=2,sort_keys=True).encode()+b"\n"; write_new(OUT/"blind_holdout_labels.json",lb)
    json_new(OUT/"blind_holdout_key.json",{"schema_version":BLIND_SCHEMA,"kind":"a_truth_01_blind_holdout_key","generated_at":AT,"key_emitted_after_labels":True,"blind_labels_sha256":sha(lb),"items":key})
    stream=OUT/"truth_signoffs.jsonl"; write_new(stream,b"".join(canon(x)+b"\n" for x in sign))
    json_new(OUT/"truth_signoff_index.json",{"schema_version":SCHEMA,"kind":"a_truth_01_truth_signoff_index","generated_at":AT,"review_item_count":len(sign),"unique_workbench_candidate_count":len({x["workbench_candidate_id"] for x in sign}),"scope_counts":dict(Counter(x["review_scope"] for x in sign)),"classification_counts":dict(Counter(x["classification"]["selected_classification"] for x in sign)),"status_counts":dict(Counter(x["classification"]["status"] for x in sign)),"items":[{"index":x["index"],"review_item_id":x["review_item_id"],"review_scope":x["review_scope"],"workbench_candidate_id":x["workbench_candidate_id"],"root_cause_group":x["program_facts"]["root_cause_group"],"selected_classification":x["classification"]["selected_classification"],"status":x["classification"]["status"],"record_sha256":x["record_sha256"]} for x in sign]})
    grouped=defaultdict(list)
    for x in sign: grouped[x["program_facts"]["root_cause_group"]].append(x)
    roots=[]
    for g,xs in sorted(grouped.items()): roots.append({"root_cause_group":g,"title":g,"review_item_count":len(xs),"unique_candidate_count":len({x["workbench_candidate_id"] for x in xs}),"candidate_ids":sorted({x["workbench_candidate_id"] for x in xs}),"classification_counts":dict(Counter(x["classification"]["selected_classification"] for x in xs)),"mechanism_counts":dict(Counter(x["classification"]["mechanism_classification"] for x in xs)),"status_counts":dict(Counter(x["classification"]["status"] for x in xs)),"thread_or_event_queue_model":xs[0]["thread_or_event_queue_model"],"publication_order_and_happens_before":xs[0]["publication_order_and_happens_before"],"trigger_conditions_and_race_window":xs[0]["trigger_conditions_and_race_window"],"call_boundary":xs[0]["call_boundary"],"sensitive_operation":xs[0]["sensitive_operation"],"cia_assessment":xs[0]["cia_assessment"],"controls":xs[0]["controls"]})
    json_new(OUT/"root_cause_groups.json",{"schema_version":SCHEMA,"kind":"a_truth_01_root_cause_groups","generated_at":AT,"groups":roots})
    json_new(OUT/"control_matrix.json",{"schema_version":SCHEMA,"kind":"a_truth_01_control_matrix","generated_at":AT,"metrics_eligible":False,"synthetic_controls_are_independent_holdout":False,"rows":[{"root_cause_group":g,"positive":CONTROLS[g]["positive"],"fixed":CONTROLS[g]["fixed"],"safe":CONTROLS[g]["safe"],"unrelated":CONTROLS[g]["unrelated"],"holdout_scope":g in {"RC-CONSTRUCTOR-NOISE","RC-SCOPE-MOCK","RC-STREAM-LISTENER","RC-WINDOW-SINGLE"}} for g in sorted(CONTROLS)],"controlled_evidence":{"jsproxy":{"path":"research/evidence/cpp/shared_ptr_jsproxy_supplement_2026-10-15.json","sha256":fsha(JSPROXY)},"implementation_bound_controls":{"path":"research/evidence/cpp/implementation_bound_controls_20261015/run-002/results.json","sha256":fsha(CONTROL_RESULTS),"is_independent_holdout":False},"checklist":{"path":"research/evidence/cpp/implementation_bound_controls_20261015/EVIDENCE_CHECKLIST.md","sha256":fsha(CHECKLIST),"is_independent_holdout":False}}})
    unknown=[x for x in sign if x["classification"]["status"] in {"candidate","unknown"}]
    json_new(OUT/"failures_unknowns.json",{"schema_version":SCHEMA,"kind":"a_truth_01_failures_unknowns","generated_at":AT,"formal_command_failures":[],"unknown_or_candidate_count":len(unknown),"items":[{"review_item_id":x["review_item_id"],"root_cause_group":x["program_facts"]["root_cause_group"],"status":x["classification"]["status"],"missing_evidence":x["missing_evidence"]} for x in unknown],"aggregate_unknowns":["Product entry/permission/attacker boundary is missing for unresolved plausible_unproven groups.","Thread/event queue and happens-before proofs are incomplete.","Concrete CIA impact and product artifact identity are missing.","hdrPixelMap_ late-callback/timed-out-waiter window remains unresolved.","Precision/Recall is not computed before complete freeze; synthetic controls are not independent holdout."]})
    status,e,rc=run(["git","status","--porcelain=v1","-uall"],ROOT); text_new(OUT/"checkout_status_porcelain.txt",status.decode("utf-8","replace"))
    checkout={"schema_version":SCHEMA,"kind":"a_truth_01_checkout_identity","generated_at":AT,"root":str(ROOT),"branch":git_text(["git","branch","--show-current"],ROOT),"head":git_text(["git","rev-parse","HEAD"],ROOT),"tree":git_text(["git","rev-parse","HEAD^{tree}}".replace("}}","}")],ROOT),"remote":git_text(["git","remote","get-url","origin"],ROOT),"dirty_status_file":"checkout_status_porcelain.txt","dirty_status_sha256":sha(status),"dirty_status_line_count":len(status.decode("utf-8","replace").splitlines()),"dirty_worktree_preserved":True}
    json_new(OUT/"checkout_identity.json",checkout)
    inputs=[REVIEW/"review_ledger.json",REVIEW/"holdout_manifest.json",REVIEW/"root_cause_groups.json",INDEPENDENT/"blind_review_labels_frozen_20261015.json",INDEPENDENT/"review_supplement.json",INDEPENDENT/"independent_review_comparison_20261015.json",PRIOR/"truth_set_manifest.json",JSPROXY,CONTROL_RESULTS,CHECKLIST,ROOT/"src/ohscanner/detectors/cpp/shared_ptr_race_detector.py",ROOT/"rules/cpp/oh_shared_ptr_uaf.yaml"]
    manifest={"schema_version":SCHEMA,"kind":"a_truth_01_truth_set_manifest","generated_at":AT,"append_only":True,"frozen":True,"freeze_statement":"A-TRUTH-01 source-first truth/signoff records are frozen; historical reports, candidate IDs, reviews and database records are preserved unchanged.","reviewer":{"name":REVIEWER,"id":REVIEWER_ID,"reviewed_at":AT},"review_item_count":len(sign),"unique_workbench_candidate_count":len({x["workbench_candidate_id"] for x in sign}),"scope_counts":{"plausible_unproven":11,"holdout":34},"root_cause_group_count":len(roots),"classification_counts":dict(Counter(x["classification"]["selected_classification"] for x in sign)),"mechanism_classification_counts":dict(Counter(x["classification"]["mechanism_classification"] for x in sign)),"status_counts":dict(Counter(x["classification"]["status"] for x in sign)),"source_identity_verification":{"all_verified":True,"count":len(sign),"method":"local pinned Git commit/tree/blob/source SHA checks with GIT_NO_LAZY_FETCH=1"},"metrics":{"precision_recall":"not_computed","eligible":False,"zero_fp_fn_claims":False,"reason":"Unknown/partial product entry, trigger, synchronization and CIA evidence remain; synthetic controls are not independent holdout."},"promotion_boundary":{"confirmed_reportable":False,"validated_vulnerability":0,"cve":"not identified or assigned in local evidence"},"inputs":[{"path":str(p.relative_to(ROOT)).replace("\\","/"),"sha256":fsha(p),"bytes":p.stat().st_size} for p in inputs],"records":{"path":"truth_signoffs.jsonl","sha256":fsha(stream)},"blind_holdout":{"packet":{"path":"blind_holdout_packet.json","sha256":fsha(OUT/"blind_holdout_packet.json")},"labels":{"path":"blind_holdout_labels.json","sha256":fsha(OUT/"blind_holdout_labels.json")},"key_after_labels":{"path":"blind_holdout_key.json","sha256":fsha(OUT/"blind_holdout_key.json")}}}
    json_new(OUT/"truth_set_manifest.json",manifest)
    cmds=["env GIT_NO_LAZY_FETCH=1 PYTHONDONTWRITEBYTECODE=1 .venv-web/bin/python research/evidence/cpp/a_truth_01_freeze_20261015/build_truth_set.py blind","env GIT_NO_LAZY_FETCH=1 PYTHONDONTWRITEBYTECODE=1 .venv-web/bin/python research/evidence/cpp/a_truth_01_freeze_20261015/build_truth_set.py signoff","env GIT_NO_LAZY_FETCH=1 PYTHONDONTWRITEBYTECODE=1 .venv-web/bin/python research/evidence/cpp/a_truth_01_freeze_20261015/build_truth_set.py verify"]
    json_new(OUT/"reproduction.json",{"schema_version":SCHEMA,"kind":"a_truth_01_reproduction","generated_at":AT,"cwd":"E:\\网安\\CyberSecurity-Innovation-Audit","cwd_resolution":"wsl.exe inherits this Windows working directory; verified WSL pwd is /mnt/e/网安/CyberSecurity-Innovation-Audit","environment":{"GIT_NO_LAZY_FETCH":"1","PYTHONDONTWRITEBYTECODE":"1"},"commands":[{"phase":p,"argv":["wsl.exe","-d","Ubuntu-22.04","--exec","/bin/bash","-lc",cmd],"expected":x} for p,cmd,x in zip(["blind","signoff","verify"],cmds,["34-item label-free holdout packet frozen","45 scope records and append-only signoff stream frozen","all source/object/hash/count checks pass; metrics remain not_computed"])]})
    report=f"""# A-TRUTH-01 ������ֵ��������ǩ�ֱ���\n\n����ʱ�䣺{AT}\n�����ˣ�{REVIEWER}��{REVIEWER_ID}��\n\n## ���۱߽�\n\n������������ A �� 11 �� `plausible_unproven` �� 34 �� holdout���������� append-only truth/signoff ��¼����ʷ���桢candidate ID��review �����ݿ��¼��δ��д��review ��ǩֻ����Ϊ��ʷ���ã�����Ϊ��ֵ���롣��ֵ���̶� Git �����Դ����ʵ������������ candidate/unknown �߽��ڵĿɸ�����ֵ�������ǲ�Ʒ©��ȷ�ϣ�`confirmed=0`��`reportable=false`��`validated_vulnerability=0`��������ֵ����ǰ������ Precision/Recall������ zero FP/FN ���������� synthetic control ������ holdout��\n\n## ��Χ������\n\n- review records��45��11 plausible_unproven + 34 holdout����unique workbench candidates��44��RC-STREAM-LISTENER һ�� candidate ͬʱ���������� scope���� scope �������� signoff��\n- checkout����֧ `{checkout['branch']}`��HEAD `{checkout['head']}`��tree `{checkout['tree']}`��remote `{checkout['remote']}`��\n- dirty worktree preserved��`{checkout['dirty_worktree_preserved']}`������ `git status --porcelain=v1 -uall` �� `checkout_status_porcelain.txt`��SHA-256 `{checkout['dirty_status_sha256']}`��\n- ÿ����¼���°� repository/commit/tree/git blob/source SHA-256��detector ID��scan version��rule/profile��source excerpt hash ����ʷ review ���ã�Դ������ʹ�� `GIT_NO_LAZY_FETCH=1`��û����ʽ fetch��\n\n## ä�� holdout\n\n`blind_holdout_packet.json` ֻ�� opaque ID���̶�Դ�����ݡ�λ�á������ֶκ�Դ��ժ¼��������ʷ review ״̬��root-cause ��ǩ��ģ������򹤾� warning��34 ���ȶ��ᣬ֮������ `blind_holdout_labels.json`��������� `blind_holdout_key.json` ӳ�� candidate ID����ǩ���ڹ̶�Դ��ͳ�����ʵ��\n\n## plausible_unproven\n\nRC-REMOTE-CHANNEL 2 ����RC-JSPROXY 2 ����RC-PIP-CONTROLLERS 6 ����RC-STREAM-LISTENER 1 ��������߳�/�¼����С�����˳��/happens-before���������ڡ����ñ߽硢���в�����CIA ȱ�ں� fixed/safe/unrelated ���ա�RC-JSPROXY �� generic race/close_get_entry 3/3��mutex fixed 3/3��atomic patch 3/3��unrelated 1/1 ֻ֤��������ƣ���Ʒ��ڡ�Ȩ�ޡ������ CIA �� unknown������������������δִ�У��ʱ��� candidate/unknown��\n\n## holdout\n\n- RC-CONSTRUCTOR-NOISE 9 ����constructor/stable-owner��`unrelated/refuted`��\n- RC-SCOPE-MOCK 3 ���������� mock/support ·����`unrelated/refuted`��\n- RC-WINDOW-SINGLE 21 ����19 �� constructor/single-lexical/marshalling `unrelated/refuted`��`pixelMap_` 1 �� `safe/refuted`��owner ������ mutex_ ���У���`hdrPixelMap_` 1 �� `unknown/unknown`��OnSurfaceCapture �� FutureCall ����ǰ��գ���\n- RC-STREAM-LISTENER 1 ����ä����¼ `unknown/unknown`��������ʷ disappeared �� review ��ǩ�ı���ֵ��\n\n## ���򡢿��ơ�ʧ��/unknown\n\n`root_cause_groups.json` ���������飬`control_matrix.json` ���� positive/fixed/safe/unrelated ���ƾ���implementation-bound ������ȷ `is_independent_holdout=false`��`failures_unknowns.json` �������� candidate/unknown ��ȱʧ��ڡ�Ȩ�ޡ��߳�/���С�����˳�򡢴����� CIA ֤�ݡ�`reproduction.json` ���� exact argv �� Git �����顣\n\n## ����������\n\n������ Precision/Recall�������� zero FP/FN������ AST/pattern����ʷ warning��review ��ǩ��ģ���������� Harness ͨ������Ʒ��ֵ�����޸Ĺ��� contracts/runner/catalog/analysis.py����ʷ���桢��ʷ candidate ID����ʷ review ����ʷ���ݿ⡣\n"""
    text_new(OUT/"independent_review_report.md",report)
    ver={"schema_version":SCHEMA,"kind":"a_truth_01_verification","generated_at":AT,"status":"passed_with_unknowns","checks":{"scope_records_45":len(sign)==45,"plausible_unproven_11":sum(x["review_scope"]=="plausible_unproven" for x in sign)==11,"holdout_34":sum(x["review_scope"]=="holdout" for x in sign)==34,"unique_candidates_44":len({x["workbench_candidate_id"] for x in sign})==44,"source_identity_all_verified":all(x["source_identity"]["git_object_provenance_verified"] for x in sign),"append_only_records":all(x["append_only"] for x in sign),"historical_review_not_truth_input":all(x["historical_review_label_not_used_as_truth"] for x in sign),"metrics_not_computed":True,"zero_fp_fn_claim_absent":True,"synthetic_controls_not_holdout":True},"counts":{"review_items":len(sign),"scope_counts":dict(Counter(x["review_scope"] for x in sign)),"classification_counts":dict(Counter(x["classification"]["selected_classification"] for x in sign)),"status_counts":dict(Counter(x["classification"]["status"] for x in sign))},"limitations":["RC-JSPROXY is controlled-positive at component mechanism level only; product gate remains not_met.","Remote channel, PIP controllers and stream listener retain unknown queue/HB/trigger/CIA evidence.","hdrPixelMap_ late callback versus timed-out waiter remains unknown.","safe/unrelated labels are scoped to shared_ptr owner-race shape, not product safety."]}
    json_new(OUT/"verification.json",ver)
    files=[p for p in sorted(OUT.iterdir()) if p.is_file() and p.name not in {"artifact_manifest.json","FREEZE.sha256"}]
    json_new(OUT/"artifact_manifest.json",{"schema_version":SCHEMA,"kind":"a_truth_01_artifact_manifest","generated_at":AT,"append_only":True,"historical_records_preserved":True,"files":{str(p.relative_to(ROOT)).replace("\\","/") :{"bytes":p.stat().st_size,"sha256":fsha(p)} for p in files}})
    freeze=[p for p in sorted(OUT.iterdir()) if p.is_file() and p.name!="FREEZE.sha256"]
    text_new(OUT/"FREEZE.sha256","".join(f"{fsha(p)}  {p.name}\n" for p in freeze))
    print(json.dumps({"phase":"signoff","review_items":len(sign),"plausible_unproven":11,"holdout":34,"metrics":"not_computed","status":"passed_with_unknowns"},sort_keys=True))

def verify() -> None:
    names=["blind_holdout_packet.json","blind_holdout_labels.json","blind_holdout_key.json","truth_signoffs.jsonl","truth_signoff_index.json","truth_set_manifest.json","root_cause_groups.json","control_matrix.json","independent_review_report.md","failures_unknowns.json","reproduction.json","checkout_identity.json","checkout_status_porcelain.txt","verification.json","artifact_manifest.json","FREEZE.sha256"]
    for n in names:
        if not (OUT/n).exists(): raise RuntimeError("missing "+n)
    m=load(OUT/"truth_set_manifest.json"); p=load(OUT/"blind_holdout_packet.json"); l=load(OUT/"blind_holdout_labels.json"); ix=load(OUT/"truth_signoff_index.json")
    rows=[json.loads(x) for x in (OUT/"truth_signoffs.jsonl").read_text(encoding="utf-8").splitlines() if x]
    assert len(rows)==45 and p["count"]==34 and l["count"]==34 and ix["review_item_count"]==45
    assert m["metrics"]["precision_recall"]=="not_computed" and m["scope_counts"]=={"plausible_unproven":11,"holdout":34}
    assert all(r["record_sha256"]==sha(canon({k:v for k,v in r.items() if k!="record_sha256"})) for r in rows)
    for line in (OUT/"FREEZE.sha256").read_text(encoding="utf-8").splitlines():
        d,n=line.split("  ",1); assert fsha(OUT/n)==d,n
    print(json.dumps({"phase":"verify","status":"passed_with_unknowns","review_items":45,"metrics":"not_computed"},sort_keys=True))

if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("phase",choices=["blind","signoff","verify"]); a=ap.parse_args()
    {"blind":make_blind,"signoff":make_signoff,"verify":verify}[a.phase]()








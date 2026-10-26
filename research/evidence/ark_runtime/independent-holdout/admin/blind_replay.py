#!/usr/bin/env python3
"""Run the frozen Ark Runtime detector against the unlabeled holdout; keep raw results in escrow."""
import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
from time import time


def digest(data): return hashlib.sha256(data).hexdigest()

def csv_rows(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as stream: return list(csv.DictReader(stream))

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runtime-repo",required=True)
    ap.add_argument("--scanner-root",required=True)
    ap.add_argument("--manifest",default=str(Path(__file__).with_name("holdout_source_manifest.csv")))
    ap.add_argument("--freeze",default=str(Path(__file__).with_name("frozen_detector.json")))
    ap.add_argument("--escrow-output",required=True)
    ap.add_argument("--summary-output",required=True)
    a=ap.parse_args()
    repo=Path(a.runtime_repo).resolve(); scanner=Path(a.scanner_root).resolve()
    freeze=json.loads(Path(a.freeze).read_text(encoding="utf-8-sig"))
    manifest_path=Path(a.manifest).resolve(); rows=csv_rows(manifest_path)
    sys.path.insert(0,str(scanner))
    from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
    from src.ohscanner.indexing import prepare_git_context
    from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
    from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel,VERSION
    model=RuntimeTypeModel()
    if VERSION!=freeze["detector_version"] or model.digest!=freeze["model_digest_sha256"]:
        raise SystemExit("frozen detector version/model digest mismatch")
    for rel,expected in freeze["implementation_sha256"].items():
        if digest((scanner/rel).read_bytes())!=expected: raise SystemExit("frozen implementation mismatch: "+rel)
    if digest((scanner/"src/parser/ast.py").read_bytes())!=freeze["parser_ast_sha256"]:
        raise SystemExit("frozen parser mismatch")
    if any(r["reviewer_1_label"] or r["reviewer_2_label"] or r["adjudicated_label"] for r in rows):
        raise SystemExit("labels are not blank; do not use this blind runner after any labels are added")
    registry=DetectorRegistry(); registry.register(ArkRuntimeTypeSafetyDetector())
    cases=[]
    for row in rows:
        context,tree,inventory,parse_coverage,sources=prepare_git_context(repo,row["repository"],row["commit"],(row["path"],))
        if tree!=row["tree"] or len(sources)!=1 or sources[0].oid!=row["blob"] or digest(sources[0].data)!=row["source_sha256"]:
            raise SystemExit("manifest source identity mismatch: "+row["sample_id"])
        reports,sidecar=run_all_with_coverage(context,registry)
        report=reports[0].to_dict()
        detector_sidecar=sidecar["detectors"][freeze["detector_id"]]
        cases.append({"sample_id":row["sample_id"],"blind_id":row["blind_id"],"commit":row["commit"],"tree":tree,"path":row["path"],"blob":sources[0].oid,"source_sha256":row["source_sha256"],"parse_status":context.units[0].parse_status,"run":report,"coverage":detector_sidecar})
    escrow={"assessment_id":"ark-runtime-c-independent-holdout-20261018-v2","detector_lock_sha256":digest(Path(a.freeze).read_bytes()),"manifest_sha256":digest(manifest_path.read_bytes()),"blind_packet_sha256":digest(manifest_path.with_name("blind_review_packet.csv").read_bytes()),"labels_frozen_before_run":False,"raw_prediction_escrow":True,"no_source_content_emitted":True,"environment":{"python":sys.version.split()[0],"tree_sitter":importlib.metadata.version("tree-sitter"),"tree_sitter_cpp":importlib.metadata.version("tree-sitter-cpp")},"cases":cases}
    ep=Path(a.escrow_output); ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(escrow,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    run_status_counts={}; parse_counts={}; coverage_counts={}; predicted_candidates=0
    for item in cases:
        status=item["run"]["status"]; run_status_counts[status]=run_status_counts.get(status,0)+1
        ps=item["parse_status"]; parse_counts[ps]=parse_counts.get(ps,0)+1
        cs=item["coverage"]["status"]; coverage_counts[cs]=coverage_counts.get(cs,0)+1
        predicted_candidates+=len(item["run"].get("diagnostics",[]))
    summary={"assessment_id":escrow["assessment_id"],"status":"blind_run_complete_labels_pending","detector_id":freeze["detector_id"],"detector_version":freeze["detector_version"],"model_digest_sha256":freeze["model_digest_sha256"],"scanner_commit":freeze["scanner_commit"],"scanner_tree":freeze["scanner_tree"],"sample_count":len(cases),"labels_frozen_before_run":False,"raw_prediction_escrow_path":"work/prediction-escrow/holdout_run.json","raw_prediction_escrow_sha256":digest(ep.read_bytes()),"source_manifest_sha256":escrow["manifest_sha256"],"blind_packet_sha256":escrow["blind_packet_sha256"],"parse_status_counts":parse_counts,"detector_report_status_counts":run_status_counts,"detector_coverage_status_counts":coverage_counts,"predicted_candidate_count":predicted_candidates,"true_positive_count":None,"false_positive_count":None,"false_negative_count":None,"precision":None,"recall":None,"limitations":["All selected source paths are outside the frozen model's applicable source paths; blocked/not-applicable results are not misses or safe outcomes.","Labels are not independently frozen; candidate hits/false positives/false negatives and all rates remain unestimable.","The blind packet contains no detector output. Keep this summary and escrow file away from reviewers until their label snapshots are frozen."]}
    sp=Path(a.summary_output); sp.parent.mkdir(parents=True,exist_ok=True); sp.write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"samples":len(cases),"candidate_predictions":predicted_candidates,"run_status_counts":run_status_counts,"coverage_status_counts":coverage_counts,"parse_status_counts":parse_counts,"escrow_sha256":summary["raw_prediction_escrow_sha256"]},ensure_ascii=False))
    return 0
if __name__=="__main__": raise SystemExit(main())

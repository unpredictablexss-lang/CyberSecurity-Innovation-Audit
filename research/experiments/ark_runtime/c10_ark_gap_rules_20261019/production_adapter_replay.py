from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel
from src.ohscanner.fixture import snapshot_digest

ARK = Path(r"E:\网安\_oh_targets\arkcompiler_ets_runtime")
OUT = Path(__file__).resolve().parent / "production-adapter-replay.json"
CASES = [
    ("IAO7GO", "3fc1d0b960e0b1bb5bfe1aad8066bb8c9aa99724", "ecmascript/compiler/native_inline_lowering.cpp", "vulnerable"),
    ("IAO7GO", "18d8532a200d0c9aa64a6dfe2b146dc841b52bf8", "ecmascript/compiler/native_inline_lowering.cpp", "fixed"),
    ("I7W51D", "3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c", "ecmascript/base/typed_array_helper.cpp", "vulnerable"),
    ("I7W51D", "82c21d656880923800c94b53b035c76d219313b5", "ecmascript/base/typed_array_helper.cpp", "fixed"),
    ("IB8BCA", "d62f6de64daa7e11a7936a6153748a7c5fae9e41", "ecmascript/base/atomic_helper.cpp", "vulnerable"),
    ("IB8BCA", "48fcec3686e45175f95b4600b579026a65149966", "ecmascript/base/atomic_helper.cpp", "fixed"),
    ("IB8BCA", "d62f6de64daa7e11a7936a6153748a7c5fae9e41", "ecmascript/builtins/builtins_dataview.cpp", "vulnerable"),
    ("IB8BCA", "48fcec3686e45175f95b4600b579026a65149966", "ecmascript/builtins/builtins_dataview.cpp", "fixed"),
    ("IB8BCA", "d62f6de64daa7e11a7936a6153748a7c5fae9e41", "ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp", "vulnerable"),
    ("IB8BCA", "48fcec3686e45175f95b4600b579026a65149966", "ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp", "fixed"),
]

def raw_object(commit, path):
    blob = subprocess.check_output(["git", "rev-parse", f"{commit}:{path}"], cwd=ARK, text=True).strip()
    raw = subprocess.check_output(["git", "cat-file", "blob", blob], cwd=ARK)
    return blob, raw

records = []
for finding_id, commit, path, role in CASES:
    blob, raw = raw_object(commit, path)
    text = raw.decode("utf-8")
    parsed = parse_source(text, "cpp")
    unit = SourceUnit(path, "cpp", text, sha256(text.encode("utf-8")).hexdigest(),
                      parsed.parse_status, tuple(json.dumps(x, sort_keys=True) for x in parsed.parse_issues))
    request = ScanRequest("c10-gap-replay", "openharmony/arkcompiler_ets_runtime", commit,
                          snapshot_digest((unit,)), "current-component:openharmony/arkcompiler_ets_runtime", "light-ast", "git_object")
    facts = {"ast": {path: parsed.to_dict()}, "source_blob_oid": {path: blob}}
    context = ScanContext(request, (unit,), facts)
    run = ArkRuntimeTypeSafetyDetector(model=RuntimeTypeModel()).detect(context, (unit,))
    records.append({
        "finding_id": finding_id,
        "role": role,
        "commit": commit,
        "tree_role_source_identity": {"path": path, "git_blob_sha1": blob, "sha256": unit.sha256},
        "parse_status": unit.parse_status,
        "detector_status": run.status,
        "file_outcomes": list(run.file_outcomes),
        "diagnostic_count": len(run.findings),
        "rule_ids": sorted({x.rule_id for x in run.findings}),
        "candidate_reasons": [x.message for x in run.findings],
        "limitations": list(run.limitations),
    })

summary = {}
for finding_id in ("IAO7GO", "I7W51D", "IB8BCA"):
    vulnerable = sum(x["diagnostic_count"] for x in records if x["finding_id"] == finding_id and x["role"] == "vulnerable")
    fixed = sum(x["diagnostic_count"] for x in records if x["finding_id"] == finding_id and x["role"] == "fixed")
    summary[finding_id] = {"vulnerable_candidate_count": vulnerable, "fixed_candidate_count": fixed,
                           "same_root_1_to_0": vulnerable > 0 and fixed == 0}
payload = {
    "method": "production ArkRuntimeTypeSafetyDetector with pinned commit/path, verified shared Git blob OID, source SHA-256, complete light-ast facts",
    "repository": "openharmony/arkcompiler_ets_runtime",
    "local_pinned_repository": str(ARK),
    "detector_id": ArkRuntimeTypeSafetyDetector.detector_id,
    "detector_version": ArkRuntimeTypeSafetyDetector.version,
    "model_version": RuntimeTypeModel().version,
    "model_digest": RuntimeTypeModel().digest,
    "summary": summary,
    "records": records,
}
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
print(json.dumps(payload, ensure_ascii=False, indent=2))


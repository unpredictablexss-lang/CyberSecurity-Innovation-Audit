from dataclasses import asdict
from hashlib import sha1, sha256
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.ark_runtime.model import (
    RuntimeTypeModel, NATIVE_EXCEPTION_RULE_ID, LENGTH_NARROWING_RULE_ID, INDEX_BOUNDS_RULE_ID,
)
from src.ohscanner.detectors.ark_runtime.runtime_exception import analyze_native_inline_exception_propagation
from src.ohscanner.detectors.ark_runtime.size_overflow import length_narrowing_result, index_bounds_result

ARK = Path(r"E:\网安\_oh_targets\arkcompiler_ets_runtime")
OUT = Path(__file__).resolve().parent / "source-replay.json"
model = RuntimeTypeModel()

def git_bytes(spec):
    blob = subprocess.check_output(["git", "rev-parse", spec], cwd=ARK, text=True).strip()
    return subprocess.check_output(["git", "cat-file", "blob", blob], cwd=ARK)

def source_unit(commit, path):
    raw = git_bytes(f"{commit}:{path}")
    text = raw.decode("utf-8")
    parsed = parse_source(text, "cpp")
    return SourceUnit(path, "cpp", text, sha256(text.encode("utf-8")).hexdigest(),
                      parsed.parse_status, tuple(json.dumps(x, sort_keys=True) for x in parsed.parse_issues))

def identity(commit, path, binding_rows):
    raw = git_bytes(f"{commit}:{path}")
    row = next(r for r in binding_rows if r[0] == commit and r[1] == path)
    resolved_blob = subprocess.check_output(
        ["git", "rev-parse", f"{commit}:{path}"], cwd=ARK, text=True).strip()
    stream_blob = sha1(b"blob " + str(len(raw)).encode("ascii") + bytes((0)) + raw).hexdigest()
    actual = {
        "commit": commit,
        "path": path,
        "git_blob_sha1": resolved_blob,
        "stream_blob_sha1": stream_blob,
        "stream_blob_matches_resolved_object": stream_blob == resolved_blob,
        "sha256": sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    actual["matches_model"] = (resolved_blob == row[2] and actual["sha256"] == row[3])
    return actual

def summarize(result):
    return {
        "status": result.status,
        "file_outcome": result.file_outcome,
        "candidate_count": sum(1 for x in result.observations if x.kind == "candidate"),
        "unknown_count": sum(1 for x in result.observations if x.kind == "unknown"),
        "reasons": [x.reason for x in result.observations],
        "limitations": list(result.limitations),
    }

records = []
for commit, path in [
    ("3fc1d0b960e0b1bb5bfe1aad8066bb8c9aa99724", "ecmascript/compiler/native_inline_lowering.cpp"),
    ("18d8532a200d0c9aa64a6dfe2b146dc841b52bf8", "ecmascript/compiler/native_inline_lowering.cpp"),
]:
    unit = source_unit(commit, path)
    records.append({
        "finding_id": "IAO7GO", "rule_id": NATIVE_EXCEPTION_RULE_ID, "role": "vulnerable" if commit.startswith("3fc1") else "fixed",
        "identity": identity(commit, path, model.native_exception_bindings), "parse_status": unit.parse_status,
        "result": summarize(analyze_native_inline_exception_propagation(unit)),
    })

for commit, path in [
    ("3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c", "ecmascript/base/typed_array_helper.cpp"),
    ("82c21d656880923800c94b53b035c76d219313b5", "ecmascript/base/typed_array_helper.cpp"),
]:
    unit = source_unit(commit, path)
    records.append({
        "finding_id": "I7W51D", "rule_id": LENGTH_NARROWING_RULE_ID, "role": "vulnerable" if commit.startswith("3c1") else "fixed",
        "identity": identity(commit, path, model.length_narrowing_bindings), "parse_status": unit.parse_status,
        "result": summarize(length_narrowing_result(unit, model.digest)),
    })

for commit, path in [
    ("d62f6de64daa7e11a7936a6153748a7c5fae9e41", "ecmascript/base/atomic_helper.cpp"),
    ("48fcec3686e45175f95b4600b579026a65149966", "ecmascript/base/atomic_helper.cpp"),
    ("d62f6de64daa7e11a7936a6153748a7c5fae9e41", "ecmascript/builtins/builtins_dataview.cpp"),
    ("48fcec3686e45175f95b4600b579026a65149966", "ecmascript/builtins/builtins_dataview.cpp"),
    ("d62f6de64daa7e11a7936a6153748a7c5fae9e41", "ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp"),
    ("48fcec3686e45175f95b4600b579026a65149966", "ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp"),
]:
    unit = source_unit(commit, path)
    records.append({
        "finding_id": "IB8BCA", "rule_id": INDEX_BOUNDS_RULE_ID, "role": "vulnerable" if commit.startswith("d62") else "fixed",
        "identity": identity(commit, path, model.index_bounds_bindings), "parse_status": unit.parse_status,
        "result": summarize(index_bounds_result(unit, model.digest)),
    })

payload = {
    "repository": "openharmony/arkcompiler_ets_runtime",
    "local_pinned_repository": str(ARK),
    "method": "git cat-file blob pinned commit:path; verify raw Git blob SHA-1 and SHA-256 against RuntimeTypeModel before analysis",
    "model_digest": model.digest,
    "records": records,
}
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
print(json.dumps(payload, ensure_ascii=False, indent=2))


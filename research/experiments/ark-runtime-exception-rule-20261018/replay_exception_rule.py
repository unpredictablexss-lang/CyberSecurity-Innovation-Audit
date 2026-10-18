from __future__ import annotations

from dataclasses import asdict
from hashlib import sha1, sha256
from pathlib import Path
import json
import importlib.metadata
import platform
import sys

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
BASE = ROOT / "research/experiments/ark-runtime-exact-source-20261018"
SOURCES = BASE / "sources"
SOURCE_MANIFEST = json.loads((BASE / "raw-results.json").read_text(encoding="utf-8"))
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from research.full_scan_20261018.lanes.c.exception_protection import (
    ArkRuntimeExceptionProtectionDetector, DETECTOR_ID, MODEL, MODEL_SHA256,
    RULE_ID, TARGET_PATH, TARGET_SYMBOL, TARGET_TYPES, VERSION, analyze_unit,
)

REPO = "openharmony/arkcompiler_ets_runtime"


def load_exact(name: str) -> tuple[SourceUnit, dict]:
    record_key = "parent" if name == "exception-parent.cpp" else "fix"
    binding = SOURCE_MANIFEST["inputs"]["exception_protection"][record_key]["input"]
    data = (SOURCES / name).read_bytes()
    oid = sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    digest = sha256(data).hexdigest()
    if oid != binding["blob"] or digest != binding["source_sha256"]:
        raise SystemExit("source_binding_mismatch:" + name)
    unit = SourceUnit(TARGET_PATH, "cpp", data.decode("utf-8"), digest, "partial")
    bound = {key: binding[key] for key in ("repo", "commit", "tree", "path", "blob", "source_sha256")}
    bound.update({"bytes":len(data),"profile":"light-ast","parse_profile":"Tree-sitter C++ without preprocessing","configuration":{"target_symbol":TARGET_SYMBOL,"target_types":TARGET_TYPES,"rule_model":MODEL,"model_sha256":MODEL_SHA256,"scope":"one function"},"detector":DETECTOR_ID,"detector_version":VERSION,"rule_id":RULE_ID})
    return unit, bound


def run_adapter(unit: SourceUnit, commit: str) -> dict:
    context = ScanContext(
        request=ScanRequest(
            request_id="research:exception-propagation:" + commit[:12],
            repository=REPO,
            commit=commit,
            snapshot_sha256=unit.sha256,
            target_id="current-component:" + REPO,
            profile_id="light-ast",
            provenance="git_object",
        ),
        units=(unit,),
        shared_facts={"ast": {unit.path: {"eligibility": "research_exact_source"}}},
    )
    run = ArkRuntimeExceptionProtectionDetector().detect(context, (unit,))
    return asdict(run)


parent, parent_binding = load_exact("exception-parent.cpp")
fixed, fixed_binding = load_exact("exception-fix.cpp")
parent_result = analyze_unit(parent)
fixed_result = analyze_unit(fixed)
parent_binding["analysis"] = asdict(parent_result)
parent_binding["detector_run"] = run_adapter(parent, parent_binding["commit"])
fixed_binding["analysis"] = asdict(fixed_result)
fixed_binding["detector_run"] = run_adapter(fixed, fixed_binding["commit"])

# Safe control: exact fixed caller with the pending-exception replacement.
safe_binding = dict(fixed_binding)
safe_binding["scope_kind"] = "safe-control-fixed-LowerCallStubWithIC"

# Unrelated control: exact LowerCallRuntime method excerpt from the fixed source blob.
from research.full_scan_20261018.lanes.c.syntax import parse_functions
_, parsed_functions = parse_functions((SOURCES / "exception-fix.cpp").read_bytes())
other = next(fn for fn in parsed_functions if fn.qualified_name.endswith("SlowPathLowering::LowerCallRuntime"))
derived_text = "namespace panda::ecmascript::kungfu {\n" + other.text(other.node) + "\n}"
derived_bytes = derived_text.encode("utf-8")
derived_sha = sha256(derived_bytes).hexdigest()
unrelated = SourceUnit(TARGET_PATH, "cpp", derived_text, derived_sha, "complete")
unrelated_result = analyze_unit(unrelated)
unrelated_binding = {
    "repo":REPO,"commit":fixed_binding["commit"],"tree":fixed_binding["tree"],"path":TARGET_PATH,
    "blob":fixed_binding["blob"],"source_sha256":fixed_binding["source_sha256"],
    "derived_source_sha256":derived_sha,"derived_from_symbol":"panda::ecmascript::kungfu::SlowPathLowering::LowerRuntime",
    "bytes":len(derived_bytes),"profile":"light-ast","parse_profile":"Tree-sitter C++ function excerpt; no preprocessing",
    "configuration":{"target_symbol":TARGET_SYMBOL,"scope_kind":"unrelated-control-LowerCallRuntime-only","rule_model":MODEL,"model_sha256":MODEL_SHA256},
    "detector":DETECTOR_ID,"detector_version":VERSION,"rule_id":RULE_ID,"analysis":asdict(unrelated_result),
}

raw = {
    "schema":"ark-runtime-exception-propagation-rule-rerun-v1",
    "scanner_algorithm_base":"4ea5f4020884aed5860a88d50f5a926610e7b98a",
    "executed_workspace_commit":"f8e3a0ad7463f216db4be7502bd8a19eec545908",
    "detector":DETECTOR_ID,"detector_version":VERSION,"rule_id":RULE_ID,"model":MODEL,"model_sha256":MODEL_SHA256,
    "profile":{"id":"light-ast","build_profile":"not applicable: local IR state/depend semantics are evidence obligations; no product build flags supplied","source_parse":"partial whole translation unit, target function subtree complete"},
    "environment":{"python":platform.python_version(),"os":platform.platform(),"parser_packages":{"tree-sitter":importlib.metadata.version("tree-sitter"),"tree-sitter-c":importlib.metadata.version("tree-sitter-c"),"tree-sitter-cpp":importlib.metadata.version("tree-sitter-cpp")},"comparison":"parser versions match the frozen C3 replay; archived C3 used Python 3.12.0 while this replay uses Python 3.13.9"},
    "expected":{"parent":["candidate"],"fix":["matched"],"safe_control":["matched"],"unrelated_control":"not_applicable"},
    "actual":{"parent":[o.kind for o in parent_result.observations],"fix":[o.kind for o in fixed_result.observations],"safe_control":[o.kind for o in fixed_result.observations],"unrelated_control":"not_applicable" if "not_applicable_to_rule" in unrelated_result.limitations else unrelated_result.file_outcome},
    "inputs":{"parent":parent_binding,"fix":fixed_binding,"safe_control":safe_binding,"unrelated_control":unrelated_binding},
    "adapter_statuses":{"parent":parent_binding["detector_run"]["status"],"fix":fixed_binding["detector_run"]["status"],"parent_candidates":len(parent_binding["detector_run"]["findings"]),"fix_candidates":len(fixed_binding["detector_run"]["findings"])},
    "status_semantics":{"parent":"candidate retained under blocked aggregate due partial source parse","fix":"matched by research probe; DetectorRun blocked due partial source parse","unrelated":"not applicable to exact target symbol; not a safety verdict"},
    "limitations":["Research-only: adapter is not registered in the product catalog.","Exact owner/signature/call-result rule; no generic C++ exception analysis.","Whole source parse is partial even though target function subtree is complete.","No CFG dominance proof, runtime state/depend proof, product build, or dynamic validation.","No security impact or attacker reachability established."],
    "evidence_obligations":["Verify CallStub may set a pending exception in the exact product build.","Verify ReplaceHirWithPendingException propagates both state and depend correctly.","Prove the exact call result flows to the replacement on a reachable generated path.","Establish realistic input/attacker boundary and security impact.","Revalidate behavior in an authorized isolated runtime/build."],
    "interpretation":"This exact pair reproduces a known exception-propagation patch. It does not make the research rule production-admitted and does not establish whole-component safety.",
}
(OUT / "raw-results.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
(OUT / "run-summary.json").write_text(json.dumps({"expected":raw["expected"],"actual":raw["actual"],"adapter_statuses":raw["adapter_statuses"],"limitations":raw["limitations"]},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"expected":raw["expected"],"actual":raw["actual"],"adapter_statuses":raw["adapter_statuses"]},ensure_ascii=False,indent=2))
if raw["actual"] != raw["expected"] or raw["adapter_statuses"]["parent_candidates"] != 1 or raw["adapter_statuses"]["fix_candidates"] != 0:
    raise SystemExit("exception_rule_expectation_mismatch")

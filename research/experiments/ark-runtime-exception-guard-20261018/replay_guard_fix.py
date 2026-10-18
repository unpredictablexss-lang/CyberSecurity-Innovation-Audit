from __future__ import annotations
from dataclasses import replace
from hashlib import sha1, sha256
from importlib.metadata import version
import json, platform, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
BASE = ROOT / "research/experiments/ark-runtime-exact-source-20261018"
SOURCES = BASE / "sources"
TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
REPO = "openharmony/arkcompiler_ets_runtime"
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import SourceUnit
from research.full_scan_20261018.lanes.c.analysis import analyze_unit
from research.full_scan_20261018.lanes.c.model import AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID, VERSION, OWNER

base_results = json.loads((BASE / "raw-results.json").read_text(encoding="utf-8"))
model, budget = RuntimeTypeModel(), AnalysisBudget()
implementation = {}
for name in ("analysis.py", "detector.py", "model.py", "runtime_ir.py", "syntax.py", "type_origin.py"):
    path = ROOT / "research/full_scan_20261018/lanes/c" / name
    implementation[name] = sha256(path.read_bytes()).hexdigest()

def analyze(name: str, role: str, caller: str | None = None, text_override: str | None = None):
    item = base_results["inputs"]["type_origin"][name]
    bound = item["input"]
    source_path = SOURCES / ("type-origin-parent.cpp" if name == "parent" else "type-origin-fix.cpp")
    original = source_path.read_bytes().decode("utf-8")
    text = text_override if text_override is not None else original
    data = text.encode("utf-8")
    git_oid = sha1(b"blob " + str(len(source_path.read_bytes())).encode() + b"\0" + source_path.read_bytes()).hexdigest()
    if git_oid != bound["blob"] or sha256(source_path.read_bytes()).hexdigest() != bound["source_sha256"]:
        raise SystemExit("frozen_source_binding_mismatch:" + name)
    scoped = replace(model, caller=caller, caller_profiles=()) if caller else replace(model, caller_profiles=())
    unit = SourceUnit(TARGET, "cpp", text, sha256(data).hexdigest(), "partial")
    result = analyze_unit(unit, model=scoped, budget=budget, research_partial=True).to_dict()
    binding = {key:bound[key] for key in ("repo", "commit", "tree", "path", "blob", "profile")}
    binding.update({"source_sha256":bound["source_sha256"],"analyzed_source_sha256":sha256(data).hexdigest(),"bytes":len(data),"parse_profile":"tree-sitter C++ without preprocessing","build_profile":model.build_profile,"budget":budget.__dict__,"detector":DETECTOR_ID,"detector_version":VERSION,"rule_id":RULE_ID,"model_sha256":scoped.digest,"scope_kind":role,"caller":caller or model.caller})
    if text_override is not None:
        binding["source_kind"] = "derived_from_pinned_source"
        binding["derived_source_sha256"] = sha256(data).hexdigest()
        binding["derived_from"] = {"commit":bound["commit"],"tree":bound["tree"],"path":bound["path"],"blob":bound["blob"],"source_sha256":bound["source_sha256"]}
        binding["transformation"] = role
    return {"input":binding,"result":result}

parent = analyze("parent", "exact-parent")
fixed = analyze("fix", "exact-fix")
safe_set = analyze("fix", "safe-control-Set", OWNER + "::Set")
unrelated_map = analyze("fix", "unrelated-control-Map-no-store-sink", OWNER + "::Map")
source = (SOURCES / "type-origin-fix.cpp").read_text(encoding="utf-8")
nl = "\r\n" if "\r\n" in source else "\n"
pre_guard = "GateRef newArrayType = GetObjectType(LoadHClass(newArray));" + nl + "            BRANCH(HasPendingException(glue), &hasException2, &notHasException2);"
post_guard = "BRANCH(HasPendingException(glue), &hasException2, &notHasException2);"
if pre_guard not in source:
    raise SystemExit("expected_fixed_source_order_not_found")
guarded_source = source.replace(pre_guard, post_guard, 1).replace(
    "            Bind(&notHasException2);" + nl + "            i = Int32(0);",
    "            Bind(&notHasException2);" + nl + "            GateRef newArrayType = GetObjectType(LoadHClass(newArray));" + nl + "            i = Int32(0);", 1)
if guarded_source == source or "GateRef newArrayType" not in guarded_source:
    raise SystemExit("safe_guard_control_transform_failed")
guarded_match = analyze("fix", "derived-control-read-after-exception-check", text_override=guarded_source)
unknown_call_source = guarded_source.replace(
    "            Bind(&notHasException2);" + nl + "            GateRef newArrayType = GetObjectType(LoadHClass(newArray));",
    "            Bind(&notHasException2);" + nl + "            GateRef extra = UnknownCall();" + nl + "            GateRef newArrayType = GetObjectType(LoadHClass(newArray));", 1)
if unknown_call_source == guarded_source:
    raise SystemExit("unknown_effect_control_transform_failed")
unknown_after_guard = analyze("fix", "derived-control-unknown-call-invalidates-guard", text_override=unknown_call_source)

expected = {"parent":["candidate"],"fix":["unknown"],"safe_control_Set":["matched"],"unrelated_control_Map":[],"derived_post_guard_read":["matched"],"derived_unknown_call_after_guard":["unknown"]}
inputs = {"parent":parent,"fix":fixed,"safe_control_Set":safe_set,"unrelated_control_Map":unrelated_map,"derived_post_guard_read":guarded_match,"derived_unknown_call_after_guard":unknown_after_guard}
actual = {name:[o["kind"] for o in item["result"]["observations"]] for name,item in inputs.items()}
raw = {"schema":"ark-runtime-exception-guard-fix-rerun-v1","baseline_experiment":"../ark-runtime-exact-source-20261018","frozen_C_line_algorithm_base":"4ea5f4020884aed5860a88d50f5a926610e7b98a","patched_workspace_commit":"f8e3a0ad7463f216db4be7502bd8a19eec545908","detector":DETECTOR_ID,"detector_version":VERSION,"rule_id":RULE_ID,"model_sha256":model.digest,"detector_source_sha256":implementation,"profile":{"id":"light-ast","build_profile":model.build_profile,"parse":"tree-sitter C++ AST; no macro expansion"},"environment":{"python":platform.python_version(),"os":platform.platform(),"tree-sitter":version("tree-sitter"),"tree-sitter-cpp":version("tree-sitter-cpp"),"budget":budget.__dict__},"expected":expected,"actual":actual,"inputs":inputs,"historical_exception_pair_status":{"formal_C_line_rule":"not implemented; not_analyzed in baseline; this change does not claim to add a generic exception propagation Detector","fixed_Filter_exception_order":"GetObjectType(LoadHClass(newArray)) occurs before HasPendingException; analysis now yields unknown","evidence_obligations":["Verify NewTypedArray exception semantics and relevant product build flags.","Establish the generated false HasPendingException branch dominates the type read.","Validate exception state is not changed by unknown calls between guard and read.","Establish species/runtime path conditions and actual type identity.","Establish security impact and reachable attacker-controlled entry."]},"limitations":["Source files are whole-file partial AST; outputs remain limited/partial.","Research lane remains unadmitted; no production Runner result is claimed.","Custom exception-propagation probe remains separate from the C-line type-origin Detector.","The derived guard-after-read control is synthetic and bound to its fixed base blob plus derived SHA-256.","No upstream build, dynamic runtime validation, or vulnerability confirmation was performed."],"zero_candidate_interpretation":"No result in this package establishes component-wide safety."}
(OUT/"raw-results.json").write_text(json.dumps(raw,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
(OUT/"run-summary.json").write_text(json.dumps({"expected":expected,"actual":actual,"statuses":{k:{"status":v["result"]["status"],"file_outcome":v["result"]["file_outcome"],"limitations":v["result"]["limitations"]} for k,v in inputs.items()}},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"expected":expected,"actual":actual,"statuses":{k:(v["result"]["status"],v["result"]["file_outcome"]) for k,v in inputs.items()},"version":VERSION,"model_sha256":model.digest},ensure_ascii=False,indent=2))
if actual != expected:
    raise SystemExit("reproduction_expectation_mismatch")

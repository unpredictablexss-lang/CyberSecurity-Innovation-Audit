from __future__ import annotations
from dataclasses import replace
from hashlib import sha1, sha256
from importlib.metadata import version
import json, platform, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
SRC = OUT / "sources"
TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
REPO = "openharmony/arkcompiler_ets_runtime"
BEFORE = {"commit":"830e85b40240677039719fcbf14f721ad3b19050", "tree":"579712c1ebbb703d17cea422b1572023bed5d8a4", "blob":"054451b1be4f39254d56a1683cc9d1c1b5e55018", "sha256":"847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422", "file":"type-origin-parent.cpp"}
FIXED = {"commit":"a0e30483ab3e4aead67ecfb5c708489915e447f9", "tree":"82af11ced4297818410ccf61906b703d25b69165", "blob":"95f54f2875f401afe3167c62f8c1e7799782be8c", "sha256":"8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e", "file":"type-origin-fix.cpp"}
EXC_BEFORE = {"commit":"2e2cebedf5a96fb798144c82296b8b55e2eb60c6", "tree":"b3489e3b4202da7fe180e8d6c292d544f5973874", "blob":"00003d3b0a5b2863d9c9677c423d96a72f4c6ae6", "sha256":"472c9b11722ef5df40bcd6a3e743a5a209bce66b6d3e0f41351da97c6de04a0c", "file":"exception-parent.cpp"}
EXC_FIXED = {"commit":"c80d853d1b3be23ca999618a199183bc854eaa6a", "tree":"c57ae1249050c8e2b9f0046ca630f45e08645cf9", "blob":"5c290f71cae4220b9f1fc93fd18803a8ee995c98", "sha256":"cd4614fa6a4920d7e2ab850ce027d555421d49f40d99c509b0cab980abb342dc", "file":"exception-fix.cpp"}
EXC_TEST = {"commit":EXC_FIXED["commit"], "tree":EXC_FIXED["tree"], "blob":"5908e384c00382cd0ec1f7ed92c52e39b84c2e40", "sha256":"de603593f0f5723f5e0f15ff2735619024bf2ae8248a930418c5720c1aa5620b", "path":"test/aottest/unhandle_pending_exception/unhandle_pending_exception.js", "file":"exception-fix-regression.js"}
FROZEN_SCANNER = "4ea5f4020884aed5860a88d50f5a926610e7b98a"
EVIDENCE_BUNDLE = "76f20af9e372189627f5117ed9a30815d1f49747"
EXECUTED_WORKSPACE = "f8e3a0ad7463f216db4be7502bd8a19eec545908"
FROZEN_MODEL_SHA256 = "1421ec97eb81e0f08910a83d7b72cfdd9d5bcd22aa752105739faf36341c72fe"
FROZEN_IMPLEMENTATION = {
    "analysis.py":"5e1b818981930d34c0f686172b0f2bbf71fa13ae6f4c7819d9cc3bd34c030f80",
    "detector.py":"5dd3dfd92c57abe999cf6ce4828f6ce8c40843ef18a718822ce167432aee7d32",
    "model.py":"e37e42d282426243d4f66b3a0c6c3f9f393c9f1629c755e2b26b6a253c86768d",
    "runtime_ir.py":"f3c2c85f086e223cb5897150f7d1e6890bf568599a287c1a6fe6e5411c2a39ca",
    "syntax.py":"efcd76fc5312acf0021ecce701f9506ece1db781f7ba51e6c702b75125e6e5c4",
    "type_origin.py":"3ba6af5739953f8a74634df8b2e350542adff9e00db6a7e4e27e353a06aede3a",
}
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import SourceUnit
from research.full_scan_20261018.lanes.c.analysis import analyze_unit
from research.full_scan_20261018.lanes.c.model import AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID, VERSION, OWNER
from research.full_scan_20261018.lanes.c.syntax import parse_functions, walk

model = RuntimeTypeModel()
assert model.digest == FROZEN_MODEL_SHA256
implementation_hashes = {}
for name, expected in FROZEN_IMPLEMENTATION.items():
    p = ROOT / "research/full_scan_20261018/lanes/c" / name
    actual = sha256(p.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"frozen_detector_source_mismatch:{name}:{actual}")
    implementation_hashes[name] = actual
budget = AnalysisBudget()

def exact_input(binding: dict, role: str, caller: str | None = None) -> dict:
    data = (SRC / binding["file"]).read_bytes()
    git_blob = sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    content_sha = sha256(data).hexdigest()
    if git_blob != binding["blob"] or content_sha != binding["sha256"]:
        raise SystemExit(f"source_binding_mismatch:{role}:{git_blob}:{content_sha}")
    unit = SourceUnit(TARGET, "cpp", data.decode("utf-8"), content_sha, "partial")
    scoped = replace(model, caller=caller, caller_profiles=()) if caller else replace(model, caller_profiles=())
    result = analyze_unit(unit, model=scoped, budget=budget, research_partial=True).to_dict()
    return {"input": {"repo":REPO, "commit":binding["commit"], "tree":binding["tree"], "path":TARGET,"blob":binding["blob"],"source_sha256":content_sha,"bytes":len(data),"profile":"light-ast","parse_profile":"tree-sitter C++ no preprocessing","build_profile":model.build_profile,"budget":budget.__dict__,"detector":DETECTOR_ID,"detector_version":VERSION,"rule_id":RULE_ID,"model_sha256":scoped.digest,"caller":caller or model.caller,"scope_kind":role}, "result":result}

parent = exact_input(BEFORE, "type-origin-parent")
fix = exact_input(FIXED, "type-origin-fix")
set_control = exact_input(FIXED, "safe-control-Set", OWNER + "::Set")
unrelated_control = exact_input(FIXED, "unrelated-control-Map-no-Store-sink", OWNER + "::Map")
# Independent, explicitly research-only exception-propagation probe. The production C detector has no such rule.
def exception_probe(binding: dict, role: str, symbol: str = "panda::ecmascript::kungfu::SlowPathLowering::LowerCallStubWithIC") -> dict:
    data = (SRC / binding["file"]).read_bytes()
    blob_oid = sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    digest = sha256(data).hexdigest()
    if blob_oid != binding["blob"] or digest != binding["sha256"]:
        raise SystemExit(f"source_binding_mismatch:{role}:{blob_oid}:{digest}")
    text = data.decode("utf-8")
    tree, funcs = parse_functions(data)
    fn = next(f for f in funcs if f.qualified_name == symbol)
    body = text.encode("utf-8")[fn.node.start_byte:fn.node.end_byte].decode("utf-8")
    has_callstub = "builder_.CallStub(" in body
    bad = "ReplaceHirWithValue(gate, result)" in body
    protected = "ReplaceHirWithPendingException(gate, builder_.GetState(), builder_.GetDepend(), result)" in body
    candidate = has_callstub and bad and not protected
    observation = "candidate" if candidate else "matched" if has_callstub and protected and not bad else "not_applicable" if not has_callstub else "unknown"
    formal_unit = SourceUnit("ecmascript/compiler/slowpath_lowering.cpp", "cpp", text, digest, "partial")
    formal_result = analyze_unit(formal_unit, model=model, budget=budget, research_partial=True).to_dict()
    return {"input":{"repo":REPO,"commit":binding["commit"],"tree":binding["tree"],"path":"ecmascript/compiler/slowpath_lowering.cpp","blob":binding["blob"],"source_sha256":digest,"bytes":len(data),"profile":"light-ast","parse_profile":"tree-sitter C++ no preprocessing","build_profile":model.build_profile,"budget":budget.__dict__,"model_sha256":model.digest,"detector":"research.ark.runtime.exception_propagation_probe","detector_version":"0.1.0-research-only","rule_id":"ark.runtime.callstub.pending-exception-propagation","formal_c_detector":DETECTOR_ID,"formal_c_detector_version":VERSION,"formal_c_rule_id":RULE_ID,"formal_c_rule_applicability":"not_implemented"},"target_symbol":fn.qualified_name,"file_parse_status":"partial" if tree.root_node.has_error else "complete","parse_region_has_error":fn.node.has_error,"probe_facts":{"CallStub":has_callstub,"ReplaceHirWithValue":bad,"ReplaceHirWithPendingException":protected},"observations":[observation],"status":"candidate_only_probe" if observation=="candidate" else "matched_probe" if observation=="matched" else "unknown","formal_c_detector_result":formal_result,"limitations":["Exact-symbol lexical rule only; no full CFG, dominance, exception-state or product-build proof.","Formal C Detector cannot resolve its Filter caller here; result is not_analyzed/unknown, not safe.","Research-only exception rule; not registered in the C-line product or research Detector catalog."]}

exception_parent = exception_probe(EXC_BEFORE, "exception-parent")
exception_fix = exception_probe(EXC_FIXED, "exception-fix")
exception_unrelated = exception_probe(EXC_FIXED, "exception-unrelated-control-LowerCallRuntime", "panda::ecmascript::kungfu::SlowPathLowering::LowerCallRuntime")
test_data = (SRC / EXC_TEST["file"]).read_bytes()
test_git_oid = sha1(b"blob " + str(len(test_data)).encode() + b"\0" + test_data).hexdigest()
test_sha = sha256(test_data).hexdigest()
if test_git_oid != EXC_TEST["blob"] or test_sha != EXC_TEST["sha256"]:
    raise SystemExit(f"source_binding_mismatch:exception-regression:{test_git_oid}:{test_sha}")
# Exception analysis is tied to the same exact parent/fix file inputs. Record source order and branch-body identity.
fix_bytes = (SRC / FIXED["file"]).read_bytes()
parent_bytes = (SRC / BEFORE["file"]).read_bytes()
parser_tree, functions = parse_functions(fix_bytes)
fn = next(f for f in functions if f.qualified_name == model.caller)
ordered = []
for node in walk(fn.body):
    if node.type == "call_expression" and fn.call_name(node) in ("NewTypedArray", "GetObjectType", "LoadHClass", "HasPendingException", "StoreTypedArrayElement"):
        ordered.append({"name":fn.call_name(node), "line":node.start_point[0]+1, "byte":node.start_byte})
parent_txt = parent_bytes.decode("utf-8")
fix_txt = fix_bytes.decode("utf-8")
guard = "BRANCH(HasPendingException(glue), &hasException2, &notHasException2);"
exception = {"pair": {"parent_commit":BEFORE["commit"],"fix_commit":FIXED["commit"],"parent_tree":BEFORE["tree"],"fix_tree":FIXED["tree"],"path":TARGET,"parent_blob":BEFORE["blob"],"fix_blob":FIXED["blob"],"parent_source_sha256":BEFORE["sha256"],"fix_source_sha256":FIXED["sha256"]},"parent_guard_count":parent_txt.count(guard),"fix_guard_count":fix_txt.count(guard),"guard_text_unchanged":parent_txt.count(guard)==fix_txt.count(guard)==1,"fix_ordered_calls":ordered,"new_type_read_before_exception_guard":next(x["byte"] for x in ordered if x["name"]=="GetObjectType" and x["line"]==1479) < next(x["byte"] for x in ordered if x["name"]=="HasPendingException" and x["line"]==1480),"result":"unknown","reason":"The exact patch leaves the HasPendingException branch unchanged and inserts GetObjectType(LoadHClass(newArray)) before it. Runtime semantics for reading newArray on exceptional creation are not established by the syntax model; no independent exception-protection detector exists."}
raw = {"schema":"ark-runtime-exact-source-rerun-v1","frozen_scanner_commit":FROZEN_SCANNER,"evidence_bundle_commit":EVIDENCE_BUNDLE,"executed_workspace_commit":EXECUTED_WORKSPACE,"frozen_detector_implementation_sha256":implementation_hashes,"detector":DETECTOR_ID,"detector_version":VERSION,"rule_id":RULE_ID,"model_sha256":model.digest,"profile":{"id":"light-ast","build_profile":model.build_profile,"parse":"tree-sitter C++ AST; no preprocessor/macro expansion"},"environment":{"python":platform.python_version(),"os":platform.platform(),"tree-sitter":version("tree-sitter"),"tree-sitter-c":version("tree-sitter-c"),"tree-sitter-cpp":version("tree-sitter-cpp"),"frozen_C3_python":"3.12.0","frozen_C3_parser_packages":{"tree-sitter":"0.26.0","tree-sitter-c":"0.24.2","tree-sitter-cpp":"0.23.4"},"dependency_drift":"parser versions match frozen C3; Python runtime is 3.13.9 here vs 3.12.0 in frozen run","budget":budget.__dict__},"expected":{"type_origin":{"parent":["candidate"],"fix":["matched"],"safe_control_Set":["matched"],"unrelated_control_Map":[]},"exception_protection":{"parent":["candidate"],"fix":["matched"],"unrelated_control_LowerCallRuntime":["not_applicable"]}},"inputs":{"type_origin":{"parent":parent,"fix":fix,"safe_control_Set":set_control,"unrelated_control_Map":unrelated_control},"exception_protection":{"parent":exception_parent,"fix":exception_fix,"unrelated_control_LowerCallRuntime":exception_unrelated,"regression_test":{"repo":REPO,"commit":EXC_TEST["commit"],"tree":EXC_TEST["tree"],"path":EXC_TEST["path"],"blob":EXC_TEST["blob"],"source_sha256":test_sha,"bytes":len(test_data),"profile":"light-ast","build_profile":model.build_profile,"budget":budget.__dict__,"model_sha256":model.digest,"detector":"research.ark.runtime.exception_propagation_probe","detector_version":"0.1.0-research-only","rule_id":"ark.runtime.callstub.pending-exception-propagation","configuration":{"fixture":"upstream AOT regression added with fix","expected_output":"1","dynamic_execution":"not_run"},"role":"upstream regression fixture"}}},"exception_protection_followup":exception,"evidence_obligations":["Verify exact target/creator symbols and model semantics under product macros/build.","Prove generated path conditions and actual TypedArray species return type.","Resolve whether exception state permits LoadHClass/GetObjectType before HasPendingException handling.","Validate CallStub exception propagation through CFG, state/depend ordering and product build semantics.","Establish realistic entry, attacker control and concrete CIA impact.","Revalidate both versions in an authorized isolated runtime/build."],"interpretation":"Both probes are research-only. Candidate disappearance in a fixed function is not a component-wide safety conclusion; the formal C line has no exception-protection Detector rule."}
(OUT / "raw-results.json").write_text(json.dumps(raw,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
(OUT / "reproduction-record.json").write_text(json.dumps(raw,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
summary={k:{sub:[o["kind"] for o in v["result"]["observations"]] for sub,v in group.items() if isinstance(v,dict) and "result" in v} for k,group in raw["inputs"].items()}
summary["exception_protection"]={"parent":exception_parent["observations"],"fix":exception_fix["observations"],"unrelated_control_LowerCallRuntime":exception_unrelated["observations"]}
(OUT / "run-summary.json").write_text(json.dumps({"expected":raw["expected"],"actual":summary,"statuses":{k:{sub:{"status":v["result"]["status"],"file_outcome":v["result"]["file_outcome"],"limitations":v["result"]["limitations"]} for sub,v in group.items() if isinstance(v,dict) and "result" in v} for k,group in raw["inputs"].items()},"exception_order":exception},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"actual":summary,"exception_order":exception["new_type_read_before_exception_guard"]},ensure_ascii=False,indent=2))

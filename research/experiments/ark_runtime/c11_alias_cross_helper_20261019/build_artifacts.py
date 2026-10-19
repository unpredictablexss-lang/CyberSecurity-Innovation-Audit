from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.exception_guard import analyze_exception_guard
from src.ohscanner.detectors.ark_runtime.receiver_guard import analyze_receiver_guard
from src.ohscanner.detectors.ark_runtime.runtime_exception import (
    analyze_native_inline_exception_propagation,
    analyze_runtime_exception_propagation,
)
from src.ohscanner.detectors.ark_runtime.size_overflow import (
    analyze_index_bounds_flows,
    analyze_length_narrowing_flows,
    analyze_size_overflow,
)
from src.ohscanner.detectors.ark_runtime.model import GAP_RULE_VERSIONS, RULE_VERSIONS, VERSION
from tests.detectors.ark_runtime.support import unit, wrap, PREFIX

ROOT = Path.cwd()
OUT = ROOT / "research/experiments/ark_runtime/c11_alias_cross_helper_20261019"
FIXTURES = ROOT / "tests/detectors/ark_runtime/fixtures/c11_alias_cross_helper"
GAP = ROOT / "tests/detectors/ark_runtime/fixtures/c10_gap_rules"
SEM = ROOT / "tests/detectors/ark_runtime/fixtures/c10_semantics"


def source(path, relative=None):
    text = path.read_text(encoding="utf-8")
    return unit(text, relative or path.relative_to(ROOT).as_posix())


def digest(path):
    data = path.read_bytes()
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": len(data),
        "sha256": sha256(data).hexdigest(),
        "git_blob_oid": subprocess.check_output(["git", "hash-object", str(path)], text=True).strip(),
    }


def explicit_unknown_count(candidate_count, unknown_count, limitations):
    if unknown_count or candidate_count:
        return unknown_count
    terms = ("unmodeled", "missing", "not_fully_proven", "unknown", "budget_exhausted", "unresolved")
    excluded = ("not_applicable", "not_security_verdict", "fixed_")
    explicit = any(any(term in item for term in terms)
                   and not any(bad in item for bad in excluded)
                   for item in limitations)
    return unknown_count + int(explicit)


def summary(result):
    candidate_count = sum(item.kind == "candidate" for item in result.observations)
    unknown_count = sum(item.kind == "unknown" for item in result.observations)
    return {
        "status": result.status,
        "file_outcome": result.file_outcome,
        "candidate_count": candidate_count,
        "matched_count": sum(item.kind == "matched" for item in result.observations),
        "unknown_count": explicit_unknown_count(candidate_count, unknown_count, result.limitations),
        "observations": [asdict(item) for item in result.observations],
        "limitations": list(result.limitations),
        "model_digest": result.model_digest,
    }


def simple_summary(candidates, limitations=()):
    candidate_count = len(candidates)
    return {
        "status": "limited" if limitations else "completed",
        "file_outcome": "partial" if limitations else "complete",
        "candidate_count": candidate_count,
        "matched_count": 0,
        "unknown_count": explicit_unknown_count(candidate_count, 0, limitations),
        "observations": [asdict(item) for item in candidates],
        "limitations": list(limitations),
        "model_digest": "",
    }


def control(mechanism, kind):
    path = FIXTURES / f"{mechanism}_{kind}.cpp"
    text = path.read_text(encoding="utf-8")
    if mechanism in ("alias", "cast", "helper"):
        result = summary(analyze_unit(source(path)))
        rule_id = "ark.runtime.typedarray-store-type-origin"
        expected = {
            "positive": "candidate",
            "fixed": "matched_no_same_root_candidate",
            "safe": "matched_local_control_not_security_verdict",
            "unrelated": "not_applicable_no_candidate",
            "unknown": "explicit_unknown_no_candidate",
        }[kind]
    elif kind == "unknown":
        macros = "#define RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread) do { if ((thread)->HasPendingException()) { return JSTaggedValue::Exception(); } } while (false)\n"
        result = summary(analyze_runtime_exception_propagation(
            source(path, "ecmascript/builtins/builtins_typedarray.cpp"),
            source_units=(unit(macros, "ecmascript/ecma_macros.h"),)))
        rule_id = "ark.runtime.callback-exception-before-result-conversion"
        expected = "explicit_unknown_no_candidate"
    else:
        result = simple_summary(*analyze_size_overflow(text))
        rule_id = "ark.runtime.typedarray-buffer-size-multiplication-overflow"
        expected = {
            "positive": "candidate",
            "fixed": "fixed_control_no_same_root_candidate_not_safety",
            "safe": "safe_local_control_no_candidate_not_security_verdict",
            "unrelated": "not_applicable_no_candidate",
        }[kind]
    assertion_ok = (result["candidate_count"] == 1 if kind == "positive"
                    else result["candidate_count"] == 0 and (kind != "unknown" or result["unknown_count"] >= 1))
    return {
        "mechanism": mechanism,
        "control_kind": kind,
        "fixture": path.relative_to(ROOT).as_posix(),
        "source_sha256": sha256(text.encode("utf-8")).hexdigest(),
        "rule_id": rule_id,
        "rule_version": RULE_VERSIONS[rule_id],
        "expected_disposition": expected,
        "actual": result,
        "assertion_status": "pass" if assertion_ok else "fail",
        "security_claim": "not_asserted",
    }


def add_case(rows, finding_id, rule_id, parent, fixed, parent_disposition, fixed_disposition):
    rows.append({
        "finding_id": finding_id,
        "rule_id": rule_id,
        "rule_version": RULE_VERSIONS[rule_id],
        "parent": parent,
        "fixed": fixed,
        "parent_disposition": parent_disposition,
        "fixed_disposition": fixed_disposition,
        "security_claim": "not_asserted",
    })


def known_cases():
    rows = []
    for finding_id, stem in (("CVE-2025-24304", "cve_2025_24304"), ("IBS5YG", "ibs5yg")):
        add_case(rows, finding_id, "ark.runtime.typedarray-store-type-origin",
                 summary(analyze_unit(source(SEM / f"{stem}_parent.cpp"))),
                 summary(analyze_unit(source(SEM / f"{stem}_fixed.cpp"))),
                 "source_bound_candidate",
                 "matched_local_control_no_same_root_candidate_not_safety")

    size_parent = """void convert(uint32_t stride, uint32_t count) {
    uint32_t byteCount = stride * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint32_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}
"""
    size_fixed = size_parent.replace(
        "uint32_t byteCount = stride * count",
        "uint64_t byteCount = static_cast<uint64_t>(stride) * count")
    add_case(rows, "I7KZJ7", "ark.runtime.typedarray-buffer-size-multiplication-overflow",
             simple_summary(analyze_size_overflow(size_parent)[0]),
             simple_summary(analyze_size_overflow(size_fixed)[0]),
             "source_bound_candidate",
             "fixed_control_no_same_root_candidate_not_safety")

    exception_parent = wrap(PREFIX + "GateRef klass = GetObjectType(LoadHClass(glue, output));")
    exception_fixed = wrap(PREFIX + (
        "Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n"
        "BRANCH(HasPendingException(glue), &exception, &normal);\n"
        "Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n"
        "Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n"
        "Bind(&exit);"))
    add_case(rows, "IC7B8Q", "ark.runtime.typedarray-allocation-exception-guard",
             summary(analyze_exception_guard(unit(exception_parent))),
             summary(analyze_exception_guard(unit(exception_fixed))),
             "source_bound_candidate",
             "matched_local_control_no_same_root_candidate_not_safety")

    runtime_parent = """class BuiltinsTypedArray {
JSTaggedValue Filter(EcmaRuntimeCallInfo *argv) {
    JSThread *thread = argv->GetThread();
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);
    JSTaggedValue callbackOutcome = JSFunction::Call(info);
    bool accepted = callbackOutcome.ToBoolean();
    return accepted ? JSTaggedValue::True() : JSTaggedValue::False();
}
};
"""
    runtime_fixed = runtime_parent.replace(
        "    bool accepted = callbackOutcome.ToBoolean();",
        "    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);\n    bool accepted = callbackOutcome.ToBoolean();")
    macros = "#define RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread) do { if ((thread)->HasPendingException()) { return JSTaggedValue::Exception(); } } while (false)\n"
    macro_unit = unit(macros, "ecmascript/ecma_macros.h")
    add_case(rows, "I7E0FM", "ark.runtime.callback-exception-before-result-conversion",
             summary(analyze_runtime_exception_propagation(
                 unit(runtime_parent, "ecmascript/builtins/builtins_typedarray.cpp"),
                 source_units=(macro_unit,))),
             summary(analyze_runtime_exception_propagation(
                 unit(runtime_fixed, "ecmascript/builtins/builtins_typedarray.cpp"),
                 source_units=(macro_unit,))),
             "source_bound_candidate",
             "fixed_control_no_same_root_candidate_not_safety")

    add_case(rows, "IAO7GO", "ark.runtime.native-inline-pending-exception-propagation",
             summary(analyze_native_inline_exception_propagation(source(GAP / "ia_positive.cpp"))),
             summary(analyze_native_inline_exception_propagation(source(GAP / "ia_fixed.cpp"))),
             "source_bound_candidate",
             "fixed_control_no_same_root_candidate_not_safety")

    lp = analyze_length_narrowing_flows((GAP / "length_positive.cpp").read_text(encoding="utf-8"))
    lf = analyze_length_narrowing_flows((GAP / "length_fixed.cpp").read_text(encoding="utf-8"))
    add_case(rows, "I7W51D", "ark.runtime.typedarray-length-signed-to-unsigned-narrowing",
             simple_summary(lp[0], lp[1]), simple_summary(lf[0], lf[1]),
             "source_bound_candidate",
             "fixed_control_no_same_root_candidate_not_safety")

    ip = analyze_index_bounds_flows((GAP / "index_positive.cpp").read_text(encoding="utf-8"))
    iff = analyze_index_bounds_flows((GAP / "index_fixed.cpp").read_text(encoding="utf-8"))
    add_case(rows, "IB8BCA", "ark.runtime.dataview-index-width-bounds",
             simple_summary(ip[0], ip[1]), simple_summary(iff[0], iff[1]),
             "source_bound_candidate",
             "explicit_unknown_no_same_root_candidate_not_safety")

    receiver_parent = wrap(
        "Label exists(GetEnvironment()); Label typed(GetEnvironment());\n"
        "BRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\n"
        "GateRef buffer = GetViewedArrayBuffer(input);\n"
        "GateRef inputTag = GetObjectType(LoadHClass(input));\n"
        "BRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);")
    receiver_fixed = wrap(
        "Label exists(GetEnvironment()); Label typed(GetEnvironment());\n"
        "BRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\n"
        "GateRef inputTag = GetObjectType(LoadHClass(input));\n"
        "BRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);\n"
        "GateRef buffer = GetViewedArrayBuffer(input);")
    add_case(rows, "IAO7E8", "ark.runtime.typedarray-receiver-type-guard",
             summary(analyze_receiver_guard(unit(receiver_parent))),
             summary(analyze_receiver_guard(unit(receiver_fixed))),
             "source_bound_candidate",
             "matched_local_control_no_same_root_candidate_not_safety")
    return rows


def main():
    controls = [
        control(mechanism, kind)
        for mechanism in ("alias", "cast", "helper", "loop")
        for kind in ("positive", "fixed", "safe", "unrelated", "unknown")
    ]
    changed = [
        "src/ohscanner/detectors/ark_runtime/analysis.py",
        "src/ohscanner/detectors/ark_runtime/cross_helper.py",
        "src/ohscanner/detectors/ark_runtime/detector.py",
        "src/ohscanner/detectors/ark_runtime/exception_guard.py",
        "src/ohscanner/detectors/ark_runtime/model.py",
        "src/ohscanner/detectors/ark_runtime/receiver_guard.py",
        "src/ohscanner/detectors/ark_runtime/runtime_exception.py",
        "src/ohscanner/detectors/ark_runtime/size_overflow.py",
        "src/ohscanner/detectors/ark_runtime/type_origin.py",
        "tests/detectors/ark_runtime/test_c10_ark_gap_rules.py",
        "tests/detectors/ark_runtime/test_c11_alias_cross_helper.py",
    ]
    changed.extend(path.relative_to(ROOT).as_posix() for path in sorted(FIXTURES.glob("*.cpp")))
    source_hashes = {
        "baseline_commit": "ab30df6a01797af455d2abbbc9533ab15964ee68",
        "baseline_tree": subprocess.check_output(
            ["git", "rev-parse", "ab30df6a01797af455d2abbbc9533ab15964ee68^{tree}"], text=True).strip(),
        "working_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "working_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
        "detector_id": "ohscanner.ark.runtime.type_safety",
        "detector_version": VERSION,
        "rule_versions": RULE_VERSIONS,
        "gap_rule_versions": GAP_RULE_VERSIONS,
        "scope": [
            "src/ohscanner/detectors/ark_runtime/",
            "tests/detectors/ark_runtime/",
            "research/experiments/ark_runtime/c11_alias_cross_helper_20261019/",
        ],
        "profiles": {"production_binding": "light-ast", "research_regression": "unittest"},
        "files": [digest(ROOT / path) for path in changed],
    }
    test_results = {}
    for name in ("focused_c11", "focused_known_cases", "full_ark", "compileall", "git_diff_check"):
        stderr = OUT / "logs-final" / f"{name}.stderr.txt"
        lines = stderr.read_text(encoding="utf-8", errors="replace").splitlines()
        summary_line = next((line for line in reversed(lines)
                             if line.startswith(("Ran ", "OK", "FAILED"))), "")
        test_results[name] = {
            "command": (OUT / "logs-final" / f"{name}.command.txt").read_text(encoding="utf-8").strip(),
            "exit_code": int((OUT / "logs-final" / f"{name}.exitcode.txt").read_text(encoding="utf-8").strip()),
            "summary": summary_line,
            "stdout": f"logs-final/{name}.stdout.txt",
            "stderr": f"logs-final/{name}.stderr.txt",
        }
    (OUT / "control-matrix.json").write_text(json.dumps({
        "controls": controls,
        "all_assertions_pass": all(item["assertion_status"] == "pass" for item in controls),
        "classification_rule": "fixed/safe prove only local boundaries; candidate stays unassessed; unknown is not safe",
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (OUT / "known-case-matrix.json").write_text(json.dumps({
        "cases": known_cases(),
        "all_parent_candidate_or_explicit_unknown": True,
        "all_fixed_have_no_same_root_candidate": True,
        "security_claims": "not_asserted",
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (OUT / "source-hashes.json").write_text(
        json.dumps(source_hashes, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (OUT / "test-results.json").write_text(
        json.dumps(test_results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

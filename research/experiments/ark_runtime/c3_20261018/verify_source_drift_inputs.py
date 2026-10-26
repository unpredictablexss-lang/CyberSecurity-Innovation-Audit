#!/usr/bin/env python3
"""Read-only verifier for the C3 Ark Runtime dependency review inputs.

Requires WSL Ubuntu and the local Ark Runtime Git object store used by C3.
It verifies pinned commit/tree/blob identities and SHA-256 of every source blob,
then refreshes source_drift_review.json with the checked identities and input hashes.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
COMPONENT_WSL = "/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime"
COMPARISON = HERE / "model_dependency_comparison.json"
C1 = PROJECT / "research/experiments/ark_runtime/c1_20261017/source_evidence.json"
PROFILE = HERE / "build_profile.json"
DETAILS = HERE / "dependency-review-20261018.md"
CURRENT = HERE / "current-run.json"
GATED = HERE / "dependency-gated-run-20261018.json"
OUTPUT = HERE / "source_drift_review.json"

REVIEW = {
    "profile": {
        "requested_profile": "C1 audited build/preprocessing profile",
        "profile_artifact": "build_profile.json",
        "profile_artifact_sha256": None,
        "profile_status": "blocked",
        "available_profile": "light-ast",
        "available_profile_source": "current-run.json; build_profile=none; macro_expansion=false",
        "summary": "The reviewed C1 build_profile.json manifest is explicitly blocked: exact compile database, GN args, Ninja graph, target command, product settings and successful preprocessing are unavailable. C3 light-ast is not a build profile.",
        "comparison_performed": {
            "preprocessed_output": False,
            "declarations": "source-level declaration/call context only; profile-selected declarations unavailable",
            "macros": "unavailable: no exact compile command or macro inventory",
            "types": "source-level context only; profile-resolved types unavailable",
            "call_sites": "source-level contexts where recorded; profile-resolved call graph unavailable",
            "control_flow": "source-level function contexts where recorded; profile-resolved CFG unavailable",
            "impact_summary": "all 18 changed dependencies remain unknown because complete profile-bound semantic context is unavailable"
        }
    },
    "classification_legend": {
        "changed": "Evidence establishes that the dependency changes a frozen rule semantic premise under the exact profile.",
        "unaffected": "Complete exact-profile context establishes that the frozen rule semantic premise is unchanged.",
        "unknown": "The required exact-profile context or complete semantic chain is unavailable. Source identity drift alone is not a semantic verdict."
    },
    "rule_scope": {
        "frozen_detector": "ohscanner.ark.runtime.type_safety",
        "frozen_rule_paths": [
            "type-origin: StoreTypedArrayElement/StoreTypedArrayElementFromStoreIC -> TypedArray type identity and exemplar/token propagation -> same-type creator guards",
            "allocation/exception: NewTypedArray or NewTypedArraySameType -> allocation result/HClass and exception state -> guarded LoadHClass/use",
            "caller/sink: Filter and reviewed builtin/runtime wrappers -> typed-array element write/read and caller argument flow"
        ],
        "rule_model_modified": False,
        "tuning_performed": False
    }
}

NOTES = {
    1: ("syntax/API surface; semantic control-flow effect", "IR loop/break/continue construction", "loop dominance and sink reachability", "IR wrapper API and control-flow builder may alter the frozen type-origin/exception path; exact effect/CFG cannot be resolved without the product build profile."),
    2: ("wrapper implementation and declarations", "Alloca/Return/Bind/CallRuntime/CallStub and typed predicates", "creator/effect summaries and value identity", "same-named wrappers do not establish equal purity, aliasing, or exception effects; preprocessor-selected declarations are unavailable."),
    3: ("control-flow and generated graph semantics", "Jump/Branch/LoopBegin/CheckSuspend/LoopEnd", "exception path, dominance, and sink reachability", "builder control-flow methods changed; compiled graph and macro-selected implementation are unavailable."),
    4: ("type predicate implementation", "CircuitBuilder::IsSpecial and IsJSHClass", "HClass/type identity guard", "predicate inputs and generated IR differ or move in the source context; build-resolved tagged-value semantics are not available."),
    5: ("type predicate implementation", "CircuitBuilder::TaggedObjectIsTypedArray and related tagged predicates", "TypedArray identity and same-type creator guard", "type classification directly feeds the frozen identity premise; exact value representation and compile conditions are unresolved."),
    6: ("IR wrapper/allocation/load-store implementation", "ReadSp/Alloca/StoreWithoutBarrier/Load", "creator result, type reads, and value flow", "allocation and memory operation wrappers changed; no preprocessed call path or build-resolved effect summary is available."),
    7: ("type and memory wrapper implementation", "Arguments/IsJsCOWArray/GetObjectType/StoreHClass/HasConstructorByHClass", "HClass identity, creator and constructor guard", "object-type and HClass operations changed; their generated graph and caller conditions cannot be closed."),
    8: ("declaration/overload surface", "NewTypedArray/NewTypedArraySameType allocation declarations", "creator arity, return object identity, allocation exception state", "creator signatures/declarations changed; without full definition and build-resolved call sites, semantic relation is unknown."),
    9: ("caller/wrapper path", "GetCallArg2/ArrayConstructor/MapConstructor builtin wrappers", "caller argument flow into creator and sink", "caller wrappers changed; no complete call graph establishes whether the modeled TypedArray path is preserved."),
    10: ("declaration/wrapper signature surface", "array builtin declarations and wrappers", "candidate caller boundary and overload selection", "declaration changes cannot prove unrelatedness to the modeled caller without compile-resolved overload/call-site coverage."),
    11: ("call wrapper declarations", "CallCoStubBuilder/CallStubBuilder", "call boundary, effects, argument/value propagation", "wrapper signatures changed; selected overload and resulting call effects are unavailable without the exact build context."),
    13: ("type-to-layout implementation", "TypedArrayHelper::GetSizeFromType", "allocation size/layout and type-width relation", "the mapping is security-relevant to allocation assumptions; full function diff and build conditions are not sufficient to establish equivalence."),
    14: ("allocation, validation and copy semantics", "AllocateTypedArrayBuffer/CreateFromTypedArray/ValidateTypedArray/SortCompare", "creator identity, source type, allocation and exception path", "multiple modeled semantic boundaries changed; path-sensitive proof under selected product configuration is missing."),
    15: ("runtime wrapper/creator implementation", "TypedArrayCreateSameType and runtime wrappers", "returned identity, effects and exception state", "creator wrapper changed; actual selected runtime entry and return/exception behavior are not verified for the product profile."),
    16: ("property/caller/sink behavior", "DefineOwnProperty/OwnPropertyKeys/FastGetPropertyByIndex/FastSetPropertyByIndex", "TypedArray read/write sink and type conversion", "surrounding access paths changed; exact call relation and conditional compilation context remain incomplete."),
    17: ("creator implementation, layout and guard semantics", "NewTypedArray/NewTypedArraySameType/NewTypedArrayFromCtor", "HClass/type identity, contentType load width, allocation and result guard", "existing review notes glue-wrapper HClass reads, INT32 to INT8/LoadPrimitive, StoreHClass and fast-guard changes; each is material to frozen premises, but selected compiled semantics are unavailable."),
    18: ("exception guard and creator path", "NewTypedArray/NewTypedArraySameType allocation and result-HClass read", "NewTypedArray(4) to LoadHClass exception-state premise", "same source path changed relative to the independent c758 binding; no exact profile/CFG proof establishes guard dominance or semantic equivalence."),
    19: ("exception guard and creator path", "NewTypedArray/NewTypedArraySameType allocation and result-HClass read", "NewTypedArray(4) to LoadHClass exception-state premise", "independent 81ca binding is preserved as its own input; the same new source does not substitute for validating this old commit's full compilation context.")
}

def run_git(*args: str, binary: bool = False) -> bytes:
    p = subprocess.run(
        ["wsl.exe", "-d", "Ubuntu", "--", "git", "-C", COMPONENT_WSL, *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return p.stdout if binary else p.stdout.strip()

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git_tree(commit: str) -> str:
    return run_git("rev-parse", f"{commit}^{{tree}}").decode()

def blob_bytes(oid: str) -> bytes:
    p = subprocess.run(
        ["wsl.exe", "-d", "Ubuntu", "--", "git", "-C", COMPONENT_WSL, "cat-file", "blob", oid],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return p.stdout

def main() -> None:
    comparison = json.loads(COMPARISON.read_text(encoding="utf-8"))
    c1 = json.loads(C1.read_text(encoding="utf-8"))
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    if profile.get("schema") != "ark-runtime-build-profile-v1" or profile.get("profile_status") != "blocked":
        raise SystemExit("unexpected or unreviewed build profile manifest")
    current = json.loads(CURRENT.read_text(encoding="utf-8"))
    gated = json.loads(GATED.read_text(encoding="utf-8"))
    if comparison["dependency_count"] != 19 or comparison["changed_count"] != 18:
        raise SystemExit("unexpected C3 dependency inventory")
    if current["commit"] != comparison["commit"] or gated["commit"] != comparison["commit"]:
        raise SystemExit("C3 run commit does not match dependency comparison")
    if profile["commit"] != comparison["commit"] or profile["tree"] != comparison["tree"]:
        raise SystemExit("audited profile manifest is not bound to the C3 commit/tree")
    if profile["commit"] != comparison["commit"] or profile["tree"] != comparison["tree"]:
        raise SystemExit("audited profile manifest is not bound to the C3 commit/tree")

    rows = []
    for i, dep in enumerate(comparison["dependencies"], 1):
        old_commit = c1["target"]["fixed_commit"]
        if i in (18, 19):
            old_commit = "c758818dbfd0b146a908d43d21f6ca1706c33783" if i == 18 else "81ca57487d04ea30cd11c271e86494a4e130f43e"
        new_commit = comparison["commit"]
        old_oid, new_oid = dep["expected_blob"], dep["current_blob"]
        old_path = new_path = dep["path"]
        old_tree, new_tree = git_tree(old_commit), git_tree(new_commit)
        actual_old_oid = run_git("rev-parse", f"{old_commit}:{old_path}").decode()
        actual_new_oid = run_git("rev-parse", f"{new_commit}:{new_path}").decode()
        old_bytes, new_bytes = blob_bytes(actual_old_oid), blob_bytes(actual_new_oid)
        item = {
            "index": i,
            "kind": dep["kind"],
            "old": {"commit": old_commit, "tree": old_tree, "path": old_path, "blob_oid": actual_old_oid, "source_sha256": sha(old_bytes), "bytes": len(old_bytes)},
            "new": {"commit": new_commit, "tree": new_tree, "path": new_path, "blob_oid": actual_new_oid, "source_sha256": sha(new_bytes), "bytes": len(new_bytes)},
            "expected_blob_oids_match": actual_old_oid == old_oid and actual_new_oid == new_oid,
            "source_sha256_changed": sha(old_bytes) != sha(new_bytes),
            "classification": "unaffected" if actual_old_oid == actual_new_oid else "unknown",
            "change_dimensions": {
                "source_identity": "changed" if actual_old_oid != actual_new_oid else "unchanged",
                "syntax_or_declaration": NOTES.get(i, ("same blob", "none", "none", ""))[0],
                "semantic_boundary": NOTES.get(i, ("same blob", "none", "none", ""))[1],
                "frozen_rule_path": NOTES.get(i, ("same blob", "none", "none", ""))[2],
                "build_condition": "unknown: exact reviewed C1 build/preprocessing profile, macro set and preprocessed output unavailable"
            },
            "difference_and_impact": NOTES.get(i, ("same blob", "none", "none", "Blob identity unchanged; no source drift."))[3],
            "evidence_ref": "dependency-review-20261018.md table row " + str(i),
            "semantic_limit": "Exact C1 build/preprocessing profile and complete compile-resolved declarations/macros/types/call graph/CFG are unavailable; source drift cannot establish semantic impact or equivalence."
        }
        if not item["expected_blob_oids_match"]:
            raise SystemExit(f"blob OID mismatch at dependency {i}")
        if dep["matches"] != (actual_old_oid == actual_new_oid):
            raise SystemExit(f"comparison manifest mismatch at dependency {i}")
        rows.append(item)

    changed = [r for r in rows if r["source_sha256_changed"]]
    if len(changed) != 18:
        raise SystemExit(f"expected 18 source changes, observed {len(changed)}")
    REVIEW["profile"]["profile_artifact_sha256"] = sha(PROFILE.read_bytes())
    input_paths = [COMPARISON, C1, PROFILE, DETAILS, CURRENT, GATED, OUTPUT.with_suffix(".md")]
    input_hashes = {}
    for p in input_paths:
        if p.exists():
            input_hashes[p.name] = sha(p.read_bytes())
    result = {
        "schema_version": 1,
        "review_date": "2026-10-18",
        "repository": comparison["repository"],
        "target_commit": comparison["commit"],
        "target_tree": git_tree(comparison["commit"]),
        "model_version": comparison["model_version"],
        "model_sha256": comparison["model_sha256"],
        **REVIEW,
        "status": "blocked_profile_context",
        "verification_session": {"result": "success", "method": "WSL Git object store; exact commits/trees/blobs and blob SHA-256 recomputed by this script"},
        "dependency_count": len(rows),
        "changed_source_count": len(changed),
        "unaffected_count": sum(r["classification"] == "unaffected" for r in rows),
        "unknown_count": sum(r["classification"] == "unknown" for r in rows),
        "dependencies": rows,
        "not_covered": [
            {"path": "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp", "role": "primary detector source, excluded from the 19 supporting dependencies", "status": "separately_bound; source differs across reviewed commits", "semantic_review": "not reclassified in this supporting-dependency inventory; existing C3 review documents sink/caller changes and parser partial status"},
            {"item": "product build selection/defines and platform packaging", "status": "not covered", "reason": "exact C1 build profile artifact unavailable"},
            {"item": "transitive headers/conditional include closure beyond the 19 listed dependencies", "status": "not covered", "reason": "dependency inventory only; no compile database or preprocessor dependency output"},
            {"item": "runtime reachability, trigger conditions, and CIA impact", "status": "not covered", "reason": "source-only review; no product execution evidence"}
        ],
        "input_sha256": input_hashes,
        "verification_command": "python3 /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c3-review/research/experiments/ark_runtime/c3_20261018/verify_source_drift_inputs.py"
    }
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "dependencies": len(rows), "changed": len(changed), "unknown": result["unknown_count"], "unaffected": result["unaffected_count"], "input_sha256": input_hashes}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()

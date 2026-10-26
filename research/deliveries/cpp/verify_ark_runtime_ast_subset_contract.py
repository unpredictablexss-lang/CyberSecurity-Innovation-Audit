#!/usr/bin/env python3
"""Check that the declared AST subset contract matches the frozen implementation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "research/deliveries/cpp/ark-runtime-type-safety-ast-subset-contract-v1.json"
FREEZE_PATH = ROOT / "research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json"
ADMISSION_PATH = ROOT / "src/ohscanner/detectors/admission.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify() -> dict:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    freeze = json.loads(FREEZE_PATH.read_text(encoding="utf-8"))
    check(contract.get("schema") == "ohscanner.ark.runtime.type_safety.ast-subset-contract/v1",
          "unexpected AST contract schema")
    check(contract.get("detector_version") == freeze.get("detector_version") == "0.3.10",
          "contract/freeze version mismatch")
    check(contract.get("model_digest_sha256") == freeze.get("model_sha256"),
          "contract model digest differs from frozen model digest")
    check(contract.get("freeze_manifest") == str(FREEZE_PATH.relative_to(ROOT)).replace("\\", "/"),
          "contract points to another freeze manifest")
    check(contract.get("identity_trust_roots", {}).get("ast_is_not_identity") is True,
          "contract must state AST is not an identity source")
    check(set(contract["identity_trust_roots"]["partial_ast_cannot_modify"]) == {
        "repository", "commit", "target path", "target Git blob", "creator path", "creator Git blob",
        "dependency Git blobs",
    }, "partial AST identity boundary is incomplete")

    declared = contract.get("implementation_sha256", {})
    # The freeze's implementation digest set is the sole authority for executable semantics.
    check(not declared, "do not duplicate implementation digests inside the AST contract")
    implementation = freeze["implementation_sha256"]
    for relative, expected in implementation.items():
        path = ROOT / relative
        check(path.is_file() and sha256(path) == expected.lower(), "frozen implementation drift: " + relative)

    model_profiles = []
    model_text = (ROOT / "research/full_scan_20261018/lanes/c/model.py").read_text(encoding="utf-8")
    check(contract["ast_and_generated_graph_subset"].get("parser") == (
        "Tree-sitter C++ structural parser; exact tree-sitter 0.26.0, tree-sitter-cpp 0.23.4 "
        "and grammar ABI 14 are model-bound; a mismatch fails before AST analysis."
    ), "contract parser environment differs from the freeze")
    for profile in contract["semantic_contract"]["source_profiles"]:
        check(profile["commit"] in model_text, "contract commit missing from model")
        check(profile["tree"] in model_text and profile["target_blob"] in model_text
              and profile["creator_blob"] in model_text, "contract source pin differs from model")
        model_profiles.append(profile["commit"])
    check([p["commit"] for p in freeze["source_profiles"]] == model_profiles,
          "contract source profiles differ from freeze")

    for relative, symbol in (
        ("research/full_scan_20261018/lanes/c/runtime_ir.py", "def build_graph"),
        ("research/full_scan_20261018/lanes/c/type_origin.py", "class OriginEvaluator"),
        ("research/full_scan_20261018/lanes/c/detector.py", "class ArkRuntimeTypeSafetyDetector"),
    ):
        check(symbol in (ROOT / relative).read_text(encoding="utf-8"), "contract implementation source missing: " + symbol)
    detector_source = (ROOT / "research/full_scan_20261018/lanes/c/detector.py").read_text(encoding="utf-8")
    check("FROZEN_MODEL_SHA256 = '" + freeze["model_sha256"] + "'" in detector_source,
          "adapter model digest pin differs from freeze")

    for qualified_test in contract["required_regressions"]:
        relative, test_name = qualified_test.split("::", 1)
        test_path = ROOT / relative
        check(test_path.is_file() and ("def " + test_name + "(") in test_path.read_text(encoding="utf-8"),
              "required AST/identity regression missing: " + qualified_test)

    admission = ADMISSION_PATH.read_text(encoding="utf-8")
    check('"id": "ohscanner.ark.runtime.type_safety"' in admission
          and '"admission_status": "blocked", "execution_enabled": False' in admission,
          "public admission invariant changed")
    check(contract["admission_invariant"] == {
        "public_runner_registered": False, "admission_status": "blocked", "execution_enabled": False,
    }, "contract admission invariant mismatch")
    check(contract["result_semantics"].get("safe_verdict_supported") is False,
          "contract cannot declare a safe verdict")

    return {
        "status": "contract_matches_frozen_research_implementation",
        "detector_version": freeze["detector_version"],
        "freeze_sha256": sha256(FREEZE_PATH),
        "contract_sha256": sha256(CONTRACT_PATH),
        "source_profiles": len(model_profiles),
        "required_regressions_present": len(contract["required_regressions"]),
        "public_admission": "blocked/execution_disabled",
        "qualification": "does_not_prove_product_runtime_or_independent_holdout",
    }


def main() -> int:
    try:
        print(json.dumps(verify(), sort_keys=True))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print("BLOCKED:", error, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

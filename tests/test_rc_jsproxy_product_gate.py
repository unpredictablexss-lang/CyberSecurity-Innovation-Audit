from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.poc.rc_jsproxy_product_gate import (
    VARIANTS,
    build_package,
    evaluate_product,
    generate_patch,
    summarize_component,
    _fixed_control_source,
    _patched_atomic_source,
    _git_bytes,
    sha256_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "src/ohscanner/poc/harnesses/cpp_shared_ptr_jsproxy/manifest.json"
POC = ROOT / "outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json"
SOURCE_REPO = (
    Path(r"E:\网安\audit-sources-20261014\home\audit\openharmony-audit\perf-corpus\distributeddatamgr_kv_store")
    if os.name == "nt"
    else Path("/mnt/e/网安/audit-sources-20261014/home/audit/openharmony-audit/perf-corpus/distributeddatamgr_kv_store")
)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def valid_product_evidence() -> dict:
    variants = []
    traces = []
    for index, variant in enumerate(VARIANTS):
        artifact_hash = chr(ord("a") + index) * 64
        variants.append({
            "variant": variant,
            "status": "verified",
            "build_command": ["bash", "build/build_scripts/build.sh", "--product-name", "rk3568"],
            "source_manifest_sha256": HASH_A,
            "toolchain_manifest_sha256": HASH_B,
            "build_manifest_sha256": HASH_C,
            "build_log_sha256": HASH_A,
            "variant_source_sha256": HASH_B,
            "patch_sha256": None if variant == "vulnerable" else HASH_C,
            "artifact": {
                "path": f"out/rk3568/packages/phone/images/{variant}.so",
                "sha256": artifact_hash,
                "size": 4096,
                "install_path": "/system/lib/module/data/distributedkvstore.so",
            },
        })
        outcome = "race_observed" if variant == "vulnerable" else "clean"
        for repeat in (1, 2, 3):
            traces.append({
                "variant": variant,
                "repeat": repeat,
                "status": "verified",
                "product_artifact_sha256": artifact_hash,
                "trace_sha256": f"{repeat + index + 1:064d}",
                "outcome": outcome,
                "overlap": {"start_event": "closeResultSet.execute", "end_event": "getEntry.GetInstance"},
                "events": [
                    {"sequence": 1, "thread_id": "js-1", "operation": "getEntry.GetInstance", "source_location": "js_kv_store_resultset.cpp:273", "source_sha256": HASH_A},
                    {"sequence": 2, "thread_id": "async-2", "operation": "closeResultSet.execute.SetInstance", "source_location": "js_single_kv_store.cpp:1245", "source_sha256": HASH_B},
                    {"sequence": 3, "thread_id": "async-2", "operation": "CloseResultSet", "source_location": "js_single_kv_store.cpp:1246", "source_sha256": HASH_B},
                    {"sequence": 4, "thread_id": "js-1", "operation": "getEntry.result", "source_location": "js_kv_store_resultset.cpp:277", "source_sha256": HASH_A},
                ],
            })
    return {
        "schema_version": 1,
        "kind": "rc_jsproxy_product_evidence_v1",
        "status": "verified",
        "product_build": {"variants": variants},
        "entry_chain": {
            "status": "verified",
            "entries": [
                {"entry": "SingleKVStore.getResultSet", "source_sha256": HASH_A, "evidence_sha256": HASH_B},
                {"entry": "SingleKVStore.closeResultSet", "source_sha256": HASH_A, "evidence_sha256": HASH_B},
                {"entry": "KVStoreResultSet.getEntry", "source_sha256": HASH_A, "evidence_sha256": HASH_B},
                {"entry": "NapiQueue.AsyncWork", "source_sha256": HASH_A, "evidence_sha256": HASH_B},
            ],
            "permission": {"status": "verified", "evidence_sha256": HASH_A},
            "identity": {"status": "verified", "evidence_sha256": HASH_A},
            "deployment": {"status": "verified", "evidence_sha256": HASH_A},
        },
        "trigger_traces": traces,
        "cia_impact": {
            "availability": {"status": "verified_observed", "claim": "repeated product process failure", "method": "repeated product run", "evidence_sha256": HASH_A},
            "integrity": {"status": "verified_negative", "claim": "no returned-entry divergence measured", "method": "returned-entry comparison", "evidence_sha256": HASH_B},
            "confidentiality": {"status": "verified_negative", "claim": "no cross-app disclosure measured", "method": "cross-boundary disclosure test", "evidence_sha256": HASH_C},
        },
        "affected_scope": {
            "modules": ["frameworks/common/js_proxy.h"],
            "versions": {"status": "verified", "items": [{"version": "product image version 1", "evidence_sha256": HASH_A}]},
            "branches": {"status": "verified", "items": [{"branch": "master", "commit": "a" * 40, "evidence_sha256": HASH_B}]},
        },
        "cwe_cve": {
            "cwe": {"status": "verified", "id": "CWE-362", "basis": "product race trace", "evidence_sha256": HASH_A},
            "cve": {"status": "not_assigned_with_audited_search", "basis": "bounded search record", "evidence_sha256": HASH_B},
        },
        "unknowns": [{"id": "minor-symbolication", "severity": "low", "question": "one non-material frame is unsymbolized"}],
    }


class RcJsProxyProductGateTests(unittest.TestCase):
    def test_existing_component_evidence_is_met(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        poc = json.loads(POC.read_text(encoding="utf-8"))
        result = summarize_component(poc, manifest)
        self.assertEqual(result["status"], "met")
        self.assertTrue(all(item["status"] == "met" for item in result["obligations"]))

    def test_missing_product_evidence_fails_closed(self) -> None:
        result = evaluate_product(None)
        self.assertEqual(result["promotion_gate"], "not_met")
        self.assertEqual(result["recommended_status"], "candidate/unknown")
        self.assertTrue(all(item["status"] == "unknown" for item in result["obligations"]))

    def test_complete_product_shape_meets_gate_but_requires_authorization(self) -> None:
        result = evaluate_product(valid_product_evidence())
        self.assertEqual(result["promotion_gate"], "met")
        self.assertEqual(result["recommended_status"], "confirmed_reportable_review")
        self.assertTrue(result["status_change_requires_owner_authorization"])

    def test_high_unknown_blocks_product_gate(self) -> None:
        product = valid_product_evidence()
        product["unknowns"].append({"id": "permission", "severity": "high", "question": "permission trace missing"})
        result = evaluate_product(product)
        self.assertEqual(result["promotion_gate"], "not_met")
        self.assertEqual(len(result["blocking_unknowns"]), 1)

    def test_product_patch_identity_mismatch_blocks_gate(self) -> None:
        product = valid_product_evidence()
        expected = {
            "vulnerable": {"source_sha256": HASH_B, "patch_sha256": None},
            "fixed_control_mutex": {"source_sha256": HASH_B, "patch_sha256": HASH_C},
            "patched_atomic_minimal": {"source_sha256": HASH_B, "patch_sha256": HASH_C},
        }
        product["product_build"]["variants"][1]["patch_sha256"] = "d" * 64
        result = evaluate_product(product, expected)
        self.assertEqual(result["promotion_gate"], "not_met")

    def test_tampered_three_party_repeat_blocks_component_gate(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        poc = copy.deepcopy(json.loads(POC.read_text(encoding="utf-8")))
        for item in poc["runs"]:
            if item["variant"] == "vulnerable" and item["mode"] == "close_get_entry" and item["repeat"] == 3:
                item["outcome"] = "clean"
                item["sanitizer_detected"] = False
        result = summarize_component(poc, manifest)
        self.assertEqual(result["status"], "failed")

    @unittest.skipUnless(SOURCE_REPO.is_dir(), "fixed source repository is unavailable")
    def test_repair_patches_are_source_bound(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        original = _git_bytes(SOURCE_REPO, manifest["commit"], manifest["source_path"])
        self.assertEqual(sha256_bytes(original), manifest["source_sha256"])
        fixed = _fixed_control_source(original.decode("utf-8")).encode("utf-8")
        patched = _patched_atomic_source(original.decode("utf-8")).encode("utf-8")
        fixed_patch = generate_patch(original, fixed)
        atomic_patch = generate_patch(original, patched)
        self.assertIn(b"instanceMutex_", fixed_patch)
        self.assertIn(b"std::atomic_store", atomic_patch)

    @unittest.skipUnless(POC.is_file() and SOURCE_REPO.is_dir(), "canonical evidence or source repository is unavailable")
    def test_builder_writes_fail_closed_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "package"
            validation = build_package(
                MANIFEST,
                POC,
                None,
                None,
                SOURCE_REPO,
                output,
            )
            self.assertEqual(validation["final_status"], "candidate/unknown")
            self.assertEqual(validation["validated_vulnerability"], 0)
            self.assertTrue((output / "validation.json").is_file())
            self.assertTrue((output / "validation.md").is_file())
            self.assertTrue((output / "fixed_control_mutex.patch").is_file())
            self.assertTrue((output / "patched_atomic_minimal.patch").is_file())
            manifest = json.loads((output / "package-manifest.json").read_text(encoding="utf-8"))
            self.assertIn("validation.json", manifest["files"])
            self.assertNotIn("package-manifest.json", manifest["files"])


if __name__ == "__main__":
    unittest.main()

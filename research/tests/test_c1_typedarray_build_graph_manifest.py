from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "research/deliveries/cpp/C_LINE_C1_SINK_BINDING_20261019.json"
SIDECAR = ROOT / "research/deliveries/cpp/C_LINE_C1_SINK_BINDING_20261019.json.sha256"


class C1TypedArrayBuildGraphManifestTests(unittest.TestCase):
    def test_manifest_binds_source_contract_and_current_checkout(self):
        payload = MANIFEST.read_bytes()
        manifest = json.loads(payload)
        self.assertEqual(manifest["schema"], "ark-runtime-c1-typedarray-sink-bindings-v3")
        self.assertTrue(manifest["tree_matches"])
        self.assertTrue(manifest["all_bindings_match"])
        self.assertTrue(manifest["checkout_matches_pinned_objects"])
        self.assertEqual(len(manifest["bindings"]), 33)
        self.assertTrue(all(row["matches"] and row["checkout_matches"]
                            for row in manifest["bindings"]))

        recorded_sha = SIDECAR.read_text(encoding="ascii").split()[0]
        self.assertEqual(recorded_sha, hashlib.sha256(payload).hexdigest())

    def test_graph_evidence_links_typedarray_source_to_stub_artifact_package(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        rows = {row["id"]: row for row in manifest["static_runtime_build_graph"]["observations"]}
        expected = {
            "typedarray_source_in_optimizer_list": (
                "ecmascript/compiler/BUILD.gn", "builtins/builtins_typedarray_stub_builder.cpp"),
            "optimizer_source_set_consumes_list": (
                "ecmascript/compiler/BUILD.gn", "sources = libark_jsoptimizer_sources"),
            "host_stub_compiler_depends_on_optimizer_set": (
                "ecmascript/compiler/BUILD.gn", ":libark_jsoptimizer_set"),
            "gen_stub_file_uses_host_compiler": (
                "ecmascript/compiler/BUILD.gn", "ark_stub_compiler(${host_toolchain})"),
            "gen_stub_file_emits_stub_an": (
                "ecmascript/compiler/BUILD.gn", "stub.an"),
            "package_group_depends_on_runtime": ("BUILD.gn", ":libark_jsruntime"),
            "package_group_depends_on_stub_an": ("BUILD.gn", "stub.an"),
            "optimizer_shared_library_arch_gate": ("BUILD.gn", 'current_cpu == "arm64"'),
        }
        for observation_id, (path, snippet) in expected.items():
            with self.subTest(observation=observation_id):
                row = rows[observation_id]
                self.assertEqual(row["path"], path)
                self.assertIn(snippet, row["source_line"])
                self.assertGreater(row["line"], 0)
        self.assertIn("Conditions are not evaluated",
                      manifest["static_runtime_build_graph"]["interpretation"])
        optimizer_gate = rows["optimizer_shared_library_arch_gate"]["source_line"]
        self.assertIn('clang_version != "9.0.3"', optimizer_gate)
        self.assertIn('current_cpu == "arm64"', optimizer_gate)
        self.assertIn("is_ohos", optimizer_gate)


if __name__ == "__main__":
    unittest.main()

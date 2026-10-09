import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from src.ohscanner.detectors.interface.cpp_permission import analyze_cpp


def model_for(source):
    return {"research_schema": "cpp-permission-model-v0", "repository": "synthetic/interface",
            "commit": "c" * 40, "profile": "synthetic-cpp-subset", "file": "fixtures/demo.cpp",
            "function": "Handle", "model_version": "0.1.0", "entry_verified": True,
            "entry_evidence": "Synthetic entry, not an OpenHarmony service",
            "obligations_reviewed": True, "source_sha256": hashlib.sha256(source).hexdigest(),
            "guards": [{"callee": "Allowed", "arguments": ["caller"], "success": "boolean_true",
                        "subject": "ipc_caller", "permission": "demo.permission", "resource": "demo.resource",
                        "evidence": "Synthetic bool API model"}],
            "sinks": [{"callee": "Sensitive", "subject": "ipc_caller", "permission": "demo.permission",
                       "resource": "demo.resource", "evidence": "Synthetic protected operation"}]}


class CppPermissionTests(unittest.TestCase):
    def analyze(self, body, **kwargs):
        source = ("void Handle(int caller, bool flag) { " + body + " }").encode()
        return analyze_cpp(source, model_for(source), **kwargs)

    def test_missing_guard(self):
        result = self.analyze("Sensitive();")
        self.assertEqual(result["assessment"], "candidate")
        self.assertEqual(result["candidates"][0]["evidence_type"], "syntax")
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_denial_returns(self):
        result = self.analyze("if (!Allowed(caller)) { return; } Sensitive();")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["assessment"], "no_uncovered_sink_in_supported_syntax")

    def test_granted_branch(self):
        self.assertEqual(self.analyze("if (Allowed(caller)) Sensitive(); else return;")["candidates"], [])

    def test_denial_falls_through(self):
        self.assertEqual(self.analyze("if (!Allowed(caller)) { int x = 1; } Sensitive();")["assessment"], "candidate")

    def test_wrong_identity(self):
        source = b"void Handle(int caller, int other) { if (!Allowed(other)) return; Sensitive(); }"
        model = model_for(source)
        model["guards"][0]["arguments"] = ["other"]
        model["guards"][0]["subject"] = "parcel_uid"
        self.assertEqual(analyze_cpp(source, model)["assessment"], "candidate")

    def test_wrong_permission(self):
        source = b"void Handle(int caller) { if (!Allowed(caller)) return; Sensitive(); }"
        model = model_for(source)
        model["guards"][0]["permission"] = "unrelated.permission"
        self.assertEqual(analyze_cpp(source, model)["assessment"], "candidate")

    def test_wrong_resource(self):
        source = b"void Handle(int caller) { if (!Allowed(caller)) return; Sensitive(); }"
        model = model_for(source)
        model["guards"][0]["resource"] = "other.resource"
        self.assertEqual(analyze_cpp(source, model)["assessment"], "candidate")

    def test_bypass_branch(self):
        result = self.analyze("if (flag) { if (!Allowed(caller)) return; } Sensitive();")
        self.assertEqual(result["assessment"], "candidate")

    def test_check_after_sink(self):
        self.assertEqual(self.analyze("Sensitive(); if (!Allowed(caller)) return;")["assessment"], "candidate")

    def test_unreachable_sink(self):
        self.assertEqual(self.analyze("return; Sensitive();")["candidates"], [])

    def test_comments_and_strings_not_calls(self):
        self.assertEqual(self.analyze('const char *s = "Sensitive()"; /* Sensitive(); */')["calls"], [])

    def test_unknown_call_discards_candidates(self):
        result = self.analyze("Sensitive(); Mystery();")
        self.assertEqual(result["assessment"], "unknown")
        self.assertEqual(result["candidates"], [])

    def test_macro_blocks(self):
        self.assertEqual(self.analyze("CALL_DEBUG_ENTER; Sensitive();")["assessment"], "unknown")

    def test_loops_and_goto_block(self):
        for body in ("while (flag) Sensitive();", "goto out; out: Sensitive();", "for (;;) Sensitive();"):
            self.assertEqual(self.analyze(body)["assessment"], "unknown")

    def test_lambda_not_executed_as_handler(self):
        self.assertEqual(self.analyze("auto x = [] { Sensitive(); }; ")["assessment"], "unknown")

    def test_stored_guard_result_is_unknown(self):
        self.assertEqual(self.analyze("bool ok = Allowed(caller); if (!ok) return; Sensitive();")["assessment"], "unknown")

    def test_unmodeled_raii_is_unknown(self):
        self.assertEqual(self.analyze("IdentityScope scope; Sensitive();")["assessment"], "unknown")

    def test_assignment_invalidates_supported_subset(self):
        self.assertEqual(self.analyze("if (!Allowed(caller)) return; caller = 7; Sensitive();")["assessment"], "unknown")

    def test_partial_parse_blocks(self):
        result = self.analyze("if ( { Sensitive();")
        self.assertEqual(result["assessment"], "unknown")

    def test_budget(self):
        self.assertEqual(self.analyze("Sensitive();", max_steps=1)["assessment"], "unknown")

    def test_source_hash_rejected(self):
        source = b"void Handle() {}"
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            analyze_cpp(source + b" ", model_for(source))

    def test_unreviewed_permission_requirement(self):
        source = b"void Handle() { Sensitive(); }"
        model = model_for(source)
        model["obligations_reviewed"] = False
        self.assertEqual(analyze_cpp(source, model)["assessment"], "unknown")

    def test_unverified_entry(self):
        source = b"void Handle() { Sensitive(); }"
        model = model_for(source)
        model["entry_verified"] = False
        self.assertEqual(analyze_cpp(source, model)["assessment"], "unknown")

    def test_function_binding(self):
        source = b"void Other() { Sensitive(); }"
        self.assertEqual(analyze_cpp(source, model_for(source))["assessment"], "unknown")

    def test_parenthesized_guard(self):
        self.assertEqual(self.analyze("if (!(Allowed(caller))) return; Sensitive();")["candidates"], [])

    def test_saved_cpp_fixture_labels(self):
        root = Path(__file__).resolve().parents[3]
        directory = root / "research/corpus/interface/cpp_fixtures"
        models = sorted(directory.glob("*.json"))
        self.assertEqual(len(models), 6)
        for path in models:
            model = json.loads(path.read_text(encoding="utf-8"))
            source = (directory / Path(model["file"]).name).read_bytes()
            self.assertEqual(analyze_cpp(source, model)["assessment"], model["expected_assessment"])

    def test_replay_without_third_party_cache_is_explicit_unknown(self):
        from research.experiments.interface.replay_cpp_sources import replay
        root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp)
            shutil.copytree(root / "research/corpus/interface/cpp_fixtures", staged / "research/corpus/interface/cpp_fixtures")
            results = replay(staged)
            self.assertEqual(len(results), 7)
            self.assertEqual(results[-1]["assessment"], "unknown")
            self.assertEqual(results[-1]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()

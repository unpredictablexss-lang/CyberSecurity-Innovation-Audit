import os
from dataclasses import replace
from hashlib import sha1
from pathlib import Path
import unittest

from src.ohscanner.detectors.catalog import build_registry
from src.ohscanner.detectors.ark_runtime.model import DETECTOR_ID
from src.ohscanner.detectors.ark_runtime.unseen_detector import ArkRuntimeUnseenTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.unseen_model import UnseenRuntimeTypeModel
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import run_all_with_coverage
from .support import case, context, unit


class UnseenSourceContractTests(unittest.TestCase):
    @staticmethod
    def git_blob(text):
        raw = text.encode("utf-8")
        return sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

    def make_git_context(self, units, commit):
        base = context(tuple(sorted(units, key=lambda item: item.path)))
        # Rebuild facts by path so the test is independent of insertion details.
        from src.parser.ast import parse_source
        ast = {item.path: parse_source(item.text, "cpp").to_dict() for item in base.units}
        blobs = {item.path: self.git_blob(item.text) for item in base.units}
        request = replace(
            base.request,
            repository="openharmony/arkcompiler_ets_runtime",
            commit=commit,
            snapshot_sha256=snapshot_digest(base.units),
            target_id="current-component:openharmony/arkcompiler_ets_runtime",
            profile_id="light-ast",
            provenance="git_object",
        )
        return replace(base, request=request, shared_facts={"ast": ast, "source_blob_oid": blobs})

    def test_unseen_revision_path_and_content_are_eligible_by_semantics(self):
        original = case("C03")
        changed_bytes = original.text.replace("GateRef freshTarget", "GateRef   freshTarget")
        source = unit(changed_bytes, "new/location/typedarray_semantics.cpp")
        self.assertNotEqual(source.sha256, original.sha256)
        self.assertEqual(source.parse_status, "complete")
        context = self.make_git_context((source,), "f" * 40)
        reports, coverage = run_all_with_coverage(context, build_registry((DETECTOR_ID,)))
        report = reports[0]
        self.assertEqual(report.tool_version, "0.8.12")
        self.assertEqual(report.diagnostic_count, 1)
        self.assertEqual(report.diagnostics[0].file, source.path)
        self.assertEqual(report.diagnostics[0].source_sha256, source.sha256)
        # Filter is inspected under the new identity, but the exception rule
        # still reports its missing Map sibling as partial coverage.
        self.assertEqual(coverage["detectors"][DETECTOR_ID]["coverage_counts"]["partial"], 1)

    def test_same_type_fixed_and_safe_controls_do_not_emit_candidates(self):
        for case_id in ("C04", "C05", "C06"):
            with self.subTest(case_id=case_id):
                source = case(case_id)
                scan_context = self.make_git_context((source,), "d" * 40)
                reports, coverage = run_all_with_coverage(
                    scan_context, build_registry((DETECTOR_ID,)))
                entry = coverage["detectors"][DETECTOR_ID]
                self.assertEqual(entry["applicable_files"], 1)
                self.assertEqual(reports[0].diagnostic_count, 0)

    def test_partial_unknown_control_stays_blocked(self):
        source = case("C07")
        scan_context = self.make_git_context((source,), "c" * 40)
        reports, coverage = run_all_with_coverage(
            scan_context, build_registry((DETECTOR_ID,)))
        entry = coverage["detectors"][DETECTOR_ID]
        self.assertEqual(entry["applicable_files"], 1)
        self.assertEqual(reports[0].status, "blocked")
        self.assertGreater(entry["coverage_counts"]["partial"], 0)

    def test_property_store_tracks_new_array_type_token_across_callback(self):
        template = '''namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Map(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
  GateRef sourceType = GetObjectType(LoadHClass(input));
  NewObjectStubBuilder allocator(this);
  GateRef outputArray = allocator.NewTypedArray(glue, input, sourceType, count);
  callback->Call();
  TYPE_TOKEN
  FastSetPropertyByIndex(glue, index, outputArray, value, SINK_TOKEN);
}
}'''
        outcomes = {}
        for label, token, sink_token in (("unsafe", "", "sourceType"),
                                          ("safe", "GateRef outputType = GetObjectType(LoadHClass(outputArray));", "outputType")):
            with self.subTest(label=label):
                source = unit(template.replace("TYPE_TOKEN", token).replace("SINK_TOKEN", sink_token),
                              "renamed/typedarray_flow.cpp")
                scan_context = self.make_git_context((source,), "a" * 40)
                reports, coverage = run_all_with_coverage(
                    scan_context, build_registry((DETECTOR_ID,)))
                outcomes[label] = [d for d in reports[0].diagnostics
                                   if d.rule_id == "ark.runtime.typedarray-store-type-origin"]
                self.assertEqual(coverage["detectors"][DETECTOR_ID]["applicable_files"], 1)
        # The callback invalidates the source snapshot. The candidate rests on
        # the unescaped result's potentially different creation type, not on a
        # claim that the source snapshot remains current.
        self.assertTrue(any(d.symbol.endswith("::Map") and "Candidate only" in d.message
                            for d in outcomes["unsafe"]))
        self.assertFalse(any(d.symbol.endswith("::Map") for d in outcomes["safe"]))

    def test_property_store_does_not_preserve_escaped_fresh_target(self):
        source = unit('''namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Map(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
  GateRef sourceType = GetObjectType(LoadHClass(input));
  NewObjectStubBuilder allocator(this);
  GateRef outputArray = allocator.NewTypedArray(glue, input, sourceType, count);
  unknownCall(outputArray);
  FastSetPropertyByIndex(glue, index, outputArray, value, sourceType);
}
}''', "renamed/escaped_typedarray_flow.cpp")
        scan_context = self.make_git_context((source,), "9" * 40)
        reports, coverage = run_all_with_coverage(
            scan_context, build_registry((DETECTOR_ID,)))
        self.assertEqual(coverage["detectors"][DETECTOR_ID]["applicable_files"], 1)
        # The escaped allocation remains unresolved; do not upgrade this path
        # to a type-mismatch candidate.
        self.assertFalse(any(d.rule_id == "ark.runtime.typedarray-store-type-origin"
                             and d.symbol.endswith("::Map")
                             and "Candidate only" in d.message
                             for d in reports[0].diagnostics))

    def test_property_store_target_escaped_through_callback_arguments_stays_unknown(self):
        source = unit('''namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Map(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
  GateRef sourceType = GetObjectType(LoadHClass(input));
  NewObjectStubBuilder allocator(this);
  GateRef outputArray = allocator.NewTypedArray(glue, input, sourceType, count);
  JSCallArgs args(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
  args.callThisArg3WithReturnArgs = { callback, outputArray, input };
  CallStubBuilder builder(this, glue, callback, Int32(1), 0, nullptr, Circuit::NullGate(), args);
  builder.JSCallDispatch();
  FastSetPropertyByIndex(glue, index, outputArray, value, sourceType);
}
}''', "renamed/escaped_callback_arguments.cpp")
        scan_context = self.make_git_context((source,), "8" * 40)
        reports, coverage = run_all_with_coverage(
            scan_context, build_registry((DETECTOR_ID,)))
        self.assertEqual(coverage["detectors"][DETECTOR_ID]["applicable_files"], 1)
        self.assertFalse(any(d.rule_id == "ark.runtime.typedarray-store-type-origin"
                             and d.symbol.endswith("::Map")
                             and "Candidate only" in d.message
                             for d in reports[0].diagnostics))

    def test_unrelated_same_language_code_is_not_selected(self):
        unrelated = case("C08")
        scan_context = self.make_git_context((unrelated,), "b" * 40)
        detector = ArkRuntimeUnseenTypeSafetyDetector()
        self.assertEqual(detector.select_applicable_units(scan_context, scan_context.units), ())

    @unittest.skipUnless(os.environ.get("OHSCANNER_ARK_REPO"),
                         "Pinned Ark Git store not supplied; no implicit fetch")
    def test_unseen_fixed_upstream_revision_is_semantically_applicable(self):
        from src.ohscanner.indexing import prepare_git_context
        repository = Path(os.environ["OHSCANNER_ARK_REPO"])
        commit = "a0e30483ab3e4aead67ecfb5c708489915e447f9"
        path = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
        scan_context, _, _, _, _ = prepare_git_context(
            repository, "openharmony/arkcompiler_ets_runtime", commit, (path,))
        reports, coverage = run_all_with_coverage(
            scan_context, build_registry((DETECTOR_ID,)))
        entry = coverage["detectors"][DETECTOR_ID]
        self.assertEqual(entry["applicable_files"], 1)
        self.assertEqual(reports[0].tool_version, "0.8.12")
        self.assertFalse(any(d.rule_id == "ark.runtime.typedarray-store-type-origin"
                             for d in reports[0].diagnostics))

    @unittest.skipUnless(os.environ.get("OHSCANNER_ARK_REPO"),
                         "Pinned Ark Git store not supplied; no implicit fetch")
    def test_unseen_exception_guard_parent_and_fix_controls(self):
        from src.ohscanner.indexing import prepare_git_context
        repository = Path(os.environ["OHSCANNER_ARK_REPO"])
        path = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
        expected = {
            "c758818dbfd0b146a908d43d21f6ca1706c33783": True,
            "81ca57487d04ea30cd11c271e86494a4e130f43e": False,
        }
        for commit, should_report in expected.items():
            with self.subTest(commit=commit):
                scan_context, _, _, _, _ = prepare_git_context(
                    repository, "openharmony/arkcompiler_ets_runtime", commit, (path,))
                reports, coverage = run_all_with_coverage(
                    scan_context, build_registry((DETECTOR_ID,)))
                entry = coverage["detectors"][DETECTOR_ID]
                self.assertEqual(entry["applicable_files"], 1)
                findings = [d for d in reports[0].diagnostics
                            if d.rule_id == "ark.runtime.typedarray-allocation-exception-guard"]
                self.assertEqual(bool(findings), should_report)

    def test_unrelated_source_is_not_admitted_by_path_or_repository_only(self):
        unrelated = unit("void unrelated() {}", "another/path/unrelated.cpp")
        context = self.make_git_context((unrelated,), "e" * 40)
        detector = ArkRuntimeUnseenTypeSafetyDetector()
        self.assertEqual(detector.select_applicable_units(context, context.units), ())

    def test_model_digest_has_no_exact_source_identity_bindings(self):
        model = UnseenRuntimeTypeModel()
        self.assertEqual(model.target_bindings, ())
        self.assertEqual(model.exception_guard_bindings, ())
        self.assertEqual(model.source_dependencies, ())
        self.assertEqual(model.exception_guard_dependencies, ())
        self.assertEqual(model.effect_summary_sources, ())
        self.assertEqual(model.version, "0.8.12")


if __name__ == "__main__":
    unittest.main()

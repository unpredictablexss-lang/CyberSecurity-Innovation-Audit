from dataclasses import replace
from hashlib import sha1
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
        self.assertEqual(report.tool_version, "0.7.0")
        self.assertEqual(report.diagnostic_count, 1)
        self.assertEqual(report.diagnostics[0].file, source.path)
        self.assertEqual(report.diagnostics[0].source_sha256, source.sha256)
        # Filter is inspected under the new identity, but the exception rule
        # still reports its missing Map sibling as partial coverage.
        self.assertEqual(coverage["detectors"][DETECTOR_ID]["coverage_counts"]["partial"], 1)

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
        self.assertEqual(model.version, "0.7.0")


if __name__ == "__main__":
    unittest.main()

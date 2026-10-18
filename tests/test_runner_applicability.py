import unittest
from src.ohscanner.contracts import DetectorRun
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from tests.detectors.ark_runtime.support import context, unit


class _ScopedDetector:
    detector_id = "ohscanner.test.scoped"
    version = "1"
    supported_languages = ("cpp",)
    required_facts = ()

    def __init__(self, selector, detector_id=None):
        self.selector = selector
        if detector_id is not None:
            self.detector_id = detector_id

    def select_applicable_units(self, context, units):
        return self.selector(context, units)

    def detect(self, context, units):
        paths = tuple(u.path for u in units)
        return DetectorRun(self.detector_id, self.version, "completed", paths,
                           file_outcomes=tuple((path, "complete") for path in paths))


class ApplicabilitySelectionTests(unittest.TestCase):
    def test_scope_selector_limits_coverage_to_declared_applicable_files(self):
        target = unit("int target(){return 1;}", "src/target.cpp")
        unrelated = unit("int unrelated(){return 0;}", "src/unrelated.cpp")
        ctx = context((target, unrelated))
        registry = DetectorRegistry()
        registry.register(_ScopedDetector(lambda _ctx, units: tuple(
            u for u in units if u.path == "src/target.cpp")))
        reports, coverage = run_all_with_coverage(ctx, registry)
        self.assertEqual(reports[0].scope_files, 1)
        self.assertEqual([row["file"] for row in reports[0].parsing], ["src/target.cpp"])
        self.assertEqual(coverage["detectors"]["ohscanner.test.scoped"]["applicable_files"], 1)

    def test_scope_selector_cannot_inject_a_source_outside_runner_input(self):
        target = unit("int target(){return 1;}", "src/target.cpp")
        ctx = context((target,))
        injected = unit("int injected(){return 2;}", "src/injected.cpp")
        registry = DetectorRegistry()
        registry.register(_ScopedDetector(lambda _ctx, _units: (injected,)))
        reports, coverage = run_all_with_coverage(ctx, registry)
        self.assertEqual(reports[0].status, "failed")
        self.assertEqual(reports[0].diagnostic_count, 0)
        self.assertEqual(coverage["detectors"]["ohscanner.test.scoped"]["status"], "failed")
        self.assertEqual(coverage["detectors"]["ohscanner.test.scoped"]["coverage_counts"]["not_analyzed"], 1)

    def test_scope_selector_cannot_duplicate_an_in_scope_source(self):
        target = unit("int target(){return 1;}", "src/target.cpp")
        ctx = context((target,))
        registry = DetectorRegistry()
        registry.register(_ScopedDetector(lambda _ctx, units: (units[0], units[0])))
        reports, coverage = run_all_with_coverage(ctx, registry)
        self.assertEqual(reports[0].status, "failed")
        entry = coverage["detectors"]["ohscanner.test.scoped"]
        self.assertEqual(entry["applicable_files"], 1)
        self.assertEqual(entry["coverage_counts"], {
            "complete": 0, "partial": 0, "not_analyzed": 1, "failed": 0})

    def test_per_file_failure_is_counted_separately_from_unanalyzed_scope(self):
        source = unit("int target(){return 1;}", "src/target.cpp")
        ctx = context((source,))

        class _FailedFileDetector(_ScopedDetector):
            def detect(self, context, units):
                return DetectorRun(self.detector_id, self.version, "failed", (),
                                   file_outcomes=((units[0].path, "failed"),))

        registry = DetectorRegistry()
        registry.register(_FailedFileDetector(lambda _ctx, units: tuple(units)))
        reports, coverage = run_all_with_coverage(ctx, registry)
        self.assertEqual(reports[0].status, "failed")
        entry = coverage["detectors"]["ohscanner.test.scoped"]
        self.assertEqual(entry["applicable_files"], 1)
        self.assertEqual(entry["coverage_counts"], {
            "complete": 0, "partial": 0, "not_analyzed": 0, "failed": 1})

    def test_selector_exception_does_not_abort_other_detectors(self):
        source = unit("int target(){return 1;}", "src/target.cpp")
        ctx = context((source,))
        registry = DetectorRegistry()
        registry.register(_ScopedDetector(lambda _ctx, _units: (_ for _ in ()).throw(RuntimeError("selector"))))
        registry.register(_ScopedDetector(lambda _ctx, units: tuple(units),
                                           detector_id="ohscanner.test.following"))
        reports, coverage = run_all_with_coverage(ctx, registry)
        by_id = {report.tool: report for report in reports}
        self.assertEqual(by_id["ohscanner.test.scoped"].status, "failed")
        self.assertEqual(by_id["ohscanner.test.following"].status, "completed")
        self.assertEqual(coverage["detectors"]["ohscanner.test.scoped"]["coverage_counts"]["not_analyzed"], 1)
        self.assertEqual(coverage["detectors"]["ohscanner.test.following"]["coverage_counts"]["complete"], 1)


if __name__ == "__main__":
    unittest.main()

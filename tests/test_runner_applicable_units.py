import hashlib
import unittest

from src.ohscanner.contracts import DetectorRun, ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


class _TargetOnlyDetector:
    detector_id = "ohscanner.test.target_scope"
    version = "1"
    supported_languages = ("cpp",)
    required_facts = ()
    ast_scope = "per_file"

    def __init__(self, selected=("target.cpp",)):
        self.selected = selected

    def select_applicable_units(self, context, units):
        return tuple(unit for unit in units if unit.path in self.selected)

    def detect(self, context, units):
        self.assert_context_scope = tuple(unit.path for unit in context.units)
        targets = tuple(unit.path for unit in units)
        return DetectorRun(self.detector_id, self.version, "completed",
                           analyzed_files=targets,
                           file_outcomes=tuple((path, "complete") for path in targets))


def _unit(path):
    text = "int value;\n"
    return SourceUnit(path, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "complete")


def _context(units):
    units = tuple(sorted(units, key=lambda item: item.path))
    request = ScanRequest("scope-test", "fixture/example", "synthetic",
                          snapshot_digest(units), "current-component:fixture/example")
    return ScanContext(request, units, {})


class RunnerApplicableUnitsTests(unittest.TestCase):
    def test_selector_counts_only_target_but_context_keeps_dependency(self):
        context = _context((_unit("target.cpp"), _unit("dependency.cpp")))
        detector = _TargetOnlyDetector(("target.cpp",))
        registry = DetectorRegistry()
        registry.register(detector)
        reports, coverage = run_all_with_coverage(context, registry)
        sidecar = coverage["detectors"][detector.detector_id]
        self.assertEqual(sidecar["applicable_files"], 1)
        self.assertEqual(sidecar["analyzed_files"], ["target.cpp"])
        self.assertEqual(detector.assert_context_scope, ("dependency.cpp", "target.cpp"))

    def test_unrelated_same_language_unit_is_not_counted(self):
        context = _context((_unit("target.cpp"), _unit("other.cpp")))
        detector = _TargetOnlyDetector(("target.cpp",))
        registry = DetectorRegistry()
        registry.register(detector)
        _, coverage = run_all_with_coverage(context, registry)
        self.assertEqual(coverage["detectors"][detector.detector_id]["applicable_files"], 1)

    def test_selector_cannot_return_out_of_context_unit(self):
        context = _context((_unit("target.cpp"),))

        class BadSelector(_TargetOnlyDetector):
            def select_applicable_units(self, _context, _units):
                return (_unit("outside.cpp"),)

        registry = DetectorRegistry()
        registry.register(BadSelector())
        with self.assertRaisesRegex(ValueError, "applicability selector"):
            run_all_with_coverage(context, registry)


if __name__ == "__main__":
    unittest.main()

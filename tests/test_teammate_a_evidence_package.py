import copy
import hashlib
import json
import re
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from research.experiments.cpp import build_evidence_package as builder
from research.experiments.cpp import validate_evidence_package as validator
from src.benchmark.historical import load_sample
from src.benchmark.report_inputs import load_report_runs
from src.benchmark.root_cause_matrix import (
    NOT_APPLICABLE,
    SampleToolRun,
    ToolCandidate,
    build_revision_hit_matrix,
)
from src.report.benchmark_report import build_benchmark_report, render_markdown


REPO_ROOT = Path(__file__).resolve().parents[1]


def rebinding(record):
    record["binding_sha256"] = validator._binding_digest(record)
    return record


def sample_from_unit(unit):
    return load_sample(
        REPO_ROOT / "benchmarks/historical" / {
            "c_utils-singleton-uaf-2026-01": "c_utils_singleton_uaf.json",
            "kernel_liteos_a-getgroups-oob-2025-12": "kernel_liteos_a_getgroups_oob.json",
            "communication_dsoftbus-null-deref-2025-11": "communication_dsoftbus_null_deref.json",
            "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02":
                "arkcompiler_ets_runtime_jsarray_sort_oob.json",
        }[unit["sample_id"]]
    )


def run_from_evidence(unit):
    request = unit["scan_context_identity"]["request"]
    binding = unit["run_binding"]
    if binding["target_id"] != request["target_id"] or binding["commit"] != request["commit"]:
        raise AssertionError("evidence request/run identity is not bound")
    if unit["result_status"] == "possible_hit":
        candidates = [ToolCandidate(
            file=unit["scope"]["files"][0],
            symbol=unit["scope"]["symbols"][0],
        )]
    elif unit["result_status"] == "miss":
        candidates = []
    elif unit["result_status"] == "unknown":
        candidates = None
    elif unit["result_status"] == "not_applicable":
        candidates = NOT_APPLICABLE
    else:
        raise AssertionError(unit["result_status"])
    return SampleToolRun(
        sample_id=unit["sample_id"],
        revision=unit["revision"],
        tool=unit["tool"]["name"],
        commit=request["commit"],
        candidates=candidates,
        run_id=binding["run_id"],
        source_report="outputs/reports/static_baselines/evidence_units.json",
        source_sha256=unit["binding_sha256"],
        reason=unit.get("not_applicable_reason", ""),
        tool_version=binding["tool_version"],
        scope_files=binding["scope_files"],
        scope_loc=binding["scope_loc"],
        analyzed_files=tuple(unit["scope"]["files"]),
        run_status=unit["execution_status"],
        limitations=tuple(unit["limitations"]),
    )


class TeammateAEvidencePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = builder.build()

    def setUp(self):
        self.package = json.loads(self.built[0])
        self.baseline = json.loads(self.built[1])
        self.units = self.package["units"]
        self.corpus = validator._corpus_index(REPO_ROOT / "research/corpus/native")
        self.record = copy.deepcopy(next(
            unit for unit in self.units
            if unit["sample_id"] == "c_utils-singleton-uaf-2026-01"
            and unit["revision"] == "vulnerable"
            and unit["tool"]["name"] == "own_text"
        ))
        self.miss_record = copy.deepcopy(self.record)

    def validate_record(self, record, name="mutated"):
        validator._validate_unit(rebinding(record), self.corpus, name)

    def assert_invalid(self, record, pattern, name="mutated"):
        with self.assertRaisesRegex(ValueError, pattern):
            self.validate_record(record, name)

    def test_deterministic_package_has_64_baseline_and_16_safe_cells(self):
        self.assertEqual(builder.build(), self.built)
        self.assertEqual(len(self.units), 80)
        baseline = [unit for unit in self.units if unit["control_role"] in {"vulnerable", "fixed"}]
        safe = [unit for unit in self.units if unit["control_role"] == "safe"]
        self.assertEqual((len(baseline), len(safe)), (64, 16))
        self.assertEqual(
            self.baseline["counts"],
            {"possible_hit": 5, "miss": 29, "unknown": 20, "not_applicable": 10},
        )
        self.assertEqual(sum(self.baseline["counts"].values()), 64)
        self.assertEqual(self.baseline["count_semantics"], "Counts are cells, not vulnerabilities or TP/FP/FN.")

    def test_interface_baseline_is_bound_to_pr5_head_and_contract(self):
        expected = {
            "branch": "feat/ohscanner-core",
            "head": "108494bfe392ae62394ea82cd44d28cc03ebb163",
            "contract_path": "src/ohscanner/contracts.py",
            "contract_sha256": "b1a9658d700b73604ca358e80a65e04df4dd1bb8c5edbb85307f1038af865aeb",
        }
        self.assertEqual(self.package["interface_baseline"], expected)
        self.assertEqual(self.baseline["interface_baseline"], expected)
        self.assertEqual(
            hashlib.sha256((REPO_ROOT / expected["contract_path"]).read_bytes()).hexdigest(),
            expected["contract_sha256"],
        )

    def test_wrong_interface_baseline_head_is_rejected(self):
        evidence = json.loads(self.built[0])
        baseline = json.loads(self.built[1])
        evidence["interface_baseline"]["head"] = "0" * 40
        baseline["interface_baseline"]["head"] = "0" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "evidence_units.json"
            baseline_path = root / "baseline_status.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "interface_baseline must bind PR #5 head"):
                validator.validate_package(
                    REPO_ROOT,
                    evidence_path=evidence_path,
                    baseline_path=baseline_path,
                )

    def test_interface_contract_hash_mismatch_is_rejected(self):
        evidence = json.loads(self.built[0])
        baseline = json.loads(self.built[1])
        original = validator.INTERFACE_BASELINE.copy()
        try:
            validator.INTERFACE_BASELINE["contract_sha256"] = "0" * 64
            evidence["interface_baseline"] = dict(validator.INTERFACE_BASELINE)
            baseline["interface_baseline"] = dict(validator.INTERFACE_BASELINE)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence_path = root / "evidence_units.json"
                baseline_path = root / "baseline_status.json"
                evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
                baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "interface contract hash mismatch"):
                    validator.validate_package(
                        REPO_ROOT,
                        evidence_path=evidence_path,
                        baseline_path=baseline_path,
                    )
        finally:
            validator.INTERFACE_BASELINE.clear()
            validator.INTERFACE_BASELINE.update(original)

    def test_pr5_identity_projection_is_bound_without_source_text(self):
        request = self.record["scan_context_identity"]["request"]
        self.assertEqual(
            set(request),
            {"request_id", "repository", "commit", "snapshot_sha256", "target_id", "profile_id", "provenance"},
        )
        self.assertRegex(request["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(request["target_id"], "current-component:" + request["repository"])
        self.assertEqual(request["profile_id"], "light-ast")
        self.assertEqual(request["provenance"], "git_object")
        self.assertEqual(len(self.record["scan_context_identity"]["units"]), 1)
        source_unit = self.record["scan_context_identity"]["units"][0]
        self.assertEqual(
            set(source_unit),
            {"path", "language", "sha256", "parse_status", "parse_issues"},
        )
        self.assertNotIn("text", source_unit)
        self.assertRegex(self.record["git_tree_sha1"], r"^[0-9a-f]{40}$")
        self.assertRegex(self.record["source_artifact"]["git_blob_sha1"], r"^[0-9a-f]{40}$")
        self.assertRegex(self.record["source_file_sha256"], r"^[0-9a-f]{64}$")

    def test_wrong_request_identity_is_rejected(self):
        mutations = {
            "wrong target_id": ("target_id", "current-component:wrong"),
            "wrong snapshot_sha256": ("snapshot_sha256", "0" * 64),
            "wrong profile_id": ("profile_id", "full-build"),
            "wrong provenance": ("provenance", "fixture"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record["scan_context_identity"]["request"][field] = value
                self.assert_invalid(record, name.replace("wrong ", "wrong "))

    def test_wrong_full_commit_is_rejected(self):
        record = copy.deepcopy(self.record)
        wrong_commit = "f" * 40
        record["exact_commit"] = wrong_commit
        record["source_artifact"]["git_commit"] = wrong_commit
        record["scan_context_identity"]["request"]["commit"] = wrong_commit
        record["run_binding"]["commit"] = wrong_commit
        record["source_artifact"]["canonical_url"] = (
            record["source_artifact"]["canonical_url"].rsplit("/", 2)[0]
            + f"/{wrong_commit}/{record['source_artifact']['repository_path']}"
        )
        record["scan_context_identity"]["shared_facts"]["source_artifact"] = record["source_artifact"]
        self.assert_invalid(record, "exact commit mismatch")

    def test_source_tree_blob_and_hash_mismatches_are_rejected(self):
        mutations = {
            "source_file_sha256": (
                lambda record: record.__setitem__("source_file_sha256", "f" * 64),
                "source artifact hash binding mismatch",
            ),
            "git_blob_sha1": (
                lambda record: record["source_artifact"].__setitem__("git_blob_sha1", "f" * 40),
                "source artifact hash binding mismatch",
            ),
            "git_tree_sha1": (
                lambda record: record.__setitem__("git_tree_sha1", "f" * 40),
                "git_tree_sha1 binding mismatch",
            ),
        }
        for name, (mutate, pattern) in mutations.items():
            with self.subTest(name=name):
                record = copy.deepcopy(self.record)
                mutate(record)
                self.assert_invalid(record, pattern, name)

    def test_source_unit_path_and_hash_mismatches_are_rejected(self):
        for field, value, pattern in (
            ("path", "other/path.cpp", "source unit path/hash mismatch"),
            ("sha256", "f" * 64, "source unit path/hash mismatch"),
        ):
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                source_unit = record["scan_context_identity"]["units"][0]
                source_unit[field] = value
                record["scan_context_identity"]["request"]["snapshot_sha256"] = builder.snapshot_digest(
                    record["scan_context_identity"]["units"]
                )
                self.assert_invalid(record, pattern)

    def test_duplicate_and_unsorted_source_units_are_rejected(self):
        duplicate = copy.deepcopy(self.record)
        duplicate["scan_context_identity"]["units"].append(
            copy.deepcopy(duplicate["scan_context_identity"]["units"][0])
        )
        self.assert_invalid(duplicate, "duplicate source unit", "duplicate-source-unit")

        unsorted = copy.deepcopy(self.record)
        first = copy.deepcopy(unsorted["scan_context_identity"]["units"][0])
        second = copy.deepcopy(unsorted["scan_context_identity"]["units"][0])
        first["path"], second["path"] = "z.cpp", "a.cpp"
        unsorted["scan_context_identity"]["units"] = [first, second]
        self.assert_invalid(unsorted, "source units must be sorted", "unsorted-source-unit")

    def test_scope_run_and_request_mismatches_are_rejected(self):
        for field, value, pattern in (
            ("scope_files", 2, "run/request/scope binding mismatch"),
            ("scope_loc", 1, "run/request/scope binding mismatch"),
            ("target_id", "current-component:wrong", "run/request/scope binding mismatch"),
            ("commit", "f" * 40, "run/request/scope binding mismatch"),
        ):
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record["run_binding"][field] = value
                self.assert_invalid(record, pattern, f"run-binding-{field}")

        mismatched_scope = copy.deepcopy(self.record)
        mismatched_scope["scope"]["files"] = ["other/path.cpp"]
        self.assert_invalid(
            mismatched_scope,
            "ScanContext shared facts mismatch scope/source",
            "scope-shared-facts",
        )

    def test_vulnerable_fixed_and_safe_roles_are_isolated(self):
        self.assert_invalid(
            {**copy.deepcopy(self.record), "revision": "fixed"},
            "mixes vulnerable/fixed",
            "mixed-revision",
        )

        safe = copy.deepcopy(next(unit for unit in self.units if unit["control_role"] == "safe"))
        self.assertEqual(safe["execution_status"], "not_run")
        self.assertIsNone(safe["run_id"])
        self.assertEqual(safe["result_status"], "unknown")
        safe["control_role"] = "fixed"
        safe["scan_context_identity"]["shared_facts"]["control_role"] = "fixed"
        self.assert_invalid(safe, "pair scope mismatch", "safe-as-baseline")

        baseline_ids = {
            cell["evidence_unit_id"] for cell in self.baseline["cells"]
        }
        safe_ids = {
            unit["evidence_unit_id"] for unit in self.units if unit["control_role"] == "safe"
        }
        self.assertEqual(len(baseline_ids), 64)
        self.assertEqual(len(safe_ids), 16)
        self.assertTrue(baseline_ids.isdisjoint(safe_ids))

    def test_failed_or_partial_analysis_cannot_be_miss(self):
        cases = (
            ("execution failed", lambda unit: unit.__setitem__("execution_status", "failed")),
            (
                "partial parsing",
                lambda unit: unit.__setitem__(
                    "parsing_coverage",
                    builder.parsing_coverage("partial_macro_context", unit["scope"]["scope_files"]),
                ),
            ),
        )
        for name, mutate in cases:
            with self.subTest(case=name):
                record = copy.deepcopy(self.miss_record)
                mutate(record)
                self.assert_invalid(record, "cannot be miss", name)

    def test_not_run_unknown_and_not_applicable_boundaries(self):
        record = copy.deepcopy(next(unit for unit in self.units if unit["control_role"] == "safe"))
        record["result_status"] = "miss"
        self.assert_invalid(record, "not_run must remain unknown", "not-run-as-miss")

        record = copy.deepcopy(self.record)
        record["result_status"] = "not_applicable"
        record["execution_status"] = "blocked"
        record["parsing_coverage"] = {
            "status": "not_applicable_no_translation_unit",
            "files_complete": 0,
            "files_partial": 0,
            "files_failed": 0,
            "files_not_applicable": 1,
            "files_not_run": 0,
        }
        self.assert_invalid(record, "explicit reason", "na-missing-reason")

        record["not_applicable_reason"] = "Required headers are unavailable; no translation unit can be formed."
        self.validate_record(record, "valid-na")

        stale_failed_shape = copy.deepcopy(record)
        stale_failed_shape["parsing_coverage"] = {
            "status": "not_applicable_no_translation_unit",
            "files_complete": 0,
            "files_partial": 0,
            "files_failed": 1,
            "files_not_applicable": 0,
            "files_not_run": 0,
        }
        self.assert_invalid(
            stale_failed_shape,
            "parsing coverage counts do not match status",
            "na-as-failed-coverage",
        )

        missing_bucket_shape = copy.deepcopy(record)
        missing_bucket_shape["parsing_coverage"].pop("files_not_run")
        self.assert_invalid(
            missing_bucket_shape,
            "parsing coverage fields mismatch",
            "missing-not-run-bucket",
        )

        record = copy.deepcopy(self.record)
        record["result_status"] = "unknown"
        record["result_evidence_count"] = 1
        self.assert_invalid(record, "unknown cannot carry", "unknown-evidence")

    def test_parsing_coverage_buckets_exclusive_and_explicit(self):
        expected_by_status = {
            "complete": "files_complete",
            "complete_unresolved_symbol": "files_partial",
            "partial_macro_context": "files_partial",
            "failed": "files_failed",
            "not_applicable_no_source_files": "files_not_applicable",
            "not_run": "files_not_run",
        }
        for status, bucket in expected_by_status.items():
            with self.subTest(status=status):
                coverage = builder.parsing_coverage(status, 2)
                self.assertEqual(coverage["status"], status)
                self.assertEqual(
                    {key: value for key, value in coverage.items() if key != "status"},
                    {
                        "files_complete": 2 if bucket == "files_complete" else 0,
                        "files_partial": 2 if bucket == "files_partial" else 0,
                        "files_failed": 2 if bucket == "files_failed" else 0,
                        "files_not_applicable": 2 if bucket == "files_not_applicable" else 0,
                        "files_not_run": 2 if bucket == "files_not_run" else 0,
                    },
                )

        safe = copy.deepcopy(next(unit for unit in self.units if unit["control_role"] == "safe"))
        self.assertEqual(safe["parsing_coverage"], {
            "status": "not_run",
            "files_complete": 0,
            "files_partial": 0,
            "files_failed": 0,
            "files_not_applicable": 0,
            "files_not_run": 1,
        })
        for status in (
            "complete",
            "complete_unresolved_symbol",
            "partial_macro_context",
            "not_applicable_no_source_files",
        ):
            generated = next(
                unit for unit in self.units
                if unit["control_role"] != "safe" and unit["parsing_coverage"]["status"] == status
            )
            self.assertEqual(
                generated["parsing_coverage"],
                builder.parsing_coverage(status, generated["scope"]["scope_files"]),
            )

    def test_binding_digest_is_not_optional(self):
        record = copy.deepcopy(self.record)
        record["binding_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binding digest mismatch"):
            validator._validate_unit(record, self.corpus, "bad-binding")

    def test_duplicate_run_id_is_rejected_by_package_validation(self):
        data = json.loads(self.built[0])
        first, second = data["units"][:2]
        second["run_id"] = first["run_id"]
        second["run_binding"]["run_id"] = first["run_id"]
        second["evidence_unit_id"] = (
            f"{second['scope']['analysis_unit_id']}:{second['tool']['name']}:{second['run_id']}"
        )
        rebinding(second)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "evidence_units.json"
            baseline_path = root / "baseline_status.json"
            evidence_path.write_text(json.dumps(data), encoding="utf-8")
            baseline_path.write_text(self.built[1], encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate run_id"):
                validator.validate_package(
                    REPO_ROOT,
                    evidence_path=evidence_path,
                    baseline_path=baseline_path,
                )

    def test_report_integration_preserves_cell_status_and_verdict_boundaries(self):
        selected = {
            "c_utils-singleton-uaf-2026-01",
            "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02",
        }
        evidence = [
            unit for unit in self.units
            if unit["sample_id"] in selected and unit["control_role"] in {"vulnerable", "fixed"}
        ]
        samples = [sample_from_unit(unit) for unit in evidence[:1]]
        samples.extend([
            load_sample(REPO_ROOT / "benchmarks/historical/arkcompiler_ets_runtime_jsarray_sort_oob.json"),
        ])
        runs = [run_from_evidence(unit) for unit in evidence]
        matrix = build_revision_hit_matrix(samples, runs, tools=sorted({unit["tool"]["name"] for unit in evidence}))
        actual = {(row.sample_id, row.revision, row.tool): row.status for row in matrix.rows}
        expected = {
            (unit["sample_id"], unit["revision"], unit["tool"]["name"]): unit["result_status"]
            for unit in evidence
        }
        self.assertEqual(actual, expected)

        report = build_benchmark_report(samples, runs=runs, tools=sorted({unit["tool"]["name"] for unit in evidence}))
        markdown = render_markdown(report)
        self.assertEqual(report.validated_vulnerability, 0)
        self.assertIn("validated_vulnerability = 0", markdown)
        self.assertIn("No Precision/Recall is computed", markdown)
        self.assertIn("possible_hit", markdown)
        self.assertIn("unknown", markdown)

    def test_report_loader_target_id_contract_gap_is_explicit(self):
        self.assertNotIn("target_id", SampleToolRun.__dataclass_fields__)
        unit = next(
            item for item in self.units
            if item["sample_id"] == "c_utils-singleton-uaf-2026-01"
            and item["revision"] == "vulnerable"
            and item["tool"]["name"] == "own_text"
        )
        request = unit["scan_context_identity"]["request"]
        sample = sample_from_unit(unit)
        report = {
            "schema_version": 1,
            "run_id": unit["run_binding"]["run_id"],
            "tool": unit["tool"]["name"],
            "tool_version": unit["tool"]["version"],
            "target_id": request["target_id"],
            "commit": request["commit"],
            "scope_files": 1,
            "scope_loc": unit["source_artifact"]["lines"],
            "status": "completed",
            "elapsed_seconds": 0.01,
            "diagnostics": [],
            "limitations": unit["limitations"],
            "parsing": [{"file": unit["scope"]["files"][0], "status": "complete"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "run.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            manifest = root / "inputs.json"
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "runs": [{
                    "sample_id": unit["sample_id"],
                    "revision": unit["revision"],
                    "report": report_path.name,
                    "analyzed_files": unit["scope"]["files"],
                }],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "target_id must equal sample_id"):
                load_report_runs(manifest, [sample])

    def test_baseline_projection_counts_cells_not_vulnerabilities(self):
        counted = Counter(cell["result_status"] for cell in self.baseline["cells"])
        self.assertEqual(
            {key: counted[key] for key in ("possible_hit", "miss", "unknown", "not_applicable")},
            self.baseline["counts"],
        )
        self.assertEqual(len(self.baseline["cells"]), 64)
        for cell in self.baseline["cells"]:
            request = next(
                unit["scan_context_identity"]["request"]
                for unit in self.units
                if unit["evidence_unit_id"] == cell["evidence_unit_id"]
            )
            self.assertEqual(cell["target_id"], request["target_id"])
            self.assertEqual(cell["commit"], request["commit"])
            self.assertEqual(cell["snapshot_sha256"], request["snapshot_sha256"])


if __name__ == "__main__":
    unittest.main()

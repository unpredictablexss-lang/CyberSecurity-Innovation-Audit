import unittest
from pathlib import Path

from src.benchmark.historical import (
    HistoricalSample,
    load_sample,
    validate_sample_label,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _sample(**overrides) -> HistoricalSample:
    base = dict(
        schema_version=1,
        sample_id="s",
        title="t",
        repository="r",
        repo_url="https://x",
        vulnerable_commit="a",
        fixed_commit="b",
        weakness="CWE-416",
        affected_files=["f.c"],
        affected_symbols=["f"],
        root_cause="rc",
        source_refs=["https://ref"],
        label_status="patch_confirmed",
        root_cause_group="lifetime_uaf",
        evidence_level="patch_and_issue",
        runtime_replay_status="not_run",
    )
    base.update(overrides)
    return HistoricalSample(**base)


class HistoricalLabelTests(unittest.TestCase):
    def test_load_sample_reads_label_fields(self) -> None:
        sample = load_sample(
            REPO_ROOT / "benchmarks" / "historical" / "c_utils_singleton_uaf.json"
        )
        self.assertEqual(sample.label_status, "patch_confirmed")
        self.assertEqual(sample.root_cause_group, "lifetime_uaf")
        self.assertEqual(sample.evidence_level, "patch_and_issue")
        self.assertEqual(sample.runtime_replay_status, "not_run")

    def test_validate_returns_no_warnings_for_complete_sample(self) -> None:
        self.assertEqual(validate_sample_label(_sample()), [])

    def test_validate_returns_warnings_for_missing_fields(self) -> None:
        warnings = validate_sample_label(
            _sample(root_cause_group="", evidence_level="", source_refs=[])
        )
        self.assertIn("root_cause_group is empty", warnings)
        self.assertIn("evidence_level is empty", warnings)
        self.assertIn("source_refs is empty", warnings)

    def test_validate_does_not_require_cve(self) -> None:
        warnings = validate_sample_label(_sample())
        self.assertNotIn("cve", " ".join(warnings))


if __name__ == "__main__":
    unittest.main()

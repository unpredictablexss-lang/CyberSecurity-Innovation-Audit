from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from src.ohscanner.cross_version import (
    assess_impact,
    candidate_observation_relation,
)


def evidence(*roles: str):
    return [
        {"role": role, "verified": True, "evidence_id": f"ev-{role}"}
        for role in roles
    ]


class CrossVersionImpactSemanticsTests(unittest.TestCase):
    def test_first_row_is_unknown_not_added(self) -> None:
        relation, reasons = candidate_observation_relation(
            False,
            True,
            comparable=True,
            first_row=True,
        )
        self.assertEqual(relation, "unknown")
        self.assertEqual(reasons, ["no_previous_comparison_row"])

    def test_observation_relations_are_separate_from_impact(self) -> None:
        self.assertEqual(
            candidate_observation_relation(
                True,
                False,
                comparable=True,
                first_row=False,
            )[0],
            "disappeared",
        )
        self.assertEqual(
            assess_impact(
                "fixed",
                evidence("source", "patch", "call_path"),
                source_present=True,
                boundary_support="fixed",
            ),
            ("unknown", ["missing_evidence:revalidation"]),
        )

    def test_disappearance_without_patch_and_revalidation_is_not_fixed(self) -> None:
        status, reasons = assess_impact(
            "fixed",
            evidence("source", "patch", "call_path"),
            source_present=True,
            boundary_support="fixed",
        )
        self.assertEqual(status, "unknown")
        self.assertIn("missing_evidence:revalidation", reasons)

    def test_fixed_requires_complete_evidence_and_boundary_support(self) -> None:
        status, reasons = assess_impact(
            "fixed",
            evidence("source", "patch", "call_path", "revalidation"),
            source_present=True,
            boundary_support="fixed",
        )
        self.assertEqual(status, "fixed")
        self.assertEqual(reasons, [])

        status, reasons = assess_impact(
            "fixed",
            evidence("source", "patch", "call_path", "revalidation"),
            source_present=True,
            boundary_support="clean_unknown",
        )
        self.assertEqual(status, "unknown")
        self.assertEqual(reasons, ["boundary_revalidation_not_fixed"])

    def test_affected_requires_source_patch_and_call_path(self) -> None:
        status, reasons = assess_impact(
            "affected",
            evidence("source", "patch"),
            source_present=True,
            boundary_support="affected",
        )
        self.assertEqual(status, "unknown")
        self.assertIn("missing_evidence:call_path", reasons)
        self.assertIn("missing_evidence:revalidation", reasons)

        status, reasons = assess_impact(
            "affected",
            evidence("source", "patch", "call_path", "revalidation"),
            source_present=True,
            boundary_support="affected",
        )
        self.assertEqual(status, "affected")
        self.assertEqual(reasons, [])

    def test_not_present_requires_exact_tree_absence(self) -> None:
        status, reasons = assess_impact(
            "not_present",
            evidence(),
            source_present=False,
            boundary_support="not_present",
        )
        self.assertEqual(status, "unknown")
        self.assertIn("missing_evidence:tree_absence", reasons)
        self.assertIn("missing_evidence:patch", reasons)
        self.assertIn("missing_evidence:call_path", reasons)
        self.assertIn("missing_evidence:revalidation", reasons)

        status, reasons = assess_impact(
            "not_present",
            evidence("tree_absence", "patch", "call_path", "revalidation"),
            source_present=False,
            boundary_support="not_present",
        )
        self.assertEqual(status, "not_present")
        self.assertEqual(reasons, [])


class RootCauseMetricsTests(unittest.TestCase):
    def test_metrics_are_blocked_without_reliable_independent_truth(self):
        from src.ohscanner.evaluation import evaluate_root_causes

        result = evaluate_root_causes(
            [{"sample_id": "s1", "root_cause_id": "rc", "prediction": "detected"}],
            [{
                "sample_id": "s1",
                "root_cause_id": "rc",
                "category": "vulnerable",
                "split": "holdout",
                "truth_verified": True,
                "truth_source": "manual-independently-signed",
            }],
            truth_manifest={"eligible_for_metrics": False},
            independent_holdout=True,
        )
        self.assertFalse(result["eligible_for_metrics"])
        self.assertEqual(
            result["counts"],
            {"TP": None, "FP": None, "FN": None, "TN": None},
        )
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])

    def test_metrics_count_independent_root_causes_not_alert_rows(self):
        from src.ohscanner.evaluation import evaluate_root_causes

        result = evaluate_root_causes(
            [
                {"sample_id": "a1", "root_cause_id": "rc-a", "prediction": "detected"},
                {"sample_id": "a2", "root_cause_id": "rc-a", "prediction": "detected"},
                {"sample_id": "b1", "root_cause_id": "rc-b", "prediction": "not_detected"},
                {"sample_id": "c1", "root_cause_id": "rc-c", "prediction": "detected"},
            ],
            [
                {"sample_id": "a1", "root_cause_id": "rc-a", "category": "vulnerable", "split": "holdout", "truth_verified": True, "truth_source": "manual-independently-signed"},
                {"sample_id": "a2", "root_cause_id": "rc-a", "category": "vulnerable", "split": "holdout", "truth_verified": True, "truth_source": "manual-independently-signed"},
                {"sample_id": "b1", "root_cause_id": "rc-b", "category": "vulnerable", "split": "holdout", "truth_verified": True, "truth_source": "manual-independently-signed"},
                {"sample_id": "c1", "root_cause_id": "rc-c", "category": "safe", "split": "holdout", "truth_verified": True, "truth_source": "manual-independently-signed"},
            ],
            truth_manifest={"eligible_for_metrics": True},
            independent_holdout=True,
        )
        self.assertEqual(result["counts"], {"TP": 1, "FP": 1, "FN": 1, "TN": 0})
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)


class MultiRepoProductBindingTests(unittest.TestCase):
    def _repo(self, root: Path, name: str, content: str):
        repo = root / name
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / "src.cpp").write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "src.cpp"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True)
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
        blob = subprocess.check_output(["git", "rev-parse", "HEAD:src.cpp"], cwd=repo, text=True).strip()
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return {
            "component_id": name,
            "repository": "fixture/" + name,
            "checkout_dir": name,
            "commit": commit,
            "tree": tree,
            "source_bindings": [{
                "path": "src.cpp",
                "source_blob_oid": blob,
                "source_sha256": digest,
            }],
        }

    def test_each_component_requires_its_own_actual_sha(self):
        from src.ohscanner.cross_version import verify_product_components

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = self._repo(root, "component-a", "int a() { return 1; }\n")
            second = self._repo(root, "component-b", "int b() { return 2; }\n")
            manifest = {
                "product_version": {
                    "components": [first, second],
                }
            }
            result = verify_product_components(manifest, root)
            self.assertEqual(result["status"], "verified")
            self.assertEqual(len(result["components"]), 2)
            self.assertEqual(
                {item["commit"] for item in result["components"]},
                {first["commit"], second["commit"]},
            )
            self.assertFalse(result["shared_product_commit_allowed"])

    def test_shared_product_commit_is_rejected(self):
        from src.ohscanner.cross_version import verify_product_components

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = self._repo(root, "component-a", "int a() { return 1; }\n")
            second = self._repo(root, "component-b", "int b() { return 2; }\n")
            manifest = {
                "product_version": {
                    "commit": first["commit"],
                    "components": [first, second],
                }
            }
            with self.assertRaisesRegex(ValueError, "shared commit"):
                verify_product_components(manifest, root)


if __name__ == "__main__":
    unittest.main()

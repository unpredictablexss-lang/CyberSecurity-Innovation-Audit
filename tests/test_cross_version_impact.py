from __future__ import annotations

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
            source_present=False,
            boundary_support=None,
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
        )
        self.assertEqual(status, "unknown")
        self.assertEqual(reasons, ["missing_evidence:call_path"])

        status, reasons = assess_impact(
            "affected",
            evidence("source", "patch", "call_path"),
            source_present=True,
        )
        self.assertEqual(status, "affected")
        self.assertEqual(reasons, [])

    def test_not_present_requires_exact_tree_absence(self) -> None:
        status, reasons = assess_impact(
            "not_present",
            evidence(),
            source_present=False,
        )
        self.assertEqual(status, "unknown")
        self.assertEqual(reasons, ["missing_evidence:tree_absence"])

        status, reasons = assess_impact(
            "not_present",
            evidence("tree_absence"),
            source_present=False,
        )
        self.assertEqual(status, "not_present")
        self.assertEqual(reasons, [])


if __name__ == "__main__":
    unittest.main()

import unittest
from src.workbench.service import finding_clusters, findings


class FindingClusterTests(unittest.TestCase):
    def report(self, diagnostics):
        return {
            "repository": "openharmony/example",
            "commit": "a" * 40,
            "snapshot_sha256": "b" * 64,
            "detector_runs": [{
                "tool": "ohscanner.cpp.shared_ptr_race",
                "tool_version": "0.2.0",
                "diagnostics": diagnostics,
            }],
            "detector_coverage": {"detectors": {
                "ohscanner.cpp.shared_ptr_race": {"evidence_obligations": []},
            }},
        }

    def diagnostic(self, identity, line, **overrides):
        result = {
            "diagnostic_id": identity, "file": "src/cache.cpp", "line": line,
            "column": 4, "rule_id": "shared-ptr-race", "symbol": "cache_",
            "message": "Candidate only: non-atomic shared_ptr member read of cache_",
            "source_sha256": "c" * 64,
        }
        result.update(overrides)
        return result

    def test_same_bound_file_symbol_groups_without_deleting_observations(self):
        report = self.report([self.diagnostic("d1", 10), self.diagnostic("d2", 28)])
        groups = finding_clusters(report)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["observation_count"], 2)
        self.assertEqual([x["line"] for x in groups[0]["candidates"]], [10, 28])
        self.assertEqual(len({x["id"] for x in groups[0]["candidates"]}), 2)
        self.assertEqual(groups[0]["root_cause_conclusion"], "not_inferred")
        self.assertEqual(len(findings(report)), 2)

    def test_source_rule_or_version_change_does_not_merge(self):
        report = self.report([
            self.diagnostic("d1", 10),
            self.diagnostic("d2", 28, source_sha256="d" * 64),
            self.diagnostic("d3", 40, rule_id="other-rule"),
        ])
        self.assertEqual(len(finding_clusters(report)), 3)

    def test_unbound_or_symbol_less_observations_stay_separate(self):
        report = self.report([
            self.diagnostic("d1", 10, source_sha256="", symbol=None),
            self.diagnostic("d2", 28, source_sha256="", symbol=None),
        ])
        groups = finding_clusters(report)
        self.assertEqual(len(groups), 2)
        self.assertTrue(all("kept separate" in x["grouping_basis"] for x in groups))

    def test_group_identity_and_member_order_are_deterministic(self):
        a = self.report([self.diagnostic("d1", 28), self.diagnostic("d2", 10)])
        b = self.report([self.diagnostic("d2", 10), self.diagnostic("d1", 28)])
        ga, gb = finding_clusters(a), finding_clusters(b)
        self.assertEqual(ga[0]["cluster_id"], gb[0]["cluster_id"])
        self.assertEqual(ga[0]["candidates"], gb[0]["candidates"])


if __name__ == "__main__":
    unittest.main()
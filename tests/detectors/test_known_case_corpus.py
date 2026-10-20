from __future__ import annotations
import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector, VERSION
from src.ohscanner.fixture import snapshot_digest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "known_cases"
MANIFEST = json.loads((FIXTURES / "known_case_manifest.json").read_text(encoding="utf-8"))
CASE_SYMBOLS = {
    "local-group-delete": "LOCAL-GROUP-DELETE",
    "local-request-path": "LOCAL-REQUEST-PATH",
    "local-request-fd": "LOCAL-REQUEST-FD",
    "local-deviceauth-negative-length": "LOCAL-DEVICEAUTH-NEGATIVE-LENGTH",
    "manual-appdomain-priority": "MANUAL-APPDOMAIN-PRIORITY",
    "manual-storage-statistics": "MANUAL-STORAGE-STATISTICS",
}


class KnownCaseCorpusTests(unittest.TestCase):
    def run_fixture(self, directory: str, control: str):
        case_dir = FIXTURES / directory
        text = (case_dir / f"{control}.cpp").read_text(encoding="utf-8")
        source_path = (case_dir / "source_path.txt").read_text(encoding="utf-8").strip()
        parse_status = "partial" if control == "unknown" else "complete"
        unit = SourceUnit(
            path=source_path,
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status=parse_status,
            parse_issues=("synthetic partial-parse control",) if parse_status == "partial" else (),
        )
        request = ScanRequest(
            request_id=f"c11:{directory}:{control}",
            repository="fixture/known-cases",
            commit="c" * 40,
            snapshot_sha256=snapshot_digest((unit,)),
            target_id="current-component:fixture/known-cases",
            profile_id="fixture-no-build",
            provenance="fixture",
        )
        return KnownDisclosedCveDetector().detect(
            ScanContext(request=request, units=(unit,)), (unit,)
        )

    def test_manifest_is_28_way_source_bound_disposition_corpus(self):
        self.assertEqual("0.17.0", VERSION)
        self.assertEqual(28, len(MANIFEST["cases"]))
        self.assertEqual(
            {"public_cve": 17, "local_dangerous_shape": 5, "manual_candidate": 4, "exclusion": 2},
            {bucket: sum(c["bucket"] == bucket for c in MANIFEST["cases"]) for bucket in
             ("public_cve", "local_dangerous_shape", "manual_candidate", "exclusion")},
        )
        self.assertEqual("ab30df6a01797af455d2abbbc9533ab15964ee68", MANIFEST["baseline_commit"])
        audit = MANIFEST["source_audit"]
        blob = subprocess.run(
            ["git", "cat-file", "blob", audit["blob"]], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
        self.assertEqual(audit["bytes"], len(blob))
        self.assertEqual(audit["sha256"], hashlib.sha256(blob).hexdigest())
        for object_type, object_id in (("commit", audit["commit"]), ("tree", audit["tree"]), ("blob", audit["blob"])):
            actual = subprocess.run(
                ["git", "cat-file", "-t", object_id], cwd=ROOT,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(object_type, actual)

    def test_public_cve_rows_have_existing_positive_fixed_or_boundary_controls(self):
        test_source = (ROOT / "tests" / "detectors" / "test_known_disclosed_cves.py").read_text(encoding="utf-8")
        rows = [c for c in MANIFEST["cases"] if c["bucket"] == "public_cve"]
        self.assertEqual(17, len(rows))
        for row in rows:
            self.assertEqual("candidate", row["scanner_expectation"])
            self.assertEqual("unknown", row["product_vulnerability"])
            self.assertTrue(row["rule_id"].startswith("ohknowncve-"))
            self.assertIn(row["identity"].lower().replace("cve-", ""), row["rule_id"])
            self.assertRegex(row["target_source_binding"], r"source unavailable/unknown")
            test_name = row["control_ref"].split("::")[-1]
            self.assertIn("def " + test_name, test_source)

    def test_review_shape_positive_fixed_safe_unrelated_and_unknown_controls(self):
        for directory, symbol in CASE_SYMBOLS.items():
            with self.subTest(directory=directory):
                positive = self.run_fixture(directory, "positive")
                self.assertEqual("completed", positive.status)
                self.assertIn(symbol, {f.symbol for f in positive.findings})
                candidate = next(f for f in positive.findings if f.symbol == symbol)
                self.assertEqual("partial", candidate.identity_quality)
                self.assertTrue(candidate.source_sha256)
                self.assertTrue(candidate.evidence_obligations)
                self.assertTrue(all(o.status in ("missing", "unknown") for o in candidate.evidence_obligations))
                self.assertIn("unconfirmed", candidate.message.lower())

                for control in ("fixed", "safe", "unrelated"):
                    run = self.run_fixture(directory, control)
                    self.assertEqual("completed", run.status)
                    self.assertNotIn(symbol, {f.symbol for f in run.findings})

                unknown = self.run_fixture(directory, "unknown")
                self.assertEqual("blocked", unknown.status)
                self.assertIn(symbol, {f.symbol for f in unknown.findings})
                self.assertTrue(any("parse_status=partial" in item for item in unknown.limitations))

    def test_unsupported_manual_candidates_are_explicitly_bounded(self):
        rows = {c["identity"]: c for c in MANIFEST["cases"] if c["bucket"] == "manual_candidate"}
        self.assertEqual(
            "explicit-unknown-auditable-limitation",
            rows["MANUAL-UPDATE-DEV-SIGNING"]["scanner_expectation"],
        )
        self.assertIsNone(rows["MANUAL-UPDATE-DEV-SIGNING"]["rule_id"])
        self.assertIn("unsupported-artifact", rows["MANUAL-UPDATE-DEV-SIGNING"]["audit_disposition"])
        self.assertEqual(
            "explicit-unknown-auditable-limitation",
            rows["MANUAL-SECURITY-ASSET-CROSS-ACCOUNT"]["scanner_expectation"],
        )
        self.assertIsNone(rows["MANUAL-SECURITY-ASSET-CROSS-ACCOUNT"]["rule_id"])
        self.assertIn("unsupported-language", rows["MANUAL-SECURITY-ASSET-CROSS-ACCOUNT"]["audit_disposition"])
        for row in rows.values():
            self.assertEqual("unknown", row["product_vulnerability"])

    def test_exclusions_are_not_applicable_and_never_product_safe(self):
        rows = [c for c in MANIFEST["cases"] if c["bucket"] == "exclusion"]
        self.assertEqual(2, len(rows))
        for row in rows:
            self.assertEqual("not-applicable", row["scanner_expectation"])
            self.assertEqual("not-applicable", row["product_vulnerability"])
            self.assertTrue(row["audit_disposition"].startswith("not-applicable-"))
            self.assertIsNone(row["rule_id"])
            self.assertRegex(row["target_source_binding"], r"source unavailable/unknown")


if __name__ == "__main__":
    unittest.main()


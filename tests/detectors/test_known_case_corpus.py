from __future__ import annotations
import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.adapters import classify_artifact, resolve_source_identity
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
    "local-pasteboard-historical-read": ("CVE-2025-25212", "CVE-2025-27247"),
}


class KnownCaseCorpusTests(unittest.TestCase):
    def run_fixture(self, directory: str, control: str, shared_facts=None):
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
            ScanContext(request=request, units=(unit,), shared_facts=shared_facts or {}), (unit,)
        )

    def test_manifest_is_28_way_source_bound_disposition_corpus(self):
        self.assertEqual("0.19.11", VERSION)
        self.assertEqual(28, len(MANIFEST["cases"]))
        self.assertEqual(
            {"public_cve": 17, "local_dangerous_shape": 5, "manual_candidate": 4, "exclusion": 2},
            {bucket: sum(c["bucket"] == bucket for c in MANIFEST["cases"]) for bucket in
             ("public_cve", "local_dangerous_shape", "manual_candidate", "exclusion")},
        )
        self.assertEqual("ddd8556768d679fcc09f1fcb37d10730f49b2c6c", MANIFEST["baseline_commit"])
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
        for directory, expected in CASE_SYMBOLS.items():
            symbols = {expected} if isinstance(expected, str) else set(expected)
            with self.subTest(directory=directory):
                positive = self.run_fixture(directory, "positive")
                self.assertEqual("completed", positive.status)
                positive_symbols = {f.symbol for f in positive.findings}
                for symbol in symbols:
                    self.assertIn(symbol, positive_symbols)
                    candidate = next(f for f in positive.findings if f.symbol == symbol)
                    self.assertEqual("partial", candidate.identity_quality)
                    self.assertTrue(candidate.source_sha256)
                    self.assertTrue(candidate.evidence_obligations)
                    self.assertTrue(all(o.status in ("missing", "unknown") for o in candidate.evidence_obligations))
                    self.assertIn("unconfirmed", candidate.message.lower())

                for control in ("fixed", "safe", "unrelated"):
                    run = self.run_fixture(directory, control)
                    self.assertEqual("completed", run.status)
                    control_symbols = {f.symbol for f in run.findings}
                    if directory == "local-pasteboard-historical-read" and control in ("fixed", "safe"):
                        self.assertIn("CVE-2025-27247", control_symbols)
                        finding = next(f for f in run.findings if f.symbol == "CVE-2025-27247")
                        self.assertIn("permission_guard", {o.kind for o in finding.evidence_obligations})
                        self.assertTrue(all(o.status == "unknown" for o in finding.evidence_obligations if o.kind == "permission_guard"))
                    else:
                        self.assertTrue(symbols.isdisjoint(control_symbols))

                unknown = self.run_fixture(directory, "unknown")
                self.assertEqual("blocked", unknown.status)
                unknown_symbols = {f.symbol for f in unknown.findings}
                for symbol in symbols:
                    self.assertIn(symbol, unknown_symbols)
                self.assertTrue(any("parse_status=partial" in item for item in unknown.limitations))

    def test_unsupported_manual_candidates_are_explicitly_bounded(self):
        rows = {c["identity"]: c for c in MANIFEST["cases"] if c["bucket"] == "manual_candidate"}
        self.assertEqual(
            "explicit-unknown-auditable-limitation",
            rows["MANUAL-UPDATE-DEV-SIGNING"]["scanner_expectation"],
        )
        self.assertIsNone(rows["MANUAL-UPDATE-DEV-SIGNING"]["rule_id"])
        self.assertIn("bounded-artifact-p12-json5", rows["MANUAL-UPDATE-DEV-SIGNING"]["c12_disposition"])
        self.assertEqual(
            "explicit-unknown-auditable-limitation",
            rows["MANUAL-SECURITY-ASSET-CROSS-ACCOUNT"]["scanner_expectation"],
        )
        self.assertIsNone(rows["MANUAL-SECURITY-ASSET-CROSS-ACCOUNT"]["rule_id"])
        self.assertIn("bounded-language-rust", rows["MANUAL-SECURITY-ASSET-CROSS-ACCOUNT"]["c12_disposition"])
        for row in rows.values():
            self.assertEqual("unknown", row["product_vulnerability"])

    def test_pasteboard_manifest_matches_current_control_bytes_and_results(self):
        case = next(row for row in MANIFEST["cases"]
                    if row["identity"] == "LOCAL-PASTEBOARD-HISTORICAL-READ")
        replay = case["repository_control_replay"]
        for control, expected_count in (("positive", 2), ("fixed", 1), ("safe", 1),
                                        ("unrelated", 0), ("unknown", 2)):
            with self.subTest(control=control):
                entry = replay["controls"][control + ".cpp"]
                data = (ROOT / entry["path"]).read_bytes()
                self.assertEqual(len(data), entry["bytes"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["source_sha256"])
                self.assertEqual(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
                                 entry["blob"])
                run = self.run_fixture("local-pasteboard-historical-read", control)
                self.assertEqual(expected_count, len(run.findings))
                result_key = "parent" if control == "positive" else control
                expected_result = (f"{expected_count} candidate(s) + blocked/partial" if control == "unknown"
                                   else f"{expected_count} candidate(s)" if control == "positive" else expected_count)
                self.assertEqual(expected_result, replay["result"][result_key])

    def test_exclusions_are_not_applicable_and_never_product_safe(self):
        rows = [c for c in MANIFEST["cases"] if c["bucket"] == "exclusion"]
        self.assertEqual(2, len(rows))
        for row in rows:
            self.assertEqual("not-applicable", row["scanner_expectation"])
            self.assertEqual("not-applicable", row["product_vulnerability"])
            self.assertTrue(row["audit_disposition"].startswith("not-applicable-"))
            self.assertIsNone(row["rule_id"])
            self.assertRegex(row["target_source_binding"], r"source unavailable/unknown")


    def test_bounded_p12_json5_rust_adapters_preserve_language_limitations(self):
        fixture_dir = FIXTURES / "artifact-adapter-controls"
        cases = (
            ("OpenHarmony.p12", "pkcs12-der-candidate", "explicit-unknown-unsupported-binary-artifact"),
            ("build-profile.json5", "json5-config-candidate", "explicit-unknown-unsupported-config-language"),
            ("security_asset.rs", "rust-source-candidate", "explicit-unknown-unsupported-language"),
        )
        inventory = []
        for name, kind, disposition in cases:
            data = (fixture_dir / name).read_bytes()
            identified = classify_artifact("artifact-adapter-controls/" + name, data)
            self.assertEqual(kind, identified.kind)
            self.assertEqual(disposition, identified.disposition)
            inventory.append(("artifact-adapter-controls/" + name, data))
        run = self.run_fixture(
            "local-request-path", "safe",
            shared_facts={"artifact_inventory": tuple(inventory)},
        )
        self.assertEqual("completed", run.status)
        for _, kind, disposition in cases:
            self.assertTrue(any(kind in item and disposition in item for item in run.limitations))

    def test_source_identity_requires_full_object_tree_and_hash_binding(self):
        class Lookup:
            repository = "openharmony/source"
            def object_type(self, object_id):
                return {"a" * 40: "commit", "b" * 40: "tree", "c" * 40: "blob"}.get(object_id, "missing")
            def blob_bytes(self, object_id):
                return b"bounded source"
            def path_blob(self, commit_id, path):
                return "c" * 40 if path == "src/file.cpp" else "d" * 40
        claim = {
            "repository": "openharmony/source",
            "commit": "a" * 40,
            "tree": "b" * 40,
            "blob": "c" * 40,
            "source_sha256": hashlib.sha256(b"bounded source").hexdigest(),
            "path": "src/file.cpp",
        }
        self.assertEqual("verified", resolve_source_identity(claim, Lookup()).status)
        short = dict(claim, commit="abc123")
        self.assertEqual("explicit-unknown", resolve_source_identity(short, Lookup()).status)
        wrong_hash = dict(claim, source_sha256="0" * 64)
        self.assertEqual("explicit-unknown", resolve_source_identity(wrong_hash, Lookup()).status)

    def test_repository_control_public_pairs_replay_parent_to_fixed(self):
        pinned = "db77164fdc2af0da02e4d3efc056d84694fd68e8"
        tree = "8c5a296d8304d98193a29a4695aaf61ca0c0996c"
        pairs = (
            (
                "CVE-2026-58313",
                "tests/fixtures/data_sensitive/d39_cve_2026_58313_lru_vulnerable.h",
                "tests/fixtures/data_sensitive/d39_cve_2026_58313_lru_fixed.h",
                "frameworks/common/include/utils/lru_cache_util.h",
                "7ce4262e3f1d2c0173d929318a4795ff1573c721",
                "68114f10d83c8f0bdc46679c7efa35ed286bef8a",
            ),
            (
                "CVE-2026-33636",
                "tests/fixtures/data_sensitive/cve_2026_33636/libpng-1.6.55-palette_neon_intrinsics.c",
                "tests/fixtures/data_sensitive/cve_2026_33636/libpng-1.6.56-palette_neon_intrinsics.c",
                "third_party/libpng/arm/palette_neon_intrinsics.c",
                "3068e9b6e62be16bee2a8f1ff8271a02f32be97f",
                "0967ea1aebd718907fda1e767957deeddbe676b3",
            ),
        )
        for symbol, parent_path, fixed_path, scan_path, parent_blob, fixed_blob in pairs:
            with self.subTest(symbol=symbol):
                self.assertEqual(parent_blob, self.pinned_blob_id(pinned, parent_path))
                self.assertEqual(fixed_blob, self.pinned_blob_id(pinned, fixed_path))
                parent = self.pinned_blob(pinned, parent_path)
                fixed = self.pinned_blob(pinned, fixed_path)
                parent_run = self.run_text(parent, scan_path, pinned, tree, parent_path, parent_blob)
                fixed_run = self.run_text(fixed, scan_path, pinned, tree, fixed_path, fixed_blob)
                self.assertIn(symbol, {f.symbol for f in parent_run.findings})
                self.assertNotIn(symbol, {f.symbol for f in fixed_run.findings})
                self.assertEqual("completed", parent_run.status)
                self.assertEqual("completed", fixed_run.status)

    @staticmethod
    def pinned_blob(commit, path):
        process = subprocess.run(
            ["git", "cat-file", "blob", f"{commit}:{path}"], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        return process.stdout.decode("utf-8")

    @staticmethod
    def pinned_blob_id(commit, path):
        process = subprocess.run(
            ["git", "rev-parse", f"{commit}:{path}"], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True,
        )
        return process.stdout.strip()

    def run_text(self, text, scan_path, commit, tree, fixture_path, fixture_blob):
        unit = SourceUnit(
            path=scan_path, language="c" if scan_path.endswith(".c") else "cpp",
            text=text, sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        request = ScanRequest(
            request_id="c12:public-control-pair", repository="fixture/known-cases",
            commit=commit, snapshot_sha256=snapshot_digest((unit,)),
            target_id="current-component:fixture/known-cases",
            profile_id="light-ast", provenance="git_object",
        )
        shared = {
            "source_identity": {
                "repository": "https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git",
                "commit": commit, "tree": tree, "blob": fixture_blob,
                "source_sha256": unit.sha256, "path": fixture_path,
            }
        }
        return KnownDisclosedCveDetector().detect(
            ScanContext(request=request, units=(unit,), shared_facts=shared), (unit,)
        )

if __name__ == "__main__":
    unittest.main()


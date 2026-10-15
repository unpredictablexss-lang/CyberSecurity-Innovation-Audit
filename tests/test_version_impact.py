"""Unit tests for the parametrized version-impact experiment.

The four-state rule and the ref plumbing are tested against a throwaway git
repository, so no network, no third-party checkout and no long scan is needed.
One test is pinned against the real AUTH-01 boundary commits and is skipped when
that local object store is absent.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
EXPERIMENT_DIR = PROJECT / "research/experiments/interface/ipc"
sys.path.insert(0, str(EXPERIMENT_DIR))

import version_impact  # noqa: E402

PAIR_GIT = Path.home() / "openharmony-audit" / "ipc-research" / "repos" / "inputmethod_imf"
AUTH01_SOURCE = "services/src/platform_callback_stub.cpp"
AUTH01_VULNERABLE = "e663b47013d534a56165ab7467fbb3e14bf7172b"
AUTH01_FIXED = "5eaddcab19bc4b22544f4bee1e8894fc2d6505dc"


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True,
                          check=False)


class ClassificationTests(unittest.TestCase):
    """The rule is the whole point: an unrecognized blob is never `fixed`."""

    V = "1" * 40
    F = "2" * 40

    def _classify(self, oid, fixed="", vulnerable=None):
        return version_impact.classify_blob(
            oid, vulnerable_blob=vulnerable or self.V, fixed_blob=fixed)

    def test_a_missing_file_is_not_present_rather_than_unknown(self):
        self.assertEqual(self._classify(None), "not_present")

    def test_the_boundary_blobs_are_named(self):
        self.assertEqual(self._classify(self.V), "affected")
        self.assertEqual(self._classify(self.F, fixed=self.F), "fixed")

    def test_an_unrelated_blob_is_unknown(self):
        self.assertEqual(self._classify("3" * 40, fixed=self.F), "unknown")

    def test_without_a_fixed_boundary_fixed_is_unreachable(self):
        # No upstream fix means no `fixed` verdict may be produced, however the
        # blob happens to look. An empty boundary must not match an empty oid.
        self.assertEqual(self._classify("3" * 40), "unknown")
        self.assertEqual(self._classify(""), "unknown")
        self.assertNotIn("fixed", [self._classify(oid, fixed="") for oid in (None, "", "3" * 40)])

    def test_the_state_vocabulary_is_the_documented_four(self):
        self.assertEqual(version_impact.STATUSES, ("affected", "fixed", "not_present", "unknown"))


class RefScanTests(unittest.TestCase):
    """Behaviour against a real (tiny) object store, so plumbing errors show up."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        self._write("a.cpp", "int v1;\n")
        self._write("b.cpp", "int b;\n")
        self._commit("c1")
        self._tag("t1")
        self.affected_commit = self._rev()
        self.affected_blob = version_impact._blob_at(self.repo, self.affected_commit, "a.cpp")

        self._write("a.cpp", "int v2;\n")
        self._commit("c2")
        self._tag("t2")
        self.fixed_commit = self._rev()
        self.fixed_blob = version_impact._blob_at(self.repo, self.fixed_commit, "a.cpp")

        (self.repo / "a.cpp").unlink()
        self._commit("c3")
        self._tag("t3")

        _git(self.repo, "checkout", "-q", "-b", "feature", "t1")
        self._write("a.cpp", "int unrelated;\n")
        self._commit("c4")
        _git(self.repo, "checkout", "-q", "-")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, text):
        (self.repo / name).write_text(text, encoding="utf-8")

    def _commit(self, message):
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.email=t@example.com", "-c", "user.name=t",
             "commit", "-q", "-m", message)

    def _tag(self, name):
        _git(self.repo, "tag", name)

    def _rev(self):
        return _git(self.repo, "rev-parse", "HEAD").stdout.strip()

    def _classify(self, refs):
        return {record["ref"]: record for record in version_impact.classify_refs(
            self.repo, refs, source_path="a.cpp",
            vulnerable_blob=self.affected_blob, fixed_blob=self.fixed_blob)}

    def test_each_ref_gets_the_four_state_verdict_with_commit_and_blob(self):
        records = self._classify(["refs/tags/t1", "refs/tags/t2", "refs/tags/t3"])
        self.assertEqual(records["refs/tags/t1"]["status"], "affected")
        self.assertEqual(records["refs/tags/t2"]["status"], "fixed")
        self.assertEqual(records["refs/tags/t3"]["status"], "not_present")
        for record in records.values():
            self.assertEqual(len(record["commit"]), 40)
            # Every record carries its own evidence: a blob digest, or the note
            # saying why there is no blob to digest.
            self.assertTrue(record["note"] or len(record["blob_sha256"]) == 64)

    def test_the_scan_uses_the_requested_source_path(self):
        # The original script classified every ref against a hardcoded path even
        # when told otherwise, so a wrong path would silently relabel the refs.
        # b.cpp is present and unchanged on every tag; reading it instead of
        # a.cpp must not produce `not_present` for t3 nor `affected` for t1.
        other = version_impact.classify_refs(
            self.repo, ["refs/tags/t1", "refs/tags/t3"], source_path="b.cpp",
            vulnerable_blob=self.affected_blob, fixed_blob=self.fixed_blob)
        self.assertEqual([record["status"] for record in other], ["unknown", "unknown"])
        self.assertEqual([record["source_path"] for record in other], ["b.cpp", "b.cpp"])

    def test_a_branch_off_the_boundary_is_unknown_not_affected(self):
        records = self._classify(["refs/heads/feature"])
        self.assertEqual(records["refs/heads/feature"]["status"], "unknown")

    def test_commit_ancestry_is_recorded_separately_from_the_blob_state(self):
        records = version_impact.classify_refs(
            self.repo, ["refs/tags/t2"], source_path="a.cpp",
            vulnerable_blob=self.affected_blob, fixed_blob=self.fixed_blob,
            vulnerable_commit=self.affected_commit, fixed_commit=self.fixed_commit)
        record = records[0]
        self.assertTrue(record["vulnerable_commit_reachable"])
        self.assertTrue(record["fixed_commit_reachable"])

    def test_a_fixed_ref_is_not_reachable_before_the_fix(self):
        records = version_impact.classify_refs(
            self.repo, ["refs/tags/t1"], source_path="a.cpp",
            vulnerable_blob=self.affected_blob, fixed_blob=self.fixed_blob,
            vulnerable_commit=self.affected_commit, fixed_commit=self.fixed_commit)
        self.assertTrue(records[0]["vulnerable_commit_reachable"])
        self.assertFalse(records[0]["fixed_commit_reachable"])

    def test_unresolvable_ref_is_unknown_with_a_note(self):
        records = version_impact.classify_refs(
            self.repo, ["refs/tags/does-not-exist"], source_path="a.cpp",
            vulnerable_blob=self.affected_blob, fixed_blob=self.fixed_blob)
        self.assertEqual(records[0]["status"], "unknown")
        self.assertEqual(records[0]["commit"], "")
        self.assertIn("resolve", records[0]["note"])

    def test_a_boundary_that_cannot_be_stated_is_an_error(self):
        with self.assertRaises(ValueError):
            version_impact.build_version_impact(
                self.repo, ["refs/tags/t1"], repository="demo", kind="demo",
                source_path="a.cpp", vulnerable_commit=self._rev(),
                fixed_commit="")
        with self.assertRaises(ValueError) as caught:
            version_impact.build_version_impact(
                self.repo, ["refs/tags/t1"], repository="demo", kind="demo",
                source_path="missing.cpp", vulnerable_commit=self._rev())
        self.assertIn("boundary", str(caught.exception))

    def test_ref_selection_filters_and_deduplicates(self):
        tags = version_impact.list_refs(self.repo, tags=True)
        self.assertEqual(sorted(tags),
                         ["refs/tags/t1", "refs/tags/t2", "refs/tags/t3"])
        self.assertEqual(version_impact.list_refs(self.repo, tags=True, globs=["t[12]"]),
                         ["refs/tags/t1", "refs/tags/t2"])
        self.assertEqual(
            version_impact.list_refs(self.repo, tags=True, explicit=["refs/tags/t1"],
                                     globs=["t1"]),
            ["refs/tags/t1"])

    def test_the_record_pins_both_boundaries_and_their_content_digests(self):
        payload = version_impact.build_version_impact(
            self.repo, version_impact.list_refs(self.repo, tags=True),
            repository="demo/repo", kind="demo_version_impact", source_path="a.cpp",
            vulnerable_commit=self.affected_commit, fixed_commit=self.fixed_commit)
        self.assertEqual(payload["vulnerable_blob"], self.affected_blob)
        self.assertEqual(payload["fixed_blob"], self.fixed_blob)
        self.assertEqual(len(payload["vulnerable_blob_sha256"]), 64)
        self.assertEqual(len(payload["fixed_blob_sha256"]), 64)
        self.assertEqual(payload["kind"], "demo_version_impact")
        # One tag per state: t1 still carries the vulnerable file, t2 carries the
        # fix, t3 does not carry the file at all. Nothing is left over.
        self.assertEqual(payload["counts"],
                         {"affected": 1, "fixed": 1, "not_present": 1, "unknown": 0})
        self.assertEqual(payload["ref_count"], 3)
        self.assertEqual(len(payload["manifest_sha256"]), 64)
        self.assertTrue(payload["known_limitations"])
        # Every blob in this store is local, so the coverage field must say the
        # digests are complete rather than silently passing the two that exist.
        self.assertEqual(payload["content_digest_coverage"],
                         {"blobs_at_refs": 3, "digests_available": 2,
                          "digests_unavailable": 1})

    def test_an_empty_ref_selection_refuses_to_write_a_scan(self):
        out = Path(self.tmp.name) / "out.json"
        with self.assertRaises(SystemExit):
            version_impact.main(["--repo-root", str(self.repo), "--repository", "demo",
                                 "--kind", "demo", "--source-path", "a.cpp",
                                 "--vulnerable-commit", self.affected_commit,
                                 "--tags", "--ref-glob", "no-such-tag",
                                 "--json-out", str(out)])
        self.assertFalse(out.exists())

    def test_the_cli_writes_a_reproducible_record(self):
        out = Path(self.tmp.name) / "impact.json"
        code = version_impact.main(["--repo-root", str(self.repo), "--repository", "demo/repo",
                                    "--kind", "demo_version_impact", "--source-path", "a.cpp",
                                    "--vulnerable-commit", self.affected_commit,
                                    "--fixed-commit", self.fixed_commit,
                                    "--tags", "--json-out", str(out)])
        self.assertEqual(code, 0)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["ref_count"], 3)
        self.assertEqual(len(payload["manifest_sha256"]), 64)
        # The digest covers the record, so a re-run over the same objects matches.
        self.assertEqual(payload["manifest_sha256"],
                         version_impact.build_version_impact(
                             self.repo, version_impact.list_refs(self.repo, tags=True),
                             repository="demo/repo", kind="demo_version_impact",
                             source_path="a.cpp",
                             vulnerable_commit=self.affected_commit,
                             fixed_commit=self.fixed_commit)["manifest_sha256"])


@unittest.skipUnless(PAIR_GIT.is_dir(), "the pinned AUTH-01 object store is required")
class Auth01BoundaryTests(unittest.TestCase):
    """Pinned against the real repository, so a moved boundary fails loudly."""

    def test_the_recorded_boundary_is_the_recorded_file(self):
        repo = PAIR_GIT
        vulnerable = version_impact._blob_at(repo, AUTH01_VULNERABLE, AUTH01_SOURCE)
        fixed = version_impact._blob_at(repo, AUTH01_FIXED, AUTH01_SOURCE)
        self.assertEqual(len(vulnerable), 40)
        self.assertEqual(len(fixed), 40)
        self.assertNotEqual(vulnerable, fixed)

    def test_the_two_boundary_commits_classify_as_affected_and_fixed(self):
        payload = version_impact.build_version_impact(
            PAIR_GIT, [AUTH01_VULNERABLE, AUTH01_FIXED],
            repository="openharmony/inputmethod_imf", kind="ipc_auth01_version_impact",
            source_path=AUTH01_SOURCE, vulnerable_commit=AUTH01_VULNERABLE,
            fixed_commit=AUTH01_FIXED)
        by_ref = {record["ref"]: record for record in payload["records"]}
        self.assertEqual(by_ref[AUTH01_VULNERABLE]["status"], "affected")
        self.assertEqual(by_ref[AUTH01_FIXED]["status"], "fixed")

    def test_the_vulnerable_commit_predates_the_fix(self):
        self.assertTrue(version_impact._is_ancestor(PAIR_GIT, AUTH01_VULNERABLE, AUTH01_FIXED))
        self.assertFalse(version_impact._is_ancestor(PAIR_GIT, AUTH01_FIXED, AUTH01_VULNERABLE))


if __name__ == "__main__":
    unittest.main()

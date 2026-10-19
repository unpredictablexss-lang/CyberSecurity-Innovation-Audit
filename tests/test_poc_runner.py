"""Unit tests for the PoC module.

The state machine, the observable parsing and the source pinning are tested
without invoking a compiler, so the suite stays fast and hermetic. One
integration test builds and runs the AUTH-01 harness for real; it is skipped
unless the toolchain and the local source stores are present.
"""
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.poc import states, sources
from src.ohscanner.poc.reachability import render_markdown as render_reachability
from src.ohscanner.poc.runner import classify_case, parse_signals
from src.ohscanner.poc.sources import PinnedFile, SourceMismatch, SourceUnavailable, materialize

PROJECT = Path(__file__).resolve().parents[1]
MANIFEST = PROJECT / "src/ohscanner/poc/harnesses/auth01_descriptor_bypass/manifest.json"
PAIR_GIT = Path.home() / "openharmony-audit" / "ipc-research" / "repos" / "inputmethod_imf"
CUTILS = Path.home() / "openharmony-targets" / "commonlibrary_c_utils"


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, check=False)


class StateMachineTests(unittest.TestCase):
    def test_ladder_never_reports_a_rung_that_did_not_happen(self):
        cases = [
            (dict(generated=False, built=False, ran=False, triggered=False, stable=False), "not_generated"),
            (dict(generated=True, built=False, ran=False, triggered=False, stable=False), "generated"),
            (dict(generated=True, built=True, ran=False, triggered=False, stable=False), "build_success"),
            (dict(generated=True, built=True, ran=True, triggered=False, stable=False), "run_success"),
            (dict(generated=True, built=True, ran=True, triggered=True, stable=False), "trigger_success"),
            (dict(generated=True, built=True, ran=True, triggered=True, stable=True), "stable_reproduced"),
        ]
        for kwargs, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(states.ladder_state(**kwargs), expected)

    def test_ladder_states_are_the_documented_six(self):
        self.assertEqual(states.POC_STATES[0], "not_generated")
        self.assertEqual(states.POC_STATES[-1], "stable_reproduced")
        self.assertEqual(len(states.POC_STATES), 6)

    def test_replay_labels(self):
        self.assertEqual(states.replay_label(()), "no_trigger")
        self.assertEqual(states.replay_label((False, False, False)), "no_trigger")
        self.assertEqual(states.replay_label((True, False, True)), "flaky")
        self.assertEqual(states.replay_label((True, True, True)), "stable_reproduced")

    def test_replay_classifies_stable_negative_controls_separately(self):
        self.assertEqual(states.classify_expected_replay("no_trigger", ("no_trigger",) * 3),
                         ("stable_rejected", (True, True, True)))
        self.assertEqual(states.classify_expected_replay("trigger", ("trigger", "no_trigger")),
                         ("flaky", (True, False)))
        self.assertEqual(states.classify_expected_replay("no_trigger", ("trigger",) * 3)[0],
                         "expectation_failed")

    def test_evidence_never_exceeds_the_state(self):
        self.assertEqual(states.evidence_for("run_success"), "static_candidate")
        self.assertEqual(states.evidence_for("trigger_success"), "dynamic_reproduced")
        self.assertEqual(states.evidence_for("stable_reproduced"), "stable_reproduced")
        # A trigger alone must not be reported as a stable reproduction.
        self.assertNotEqual(states.evidence_for("trigger_success"), "stable_reproduced")


class ObservableTests(unittest.TestCase):
    def test_parse_signals_takes_the_last_group(self):
        stdout = "mode=notoken ret=0 messages_sent=1\nnoise\n"
        self.assertEqual(parse_signals(stdout), {"ret": 0, "messages_sent": 1})
        self.assertNotIn("mode", parse_signals(stdout))

    def test_parse_signals_ignores_non_numeric_values(self):
        self.assertEqual(parse_signals("mode=notoken\n"), {})

    def test_classify_prefers_a_sanitizer_report_over_a_signal(self):
        observable = {"field": "messages_sent", "trigger_min": 1}
        crash = "messages_sent=1\n==12==ERROR: AddressSanitizer: heap-buffer-overflow"
        self.assertEqual(classify_case(crash, "", parse_signals(crash), observable), "crash")

    def test_classify_uses_the_declared_field_and_threshold(self):
        observable = {"field": "messages_sent", "trigger_min": 1}
        self.assertEqual(classify_case("messages_sent=1", "", {"messages_sent": 1}, observable), "trigger")
        self.assertEqual(classify_case("messages_sent=0", "", {"messages_sent": 0}, observable), "no_trigger")

    def test_classify_does_not_trigger_on_a_missing_field(self):
        observable = {"field": "messages_sent", "trigger_min": 1}
        self.assertEqual(classify_case("", "", {}, observable), "no_trigger")


class HostExecutionBoundaryTests(unittest.TestCase):
    def test_poc_runner_refuses_to_execute_outside_the_docker_container(self):
        import os
        from unittest.mock import patch
        from src.ohscanner.poc import run_poc
        with tempfile.TemporaryDirectory() as work, patch.dict(os.environ, {"OHSCANNER_VALIDATION_CONTAINER": "1"}):
            with self.assertRaisesRegex(RuntimeError, "Docker validation container"):
                run_poc(MANIFEST, PAIR_GIT, work)


class SourcePinningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        _git("init", "-q", cwd=self.repo)
        (self.repo / "f.cpp").write_text("int vulnerable;\n")
        _git("add", "f.cpp", cwd=self.repo)
        _git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "v",
             cwd=self.repo)
        self.commit = _git("rev-parse", "HEAD", cwd=self.repo).stdout.strip()
        self.digest = hashlib.sha256((self.repo / "f.cpp").read_bytes()).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_materialize_writes_and_verifies(self):
        destination = self.root / "out"
        written = materialize(
            [PinnedFile(commit=self.commit, path="f.cpp", sha256=self.digest)],
            self.repo, destination)
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0].read_text(), "int vulnerable;\n")

    def test_materialize_refuses_a_changed_blob(self):
        with self.assertRaises(SourceMismatch):
            materialize([PinnedFile(commit=self.commit, path="f.cpp", sha256="0" * 64)],
                        self.repo, self.root / "out2")

    def test_materialize_reports_a_missing_blob(self):
        with self.assertRaises(SourceUnavailable):
            materialize([PinnedFile(commit=self.commit, path="missing.cpp", sha256="0" * 64)],
                        self.repo, self.root / "out3")

    def test_pinned_files_reads_revision_when_asked(self):
        entries = [{"commit": self.commit, "path": "f.cpp", "sha256": self.digest,
                    "revision": "fixed"}]
        self.assertEqual(sources.pinned_files(entries, revision_field=True)[0].revision, "fixed")
        self.assertEqual(sources.pinned_files(entries)[0].revision, "")


class ManifestTests(unittest.TestCase):
    """The harness manifest is data that the runner trusts; keep it well-formed."""

    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_every_source_declares_a_revision_and_a_commit(self):
        for entry in self.manifest["sources"]:
            with self.subTest(path=entry["path"]):
                self.assertIn(entry["revision"], self.manifest["revisions"])
                self.assertEqual(len(entry["commit"]), 40)
                self.assertEqual(len(entry["sha256"]), 64)

    def test_cases_declare_role_and_expectations_for_every_revision(self):
        revisions = set(self.manifest["revisions"])
        for case in self.manifest["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIn(case["role"], ("attack", "control"))
                self.assertTrue(set(case["expect"]) == revisions)

    def test_at_least_one_attack_case_is_expected_to_trigger(self):
        triggerable = [case for case in self.manifest["cases"]
                       if case["role"] == "attack"
                       and case["expect"].get("vulnerable") == "trigger"]
        self.assertTrue(triggerable, "a PoC with no triggerable attack case proves nothing")

    def test_limitations_state_that_reachability_is_not_established(self):
        joined = " ".join(self.manifest["known_limitations"]).lower()
        self.assertIn("reachability", joined)


@unittest.skipUnless(PAIR_GIT.is_dir(), "the pinned source store is required")
class ReachabilityEvidenceTests(unittest.TestCase):
    """Reachability relations must be digest- and line-verified, not trusted."""

    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.entry = self.manifest["reachability"]

    def test_the_harness_declares_a_partial_reachability_block(self):
        self.assertEqual(self.entry["status"], "partial")
        self.assertTrue(self.entry["relations"])
        for relation in self.entry["relations"]:
            with self.subTest(kind=relation["kind"]):
                self.assertTrue(relation["establishes"])
                # Every relation must name what it does NOT establish, so the
                # remaining gap cannot be implied away.
                self.assertTrue(relation["does_not_establish"])

    def test_verification_checks_the_digest_and_the_quoted_line(self):
        from src.ohscanner.poc.reachability import verify
        evidence = verify(self.entry, PAIR_GIT)
        self.assertEqual(evidence.status, "partial")
        self.assertEqual(len(evidence.relations), len(self.entry["relations"]))
        for relation in evidence.relations:
            self.assertEqual(len(relation.commit), 40)
            self.assertEqual(len(relation.sha256), 64)
            self.assertTrue(relation.evidence)

    def test_no_block_means_no_claim(self):
        from src.ohscanner.poc.reachability import verify
        self.assertIsNone(verify(None, PAIR_GIT))

    def test_a_moved_quote_fails_instead_of_describing_other_code(self):
        from src.ohscanner.poc.reachability import ReachabilityQuoteMismatch, verify
        broken = json.loads(json.dumps(self.entry))
        broken["relations"][0]["line"] = broken["relations"][0]["line"] + 40
        with self.assertRaises(ReachabilityQuoteMismatch):
            verify(broken, PAIR_GIT)

    def test_a_changed_digest_fails(self):
        from src.ohscanner.poc.sources import SourceMismatch
        from src.ohscanner.poc.reachability import verify
        broken = json.loads(json.dumps(self.entry))
        broken["relations"][0]["sha256"] = "0" * 64
        with self.assertRaises(SourceMismatch):
            verify(broken, PAIR_GIT)

    def test_the_rendered_record_states_what_is_not_established(self):
        from src.ohscanner.poc.reachability import verify
        rendered = render_reachability(verify(self.entry, PAIR_GIT))
        self.assertIn("没有证明", rendered)
        self.assertIn("partial", rendered)


@unittest.skip("AUTH-01 runtime harness must execute only through the Docker validation worker")
@unittest.skipUnless(shutil.which("clang++") and PAIR_GIT.is_dir() and CUTILS.is_dir(),
                     "clang++, the pinned source store and the c_utils checkout are required")
class Auth01IntegrationTests(unittest.TestCase):
    """Builds and runs the AUTH-01 harness for real."""

    def test_attack_triggers_on_the_vulnerable_revision_only(self):
        from src.ohscanner.poc import run_poc
        with tempfile.TemporaryDirectory() as work:
            result = run_poc(MANIFEST, PAIR_GIT, work, cutils_dir=CUTILS, repeats=2)

        vulnerable = result.revisions["vulnerable"]
        fixed = result.revisions["fixed"]
        self.assertTrue(vulnerable.build.ok, vulnerable.build.stderr[-500:])
        self.assertTrue(fixed.build.ok, fixed.build.stderr[-500:])

        attack = {case.case_id: case for case in vulnerable.cases}["no_token"]
        self.assertEqual(attack.verdict, "trigger")
        self.assertGreaterEqual(attack.signals.get("messages_sent", 0), 1)

        rejected = {case.case_id: case for case in fixed.cases}["no_token"]
        self.assertEqual(rejected.verdict, "no_trigger")

        # The fixed revision must still serve a well-formed request.
        control = {case.case_id: case for case in fixed.cases}["correct_token"]
        self.assertEqual(control.verdict, "trigger")

        self.assertTrue(all(vulnerable.expectations_met.values()))
        self.assertTrue(all(fixed.expectations_met.values()))

    def test_record_keeps_validated_vulnerability_at_zero(self):
        from src.ohscanner.poc import render_markdown, run_poc
        with tempfile.TemporaryDirectory() as work:
            result = run_poc(MANIFEST, PAIR_GIT, work, cutils_dir=CUTILS, repeats=1)
        self.assertEqual(result.validated_vulnerability, 0)
        self.assertIn("validated_vulnerability", json.dumps(result.to_dict()))
        self.assertIn("EvidenceObligation", render_markdown(result))


if __name__ == "__main__":
    unittest.main()

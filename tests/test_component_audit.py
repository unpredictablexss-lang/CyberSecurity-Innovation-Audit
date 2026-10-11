"""Component audit driver: scope derivation, sharding, coverage depth, digest.

Every Git fixture is created locally in a temporary repository. No external
scanner runs, nothing is claimed to be a vulnerability, and the assertions below
pin the honest-reporting properties the driver exists for: an excluded file is
named with its reason, a shard failure never becomes a clean result, and a
candidate whose obligations were not recorded says so.
"""
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from src.ohscanner.detectors.interface import audit as audit_module
from src.ohscanner.detectors.interface.audit import (
    PASS_DETECTORS,
    PRODUCTION_EXCLUDED_SEGMENTS,
    TreeEntry,
    audit_component,
    plan_scope,
    plan_shards,
    render_markdown,
    shard_digest,
)

PROJECT = Path(__file__).resolve().parents[1]
IPC_FIXTURES = PROJECT / "tests" / "fixtures" / "ipc"
REPOSITORY = "fixture/component-audit"
OVERSIZE = 1_100_000

# A stub whose trailing malformed function leaves the file in a partial parse
# while the OnRemoteRequest body above it is still interpretable. This is the
# case the two-pass design exists for: the candidate is real, the parse is not.
BROKEN = """#define Stub Fixture_broken
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
OnCallback();
return 0;
}
int unclosed( {
"""


def git(repo, *args):
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, check=True, text=True, timeout=30,
    )
    return done.stdout.strip()


class ComponentAuditTestCase(unittest.TestCase):
    """Shared temporary Git repository with one file of every scope class."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "ci@example.invalid")
        git(self.repo, "config", "user.name", "audit CI")
        for directory in ("src", "tests", "third_party", "docs"):
            (self.repo / directory).mkdir()
        shutil.copy(IPC_FIXTURES / "common_types.h", self.repo / "src" / "types.h")
        self.write("src/relay.cpp", self.fixture("relay_positive.cpp", "Fixture_relay"))
        self.write("src/capability.cpp",
                   self.fixture("capability_positive.cpp", "Fixture_capability"))
        self.write("src/broken.cpp", BROKEN)
        # `contest` contains the excluded word as a filename substring, not as a
        # path segment. Excluding it would be the substring bug this pins.
        self.write("src/contest.cpp", """#include "types.h"
int Fixture_contest::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
OnCallback();
return 0;
}
""")
        self.write("tests/test_relay.cpp", self.fixture("relay_positive.cpp", "Fixture_test_relay"))
        self.write("third_party/vendor.cpp", self.fixture("relay_positive.cpp", "Fixture_vendor"))
        self.write("docs/README.md", "# fixture\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "component audit fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")

    def write(self, relative, text):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def fixture(self, name, stub):
        """A reviewed interface fixture under a distinct stub class name."""
        lines = (IPC_FIXTURES / name).read_text(encoding="utf-8").splitlines()
        lines[0] = "#define Stub " + stub
        return "\n".join(lines) + "\n"

    def commit_all(self, message):
        """Commit the worktree and return the new pinned SHA."""
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", message)
        return git(self.repo, "rev-parse", "HEAD")

    def plan(self, **kwargs):
        kwargs.setdefault("includes", (".",))
        return plan_scope(self.repo, REPOSITORY, self.commit, **kwargs)

    def paths(self, plan):
        return sorted(item.path for item in plan.selected)

    def audit(self, **kwargs):
        kwargs.setdefault("excerpt_context", 3)
        return audit_component(self.repo, REPOSITORY, self.commit, **kwargs)


class ScopePlanningTests(ComponentAuditTestCase):
    def test_production_scope_excludes_test_and_vendored_trees(self):
        plan = self.plan(production_only=True)
        self.assertEqual(self.paths(plan), [
            "src/broken.cpp", "src/capability.cpp", "src/contest.cpp",
            "src/relay.cpp", "src/types.h",
        ])
        self.assertEqual(plan.counts["tracked_entries"], 8)
        self.assertEqual(plan.counts["excluded_pattern"], 2)
        self.assertEqual(plan.counts["non_source"], 1)
        self.assertEqual(plan.counts["selected_files"], 5)
        self.assertEqual(
            sorted(item["reason"] for item in plan.skipped_examples),
            ["production_exclude:tests", "production_exclude:third_party"],
        )

    def test_test_trees_are_included_when_production_only_is_off(self):
        plan = self.plan(production_only=False)
        self.assertIn("tests/test_relay.cpp", self.paths(plan))
        self.assertIn("third_party/vendor.cpp", self.paths(plan))
        self.assertEqual(plan.counts["selected_files"], 7)
        self.assertEqual(plan.counts["excluded_pattern"], 0)

    def test_exclusion_matches_whole_path_segments_not_substrings(self):
        self.assertIn("src/contest.cpp", self.paths(self.plan(production_only=True)))
        self.assertIn("tests", PRODUCTION_EXCLUDED_SEGMENTS)
        # The regression this pins: a substring list that spells "/test/" but not
        # "/tests/" counted a whole test tree as production code.
        for segment in ("test", "tests", "unittest", "fuzztest", "mock", "third_party"):
            self.assertIn(segment, PRODUCTION_EXCLUDED_SEGMENTS)

    def test_explicit_exclude_prefix_is_reported_with_its_own_reason(self):
        plan = self.plan(includes=(".",), excludes=("third_party",), production_only=False)
        self.assertNotIn("third_party/vendor.cpp", self.paths(plan))
        self.assertIn("tests/test_relay.cpp", self.paths(plan))
        self.assertEqual(plan.excludes, ("third_party",))
        self.assertEqual([item["reason"] for item in plan.skipped_examples],
                         ["explicit_exclude"])

    def test_oversize_blob_is_counted_with_its_reason_and_never_selected(self):
        self.write("src/huge.cpp", "// " + "x" * OVERSIZE + "\n")
        commit = self.commit_all("add an oversize source")
        plan = plan_scope(self.repo, REPOSITORY, commit)
        self.assertEqual(plan.counts["oversize"], 1)
        self.assertNotIn("src/huge.cpp", self.paths(plan))
        self.assertIn({"file": "src/huge.cpp", "reason": "oversize"},
                      list(plan.skipped_examples))

    def test_scope_with_nothing_left_raises_instead_of_reporting_clean(self):
        with self.assertRaisesRegex(ValueError, "no supported UTF-8 source"):
            self.plan(includes=("src",), excludes=("src",), production_only=False)

    def test_moving_ref_is_refused_in_favour_of_a_pinned_sha(self):
        with self.assertRaisesRegex(ValueError, "full lowercase Git commit SHA"):
            plan_scope(self.repo, REPOSITORY, "HEAD")

    def test_plan_is_deterministic_for_the_same_commit(self):
        first, second = self.plan(), self.plan()
        self.assertEqual(first.plan_sha256, second.plan_sha256)
        self.assertEqual(
            [[item.path for item in shard] for shard in first.shards],
            [[item.path for item in shard] for shard in second.shards],
        )


class ShardingTests(unittest.TestCase):
    def entries(self, count, size=10):
        return tuple(
            TreeEntry("src/f%02d.cpp" % index, "%040x" % index, size)
            for index in range(count)
        )

    def test_shards_respect_the_file_and_byte_bounds(self):
        shards = plan_shards(self.entries(7), max_files=3, max_bytes=25)
        for shard in shards:
            self.assertLessEqual(len(shard), 3)
            self.assertLessEqual(sum(item.size for item in shard), 25)
        # The byte bound dominates here: two 10-byte files fit in 25, a third does not.
        self.assertEqual([len(shard) for shard in shards], [2, 2, 2, 1])

    def test_shard_membership_is_a_partition_of_the_sorted_scope(self):
        entries = self.entries(7)
        shards = plan_shards(entries, max_files=3, max_bytes=10_000)
        self.assertEqual([len(shard) for shard in shards], [3, 3, 1])
        flat = [item.path for shard in shards for item in shard]
        self.assertEqual(flat, [item.path for item in entries])
        self.assertEqual(len(flat), len(set(flat)))

    def test_byte_bound_splits_a_shard_before_the_core_loader_refuses_it(self):
        entries = self.entries(3, size=10)
        shards = plan_shards(entries, max_files=100, max_bytes=25)
        self.assertEqual([len(shard) for shard in shards], [2, 1])
        for shard in shards:
            self.assertLessEqual(sum(item.size for item in shard), 25)

    def test_unsatisfiable_bounds_are_refused(self):
        with self.assertRaisesRegex(ValueError, "single source exceeds the shard byte bound"):
            plan_shards(self.entries(1, size=100), max_files=10, max_bytes=5)
        with self.assertRaisesRegex(ValueError, "shard bounds must be positive"):
            plan_shards(self.entries(1), max_files=0, max_bytes=10)

    def test_shard_digest_binds_paths_to_blob_identities(self):
        first = (TreeEntry("a.cpp", "1" * 40, 5),)
        renamed = (TreeEntry("b.cpp", "1" * 40, 5),)
        different_oid = (TreeEntry("a.cpp", "2" * 40, 5),)
        self.assertNotEqual(shard_digest(first), shard_digest(renamed))
        self.assertNotEqual(shard_digest(first), shard_digest(different_oid))


class TwoPassAuditTests(ComponentAuditTestCase):
    """The split that keeps recall and recorded obligations from hiding each other."""

    def setUp(self):
        super().setUp()
        self.report = self.audit()

    def pass_view(self, name):
        views = [view for view in self.report["coverage"]["run_state"]["pass_runs"]
                 if view["pass"] == name]
        self.assertEqual(len(views), 1)
        return views[0]

    def test_complete_ast_pass_completes_over_a_named_scope(self):
        view = self.pass_view("complete-ast")
        self.assertEqual(view["detector_status"], "completed")
        self.assertEqual(view["applicable_files"], 5)
        self.assertEqual(view["analyzed_files"], 4)
        self.assertEqual(view["scope_files"], 4)
        self.assertGreater(view["scope_loc"], 0)
        self.assertEqual(view["unexamined_reasons"], {"incomplete_ast:partial": 1})

    def test_all_files_pass_keeps_recall_and_admits_the_zero_counter(self):
        view = self.pass_view("all-files")
        self.assertEqual(view["detector_status"], "blocked")
        self.assertEqual(view["diagnostics"], 4)
        self.assertGreater(view["diagnostics"], self.pass_view("complete-ast")["diagnostics"])
        # The shared runner zeroes these for a blocked run; the driver must show
        # the zero *and* the counts that describe what was actually done.
        self.assertEqual(view["scope_files"], 0)
        self.assertEqual(view["applicable_files"], 5)
        self.assertTrue(any("blocked run records" in note
                            for note in self.report["coverage"]["analysis_coverage"]["notes"]))

    def test_candidates_carry_binding_evidence_and_stay_candidates(self):
        self.assertGreaterEqual(len(self.report["candidates"]), 2)
        for item in self.report["candidates"]:
            self.assertEqual(item["source_binding"], "bound")
            self.assertRegex(item["source_sha256"], r"^[a-f0-9]{64}$")
            self.assertEqual(item["evidence_type"], "syntax")
            self.assertEqual(item["severity"], "unassessed")
            self.assertEqual(item["confidence"], "unassessed")
            self.assertIn(item["file_parse_status"], ("complete", "partial"))
        self.assertEqual(self.report["validated_vulnerability"], 0)

    def test_partial_parse_candidate_is_kept_and_labelled_not_dropped(self):
        partial = [item for item in self.report["candidates"]
                   if item["file"] == "src/broken.cpp"]
        self.assertEqual(len(partial), 1)
        item = partial[0]
        self.assertEqual(item["file_parse_status"], "partial")
        # Only the wider pass can see it; its obligations are therefore not
        # recorded, and the row says so instead of implying none are needed.
        self.assertEqual(item["passes"], ["all-files"])
        self.assertFalse(item["obligations_recorded"])
        self.assertEqual(item["obligations"], [])
        markdown = render_markdown(self.report)
        self.assertIn("not** shown to be absent", markdown)

    def test_candidate_seen_by_both_passes_is_counted_once_with_obligations(self):
        complete = [item for item in self.report["candidates"]
                    if item["file_parse_status"] == "complete"]
        self.assertTrue(complete)
        for item in complete:
            self.assertEqual(item["passes"], ["all-files", "complete-ast"])
            self.assertTrue(item["obligations_recorded"])
            self.assertGreaterEqual(len(item["obligations"]), 3)
            kinds = {obligation["kind"] for obligation in item["obligations"]}
            self.assertIn("entry_reachability", kinds)
            self.assertIn("security_impact", kinds)
        keys = {(item["file"], item["line"], item["rule_id"]) for item in self.report["candidates"]}
        self.assertEqual(len(keys), len(self.report["candidates"]))

    def test_parse_depth_of_every_audited_file_is_reported(self):
        coverage = self.report["coverage"]["analysis_coverage"]
        self.assertEqual(coverage["parse_status"], {"complete": 4, "partial": 1})
        self.assertEqual(coverage["files_selected"], 5)
        self.assertEqual(coverage["files_analyzed"], 4)
        self.assertEqual(coverage["candidates_by_file_parse_status"],
                         {"complete": 3, "partial": 1})

    def test_root_cause_intersection_is_not_measured_rather_than_implied(self):
        intersection = self.report["coverage"]["root_cause_intersection"]
        self.assertEqual(intersection["state"], "not_measured")
        self.assertIn("no labelled root-cause set", intersection["reason"].lower())

    def test_scope_counts_are_reported_next_to_the_candidate_list(self):
        counts = self.report["scope"]["counts"]
        self.assertEqual(counts["excluded_pattern"], 2)
        self.assertEqual(counts["selected_files"], 5)
        self.assertEqual(counts["shards"], 1)
        markdown = render_markdown(self.report)
        self.assertIn("## 4. Not audited", markdown)
        self.assertIn("tests/test_relay.cpp", markdown)
        self.assertIn("production_exclude:tests", markdown)

    def test_planned_files_read_is_proved_not_assumed(self):
        report = self.audit()
        for view in report["coverage"]["run_state"]["pass_runs"]:
            self.assertEqual(view["planned_files"], 5)
            self.assertEqual(view["loaded_files"], 5)
        self.assertEqual(report["coverage"]["analysis_coverage"]["plan_vs_load"]["mismatches"], [])

    def test_file_the_loader_drops_is_reported_as_a_gap_not_assumed_read(self):
        # A non-UTF8 blob passes scope planning but not the shared loader's decode.
        (self.repo / "src" / "latin1.cpp").write_bytes(
            b"// \xff\xfe not valid UTF-8\nint f() { return 1; }\n")
        commit = self.commit_all("add a non-UTF8 source")
        report = audit_component(self.repo, REPOSITORY, commit, excerpt_context=0)
        mismatches = report["coverage"]["analysis_coverage"]["plan_vs_load"]["mismatches"]
        self.assertEqual(len(mismatches), 2)  # one per pass
        for mismatch in mismatches:
            self.assertEqual(mismatch["planned_files"], 6)
            self.assertEqual(mismatch["loaded_files"], 5)
            self.assertEqual(mismatch["dropped_by_loader"], 1)
        self.assertTrue(any("read fewer files than the plan" in note
                            for note in report["coverage"]["analysis_coverage"]["notes"]))
        self.assertIn("planned, 5 read", render_markdown(report))

    def test_file_no_detector_claims_is_reported_rather_than_disappearing(self):
        # A .js file is source for the scope planner but outside this detector's
        # declared languages. It must not vanish from the coverage arithmetic.
        self.write("src/bridge.js", "function bridge() { return 1; }\n")
        commit = self.commit_all("add a JS file the interface detector does not claim")
        report = audit_component(self.repo, REPOSITORY, commit, excerpt_context=0)
        coverage = report["coverage"]["analysis_coverage"]
        self.assertEqual(coverage["files_selected"], 6)
        self.assertEqual(coverage["files_in_scope_without_a_claiming_detector"], {"js": 1})
        self.assertEqual(coverage["files_in_scope_without_a_claiming_detector_examples"],
                         [{"file": "src/bridge.js", "language": "js"}])
        self.assertEqual(sum(coverage["parse_status"].values()), 5)
        self.assertTrue(any("no selected detector declares" in note
                            for note in coverage["notes"]))
        self.assertIn("no selected detector declares", render_markdown(report))

    def test_audit_scope_honours_include_prefixes(self):
        report = self.audit(includes=("src/capability.cpp",))
        self.assertEqual(report["scope"]["counts"]["selected_files"], 1)
        self.assertEqual({item["file"] for item in report["candidates"]},
                         {"src/capability.cpp"})

    def test_excerpt_is_read_from_the_pinned_blob_not_the_worktree(self):
        # Rewrite the tracked file after the commit. A worktree read would show
        # the marker; a pinned read cannot.
        self.write("src/relay.cpp", "// WORKTREE-ONLY-MARKER\nint Gone() { return 1; }\n")
        report = self.audit()
        relay = [item for item in report["candidates"] if item["file"] == "src/relay.cpp"]
        self.assertEqual(len(relay), 1)
        excerpt = "\n".join(row["text"] for row in relay[0]["excerpt"]["lines"])
        self.assertNotIn("WORKTREE-ONLY-MARKER", excerpt)
        self.assertIn("OnRemoteRequest", excerpt)
        self.assertRegex(relay[0]["excerpt"]["blob_oid"], r"^[a-f0-9]{40}$")
        self.assertNotIn("WORKTREE-ONLY-MARKER", render_markdown(report))

    def test_max_files_forces_sharding_without_changing_the_candidate_set(self):
        report = self.audit(max_files=2)
        self.assertEqual(report["scope"]["counts"]["shards"], 3)
        self.assertEqual(
            sorted(path for shard in report["scope"]["shards"] for path in shard["paths"]),
            ["src/broken.cpp", "src/capability.cpp", "src/contest.cpp",
             "src/relay.cpp", "src/types.h"],
        )
        locations = {(item["file"], item["line"], item["rule_id"])
                     for item in report["candidates"]}
        self.assertEqual(len(locations), 4)


class FailureReportingTests(ComponentAuditTestCase):
    def test_shard_failure_is_reported_and_never_becomes_a_clean_result(self):
        with mock.patch.object(audit_module, "_run_shard",
                               side_effect=ValueError("shard exploded")):
            report = self.audit()
        self.assertEqual(report["candidates"], [])
        self.assertTrue(report["shard_errors"])
        self.assertIn("shard exploded", report["shard_errors"][0]["error"])
        self.assertEqual(report["shard_errors"][0]["files_not_analyzed"], 5)
        markdown = render_markdown(report)
        self.assertIn("Failed shards (never converted into \"no candidates\")", markdown)
        self.assertIn("not proof of safety", markdown)

    def test_component_without_candidates_is_never_presented_as_clean(self):
        repo = self.root / "clean-repository"
        repo.mkdir()
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "ci@example.invalid")
        git(repo, "config", "user.name", "audit CI")
        (repo / "src").mkdir()
        (repo / "src" / "plain.cpp").write_text(
            "int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "no candidates")
        commit = git(repo, "rev-parse", "HEAD")
        report = audit_component(repo, REPOSITORY, commit, excerpt_context=0)
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["validated_vulnerability"], 0)
        markdown = render_markdown(report)
        self.assertIn("This is not proof of safety", markdown)
        self.assertIn("Zero candidates does NOT mean the component is free of vulnerabilities",
                      markdown)
        # The empty candidate list must not read as a verdict either way.
        self.assertNotIn("is clean", markdown)

    def test_unknown_pass_name_is_refused(self):
        plan = self.plan()
        with self.assertRaisesRegex(ValueError, "unknown pass"):
            audit_module.run_audit(self.repo, REPOSITORY, self.commit, plan,
                                   passes=("all-files", "made-up"))


class CommandLineTests(ComponentAuditTestCase):
    def test_plan_only_prints_the_plan_without_running_detectors(self):
        json_out = self.root / "unused.json"
        buffer = StringIO()
        with redirect_stdout(buffer), mock.patch.object(audit_module, "_run_shard") as runner:
            code = audit_module.main([
                "--repo-dir", str(self.repo), "--repository", REPOSITORY,
                "--commit", self.commit, "--plan-only", "--json-out", str(json_out),
            ])
        self.assertEqual(code, 0)
        runner.assert_not_called()
        self.assertFalse(json_out.exists())
        printed = json.loads(buffer.getvalue())
        self.assertEqual(printed["counts"]["selected_files"], 5)
        self.assertTrue(printed["plan_sha256"])

    def test_cli_writes_json_and_markdown_and_refuses_a_shared_output_path(self):
        json_out = self.root / "audit.json"
        md_out = self.root / "audit.md"
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = audit_module.main([
                "--repo-dir", str(self.repo), "--repository", REPOSITORY,
                "--commit", self.commit, "--json-out", str(json_out),
                "--md-out", str(md_out),
            ])
        self.assertEqual(code, 0)
        report = json.loads(json_out.read_text(encoding="utf-8"))
        self.assertEqual(report["experiment_kind"], "component_audit")
        self.assertEqual(report["commit"], self.commit)
        self.assertEqual(report["validated_vulnerability"], 0)
        self.assertEqual(md_out.read_text(encoding="utf-8"), render_markdown(report))
        self.assertIn("NOT vulnerabilities", buffer.getvalue())
        with self.assertRaises(SystemExit):
            audit_module.main([
                "--repo-dir", str(self.repo), "--repository", REPOSITORY,
                "--commit", self.commit, "--json-out", str(json_out),
                "--md-out", str(json_out),
            ])

    def test_pass_table_covers_the_two_documented_passes(self):
        self.assertEqual(sorted(PASS_DETECTORS), ["all-files", "complete-ast"])
        self.assertEqual(PASS_DETECTORS["complete-ast"].required_facts, ("ast",))
        self.assertEqual(PASS_DETECTORS["all-files"].required_facts, ())
        self.assertNotEqual(PASS_DETECTORS["complete-ast"].detector_id,
                            PASS_DETECTORS["all-files"].detector_id)


if __name__ == "__main__":
    unittest.main()

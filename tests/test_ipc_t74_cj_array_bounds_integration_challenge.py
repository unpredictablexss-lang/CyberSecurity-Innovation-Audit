from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "fixtures/ipc/t74_cj_array_bounds/manifest.json"
ROOT = Path(__file__).resolve().parents[3]
IPC_GIT = Path(os.environ.get("T74_IPC_GIT", ROOT / "tmp/t71-communication-ipc"))
SOURCE = "interfaces/innerkits/cj/src/message_sequence_impl.cpp"
RULE = "ipc.parcel.array-allocation-width"
RULE_ROOT = "MessageSequenceImpl::CJ_ReadRemoteObjectArray"


def load_git_source(commit: str, path: str) -> str:
    return subprocess.check_output(["git", "-C", str(IPC_GIT), "show", f"{commit}:{path}"], text=True)


def extract_function(text: str, needle: str) -> str:
    start = text.index(needle)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError(f"unterminated function: {needle}")


def make_run(source: str, *, repository: str, commit: str, provenance: str):
    parsed = parse_source(source, language="cpp")
    unit = SourceUnit(SOURCE, "cpp", source, hashlib.sha256(source.encode()).hexdigest(), parsed.parse_status)
    request = ScanRequest(
        "t74-overlay-challenge", repository, commit, snapshot_digest((unit,)),
        "current-component:" + repository,
        profile_id="light-ast" if provenance == "git_object" else "t74-fixture",
        provenance=provenance,
    )
    context = ScanContext(request, (unit,), {"ast": {SOURCE: parsed.to_dict()}})
    result = IpcInterfaceDetector().detect(context, (unit,))
    return request, unit, result, tuple(f for f in result.findings if f.rule_id == RULE)


class T74CjArrayBoundsOverlayChallenge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))
        if not (IPC_GIT / ".git").exists():
            raise unittest.SkipTest(f"official communication_ipc Git object repo missing: {IPC_GIT}")
        cls.cases = {row["case_id"]: row for row in cls.manifest["cases"]}

    def official(self, case_id: str):
        row = self.cases[case_id]
        text = load_git_source(row["commit"], row["file"])
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), row["source_sha256"])
        parsed = parse_source(text, language="cpp")
        self.assertEqual(parsed.parse_status, "complete")
        return text, make_run(text, repository=row["repository"], commit=row["commit"], provenance="git_object")

    def test_both_pinned_vulnerable_revisions_have_one_root_finding_each(self):
        roots = set()
        for case_id in ("old-cve-parent", "old-umbrella-issue-revision"):
            with self.subTest(case_id=case_id):
                _text, (request, unit, result, findings) = self.official(case_id)
                self.assertEqual(request.provenance, "git_object")
                self.assertEqual(request.profile_id, "light-ast")
                self.assertEqual(request.repository, self.cases[case_id]["repository"])
                self.assertEqual(request.commit, self.cases[case_id]["commit"])
                self.assertEqual(result.status, "completed")
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding.symbol, RULE_ROOT)
                self.assertEqual(finding.source_sha256, unit.sha256)
                self.assertEqual(finding.candidate_cwe, "CWE-131")
                self.assertEqual(finding.consequence_cwe, "CWE-787")
                self.assertEqual(finding.rule_version, "0.1.0")
                risk = finding.risk_assessment
                self.assertEqual(risk["identifier"], "CVE-2025-26474 (候选映射；非根因证明)")
                self.assertIn("provenance only", risk["mapping_basis"])
                self.assertEqual(risk["source_location"]["file"], SOURCE)
                self.assertEqual(risk["source_location"]["symbol"], RULE_ROOT)
                self.assertIn("data06_runtime_poc_20261021/run.sh", risk["poc"]["replay"])
                self.assertIn("vulnerable.stderr.raw.b64", risk["poc"]["raw_output"])
                self.assertEqual(64, len(risk["poc"]["raw_output_sha256"]))
                self.assertIn("de3a68cc8b7d6f18017fd261060def0e38dce54a", risk["fixed_versions"][0])
                self.assertIn("no OpenHarmony binary", risk["component_retest"]["scope"])
                roots.add(("CVE-2025-26474", finding.file, finding.symbol))
        self.assertEqual(len(roots), 1, "two vulnerable revisions are replays of one CVE/function root")

    def test_official_fixed_revision_has_zero_rule_findings(self):
        _text, (request, unit, result, findings) = self.official("official-security-fix")
        self.assertEqual(request.provenance, "git_object")
        self.assertEqual(request.commit, self.cases["official-security-fix"]["commit"])
        self.assertEqual(unit.sha256, self.cases["official-security-fix"]["source_sha256"])
        self.assertEqual(result.status, "completed")
        self.assertEqual(findings, ())

    def test_safe_unrelated_wrong_repository_and_check_only_controls(self):
        vulnerable_text = load_git_source(self.cases["old-cve-parent"]["commit"], SOURCE)
        method = extract_function(vulnerable_text, "RemoteObjectArray MessageSequenceImpl::CJ_ReadRemoteObjectArray")
        sized = method.replace("malloc(arrayLength)", "malloc(sizeof(int32_t) * arrayLength)", 1)
        sized = sized.replace("malloc(arrayLength)", "malloc(sizeof(int64_t) * arrayLength)", 1)
        zero_only = """
        RemoteObjectArray MessageSequenceImpl::CJ_ReadRemoteObjectArray(int32_t* errCode) {
            RemoteObjectArray res = { nullptr, nullptr, 0 };
            int32_t arrayLength = nativeParcel_->ReadInt32();
            if (arrayLength <= 0) { return res; }
            return res;
        }
        """
        unrelated = method.replace("CJ_ReadRemoteObjectArray", "ReadObjectArray", 1)
        check_only = """
        RemoteObjectArray MessageSequenceImpl::CJ_ReadRemoteObjectArray(int32_t* errCode) {
            RemoteObjectArray res = { nullptr, nullptr, 0 };
            int32_t arrayLength = nativeParcel_->ReadInt32();
            if (arrayLength <= 0) { return res; }
            if (CheckReadLength(static_cast<size_t>(arrayLength), BYTE_SIZE_32)) { return res; }
            return res;
        }
        """
        controls = [
            ("sized-positive-control", sized, "openharmony/communication_ipc", "t74-sized-control"),
            ("nonpositive-only-safe", zero_only, "openharmony/communication_ipc", "t74-nonpositive"),
            ("unrelated-method", unrelated, "openharmony/communication_ipc", "t74-unrelated"),
            ("checkreadlength-only", check_only, "openharmony/communication_ipc", "t74-guard-only"),
        ]
        for name, text, repository, commit in controls:
            with self.subTest(name=name):
                _request, _unit, result, findings = make_run(
                    text, repository=repository, commit=commit, provenance="fixture")
                self.assertEqual(result.status, "completed")
                self.assertEqual(findings, ())

        _request, _unit, result, findings = make_run(
            vulnerable_text, repository="openharmony/another_component",
            commit=self.cases["old-cve-parent"]["commit"], provenance="git_object")
        self.assertEqual(result.status, "completed")
        self.assertEqual(findings, ())

    def comment_only_control(self):
        comment_only = """
        RemoteObjectArray MessageSequenceImpl::CJ_ReadRemoteObjectArray(int32_t* errCode) {
            /*
            int32_t arrayLength = nativeParcel_->ReadInt32();
            if (arrayLength <= 0) { return res; }
            if (CheckReadLength(static_cast<size_t>(arrayLength), BYTE_SIZE_32)) {
              int32_t* type = static_cast<int32_t*>(malloc(arrayLength));
              int64_t* id = static_cast<int64_t*>(malloc(arrayLength));
              for (uint32_t i = 0; i < (uint32_t)arrayLength; ++i) {
                type[i] = 0; id[i] = 0;
              }
            }
            */
            return {};
        }
        """
        return make_run(
            comment_only, repository="openharmony/communication_ipc",
            commit="t74-comment-only-fixture", provenance="fixture")

    def test_comment_only_negative_stays_suppressed_after_masking_fix(self):
        _request, _unit, result, findings = self.comment_only_control()
        self.assertEqual(result.status, "completed")
        # Semantically this control contains no count, allocations, or stores.
        # The pre-fix raw-body regex implementation reported one false positive;
        # this post-fix regression pins suppression of that comment-only shape.
        self.assertEqual(findings, ())

    def test_pre_fix_raw_comment_scan_reproduces_one_actual_detector_finding(self):
        _request, _unit, _result, findings = self.comment_only_control()
        self.assertEqual(findings, ())  # current post-fix implementation
        # The pre-fix implementation passed raw function-body bytes to the same
        # regex chain. Identity masking reproduces that exact pre-fix behavior
        # through IpcInterfaceDetector without changing production files.
        import src.ohscanner.detectors.interface.ffi_array_bounds as bounds
        with patch.object(bounds, "_mask_non_code",
                          side_effect=lambda source, start, end, root: source[start:end]):
            _request, _unit, result, findings = self.comment_only_control()
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, RULE)

    def test_manifest_pins_source_identity_and_counts_one_case_root(self):
        official = self.manifest["cases"]
        self.assertEqual([row["case_id"] for row in official], [
            "old-cve-parent", "old-umbrella-issue-revision", "official-security-fix"])
        self.assertTrue(all(row["source_kind"] == "git" and row["commit"] for row in official))
        self.assertTrue(all(row["source_sha256"] for row in official))
        self.assertTrue(self.manifest["deduplication_contract"]["one_distinct_root_across_both_old_revisions"])
        self.assertEqual(self.manifest["deduplication_contract"]["root_identity"], [
            "CVE-2025-26474", SOURCE, RULE_ROOT])
        comment_case = next(row for row in self.manifest["synthetic_controls"]
                            if row["case_id"] == "comment-only-regex-negative")
        self.assertEqual(comment_case["pre_fix_observed_rule_count"], 1)
        self.assertEqual(comment_case["current_expected_rule_count"], 0)


if __name__ == "__main__":
    unittest.main()

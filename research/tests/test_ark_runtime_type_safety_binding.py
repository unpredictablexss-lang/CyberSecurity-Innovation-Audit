from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.admission import pending_admission
from src.ohscanner.detectors.catalog import build_registry, default_detector_ids
from research.full_scan_20261018.lanes.c.detector import ArkRuntimeTypeSafetyDetector
from research.full_scan_20261018.lanes.c.model import MODEL_REPOSITORY, RuntimeTypeModel


TARGET_PATH = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
CREATOR_PATH = "ecmascript/compiler/new_object_stub_builder.cpp"


def unit(path: str) -> SourceUnit:
    text = "// deliberately not the pinned source object\n"
    return SourceUnit(path, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "partial")


def context(units, *, repository=MODEL_REPOSITORY, commit=None, target=None, blobs=None):
    model = RuntimeTypeModel()
    commit = commit or model.target_source[0]
    target = target or "current-component:" + repository
    request = ScanRequest("binding-test", repository, commit, "a" * 64, target,
                          profile_id="light-ast", provenance="git_object")
    return ScanContext(request, tuple(sorted(units, key=lambda u: u.path)),
                       {"source_blob_oid": blobs or {}})


class TypeSafetyBindingTests(unittest.TestCase):
    def blocked(self, ctx, units, reason):
        run = ArkRuntimeTypeSafetyDetector().detect(ctx, tuple(units))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertIn(reason, run.limitations)

    def test_rejects_other_repository_before_parsing(self):
        source = unit(TARGET_PATH)
        self.blocked(context((source,), repository="fork/arkcompiler_ets_runtime"),
                     (source,), "model_repository_mismatch")

    def test_rejects_model_version_mismatch_before_source_analysis(self):
        source = unit(TARGET_PATH)
        model = replace(RuntimeTypeModel(), version="0.3.1")
        run = ArkRuntimeTypeSafetyDetector(model=model).detect(context((source,)), (source,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertIn("model_version_mismatch", run.limitations)

    def test_public_registry_keeps_research_adapter_blocked(self):
        detector_id = "ohscanner.ark.runtime.type_safety"
        row = pending_admission(detector_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["lane"], "C")
        self.assertEqual(row["admission_status"], "blocked")
        self.assertFalse(row["execution_enabled"])
        self.assertNotIn(detector_id, default_detector_ids())
        with self.assertRaisesRegex(ValueError, "admission blocked"):
            build_registry((detector_id,))

    def test_official_ets_frontend_same_name_holdout_is_blocked(self):
        source = unit(TARGET_PATH)
        self.blocked(context((source,), repository="openharmony/arkcompiler_ets_frontend",
                             commit="fadba67b0bdf625d30d69e0940e26c52992669df"),
                     (source,), "model_repository_mismatch")

    def test_rejects_other_commit_before_parsing(self):
        source = unit(TARGET_PATH)
        self.blocked(context((source,), commit="1" * 40), (source,), "model_commit_mismatch")

    def test_known_parent_commit_uses_its_own_exact_profile(self):
        source = unit(TARGET_PATH)
        parent = RuntimeTypeModel().source_profiles[0][0]
        self.blocked(context((source,), commit=parent), (source,),
                     "required_model_source_missing:" + CREATOR_PATH)

    def test_requires_exact_creator_dependency_in_context(self):
        source = unit(TARGET_PATH)
        self.blocked(context((source,)), (source,), "required_model_source_missing:" + CREATOR_PATH)

    def test_recomputes_creator_git_blob_instead_of_trusting_manifest_only(self):
        target, creator = unit(TARGET_PATH), unit(CREATOR_PATH)
        model = RuntimeTypeModel()
        declared = {TARGET_PATH: model.target_source[2], CREATOR_PATH: model.creator_dependency[2]}
        self.blocked(context((target, creator), blobs=declared), (target,),
                     "required_model_source_blob_mismatch:" + CREATOR_PATH)

    def test_recomputes_target_git_blob_instead_of_trusting_manifest_only(self):
        commit = "6" * 40
        expected_target_text = "int target() { return 0; }\n"
        actual_target_text = "int target() { return 1; }\n"
        creator_text = "int creator() { return 0; }\n"
        dependency_text = "// target binding dependency\n"

        def git_oid(text):
            data = text.encode()
            return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

        target = SourceUnit(TARGET_PATH, "cpp", actual_target_text,
                            hashlib.sha256(actual_target_text.encode()).hexdigest(), "complete")
        creator = SourceUnit(CREATOR_PATH, "cpp", creator_text,
                             hashlib.sha256(creator_text.encode()).hexdigest(), "complete")
        dependency_path = "ecmascript/compiler/dependency.h"
        dependency = SourceUnit(dependency_path, "cpp", dependency_text,
                                hashlib.sha256(dependency_text.encode()).hexdigest(), "complete")
        model = replace(
            RuntimeTypeModel(),
            source_profiles=((commit, "7" * 40, git_oid(expected_target_text), git_oid(creator_text)),),
            effect_summary_sources=(("dependency.h", git_oid(dependency_text)),),
            additional_source_dependencies=(),
        )
        ctx = ScanContext(
            ScanRequest("target-blob-test", MODEL_REPOSITORY, commit, "a" * 64,
                        "current-component:" + MODEL_REPOSITORY,
                        profile_id="light-ast", provenance="git_object"),
            tuple(sorted((target, creator, dependency), key=lambda u: u.path)),
            {"source_blob_oid": {TARGET_PATH: git_oid(expected_target_text),
                                 CREATOR_PATH: git_oid(creator_text),
                                 dependency_path: git_oid(dependency_text)},
             "ast": {TARGET_PATH: {}}},
        )
        run = ArkRuntimeTypeSafetyDetector(model=model).detect(ctx, (target,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertIn("required_model_source_blob_mismatch:" + TARGET_PATH, run.limitations)

    def test_requires_model_effect_dependency_blob(self):
        commit = "2" * 40
        target_text = "int unrelated() { return 0; }\n"
        creator_text = "int creator() { return 0; }\n"
        dependency_text = "// frozen effect summary dependency\n"

        def git_oid(text):
            data = text.encode()
            return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

        target = SourceUnit(TARGET_PATH, "cpp", target_text, hashlib.sha256(target_text.encode()).hexdigest(), "complete")
        creator = SourceUnit(CREATOR_PATH, "cpp", creator_text, hashlib.sha256(creator_text.encode()).hexdigest(), "complete")
        dependency_path = "ecmascript/compiler/dependency.h"
        dependency = SourceUnit(dependency_path, "cpp", dependency_text,
                               hashlib.sha256(dependency_text.encode()).hexdigest(), "complete")
        model = replace(
            RuntimeTypeModel(),
            source_profiles=((commit, "3" * 40, git_oid(target_text), git_oid(creator_text)),),
            effect_summary_sources=(("dependency.h", git_oid(dependency_text)),),
            additional_source_dependencies=(),
        )
        request = ScanRequest("dependency-test", MODEL_REPOSITORY, commit, "a" * 64,
                              "current-component:" + MODEL_REPOSITORY,
                              profile_id="light-ast", provenance="git_object")
        blobs = {TARGET_PATH: git_oid(target_text), CREATOR_PATH: git_oid(creator_text)}
        ctx = ScanContext(request, tuple(sorted((target, creator), key=lambda u: u.path)),
                          {"source_blob_oid": blobs, "ast": {TARGET_PATH: {}}})
        run = ArkRuntimeTypeSafetyDetector(model=model).detect(ctx, (target,))
        self.assertEqual(run.status, "blocked")
        self.assertIn("required_model_source_missing:" + dependency_path, run.limitations)

        blobs[dependency_path] = git_oid(dependency_text)
        full_ctx = ScanContext(request, tuple(sorted((target, creator, dependency), key=lambda u: u.path)),
                               {"source_blob_oid": blobs, "ast": {TARGET_PATH: {}}})
        accepted = ArkRuntimeTypeSafetyDetector(model=model).detect(full_ctx, (target,))
        self.assertEqual(accepted.status, "completed")
        self.assertEqual(accepted.findings, ())

    def test_exact_blob_identity_does_not_admit_a_partial_target(self):
        commit = "4" * 40
        target_text = "int recovered_target() {\n    return 0;\n"
        creator_text = "int creator() { return 0; }\n"
        dependency_text = "// exact model dependency\n"

        def git_oid(text):
            data = text.encode()
            return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

        target = SourceUnit(TARGET_PATH, "cpp", target_text,
                            hashlib.sha256(target_text.encode()).hexdigest(), "partial")
        creator = SourceUnit(CREATOR_PATH, "cpp", creator_text,
                             hashlib.sha256(creator_text.encode()).hexdigest(), "complete")
        dependency_path = "ecmascript/compiler/dependency.h"
        dependency = SourceUnit(dependency_path, "cpp", dependency_text,
                                hashlib.sha256(dependency_text.encode()).hexdigest(), "complete")
        model = replace(
            RuntimeTypeModel(),
            source_profiles=((commit, "5" * 40, git_oid(target_text), git_oid(creator_text)),),
            effect_summary_sources=(("dependency.h", git_oid(dependency_text)),),
            additional_source_dependencies=(),
        )
        request = ScanRequest("partial-binding-test", MODEL_REPOSITORY, commit, "a" * 64,
                              "current-component:" + MODEL_REPOSITORY,
                              profile_id="light-ast", provenance="git_object")
        units = tuple(sorted((target, creator, dependency), key=lambda u: u.path))
        blobs = {TARGET_PATH: git_oid(target_text), CREATOR_PATH: git_oid(creator_text),
                 dependency_path: git_oid(dependency_text)}
        ctx = ScanContext(request, units, {"source_blob_oid": blobs, "ast": {TARGET_PATH: {"recovered": True}}})

        run = ArkRuntimeTypeSafetyDetector(model=model).detect(ctx, (target,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertEqual(run.file_outcomes, ((TARGET_PATH, "not_analyzed"),))
        self.assertIn(TARGET_PATH + ": production requires complete C++ AST", run.limitations)


if __name__ == "__main__":
    unittest.main()

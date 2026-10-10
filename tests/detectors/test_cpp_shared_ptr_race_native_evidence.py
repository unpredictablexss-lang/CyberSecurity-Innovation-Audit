from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from research.experiments.cpp.prepare_shared_ptr_race_binding import (
    main as prepare_binding_main,
)
from research.experiments.cpp.shared_ptr_race_native_evidence import (
    binding_manifest_sha256,
    build,
    load_pinned_unit,
    main,
)
from src.ohscanner.contracts import SourceUnit
from tests.detectors.shared_ptr_race_fixture_support import (
    load_shared_ptr_race_units,
    unit_by_path,
)


def _git(directory: Path, *args: str, input_text: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *args],
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()


class SharedPtrRaceNativeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.units = load_shared_ptr_race_units()
        cls.vulnerable_text = unit_by_path(
            cls.units, "vulnerable_non_atomic_shared_ptr.cpp"
        ).text
        cls.fixed_text = unit_by_path(
            cls.units, "fixed_atomic_shared_ptr.cpp"
        ).text

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "pinned-repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "ci@example.invalid")
        _git(self.repo, "config", "user.name", "CI")
        _git(self.repo, "remote", "add", "origin", "https://github.com/synthetic/fixture.git")
        (self.repo / "base" / "include").mkdir(parents=True)
        self.source_path = "base/include/singleton.h"

    def _commit_raw(self, raw: bytes, message: str) -> str:
        (self.repo / self.source_path).write_bytes(raw)
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", message)
        return _git(self.repo, "rev-parse", "HEAD")

    def _commit(self, text: str, message: str) -> str:
        return self._commit_raw(text.encode("utf-8"), message)

    def _binding(self, vulnerable_commit: str, fixed_commit: str):
        revisions = {}
        for revision, commit in (
            ("vulnerable", vulnerable_commit),
            ("fixed", fixed_commit),
        ):
            pinned = load_pinned_unit(
                self.repo, "synthetic/fixture", commit, self.source_path
            )
            revisions[revision] = {
                "commit": commit,
                "git_tree": pinned.git_tree,
                "blob_oid": pinned.blob_oid,
                "source_sha256": pinned.unit.sha256,
            }
        manifest = {
            "schema_version": 1,
            "repository": "synthetic/fixture",
            "source_path": self.source_path,
            "revisions": revisions,
        }
        return manifest, binding_manifest_sha256(manifest)

    def _pair(self):
        vulnerable = self._commit(self.vulnerable_text, "vulnerable shape")
        fixed = self._commit(self.fixed_text, "fixed shape")
        manifest, manifest_sha256 = self._binding(vulnerable, fixed)
        return vulnerable, fixed, manifest, manifest_sha256

    def test_load_pinned_unit_preserves_raw_lf_and_crlf_hash(self) -> None:
        cases = {
            "lf": self.vulnerable_text.encode("utf-8"),
            "crlf": self.vulnerable_text.replace("\n", "\r\n").encode("utf-8"),
            "bom": b"\xef\xbb\xbf" + self.fixed_text.encode("utf-8"),
        }
        for label, raw in cases.items():
            with self.subTest(newline=label):
                commit = self._commit_raw(raw, label)
                pinned = load_pinned_unit(
                    self.repo,
                    "synthetic/fixture",
                    commit,
                    self.source_path,
                )
                self.assertIsInstance(pinned.unit, SourceUnit)
                self.assertEqual(pinned.unit.text, raw.decode("utf-8"))
                self.assertEqual(pinned.unit.sha256, hashlib.sha256(raw).hexdigest())
                self.assertRegex(pinned.blob_oid, r"^[a-f0-9]{40}$")
                self.assertRegex(pinned.git_tree, r"^[a-f0-9]{40}$")

    def test_load_pinned_unit_rejects_non_utf8_blob(self) -> None:
        commit = self._commit_raw(
            self.fixed_text.encode("utf-8") + b"\xff", "invalid utf8"
        )
        with self.assertRaisesRegex(ValueError, "no supported UTF-8 sources"):
            load_pinned_unit(
                self.repo, "synthetic/fixture", commit, self.source_path
            )

    def test_load_pinned_unit_rejects_wrong_origin_and_commit(self) -> None:
        commit = self._commit(self.vulnerable_text, "vulnerable shape")
        _git(self.repo, "remote", "set-url", "origin", "https://github.com/wrong/repository.git")
        with self.assertRaisesRegex(ValueError, "origin repository"):
            load_pinned_unit(
                self.repo, "synthetic/fixture", commit, self.source_path
            )

        _git(self.repo, "remote", "set-url", "origin", "https://github.com/synthetic/fixture.git")
        with self.assertRaisesRegex(ValueError, "Git object operation failed"):
            load_pinned_unit(
                self.repo, "synthetic/fixture", "0" * 40, self.source_path
            )

    def test_pinned_run_ignores_uncommitted_worktree_drift(self) -> None:
        vulnerable = self._commit(self.vulnerable_text, "vulnerable shape")
        (self.repo / self.source_path).write_text(self.fixed_text, encoding="utf-8")
        pinned = load_pinned_unit(
            self.repo, "synthetic/fixture", vulnerable, self.source_path
        )
        self.assertEqual(pinned.unit.text, self.vulnerable_text)

    def test_build_produces_separate_vulnerable_and_fixed_records(self) -> None:
        _vulnerable, _fixed, manifest, manifest_sha256 = self._pair()
        evidence_text, markdown = build(
            self.repo,
            manifest,
            manifest_sha256,
            repository="synthetic/fixture",
            source_repo_path=self.source_path,
        )
        evidence = json.loads(evidence_text)
        self.assertEqual(
            [item["evidence_class"] for item in evidence["records"]],
            ["vulnerable", "fixed"],
        )
        self.assertGreater(len(evidence["records"][0]["finding_bindings"]), 0)
        self.assertEqual(evidence["records"][1]["finding_bindings"], [])
        for record in evidence["records"]:
            artifact = record["source_artifacts"][0]
            self.assertRegex(artifact["git_tree"], r"^[a-f0-9]{40}$")
            self.assertRegex(artifact["git_blob_oid"], r"^[a-f0-9]{40}$")
        self.assertIn("vulnerable", markdown)
        self.assertIn("fixed", markdown)

    def test_binding_manifest_hash_and_pinned_values_are_enforced(self) -> None:
        _vulnerable, _fixed, manifest, manifest_sha256 = self._pair()
        with self.assertRaisesRegex(ValueError, "manifest hash mismatch"):
            build(
                self.repo,
                manifest,
                "0" * 64,
                repository="synthetic/fixture",
                source_repo_path=self.source_path,
            )

        tampered = json.loads(json.dumps(manifest))
        tampered["revisions"]["vulnerable"]["blob_oid"] = "1" * 40
        with self.assertRaisesRegex(ValueError, "does not match vulnerable binding"):
            build(
                self.repo,
                tampered,
                binding_manifest_sha256(tampered),
                repository="synthetic/fixture",
                source_repo_path=self.source_path,
            )

    def test_stale_binding_hash_rejects_vulnerable_fixed_swap(self) -> None:
        _vulnerable, _fixed, manifest, manifest_sha256 = self._pair()
        swapped = copy.deepcopy(manifest)
        swapped["revisions"]["vulnerable"], swapped["revisions"]["fixed"] = (
            swapped["revisions"]["fixed"],
            swapped["revisions"]["vulnerable"],
        )
        with self.assertRaisesRegex(ValueError, "manifest hash mismatch"):
            build(
                self.repo,
                swapped,
                manifest_sha256,
                repository="synthetic/fixture",
                source_repo_path=self.source_path,
            )

    def test_prepare_binding_cli_outputs_reproducible_manifest_and_hash(self) -> None:
        vulnerable = self._commit(self.vulnerable_text, "vulnerable shape")
        fixed = self._commit(self.fixed_text, "fixed shape")
        manifest_path = self.root / "prepared-binding.json"
        hash_path = self.root / "prepared-binding.sha256"
        prepare_binding_main(
            [
                "--repo-root",
                str(self.repo),
                "--repository",
                "synthetic/fixture",
                "--source-path",
                self.source_path,
                "--vulnerable-commit",
                vulnerable,
                "--fixed-commit",
                fixed,
                "--json-out",
                str(manifest_path),
                "--sha256-out",
                str(hash_path),
            ]
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        recorded_hash = hash_path.read_text(encoding="utf-8").strip()
        self.assertEqual(recorded_hash, binding_manifest_sha256(manifest))
        evidence_text, _markdown = build(
            self.repo,
            manifest,
            recorded_hash,
            repository="synthetic/fixture",
            source_repo_path=self.source_path,
        )
        self.assertEqual(len(json.loads(evidence_text)["records"]), 2)

    def test_native_evidence_cli_write_check_roundtrip(self) -> None:
        vulnerable, fixed, manifest, manifest_sha256 = self._pair()
        binding_path = self.root / "binding.json"
        binding_path.write_text(json.dumps(manifest), encoding="utf-8")
        json_out = self.root / "evidence.json"
        md_out = self.root / "evidence.md"
        arguments = [
            "--repo-root",
            str(self.repo),
            "--binding-manifest",
            str(binding_path),
            "--binding-sha256",
            manifest_sha256,
            "--repository",
            "synthetic/fixture",
            "--source-path",
            self.source_path,
            "--json-out",
            str(json_out),
            "--md-out",
            str(md_out),
        ]
        self.assertEqual(vulnerable, manifest["revisions"]["vulnerable"]["commit"])
        self.assertEqual(fixed, manifest["revisions"]["fixed"]["commit"])
        main(arguments)
        main([*arguments, "--check"])

    def test_native_evidence_check_rejects_output_drift(self) -> None:
        for output_name in ("evidence.json", "evidence.md"):
            with self.subTest(output=output_name):
                _vulnerable, _fixed, manifest, manifest_sha256 = self._pair()
                binding_path = self.root / "binding.json"
                binding_path.write_text(json.dumps(manifest), encoding="utf-8")
                json_out = self.root / "evidence.json"
                md_out = self.root / "evidence.md"
                arguments = [
                    "--repo-root",
                    str(self.repo),
                    "--binding-manifest",
                    str(binding_path),
                    "--binding-sha256",
                    manifest_sha256,
                    "--repository",
                    "synthetic/fixture",
                    "--source-path",
                    self.source_path,
                    "--json-out",
                    str(json_out),
                    "--md-out",
                    str(md_out),
                ]
                main(arguments)
                drifted = self.root / output_name
                drifted.write_text(
                    drifted.read_text(encoding="utf-8") + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(SystemExit, "evidence .* mismatch"):
                    main([*arguments, "--check"])


if __name__ == "__main__":
    unittest.main()

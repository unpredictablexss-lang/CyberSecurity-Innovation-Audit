"""Self-tests for fail-closed official-store selection and object verification."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "official_git_object_evidence.py"
SPEC = importlib.util.spec_from_file_location("official_git_object_evidence", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TemporaryGitStore:
    def __init__(self, root: Path):
        self.path = root / "synthetic.git"
        subprocess.run(["git", "init", "--bare", str(self.path)], check=True, capture_output=True)
        subprocess.run(["git", "--git-dir", str(self.path), "remote", "add", "origin", MODULE.OFFICIAL_REMOTE], check=True, capture_output=True)
        self.env = os.environ.copy()
        self.env.update({"GIT_AUTHOR_NAME": "D2 selftest", "GIT_AUTHOR_EMAIL": "d2-selftest@example.invalid", "GIT_COMMITTER_NAME": "D2 selftest", "GIT_COMMITTER_EMAIL": "d2-selftest@example.invalid"})

    def git(self, *args: str, input_bytes: bytes | None = None) -> bytes:
        return subprocess.run(["git", "--git-dir", str(self.path), *args], input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, env=self.env).stdout

    def make_commit(self, case_index: int, side: str, contents: dict[str, bytes], parent: str | None = None) -> tuple[str, str, list[dict]]:
        entries = []
        files = []
        for path, data in sorted(contents.items()):
            blob = self.git("hash-object", "-w", "--stdin", input_bytes=data).decode().strip()
            entries.append(f"100644 blob {blob}\t{path}\n")
            files.append({"path": path, "recorded_git_blob_oid": blob, "recorded_source_sha256": hashlib.sha256(data).hexdigest(), "recorded_bytes": len(data)})
        tree = self.git("mktree", input_bytes="".join(entries).encode()).decode().strip()
        args = ["commit-tree", tree]
        if parent:
            args.extend(["-p", parent])
        commit = self.git(*args, input_bytes=f"{case_index}-{side}\n".encode()).decode().strip()
        return commit, tree, files


class OfficialGitObjectEvidenceTests(unittest.TestCase):
    def test_missing_store_fails_closed(self) -> None:
        with self.assertRaisesRegex(MODULE.StoreError, "not configured"):
            MODULE.resolve_store(None, {})

    def test_non_bare_or_wrong_origin_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            normal = Path(tmp) / "working"
            subprocess.run(["git", "init", str(normal)], check=True, capture_output=True)
            with self.assertRaisesRegex(MODULE.StoreError, "not a bare"):
                MODULE.resolve_store(normal / ".git")
            bare = Path(tmp) / "bad.git"
            subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True)
            subprocess.run(["git", "--git-dir", str(bare), "remote", "add", "origin", "https://example.invalid/not-ark.git"], check=True, capture_output=True)
            with self.assertRaisesRegex(MODULE.StoreError, "official OpenHarmony Gitee"):
                MODULE.resolve_store(bare)
            push_bad = Path(tmp) / "push-bad.git"
            subprocess.run(["git", "init", "--bare", str(push_bad)], check=True, capture_output=True)
            subprocess.run(["git", "--git-dir", str(push_bad), "remote", "add", "origin", MODULE.OFFICIAL_REMOTE], check=True, capture_output=True)
            subprocess.run(["git", "--git-dir", str(push_bad), "config", "remote.origin.pushurl", "https://example.invalid/not-ark.git"], check=True, capture_output=True)
            with self.assertRaisesRegex(MODULE.StoreError, "push URL must be exactly"):
                MODULE.resolve_store(push_bad)

    def test_six_pairs_and_26_files_verify_in_synthetic_bare_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TemporaryGitStore(Path(tmp))
            _, metadata = MODULE.resolve_store(store.path)
            manifest_cases = []
            # Match the real case file-count distribution: 2+2, 4+4, 4+4,
            # 1+1, 1+1, 1+1 = 26 parent/fixed file records.
            per_case = [2, 4, 4, 1, 1, 1]
            for index, count in enumerate(per_case):
                parent_content = {f"case{index}_file{j}.cpp": f"parent {index} {j}\n".encode() for j in range(count)}
                fixed_content = {path: data + b"fixed\n" for path, data in parent_content.items()}
                parent_commit, parent_tree, parent_files = store.make_commit(index, "parent", parent_content)
                fixed_commit, fixed_tree, fixed_files = store.make_commit(index, "fixed", fixed_content, parent_commit)
                manifest_cases.append({
                    "case_id": f"CASE-{index}", "source_identity_status": "recorded_complete",
                    "parent": {"commit": parent_commit, "tree": parent_tree, "files": parent_files},
                    "fixed": {"commit": fixed_commit, "tree": fixed_tree, "files": fixed_files},
                })
            manifest_cases.extend({"case_id": f"OUT-{i}", "source_identity_status": "recorded_incomplete"} for i in range(10))
            record = MODULE.build_record({"cases": manifest_cases}, store.path, metadata, generated_at="2026-01-01T00:00:00+00:00", require_pinned_manifest=False)
            self.assertEqual(record["status"], "verified_synthetic_fixture")
            self.assertEqual(record["evidence_scope"]["complete_case_count"], 6)
            self.assertEqual(record["evidence_scope"]["file_count"], 26)
            self.assertEqual(record["evidence_scope"]["commit_tree_pair_count"], 12)
            self.assertEqual(record["evidence_scope"]["out_of_scope_case_count"], 10)
            self.assertEqual(record["acquisition_and_custody"]["status"], "NOT_INDEPENDENTLY_VERIFIED")
            self.assertEqual(record["product_profile"]["build_profile_status"], "BLOCKED")
            self.assertEqual(record["product_profile"]["preprocess_profile_status"], "BLOCKED")

    def test_changed_manifest_identity_is_rejected(self) -> None:
        manifest_path = Path(__file__).resolve().parents[1] / "ark_parent_fix_build_profile_manifest.v1.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["cases"] = list(manifest["cases"])
        changed = dict(manifest["cases"][0])
        changed["case_id"] = "REPLACED_CASE_WITH_SAME_COUNTS"
        manifest["cases"][0] = changed
        manifest.pop("payload_sha256")
        manifest["payload_sha256"] = MODULE.sha256(MODULE.canonical_json_bytes(manifest))
        result = MODULE.validate_manifest_identity(manifest)
        self.assertEqual(result["status"], "manifest_identity_unpinned")
        self.assertIn("manifest_not_pinned", result["errors"])
        self.assertIn("complete_case_id_mismatch", result["errors"])

    def test_file_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TemporaryGitStore(Path(tmp))
            _, metadata = MODULE.resolve_store(store.path)
            cases = []
            for index, count in enumerate([2, 4, 4, 1, 1, 1]):
                content = {f"f{index}_{i}.cpp": f"source {index} {i}\n".encode() for i in range(count)}
                pc, pt, pf = store.make_commit(index, "parent", content)
                fc, ft, ff = store.make_commit(index, "fixed", {k: v + b"fixed\n" for k, v in content.items()}, pc)
                cases.append({"case_id": str(index), "source_identity_status": "recorded_complete", "parent": {"commit": pc, "tree": pt, "files": pf}, "fixed": {"commit": fc, "tree": ft, "files": ff}})
            cases[0]["parent"]["files"][0]["recorded_source_sha256"] = "0" * 64
            record = MODULE.build_record({"cases": cases}, store.path, metadata, generated_at="2026-01-01T00:00:00+00:00", require_pinned_manifest=False)
            self.assertEqual(record["status"], "verification_failed")
            self.assertEqual(record["evidence_scope"]["file_count"], 26)
            self.assertTrue(any("fixed_object_or_source_mismatch" in case["errors"] or "parent_object_or_source_mismatch" in case["errors"] for case in record["cases"]))
            self.assertTrue(any("parent_object_or_source_mismatch" in error for error in record["errors"]))
            self.assertEqual(record["product_profile"]["build_profile_status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()

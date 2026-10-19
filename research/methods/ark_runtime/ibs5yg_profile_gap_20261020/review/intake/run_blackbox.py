#!/usr/bin/env python3
"""Run independent synthetic CLI cases against one exact D5 validator path."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


FIELDS = (
    "openharmony_release",
    "product_build_id_or_image_version",
    "source_branch_or_release_tag",
    "locked_manifest_uri_plus_sha256_or_immutable_commit",
    "product_name",
    "board_or_device_target",
)
SCHEMA = "ohscanner.ark-runtime.ibs5yg-d5-intake/v1"
CASE_ID = "ARK-TYPEDARRAY-FILTER-RESULT-TYPE-ORIGIN-IBS5YG"
STRUCTURE = "STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW"
BLOCKED = "WAITING_OR_BLOCKED"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def base_case(root: Path) -> dict:
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    manifest_bytes = b"<manifest>synthetic</manifest>\n"
    manifest_digest = sha(manifest_bytes)
    values = {
        "openharmony_release": "SYNTHETIC-RELEASE",
        "product_build_id_or_image_version": "SYNTHETIC-BUILD",
        "source_branch_or_release_tag": "SYNTHETIC-REF",
        "locked_manifest_uri_plus_sha256_or_immutable_commit": "https://synthetic.invalid/manifest.xml#sha256=" + manifest_digest,
        "product_name": "SYNTHETIC-PRODUCT",
        "board_or_device_target": "SYNTHETIC-BOARD",
    }
    fields = {}
    for index, (name, value) in enumerate(values.items()):
        rel = f"evidence/{name}.txt"
        payload = manifest_bytes if name == "locked_manifest_uri_plus_sha256_or_immutable_commit" else f"t5-byte-fixture-{index}\n".encode()
        (root / rel).write_bytes(payload)
        fields[name] = {
            "value": value,
            "evidence": {
                "path": rel,
                "sha256": sha(payload),
                "issuer": "SYNTHETIC-UNVERIFIED-ISSUER",
                "build_identity": values.copy(),
            },
        }
    return {"schema": SCHEMA, "case_id": CASE_ID, "fields": fields}


def invoke(validator: Path, doc: dict, root: Path) -> tuple[int, dict, str]:
    manifest = root / "input.json"
    manifest.write_text(json.dumps(doc, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(validator), "--manifest", str(manifest), "--evidence-root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        output = {"parse_error": True, "stdout": completed.stdout, "stderr": completed.stderr}
    return completed.returncode, output, sha(manifest.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validator", type=Path, required=True)
    args = parser.parse_args()
    validator = args.validator.resolve(strict=True)
    results = []

    def run(name: str, mutate, wanted_status: str, wanted_code: int, wanted_error: str | None = None) -> None:
        with tempfile.TemporaryDirectory(prefix="t5-intake-") as tmp:
            root = Path(tmp)
            doc = base_case(root)
            mutate(doc, root)
            rc, output, digest = invoke(validator, doc, root)
            errors = {item.get("code") for item in output.get("errors", []) if isinstance(item, dict)}
            ok = rc == wanted_code and output.get("status") == wanted_status and (wanted_error is None or wanted_error in errors)
            results.append({
                "id": name,
                "passed": ok,
                "exit_code": rc,
                "status": output.get("status"),
                "admission_ready": output.get("admission_ready"),
                "error_codes": sorted(str(code) for code in errors),
                "input_sha256": digest,
                "expected_exit_code": wanted_code,
                "expected_status": wanted_status,
                "expected_error": wanted_error,
            })

    run("P01-valid-synthetic-control", lambda d, r: None, STRUCTURE, 0)
    run("P02-all-six-missing", lambda d, r: d["fields"].update({key: None for key in FIELDS}), BLOCKED, 2, "field_missing_or_not_object")

    for index, field in enumerate(FIELDS, 1):
        run(f"N{index:02d}-missing-{field}", lambda d, r, f=field: d["fields"].pop(f), BLOCKED, 2, "field_set_mismatch")

    def tamper(d, root):
        entry = d["fields"][FIELDS[0]]["evidence"]
        (root / entry["path"]).write_bytes(b"tampered\n")
    run("N08-evidence-hash-mismatch", tamper, BLOCKED, 2, "evidence_sha256_mismatch")

    def traversal(d, root): d["fields"][FIELDS[0]]["evidence"].update(path="../outside.txt")
    run("N09-path-traversal", traversal, BLOCKED, 2, "evidence_path_not_safe_relative")

    def posix_absolute(d, root): d["fields"][FIELDS[0]]["evidence"].update(path=str((root / "evidence").resolve() / "openharmony_release.txt"))
    run("N10-absolute-posix-path", posix_absolute, BLOCKED, 2, "evidence_path_not_safe_relative")

    def windows_absolute(d, root): d["fields"][FIELDS[0]]["evidence"].update(path="C:/outside/evidence.txt")
    run("N11-absolute-drive-path", windows_absolute, BLOCKED, 2, "evidence_path_not_safe_relative")

    def missing_issuer(d, root): d["fields"][FIELDS[0]]["evidence"].pop("issuer")
    run("N12-missing-issuer", missing_issuer, BLOCKED, 2, "evidence_keys_mismatch")

    def conflicting_build(d, root): d["fields"][FIELDS[1]]["evidence"]["build_identity"]["product_build_id_or_image_version"] = "OTHER-BUILD"
    run("N13-conflicting-build-identity", conflicting_build, BLOCKED, 2, "conflicting_build_identity")

    def mixed_product_release(d, root):
        d["fields"][FIELDS[4]]["value"] = "OTHER-PRODUCT"
        d["fields"][FIELDS[4]]["evidence"]["build_identity"]["product_name"] = "OTHER-PRODUCT"
    run("N14-mixed-product-release-binding", mixed_product_release, BLOCKED, 2, "conflicting_build_identity")

    def forged_status(d, root): d["status"] = "READY"
    run("N15-status-spoof-extra-field", forged_status, BLOCKED, 2, "unexpected_or_missing_top_level_keys")

    def unverifiable_issuer(d, root): d["fields"][FIELDS[0]]["evidence"]["issuer"] = "ORG:CLAIMED-TRUSTED-BUT-UNVERIFIED"
    run("N16-unverified-issuer-label-structural-only", unverifiable_issuer, STRUCTURE, 0)

    def manifest_digest_mismatch(d, root):
        value = "https://synthetic.invalid/manifest.xml#sha256=" + "b" * 64
        d["fields"][FIELDS[3]]["value"] = value
        for field in FIELDS:
            d["fields"][field]["evidence"]["build_identity"][FIELDS[3]] = value
        # The field evidence file still contains unrelated synthetic attestation bytes;
        # the URI digest is intentionally not the digest of any retrieved manifest bytes.
    run("N17-manifest-uri-digest-not-bound-to-retrieved-bytes", manifest_digest_mismatch, BLOCKED, 2, "manifest_digest_does_not_match_evidence_bytes")

    def immutable_but_unresolved_manifest(d, root):
        value = "https://synthetic.invalid/nonexistent.xml?sha256=" + "c" * 64
        d["fields"][FIELDS[3]]["value"] = value
        for field in FIELDS:
            d["fields"][field]["evidence"]["build_identity"][FIELDS[3]] = value
    run("N18-manifest-uri-unresolved", immutable_but_unresolved_manifest, BLOCKED, 2, "manifest_digest_does_not_match_evidence_bytes")

    def fake_commit_reference(d, root):
        value = "commit:" + "d" * 40
        d["fields"][FIELDS[3]]["value"] = value
        for field in FIELDS:
            d["fields"][field]["evidence"]["build_identity"][FIELDS[3]] = value
    run("N19-fake-immutable-commit-unresolved", fake_commit_reference, BLOCKED, 2, "manifest_commit_unresolved_or_evidence_bytes_mismatch")

    with tempfile.TemporaryDirectory(prefix="t5-intake-link-") as tmp:
        root = Path(tmp)
        doc = base_case(root)
        outside = root.parent / (root.name + "-outside")
        outside.mkdir()
        (outside / "escaped.txt").write_bytes(b"outside\n")
        link = root / "evidence" / "escape"
        link_status = "NOT_RUN"
        try:
            if os.name == "nt":
                completed = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, text=True, check=False)
                linked = completed.returncode == 0
                link_status = "JUNCTION" if linked else "NOT_SUPPORTED_BY_HOST"
            else:
                link.symlink_to(outside, target_is_directory=True)
                linked = True
                link_status = "SYMLINK"
            if linked:
                entry = doc["fields"][FIELDS[0]]["evidence"]
                entry["path"] = "evidence/escape/escaped.txt"
                entry["sha256"] = sha(b"outside\n")
                rc, output, digest = invoke(validator, doc, root)
                errors = {item.get("code") for item in output.get("errors", []) if isinstance(item, dict)}
                ok = rc == 2 and output.get("status") == BLOCKED and "evidence_path_contains_symlink_or_reparse_point" in errors
                results.append({"id":"N20-symlink-or-junction-escape","passed":ok,"status":output.get("status"),"exit_code":rc,"admission_ready":output.get("admission_ready"),"error_codes":sorted(str(code) for code in errors),"input_sha256":digest,"link_type":link_status})
            else:
                results.append({"id":"N20-symlink-or-junction-escape","passed":None,"status":"NOT_SUPPORTED_BY_HOST","link_type":link_status})
        finally:
            try:
                if link.exists() or link.is_symlink():
                    link.rmdir()
                (outside / "escaped.txt").unlink()
                outside.rmdir()
            except OSError:
                pass

    result = {
        "schema": "ohscanner.g12-pc-t5-blackbox-run/v1",
        "validator": str(validator),
        "validator_sha256": sha(validator.read_bytes()),
        "case_count": len(results),
        "passed": all(item["passed"] is True for item in results if item["passed"] is not None),
        "checks": results,
        "limitation": "Synthetic structural gate tests only. No real issuer, manifest authority, product identity, source custody, or product build was verified.",
    }
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

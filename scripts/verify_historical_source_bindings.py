"""Verify exact historical CVE commit, parent, blob, symbol and patch bindings."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict
from urllib.parse import quote
from urllib.request import Request, urlopen


API_ROOT = "https://gitee.com/api/v5"
HEX40 = set("0123456789abcdef")
HEX64 = set("0123456789abcdef")


def _is_hex(value: Any, length: int, alphabet: set[str]) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and set(value) <= alphabet
        and set(value) != {"0"}
    )


def _get(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "OHScanner-historical-binding-verifier"})
    with urlopen(request, timeout=30) as response:
        return response.read()


def _json(url: str) -> Any:
    return json.loads(_get(url).decode("utf-8"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_local_shape(sample: Dict[str, Any], binding: Dict[str, Any]) -> None:
    if binding.get("schema_version") != 1:
        raise ValueError("source binding requires schema_version 1")
    for field in ("sample_id", "repository", "cve"):
        if binding.get(field) != sample.get(field):
            raise ValueError(f"source binding {field} does not match sample manifest")
    if binding.get("affected_file") not in sample.get("affected_files", []):
        raise ValueError("source binding affected_file does not match sample manifest")
    if binding.get("affected_symbol") not in sample.get("affected_symbols", []):
        raise ValueError("source binding affected_symbol does not match sample manifest")
    for field in ("vulnerable_commit", "fixed_commit"):
        if binding.get(field) != sample.get(field) or not _is_hex(binding[field], 40, HEX40):
            raise ValueError(f"source binding {field} is not an exact matched commit")
    for field in ("vulnerable_blob_sha1", "fixed_blob_sha1"):
        if not _is_hex(binding.get(field), 40, HEX40):
            raise ValueError(f"source binding {field} must be a Git blob SHA-1")
    for field in ("vulnerable_sha256", "fixed_sha256", "patch_sha256"):
        if not _is_hex(binding.get(field), 64, HEX64):
            raise ValueError(f"source binding {field} must be a SHA-256")
    if not isinstance(binding.get("pr_number"), int) or binding["pr_number"] <= 0:
        raise ValueError("source binding requires a positive PR number")


def verify_binding(sample: Dict[str, Any], binding: Dict[str, Any]) -> Dict[str, Any]:
    _validate_local_shape(sample, binding)
    repo = quote(binding["repository"], safe="/")
    path = quote(binding["affected_file"], safe="/")
    pr = _json(f"{API_ROOT}/repos/{repo}/pulls/{binding['pr_number']}")
    if pr.get("state") != "merged":
        raise ValueError("source binding PR is not merged")
    commits = _json(f"{API_ROOT}/repos/{repo}/pulls/{binding['pr_number']}/commits")
    if not isinstance(commits, list) or not commits:
        raise ValueError("source binding PR has no commit list")
    fixed_commit = commits[0]
    if fixed_commit.get("sha") != binding["fixed_commit"]:
        raise ValueError("PR head commit does not match fixed_commit")
    parents = fixed_commit.get("parents", {}).get("shas", [])
    if parents != [binding["vulnerable_commit"]]:
        raise ValueError("PR head parent does not match vulnerable_commit")

    commit = _json(f"{API_ROOT}/repos/{repo}/commits/{binding['fixed_commit']}")
    changed = {item.get("filename") for item in commit.get("files", [])}
    if binding["affected_file"] not in changed:
        raise ValueError("affected_file is absent from the fixed commit")

    symbol_leaf = binding["affected_symbol"].split("::")[-1]
    verified = {}
    for role, commit_ref in (
        ("vulnerable", binding["vulnerable_commit"]),
        ("fixed", binding["fixed_commit"]),
    ):
        content = _json(f"{API_ROOT}/repos/{repo}/contents/{path}?ref={commit_ref}")
        expected_blob = binding[f"{role}_blob_sha1"]
        if content.get("sha") != expected_blob:
            raise ValueError(f"{role} blob SHA-1 mismatch")
        raw = _get(content["download_url"])
        expected_sha256 = binding[f"{role}_sha256"]
        if _sha256(raw) != expected_sha256:
            raise ValueError(f"{role} source SHA-256 mismatch")
        if symbol_leaf.encode("utf-8") not in raw:
            raise ValueError(f"{role} source does not contain affected symbol")
        verified[role] = {
            "commit": commit_ref,
            "blob_sha1": expected_blob,
            "sha256": expected_sha256,
            "bytes": len(raw),
        }

    patch = _get(binding["pr_url"] + ".patch")
    if _sha256(patch) != binding["patch_sha256"]:
        raise ValueError("PR patch SHA-256 mismatch")
    return {
        "sample_id": binding["sample_id"],
        "cve": binding["cve"],
        "status": "verified",
        "pr_state": pr["state"],
        "vulnerable": verified["vulnerable"],
        "fixed": verified["fixed"],
        "patch_sha256": binding["patch_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples-dir", type=Path, default=Path("benchmarks/historical"))
    parser.add_argument("--bindings-dir", type=Path, default=Path("benchmarks/historical/source_bindings"))
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    results = []
    for binding_path in sorted(args.bindings_dir.glob("*.json")):
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        sample_path = args.samples_dir / (binding["sample_id"].replace("_", "-") + ".json")
        if not sample_path.exists():
            matches = [
                path for path in args.samples_dir.glob("*.json")
                if json.loads(path.read_text(encoding="utf-8")).get("sample_id") == binding["sample_id"]
            ]
            if len(matches) != 1:
                raise ValueError(f"cannot uniquely resolve sample manifest for {binding['sample_id']}")
            sample_path = matches[0]
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
        results.append(verify_binding(sample, binding))
    output = {
        "schema_version": 1,
        "experiment_kind": "historical_source_binding_verification",
        "results": results,
        "interpretation": (
            "Exact commit/parent/blob/symbol/patch binding only. Historical labels "
            "remain evidence records, not new vulnerability discoveries."
        ),
    }
    rendered = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

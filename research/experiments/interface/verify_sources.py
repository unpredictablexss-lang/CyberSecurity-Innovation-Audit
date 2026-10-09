"""Offline fixed-blob integrity checks; never fetches missing sources."""
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


def verify(manifest_path, source_root):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8-sig"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    commit = manifest.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("full commit SHA required")
    if not isinstance(manifest.get("repository"), str) or not manifest["repository"].strip():
        raise ValueError("repository required")
    if not isinstance(manifest.get("files"), list) or not manifest["files"]:
        raise ValueError("nonempty source manifest required")
    source_root = Path(source_root).resolve()
    records = []
    seen = set()
    for record in manifest["files"]:
        if not isinstance(record, dict):
            raise ValueError("source record must be an object")
        relative = record.get("path")
        if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative or PurePosixPath(relative).is_absolute() or any(part in {"", ".", ".."} for part in relative.split("/")):
            raise ValueError("unsafe source path")
        if relative in seen:
            raise ValueError("duplicate source path")
        seen.add(relative)
        for key, size in (("git_blob_sha1", 40), ("sha256", 64)):
            value = record.get(key)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % size, value):
                raise ValueError(f"invalid {key}")
        if type(record.get("bytes")) is not int or record["bytes"] < 0:
            raise ValueError("invalid byte count")
        path = (source_root / relative).resolve()
        if source_root not in path.parents:
            raise ValueError("source path escapes root")
        data = path.read_bytes()
        git_hash = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        if git_hash != record["git_blob_sha1"] or sha256 != record["sha256"] or len(data) != record["bytes"]:
            raise ValueError(f"source hash mismatch: {relative}")
        records.append({"file": relative, "sha256": sha256, "git_blob_verified": True})
    return {"repository": manifest["repository"], "commit": manifest["commit"],
            "verified_files": records, "limitations": ["Blob integrity only; no build, runtime or graph coverage proof."]}


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    result = verify(root / "research/corpus/interface/mmi_source_manifest.json",
                    root / "research/experiments/interface/local_sources")
    print(json.dumps(result, indent=2, ensure_ascii=False))

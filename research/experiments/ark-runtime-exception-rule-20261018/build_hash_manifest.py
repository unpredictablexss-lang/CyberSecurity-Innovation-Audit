import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
paths = [
    OUT / "README.md",
    OUT / "commands.txt",
    OUT / "build_hash_manifest.py",
    OUT / "replay_exception_rule.py",
    OUT / "raw-results.json",
    OUT / "run-summary.json",
    OUT / "test-results.txt",
    ROOT / "research/full_scan_20261018/lanes/c/exception_protection.py",
    ROOT / "research/full_scan_20261018/lanes/c/analysis.py",
    ROOT / "research/full_scan_20261018/lanes/c/model.py",
    ROOT / "research/full_scan_20261018/lanes/c/type_origin.py",
    ROOT / "research/tests/test_ark_runtime_exception_protection_detector.py",
    ROOT / "research/tests/test_ark_runtime_exception_guard.py",
    ROOT / "research/experiments/ark-runtime-exact-source-20261018/sources/exception-parent.cpp",
    ROOT / "research/experiments/ark-runtime-exact-source-20261018/sources/exception-fix.cpp",
]
entries = []
for path in paths:
    if not path.is_file():
        raise SystemExit(f"missing manifest input: {path}")
    data = path.read_bytes()
    entries.append({"path": path.relative_to(ROOT).as_posix(), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
manifest = {
    "schema": "ohscanner.hash-manifest.v1",
    "algorithm": "SHA-256",
    "scope": "research-only Ark Runtime exception propagation replay and implementation inputs",
    "files": entries,
}
manifest_path = OUT / "hash-manifest.json"
manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
manifest_path.write_bytes(manifest_bytes)
digest = hashlib.sha256(manifest_bytes).hexdigest()
(OUT / "hash-manifest.sha256").write_text(f"{digest}  hash-manifest.json\n", encoding="ascii")
print(json.dumps({"manifest": manifest_path.relative_to(ROOT).as_posix(), "sha256": digest, "files": len(entries)}, indent=2))

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

POC = ROOT / "research/data_sensitive/D25_CJSON_CVE_2025_57052_POC.c"
REPOSITORY = "DaveGamble/cJSON"
VERSIONS = {
    "before": {
        "commit": "8f2beb57ddad1f94bed899790b00f46df893ccac",
        "cJSON_Utils.c": ("63651dfbb842ca980b881a6a27abff8c0aaff028",
                         "c405ae37f92d738796badefd9692d081a3564d3d7cc5a856278bf471067267c6"),
        "cJSON.c": ("ca824f0e7fbf7075a9ff9635e40c65591e402beb",
                    "f892717f26cf3d21b7108de50cea95b6e48092950427615fe1d8d9c46ea09cca"),
        "cJSON.h": ("37520bbcf87988b013dd6656983caf55f4e8a19d",
                    "fda63720ffad1d007802f62204831018d167084c26e2ce08ad36f11529a90682"),
        "cJSON_Utils.h": ("a970c65046740dbea82d694ba0f5cd0a5e3ab074",
                          "1050a7cce8ffe352c509e0c1faad505b9b8a09cac3a1c45c544447868e05f3b5"),
    },
    "after": {
        "commit": "74e1ff4994aa4139126967f6d289b675b4b36fef",
        "cJSON_Utils.c": ("8fa24f8e9bf452cf1ba49d1325c85423ce742c74",
                         "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9"),
        "cJSON.c": ("ca824f0e7fbf7075a9ff9635e40c65591e402beb",
                    "f892717f26cf3d21b7108de50cea95b6e48092950427615fe1d8d9c46ea09cca"),
        "cJSON.h": ("37520bbcf87988b013dd6656983caf55f4e8a19d",
                    "fda63720ffad1d007802f62204831018d167084c26e2ce08ad36f11529a90682"),
        "cJSON_Utils.h": ("a970c65046740dbea82d694ba0f5cd0a5e3ab074",
                          "1050a7cce8ffe352c509e0c1faad505b9b8a09cac3a1c45c544447868e05f3b5"),
    },
}


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def load_revision(source_dir: Path, label: str) -> tuple[dict, bytes]:
    spec = VERSIONS[label]
    bindings = {}
    for name, expected in spec.items():
        if name == "commit":
            continue
        expected_blob, expected_sha256 = expected
        raw = (source_dir / name).read_bytes()
        blob = git_blob_sha(raw)
        sha256 = hashlib.sha256(raw).hexdigest()
        if (blob, sha256) != (expected_blob, expected_sha256):
            raise ValueError(f"{label}:{name} source binding mismatch")
        bindings[name] = {"blob": blob, "sha256": sha256, "size": len(raw)}
    return {"commit": spec["commit"], "files": bindings}, (source_dir / "cJSON_Utils.c").read_bytes()


def static_scan(data: bytes, commit: str) -> list[dict]:
    text = data.decode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    unit = SourceUnit(path="cJSON_Utils.c", language="c", text=text, sha256=digest,
                      parse_status="complete")
    request = ScanRequest(
        request_id="d25-cjson-" + commit[:12], repository=REPOSITORY, commit=commit,
        snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:" + REPOSITORY,
        profile_id="pinned-upstream-single-file", provenance="fixture",
    )
    run = KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
    return [{"file": f.file, "line": f.line, "symbol": f.symbol, "rule_id": f.rule_id,
             "source_sha256": f.source_sha256, "message": f.message}
            for f in run.findings if f.symbol == "CVE-2025-57052"]


def component_poc(source_dir: Path, temp: Path, label: str) -> dict:
    binary = temp / f"{label}-poc"
    command = [
        "gcc", "-std=c99", "-O0", "-static", "-I", str(source_dir),
        str(source_dir / "cJSON.c"), str(source_dir / "cJSON_Utils.c"),
        str(POC), "-o", str(binary),
    ]
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if compiled.returncode:
        raise RuntimeError(f"compile failed ({compiled.returncode}): {compiled.stderr[-2000:]}")
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    run = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--mount", "--net", "--fork", str(binary)],
        capture_output=True, text=True, timeout=10,
    )
    if run.returncode:
        raise RuntimeError(
            f"isolated PoC failed ({run.returncode}): {run.stdout[-1000:]} {run.stderr[-2000:]}"
        )
    values = {}
    for token in run.stdout.strip().split():
        key, value = token.split("=", 1)
        values[key] = value
    return {"compiler": subprocess.run(["gcc", "--version"], capture_output=True, text=True,
                                       timeout=5).stdout.splitlines()[0],
            "compile_command": command, "binary_sha256": binary_sha256,
            "execution": "rootless_user_mount_network_namespace",
            "stdout": run.stdout.strip(), "observed": values}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-source-dir", required=True, type=Path)
    parser.add_argument("--after-source-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "research/data_sensitive/D25_CJSON_CVE_2025_57052_REPLAY.json")
    args = parser.parse_args()
    try:
        before, before_source = load_revision(args.before_source_dir, "before")
        after, after_source = load_revision(args.after_source_dir, "after")
        with tempfile.TemporaryDirectory(prefix="ohscanner-d25-cjson-") as temp_dir:
            temp = Path(temp_dir)
            before_poc = component_poc(args.before_source_dir, temp, "before")
            after_poc = component_poc(args.after_source_dir, temp, "after")
        result = {
            "schema": 1,
            "experiment": "D25 cJSON CVE-2025-57052 source and component reproduction",
            "repository": REPOSITORY,
            "detector": KnownDisclosedCveDetector.detector_id,
            "detector_version": KnownDisclosedCveDetector.version,
            "before": {**before, "cve_candidates": static_scan(before_source, before["commit"]),
                       "component_poc": before_poc},
            "after": {**after, "cve_candidates": static_scan(after_source, after["commit"]),
                      "component_poc": after_poc},
            "expected": {
                "before_candidate": True, "after_candidate": False,
                "before_secret_resolution": True, "after_secret_resolution": False,
            },
            "validated_vulnerability": 0,
            "product_status": "unknown",
            "limitations": [
                "This proves behavior of the pinned upstream cJSON component only, with synthetic JSON and no product caller.",
                "The detector input is one source file bound by upstream Git blob and SHA-256; this is a direct detector call, not a whole-repository Runner scan.",
                "No OpenHarmony product build inclusion, attacker path, impact, affected release, or remediation build is established.",
            ],
        }
        if not result["before"]["cve_candidates"] or result["after"]["cve_candidates"]:
            raise AssertionError("before/fixed static rule expectations failed")
        for key, expected in (("resolved", "1"), ("synthetic_secret", "1")):
            if before_poc["observed"].get(key) != expected:
                raise AssertionError(f"before PoC {key} mismatch: {before_poc['observed']}")
        for key, expected in (("resolved", "0"), ("synthetic_secret", "0")):
            if after_poc["observed"].get(key) != expected:
                raise AssertionError(f"fixed PoC {key} mismatch: {after_poc['observed']}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(args.output), "detector_version": result["detector_version"],
                          "before_candidates": len(result["before"]["cve_candidates"]),
                          "after_candidates": len(result["after"]["cve_candidates"]),
                          "before_poc": before_poc["observed"], "after_poc": after_poc["observed"],
                          "validated_vulnerability": 0}, ensure_ascii=False, indent=2))
        return 0
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, AssertionError) as exc:
        print(json.dumps({"status": "blocked", "error_type": type(exc).__name__, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

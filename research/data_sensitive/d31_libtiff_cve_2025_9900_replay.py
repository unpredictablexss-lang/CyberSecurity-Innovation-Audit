#!/usr/bin/env python3
"""Replay the pinned libtiff CVE-2025-9900 source candidate and ASan PoC."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
DRIVER = ROOT / "tests/fixtures/data_sensitive/cve_2025_9900_read_small_raster.c"
FIX_PATCH = ROOT / "tests/fixtures/data_sensitive/cve_2025_9900_upstream_fix.patch"
COMMIT = "d4a0516c477dfbaf1153ae295893ab75aadd63d4"
SOURCE_BLOB = "5121e85b9eb2bc734b557892c0968f629d370b82"
SOURCE_SHA256 = "4b664c80e2e208c2a9cd33042419f69e590ff088c1a3befe99581d1b1df5471a"
DEFAULT_REPO = Path("/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/third_party_libtiff")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def run(command: list[str], *, cwd: Path | None = None, env=None, timeout=180):
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)

def pinned_source(repo: Path, destination: Path) -> dict:
    subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{COMMIT}^{{commit}}"], check=True)
    tree = run(["git", "-C", str(repo), "rev-parse", f"{COMMIT}^{{tree}}"], timeout=20).stdout.strip()
    archive = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", COMMIT], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if archive.returncode:
        raise RuntimeError("git archive failed: " + archive.stderr.decode(errors="replace"))
    with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
        members = tar.getmembers()
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"unsafe member in pinned Git archive: {member.name}")
        tar.extractall(destination, members=members)
    source = destination / "libtiff/tif_getimage.c"
    raw = source.read_bytes()
    blob = run(["git", "-C", str(repo), "rev-parse", f"{COMMIT}:libtiff/tif_getimage.c"], timeout=20).stdout.strip()
    if blob != SOURCE_BLOB or sha256(raw) != SOURCE_SHA256:
        raise ValueError(f"pinned source identity mismatch: blob={blob}, sha256={sha256(raw)}")
    return {"repository": "OpenHarmony-GitCode-Mirror/third_party_libtiff", "commit": COMMIT, "tree": tree, "source_file": "libtiff/tif_getimage.c", "source_git_blob": blob, "source_sha256": sha256(raw), "version": "4.7.0", "dirty_checkout_policy": "git archive of the pinned commit; uncommitted working-tree bytes are excluded"}

def build(source: Path, build_dir: Path, name: str) -> Path:
    configure = run([
        "cmake", "-S", str(source), "-B", str(build_dir),
        "-Dtiff-tools=OFF", "-Dtiff-tests=OFF", "-Dtiff-contrib=OFF", "-Dtiff-docs=OFF", "-Dtiff-install=OFF",
        "-Dzlib=OFF", "-Djpeg=OFF", "-Dlerc=OFF", "-Dwebp=OFF", "-Dlzma=OFF", "-Dzstd=OFF",
        "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_C_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g",
    ])
    if configure.returncode:
        raise RuntimeError(f"{name} CMake configure failed:\n{configure.stdout}\n{configure.stderr}")
    built = run(["cmake", "--build", str(build_dir), "--target", "tiff", "-j2"], timeout=240)
    if built.returncode:
        raise RuntimeError(f"{name} libtiff build failed:\n{built.stdout}\n{built.stderr}")
    executable = build_dir / f"repro-{name}"
    compile_result = run([
        os.environ.get("CC", "gcc"), "-g", "-fsanitize=address", "-fno-omit-frame-pointer",
        f"-I{source / 'libtiff'}", f"-I{build_dir / 'libtiff'}", str(DRIVER),
        f"-L{build_dir / 'libtiff'}", f"-Wl,-rpath,{build_dir / 'libtiff'}", "-ltiff", "-o", str(executable),
    ])
    if compile_result.returncode:
        raise RuntimeError(f"{name} PoC build failed:\n{compile_result.stdout}\n{compile_result.stderr}")
    return executable

def execute(executable: Path, temp: Path, label: str, mode: str) -> dict:
    image = temp / f"{label}.tif"
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=0"
    result = run([str(executable), str(image), mode], env=env, timeout=20)
    output = result.stdout + result.stderr
    write_overflow = "AddressSanitizer" in output and "WRITE memory access" in output and "put8bitcmaptile" in output
    any_asan = "AddressSanitizer" in output
    return {"case": label, "mode": mode, "return_code": result.returncode, "write_overflow_in_put8bitcmaptile": write_overflow, "any_asan_report": any_asan, "tiff_sha256": sha256(image.read_bytes()) if image.exists() else None, "output_excerpt": output[-1800:]}

def scan_candidate(repo: Path) -> dict:
    from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
    from src.ohscanner.execution import run_reviewed_detectors
    registry_module = __import__("src.ohscanner.runner", fromlist=["DetectorRegistry"])
    registry = registry_module.DetectorRegistry()
    registry.register(KnownDisclosedCveDetector())
    first = run_reviewed_detectors(repo, "OpenHarmony-GitCode-Mirror/third_party_libtiff", COMMIT, ["libtiff/tif_getimage.c"], registry)
    second = run_reviewed_detectors(repo, "OpenHarmony-GitCode-Mirror/third_party_libtiff", COMMIT, ["libtiff/tif_getimage.c"], registry)
    def signature(report):
        return [(f["file"], f["line"], f["rule_id"], f["source_sha256"], f["symbol"]) for run_record in report["detector_runs"] for f in run_record["diagnostics"]]
    if signature(first) != signature(second):
        raise RuntimeError("pinned detector replay is not stable")
    findings = [f for record in first["detector_runs"] for f in record["diagnostics"] if f["symbol"] == "CVE-2025-9900"]
    if len(findings) != 1:
        raise RuntimeError(f"expected one CVE-2025-9900 candidate, found {len(findings)}")
    finding = findings[0]
    return {"status": "candidate", "finding": finding, "repeat_equal": True, "coverage": first["detector_coverage"], "validated_vulnerability": first["validated_vulnerability"]}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO, help="read-only Git mirror containing the pinned commit")
    parser.add_argument("--output", type=Path, default=ROOT / "research/data_sensitive/D31_LIBTIFF_CVE_2025_9900_REPLAY.json")
    args = parser.parse_args()
    repo = args.repo.resolve()
    with tempfile.TemporaryDirectory(prefix="ohscanner-d31-cve9900-") as directory:
        temp = Path(directory)
        affected = temp / "affected"
        affected.mkdir()
        source = pinned_source(repo, affected)
        fixed = temp / "fixed"
        shutil.copytree(affected, fixed)
        patch = run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(FIX_PATCH)], cwd=fixed)
        if patch.returncode:
            raise RuntimeError(f"upstream fix patch failed:\n{patch.stdout}\n{patch.stderr}")
        vulnerable_exe = build(affected, temp / "build-vulnerable", "vulnerable")
        fixed_exe = build(fixed, temp / "build-fixed", "fixed")
        rounds = []
        for number in range(1, 4):
            results = [
                execute(vulnerable_exe, temp, f"vulnerable-{number}", "underflow"),
                execute(fixed_exe, temp, f"fixed-{number}", "underflow"),
                execute(vulnerable_exe, temp, f"control-{number}", "safe"),
            ]
            if not results[0]["write_overflow_in_put8bitcmaptile"]:
                raise RuntimeError(f"round {number}: expected ASan write fault not observed")
            if results[1]["any_asan_report"] or results[2]["any_asan_report"]:
                raise RuntimeError(f"round {number}: ASan report in fixed or safe control")
            rounds.append({"round": number, "cases": results})
        document = {
            "schema": 1,
            "experiment": "D31 libtiff CVE-2025-9900 ASan component replay",
            "source": source,
            "fix": {"upstream": "libtiff MR !732", "patch_file": str(FIX_PATCH.relative_to(ROOT)), "patch_sha256": hashlib.sha256(FIX_PATCH.read_bytes()).hexdigest(), "method": "apply the MR !732 code delta to a second extracted copy of the same pinned 4.7.0 source"},
            "runtime": {"compiler": os.environ.get("CC", "gcc"), "instrumentation": "AddressSanitizer", "platform": "Linux x86_64 WSL", "image": "synthetic valid 16x16 8-bit palette TIFF", "trigger": "request TIFFReadRGBAImageOriented into a 16x1 raster while the TIFF contains 16 rows", "control": "same TIFF with a correctly sized 16x16 raster"},
            "detector": scan_candidate(repo),
            "rounds": rounds,
            "interpretation": "The pinned component reproduces an ASan invalid write in put8bitcmaptile after TIFFReadRGBAImageOriented computes its raster offset from an undersized caller height. The fixed-source comparison applies the upstream MR !732 delta to the same source snapshot. This is component-level evidence only; product build, caller reachability, affected OpenHarmony release and product impact remain unknown.",
            "product_status": "unknown",
            "validated_vulnerability": 0,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "candidate": document["detector"]["finding"]["symbol"], "source_status": document["detector"]["finding"]["message"], "rounds": len(rounds), "vulnerable_write_faults": sum(case["write_overflow_in_put8bitcmaptile"] for r in rounds for case in r["cases"]), "fixed_asan_reports": sum(case["any_asan_report"] for r in rounds for case in r["cases"] if case["case"].startswith("fixed")), "control_asan_reports": sum(case["any_asan_report"] for r in rounds for case in r["cases"] if case["case"].startswith("control")), "validated_vulnerability": 0}, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

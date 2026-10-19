from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SOURCE = Path(r"D:\openHarmonyScanner\openharmony\third_party\cJSON")
SOURCE_OLD = Path(r"D:\openHarmonyScanner\outputs\ark-runtime-isolated-validation-20261018\openharmony-5.0.2\third_party\cJSON")
OUT = Path(__file__).resolve().parent
EXPECTED = {
    "cJSON.c": "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb",
    "cJSON_Utils.c": "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9",
}
EXPECTED_OLD = {
    "cJSON.c": "5518fa1468362e7b357ee4239aeddcdae081c001467a6073ddc6a25930b83fc7",
    "cJSON_Utils.c": "9cdd62376a8e46de94fc63bc899d928c56ed6e08a5109be5d64ebe9a6a4add4d",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd: list[str], *, cwd: Path) -> str:
    done = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if done.returncode:
        raise RuntimeError(f"command failed ({done.returncode}): {cmd}\n{done.stderr[-3000:]}")
    return done.stdout.strip()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    runs = []
    source_identities = {}
    for profile, source, expected, target_paths, version in (
        ("openharmony_latest", SOURCE, EXPECTED, ["cJSON.c", "cJSON_Utils.c"], "1.7.19"),
        ("openharmony_5_0_2", SOURCE_OLD, EXPECTED_OLD, ["cJSON.c", "cJSON_Utils.c"], "1.7.17"),
    ):
        observed = {name: sha(source / name) for name in expected}
        if observed != expected:
            raise SystemExit(f"{profile} target source hash mismatch: {observed}")
        source_identities[profile] = {"source_root": str(source), "version_note": version, "target_file_sha256": observed}

        temp = Path(tempfile.mkdtemp(prefix=f"a-cjson-d4-{profile}-"))
        repo = temp / "third_party_cJSON"
        repo.mkdir(parents=True)
        for relative in (*target_paths, "tests/compare_tests.c", "tests/json_patch_tests.c"):
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, target)
        run(["git", "init", "--quiet"], cwd=repo)
        run(["git", "add", "-A"], cwd=repo)
        run(["git", "-c", "user.name=D4 source snapshot", "-c", "user.email=d4-local@example.invalid", "commit", "--quiet", "-m", f"Exact {profile} cJSON source snapshot"], cwd=repo)
        commit = run(["git", "rev-parse", "HEAD"], cwd=repo)

        for label, includes in (
            (f"{profile}_exact_target", target_paths),
            (f"{profile}_unrelated_test_sources", ["tests/compare_tests.c", "tests/json_patch_tests.c"]),
        ):
            json_out = OUT / f"{label}.json"
            md_out = OUT / f"{label}.md"
            command = [sys.executable, "-m", "src.cli", "ohscan-run", "--repo-dir", str(repo), "--repository", "openharmony/third_party_cJSON", "--commit", commit, "--detector", "ohscanner.known_disclosed_cves", "--json-out", str(json_out), "--md-out", str(md_out)]
            for include in includes:
                command.extend(("--include", include))
            stdout = run(command, cwd=ROOT)
            report = json.loads(json_out.read_text(encoding="utf-8"))
            detector = report["detector_runs"][0]
            runs.append({
                "label": label, "includes": includes, "command": command, "stdout": stdout,
                "json_report": json_out.name, "md_report": md_out.name,
                "task_status": report.get("status"), "detector_status": detector.get("status"),
                "commit": report.get("commit"), "tree": report.get("git_tree"),
                "snapshot_sha256": report.get("snapshot_sha256"), "source_parsing": report.get("source_parsing"),
                "coverage": report.get("detector_coverage", {}).get("detectors", {}).get("ohscanner.known_disclosed_cves"),
                "findings": [{"file": f.get("file"), "line": f.get("line"), "rule_id": f.get("rule_id"), "symbol": f.get("symbol"), "source_sha256": f.get("source_sha256"), "message": f.get("message")} for f in detector.get("diagnostics", [])],
            })

    artifact = {
        "schema_version": 1,
        "experiment": "D4 exact-source CLI calibration, no synthetic source substitution",
        "scanner_base": "db77164fdc2af0da02e4d3efc056d84694fd68e8",
        "detector_id": "ohscanner.known_disclosed_cves",
        "detector_version": "0.16.0",
        "declared_target": "openharmony/third_party_cJSON",
        "advisory_source_identity": {
            "commit": "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748",
            "tree": "0d8e50cc18f9ae178e9969eed40f8a0c94fb3856",
            "snapshot_sha256": "648f483aac768e54d504a3b38aea53bfe3c653521580a0cdb51c763182417731",
        },
        "source_identities": source_identities,
        "source_packaging": {
            "kind": "temporary local Git snapshot of the exact current OpenHarmony cJSON working-tree bytes",
            "directory": "temporary per-profile Git snapshots, with exact target/control file bytes and no edits",
            "note": "Temporary Git commits package byte-identical target files for the pinned-source CLI; they do not synthesize, patch, or claim original upstream commit identity.",
        },
        "runs": runs,
        "limitations": [
            "No authoritative vulnerable/fixed source pair is available in the pinned upstream source: current disclosures describe the upstream affected version through 1.7.19 and no upstream fix as of 2026-08-28.",
            "The exact current OH source is byte-identical to D49 cJSON.c and cJSON_Utils.c, but this checkout is a source snapshot and its Git metadata is not usable for the original commit identity.",
            "The comparison/json-patch test files are unrelated-source controls, not safe fixed versions of the affected implementation.",
            "The source matcher remains CVE-specific lexical prototype behavior; it does not establish generic algorithmic-complexity analysis or full-file safety because parser coverage is blocked/partial.",
        ],
    }
    (OUT / "exact_source_cli_replay.json").write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"evidence": str(OUT / "exact_source_cli_replay.json"), "runs": [{"label": r["label"], "status": r["detector_status"], "findings": [(f["symbol"], f["file"], f["line"]) for f in r["findings"]]} for r in runs]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

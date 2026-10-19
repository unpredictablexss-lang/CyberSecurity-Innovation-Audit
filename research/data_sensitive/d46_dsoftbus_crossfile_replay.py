#!/usr/bin/env python3
"""Offline two-round validation of the exact DSoftBus 9f922677 source profile."""
from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

REPOSITORY = "openharmony/communication_dsoftbus"
COMMIT = "9f922677e147b939d6db899bde181d609d64711b"
TREE = "4b114179868d96c69eedc4520037552ddc3d65dd"
FILES = (
    "interfaces/kits/authentication/auth_session_key_struct.h",
    "adapter/common/include/softbus_adapter_crypto.h",
    "core/authentication/src/auth_hichain.c",
    "dfx/interface/include/auth_log.h",
    "dfx/log/src/auth_log.c",
    "core/authentication/src/auth_session_fsm.c",
)


def git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env.update({
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
    })
    result = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, check=False, timeout=20,
    )
    if result.returncode:
        raise RuntimeError("offline Git object read failed: " + args[0] + " "
                           + result.stderr.decode("utf-8", "replace")[:200])
    return result.stdout


def signature(run):
    return sorted((f.file, f.line, f.rule_id, f.symbol or "", f.source_sha256, f.message)
                  for f in run.findings)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-repo", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "research/data_sensitive/D46_DSOFTBUS_CROSSFILE.json")
    args = parser.parse_args()
    repo = args.git_repo.resolve(strict=True)
    tree = git(repo, "rev-parse", COMMIT + "^{tree}").decode().strip()
    if tree != TREE:
        raise SystemExit("fixed tree mismatch; refusing to run")
    sources = []
    source_rows = []
    for path in FILES:
        blob = git(repo, "rev-parse", COMMIT + ":" + path).decode().strip()
        data = git(repo, "show", COMMIT + ":" + path)
        text = data.decode("utf-8")
        source_rows.append({
            "path": path, "blob": blob, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        if path.endswith(".c"):
            language = "c"
        else:
            language = "cpp"
        from src.ohscanner.git_source import GitSource
        sources.append(GitSource(path, language, blob, data))

    text_by_path = {row["path"]: git(repo, "show", COMMIT + ":" + row["path"]).decode("utf-8")
                    for row in source_rows}
    anchors = {
        "session_key_material_and_length": (
            "uint8_t value[SESSION_KEY_LENGTH];" in text_by_path[FILES[0]]
            and "uint32_t len;" in text_by_path[FILES[0]]
        ),
        "crypto_source_writes_key_output_argument": (
            "SoftBusGenerateSessionKey(char *key, uint32_t len)" in text_by_path[FILES[1]]
        ),
        "session_callback_key_is_argument_one": (
            "OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)"
            in text_by_path[FILES[2]]
        ),
        "auth_log_wrapper_preserves_format_position": (
            "#define AUTH_LOGI(label, fmt, ...)" in text_by_path[FILES[3]]
        ),
        "session_key_save_is_queued": (
            "return PostMessageToAuthFsm(FSM_MSG_SAVE_SESSION_KEY, authSeq, key, len);"
            in text_by_path[FILES[5]]
        ),
        "queue_payload_copies_bytes": (
            "memcpy_s(para->data, len, data, len)" in text_by_path[FILES[5]]
        ),
    }
    if not all(anchors.values()):
        raise SystemExit("reviewed source-contract anchor drift; refusing to apply model")

    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources

    units, ast, _ = index_sources(tuple(sources))
    units = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest(
        request_id="d45-dsoftbus-current-profile",
        repository=REPOSITORY,
        commit=COMMIT,
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + REPOSITORY,
        profile_id="light-ast",
        provenance="git_object",
    )
    detector = SensitiveExposureDetector()
    runs = []
    timings = []
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    for _ in range(2):
        start = time.perf_counter()
        runs.append(detector.detect(ScanContext(request, units, {"ast": ast}), units))
        timings.append(time.perf_counter() - start)
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    stable = (signature(runs[0]) == signature(runs[1])
              and runs[0].file_outcomes == runs[1].file_outcomes
              and runs[0].status == runs[1].status)
    result = {
        "schema": 1,
        "study": "D46 bounded cross-file DSoftBus source-to-sink replay",
        "repository": REPOSITORY,
        "commit": COMMIT,
        "tree": tree,
        "detector": {
            "id": detector.detector_id,
            "version": detector.version,
            "source_model_version": "0.4.0",
            "source_profile_catalog_version": "0.2.0",
            "sink_model_version": "0.8.0",
        },
        "profile_contract_anchors": anchors,
        "files": source_rows,
        "snapshot_sha256": request.snapshot_sha256,
        "rounds": [{
            "status": run.status,
            "file_outcomes": [list(row) for row in run.file_outcomes],
            "finding_count": len(run.findings),
            "findings": [{
                "file": f.file, "line": f.line, "rule_id": f.rule_id,
                "symbol": f.symbol, "candidate_cwe": f.candidate_cwe,
                "source_sha256": f.source_sha256, "message": f.message,
                "obligations": [{"kind": o.kind, "description": o.description}
                                for o in f.evidence_obligations],
            } for f in run.findings],
            "limitations": list(run.limitations),
        } for run in runs],
        "round_seconds": timings,
        "candidate_and_coverage_stable": stable,
        "peak_rss_kib": rss_after,
        "validated_vulnerability": 0,
        "labels": "development compatibility regression; not independent holdout",
        "network": "disabled for Git operations",
        "checkout_or_ref_change": "not performed",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "output": str(args.output), "tree": tree, "snapshot_sha256": request.snapshot_sha256,
        "stable": stable, "round_statuses": [run.status for run in runs],
        "finding_counts": [len(run.findings) for run in runs],
        "file_outcomes": [list(row) for row in runs[0].file_outcomes],
        "seconds": timings, "peak_rss_kib": rss_after,
    }, ensure_ascii=False))
    return 0 if stable else 2


if __name__ == "__main__":
    raise SystemExit(main())

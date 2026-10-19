#!/usr/bin/env python3
"""Read-only verification for T26's CR-0019 source, queue and CLI binding."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

COMMIT = "560c5cdadf08b4beeb691e93d70ff32cc2dca8bd"
TREE = "f731230c116c94d7619f5514c828b33ffac69924"
QUEUE_ID = "CR-0019"
EXPECTED = {
    "frameworks/native/proxy/src/data_proxy_observer_stub.cpp": ("fa48e35a0fab0dbc776fb98b7f162c6f62432842", "0b48c5461891d336a34d6d0f2e458ed3f2d175aaa1980fe7c351080c0e5cc6e2"),
    "frameworks/native/proxy/include/data_proxy_observer_stub.h": ("63f1890e131dad0f1dbea20b47a3fc08bc5bc79e", "fab056ad41636ace7b8366480dedc856ba377f9f899c63581d6a661f09d33292"),
    "frameworks/native/proxy/include/data_proxy_observer.h": ("96e404acfc238ee98125f1a8b7441374cecbeee2", "8ea4725358808f50e269bbcaf36eafdb1d2cd42f1504786a4e881fa7053fafcf"),
    "frameworks/native/proxy/src/proxy_data_subscriber_manager.cpp": ("b8238d6469f7f05ce8174c5ec2cd64360656c353", "ec6fb736da6574245c0e31ad66816bd6c9d72395f6f8838d0ad0c39c04211e21"),
    "frameworks/native/proxy/src/data_share_service_proxy.cpp": ("9874af8e13bc2e47b3212f70f6ba557b7f8c6a47", "28170247510d60ef6b7922ca1067c32356c1d116907a2bc45d464c4cf67a1b4f"),
    "frameworks/native/common/src/datashare_itypes_utils.cpp": ("8e6d1fafc8fb5d9b4d2d02357564a6b512d7f755", "89dcced0d37d46c98bcb7bd2cb6d941f6b1342902287e9667f1afd330d85dc77"),
    "interfaces/inner_api/BUILD.gn": ("c72803136f1a6d2b4987905e66f8fc50c21d1766", "e05b15674ca4f73e302690efe112947da99784c434dffddc202d9be61a1659f1"),
}


def git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--queue-json", type=Path, required=True)
    parser.add_argument("--cli-json", type=Path, required=True)
    args = parser.parse_args()
    git_dir = args.source_git_dir.resolve()
    queue_bytes = args.queue_json.read_bytes()
    queue_doc = json.loads(queue_bytes)
    rows = queue_doc["queue"]
    if len(rows) != 345 or hashlib.sha256(queue_bytes).hexdigest() != "cb528dcbcf91482db4d15264425bd43ea2332b45b6c3c86b88f34a5bc823733c":
        raise SystemExit("frozen queue count/hash mismatch")
    hits = [row for row in rows if row["queue_id"] == QUEUE_ID]
    if len(hits) != 1:
        raise SystemExit("CR-0019 missing/duplicated")
    row = hits[0]
    if (row["repository"], row["commit"], row["tree"], row["path"], row["line"], row["blob"], row["source_sha256"]) != (
        "openharmony/distributeddatamgr_data_share", COMMIT, TREE,
        "frameworks/native/proxy/src/data_proxy_observer_stub.cpp", 222,
        "fa48e35a0fab0dbc776fb98b7f162c6f62432842",
        "0b48c5461891d336a34d6d0f2e458ed3f2d175aaa1980fe7c351080c0e5cc6e2",
    ):
        raise SystemExit("queue provenance mismatch")
    if row["original_status"] != "not_testable" or row["queue_status"] != "paused_pending_evidence":
        raise SystemExit("original queue states changed")
    if git(git_dir, "rev-parse", f"{COMMIT}^{{commit}}").decode().strip() != COMMIT:
        raise SystemExit("pinned commit missing")
    if git(git_dir, "show", "-s", "--format=%T", COMMIT).decode().strip() != TREE:
        raise SystemExit("pinned tree mismatch")
    for path, (blob_expected, sha_expected) in EXPECTED.items():
        data = git(git_dir, "show", f"{COMMIT}:{path}")
        blob = git(git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip()
        if blob != blob_expected or hashlib.sha256(data).hexdigest() != sha_expected:
            raise SystemExit(f"source identity mismatch: {path}")
    target = git(git_dir, "show", f"{COMMIT}:{row['path']}").decode().splitlines()
    if "OnChangeFromProxyData(changeInfo);" not in target[221]:
        raise SystemExit("source line binding mismatch")
    header = git(git_dir, "show", f"{COMMIT}:frameworks/native/proxy/include/data_proxy_observer_stub.h").decode()
    iface = git(git_dir, "show", f"{COMMIT}:frameworks/native/proxy/include/data_proxy_observer.h").decode()
    source = "\n".join(target)
    if "IRemoteStub<IProxyDataObserver>" not in header or "OHOS.DataShare.IProxyDataObserver" not in iface:
        raise SystemExit("implemented interface descriptor evidence missing")
    if "PublishedDataObserverStub::GetDescriptor()" not in source:
        raise SystemExit("compared descriptor evidence missing")
    report = json.loads(args.cli_json.read_text(encoding="utf-8"))
    if (report["commit"], report["git_tree"], report["profile_id"], report["snapshot_sha256"]) != (COMMIT, TREE, "light-ast", "162723a8b65a7900a04b8fe6bf19ec862d19c83ff35bdbe3217f6797dd384122"):
        raise SystemExit("CLI provenance mismatch")
    if report["source_parsing"]["parsing_status"] != {"complete": 4, "partial": 1}:
        raise SystemExit("CLI parse coverage mismatch")
    run, = report["detector_runs"]
    if (run["tool"], run["tool_version"], run["diagnostic_count"]) != ("ohscanner.interface.ipc", "0.12.12", 1):
        raise SystemExit("CLI detector identity/count mismatch")
    diag, = run["diagnostics"]
    if (diag["file"], diag["line"], diag["rule_id"], diag["candidate_cwe"]) != (row["path"], 222, "ipc.relay.descriptor-boundary", "CWE-441"):
        raise SystemExit("CLI finding binding mismatch")
    print("T26 CR-0019 source identities, frozen 345-row queue/status, interface mismatch and CLI candidate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

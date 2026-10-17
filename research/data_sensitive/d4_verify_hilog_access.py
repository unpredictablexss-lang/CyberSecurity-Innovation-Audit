#!/usr/bin/env python3
"""Offline verification for D4's adjacent-date HiLog control-socket evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE = Path(__file__).with_name("D4_HILOG_ACCESS_EVIDENCE.json")
DEFAULT_CACHE = ROOT / "outputs" / "d4-source-cache"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--source-cache", type=Path, default=DEFAULT_CACHE)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    snapshots = evidence["api_snapshots"]
    commit_bytes = (args.evidence.parent / snapshots["commit_file"]).read_bytes()
    tree_bytes = (args.evidence.parent / snapshots["tree_file"]).read_bytes()
    assert sha256(commit_bytes) == snapshots["commit_response_sha256"]
    assert sha256(tree_bytes) == snapshots["tree_response_sha256"]
    commit_doc = json.loads(commit_bytes)
    tree_doc = json.loads(tree_bytes)
    assert commit_doc["sha"] == evidence["commit"]
    assert commit_doc["tree"]["sha"] == evidence["tree_sha"]
    assert tree_doc["sha"] == evidence["tree_sha"]
    assert tree_doc["truncated"] is False
    assert len(tree_doc["tree"]) == evidence["tree_recursive_entries"]
    api_paths = {row["path"]: row for row in tree_doc["tree"]}
    mappings = {row["path"]: row for row in evidence["tree_path_mappings"]}
    objects = {row["path"]: row for row in evidence["objects"]}
    assert len(api_paths) == evidence["tree_recursive_entries"]
    assert set(mappings) == set(objects) and len(objects) == 4
    for path, row in mappings.items():
        assert path in api_paths
        assert all(api_paths[path].get(k) == row.get(k) for k in ("path", "mode", "type", "sha", "size"))
    print("PASS saved commit/tree API snapshots, full recursive listing and four exact path mappings")

    sources: dict[str, str] = {}
    for path, row in objects.items():
        tree = mappings[path]
        assert tree["type"] == "blob" and tree["mode"] == "100644"
        assert tree["sha"] == row["blob_sha1"]
        data = (args.source_cache / row["blob_sha1"]).read_bytes()
        assert len(data) == row["size"] == tree["size"]
        assert git_blob_sha(data) == row["blob_sha1"]
        assert sha256(data) == row["sha256"]
        sources[path] = data.decode("utf-8")
    print("PASS four exact source blobs match Git blob SHA-1, SHA-256, size and tree path")

    config = json.loads(sources["services/hilogd/etc/hilogd.cfg"])
    service = next(row for row in config["services"] if row["name"] == "hilogd")
    sockets = {row["name"]: row for row in service["socket"]}
    control = sockets["hilogControl"]
    input_socket = sockets["hilogInput"]
    assert service["disabled"] == 1 and service["start-mode"] == "boot"
    assert service["uid"] == "logd"
    assert (control["family"], control["type"], control["permissions"], control["uid"], control["gid"]) == (
        "AF_UNIX", "SOCK_SEQPACKET", "0600", "logd", "logd"
    )
    assert (input_socket["family"], input_socket["type"], input_socket["permissions"]) == (
        "AF_UNIX", "SOCK_DGRAM", "0666"
    )
    print("PASS distinct control/input socket configuration and disabled-service caveat")

    header = sources["frameworks/native/include/hilog_common.h"]
    assert '#define CONTROL_SOCKET_NAME "hilogControl"' in header
    assert '#define INPUT_SOCKET_NAME "hilogInput"' in header
    client = sources["services/hilogtool/main.cpp"]
    assert "SeqPacketSocketClient controller(CONTROL_SOCKET_NAME, 0);" in client
    assert "LogQueryResponseOp(controller, recvBuffer" in client
    server = sources["services/hilogd/service_controller.cpp"]
    assert "void ServiceController::HandleLogQueryRequest()" in server
    assert "m_hilogBuffer.Query(m_filters, m_bufReader" in server
    assert "WriteLogQueryRespond(SENDIDA, LOG_QUERY_RESPONSE, logData);" in server
    print("PASS client uses control socket; server query reads and returns ring-buffer logs")
    print("LIMITATION service activation, product overrides, alternate paths and runtime ACL are unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
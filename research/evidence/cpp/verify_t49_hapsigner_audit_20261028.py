#!/usr/bin/env python3
"""Verify T49 CR-0300 source binding, replay, build context and A0 preservation."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMIT = "2697b2298b111e90c0999e79595645a68437f3d7"
TREE = "dbee4af9158f1d0663a0a776d2e7db5aa1f9201c"
SOURCE = "binary_sign_tool/hap/sign/include/elf_sign_context.h"
BLOB = "44e062bc5572c3a658cc9eaceb149f70e320f963"
SHA = "cde0bb719af2db91517921d44f31d439126658f36125bd9d703c249fd0869808"
CONTEXT = {
    "binary_sign_tool/BUILD.gn": ("9a26b0faf22abb6934775a68d2a5dfda9efc1736", "2d361aa500d42adf869f51b205e04adf08bde12ade9b671c043e5fe8220d61b0"),
    "binary_sign_tool/hap/signature_tools_hap.gni": ("23e6ef22ab6c10c7f53ee31571769c806e63a55b", "178616872c52b2749252c097bd374e78f613228688111a99ef3920d74d7caf12"),
    "binary_sign_tool/hap/sign/src/sign_elf.cpp": ("0abb0625cc6f8c8446a8d31772e58ca8cc21aeef", "dc1578936151b9827da1ae0a081ad043f2827528d4581cf76e2f4784b151cec3"),
    "binary_sign_tool/hap/sign/src/elf_sign_context.cpp": ("cf7eb6d64412d0252099802394361daaf40dcc3f", "28c05f60371bb1f4a917334d2c49112acab1672857198e45f049d662c0cdccd5"),
    "binary_sign_tool/hap/sign/src/elf_sign_writer.cpp": ("462231792af20ba521cead7cfedff10420f8144d", "0ce5cd0ec253fb1a0ad5a92ad0aeaff52f55d5a20b592a626e82081fb98e9722"),
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--queue-csv", type=Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv")
    parser.add_argument("--queue-json", type=Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json")
    args = parser.parse_args()
    repo = args.source_repo.resolve()
    assert git(repo, "rev-parse", "HEAD").decode().strip() == COMMIT
    assert git(repo, "show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    src = git(repo, "show", f"{COMMIT}:{SOURCE}")
    assert git(repo, "rev-parse", f"{COMMIT}:{SOURCE}").decode().strip() == BLOB
    assert hashlib.sha256(src).hexdigest() == SHA
    src_text = src.decode()
    assert "const std::shared_ptr<ELFIO::endianess_convertor>& GetConvertor() const" in src_text
    assert "std::shared_ptr<ELFIO::endianess_convertor> convertor;" in src_text

    for path, (blob, sha) in CONTEXT.items():
        content = git(repo, "show", f"{COMMIT}:{path}")
        assert git(repo, "rev-parse", f"{COMMIT}:{path}").decode().strip() == blob, path
        assert hashlib.sha256(content).hexdigest() == sha, path
    build = git(repo, "show", f"{COMMIT}:binary_sign_tool/BUILD.gn").decode()
    hap = git(repo, "show", f"{COMMIT}:binary_sign_tool/hap/signature_tools_hap.gni").decode()
    sign_elf = git(repo, "show", f"{COMMIT}:binary_sign_tool/hap/sign/src/sign_elf.cpp").decode()
    context_cpp = git(repo, "show", f"{COMMIT}:binary_sign_tool/hap/sign/src/elf_sign_context.cpp").decode()
    assert 'ohos_executable("binary-sign-tool")' in build and "signature_tools_main_src += signature_tools_hap_src" in build
    assert '"${signature_tools_hap}/sign/src/elf_sign_context.cpp"' in hap
    assert '"${signature_tools_hap}/sign/src/sign_elf.cpp"' in hap
    assert "ElfSignContext ctx;" in sign_elf and "ctx.Load(elfReader, inputFile)" in sign_elf
    assert "convertor = reader.get_convertor();" in context_cpp

    rows = list(csv.DictReader(args.queue_csv.open(encoding="utf-8-sig", newline="")))
    qjson = json.loads(args.queue_json.read_text(encoding="utf-8"))["queue"]
    cmap = {row["queue_id"]: row for row in rows}
    jmap = {row["queue_id"]: row for row in qjson}
    assert len(rows) == len(qjson) == len(cmap) == len(jmap) == 345
    assert set(cmap) == set(jmap)
    original = cmap["CR-0300"]
    assert original["repository"] == "openharmony/developtools_hapsigner"
    for key, value in {"commit": COMMIT, "tree": TREE, "path": SOURCE, "line": "46", "blob": BLOB, "source_sha256": SHA,
                       "original_status": "not_testable", "queue_status": "paused_pending_evidence"}.items():
        assert str(original[key]) == str(jmap["CR-0300"][key]) == value

    audit = json.loads((HERE / "t49_hapsigner_audit_20261028.json").read_text(encoding="utf-8"))
    raw = json.loads((HERE / "t49_hapsigner_cli_20261028.json").read_text(encoding="utf-8"))
    assert audit["status"] == "PARTIAL/BLOCK" and audit["queue"]["states_changed"] is False
    assert raw["repository"] == "openharmony/developtools_hapsigner"
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["status"] == "completed" and raw["validated_vulnerability"] == 0
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", 0)
    assert run["parsing"][0]["status"] == "complete"
    assert run["parsing"][0]["file"] == SOURCE

    print("PASS T49: exact hapsigner commit/tree/blob/SHA for CR-0300")
    print("PASS T49: current shared_ptr_race 0.5.1 exact-source replay; complete parse, zero diagnostics")
    print("PASS T49: exact source call chain and binary-sign-tool GN inclusion bound")
    print("PASS T49: A0 345-row queue reconciles; CR-0300 status remains unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

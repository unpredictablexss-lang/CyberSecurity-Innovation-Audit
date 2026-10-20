#!/usr/bin/env python3
"""Verify D43 exact source bindings, current CLI mapping, and unchanged A0 rows."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = "aacc11729e95d19171fdbf70c30859ce2a05e246"
COMMIT = "d91f43e80d892bca694c6b0fce8ea27cd644919f"
TREE = "8c5eecdad09e2fe960ce5f3728959a4726f0a91d"
REPOSITORY = "openharmony/arkcompiler_taihe_ffi_gen"
IDS = {f"CR-{i:04d}" for i in range(197, 214)}
QUEUE_CSV = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
RAW = HERE / "d43_taihe_ffi_gen_cli_20261025.json"
REPLAY = HERE / "d43_taihe_ffi_gen_replay_20261025.json"


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_repo.resolve()
    assert git(source, "rev-parse", COMMIT + "^{commit}").decode().strip() == COMMIT
    assert git(source, "rev-parse", COMMIT + "^{tree}").decode().strip() == TREE

    rows = list(csv.DictReader(QUEUE_CSV.open(encoding="utf-8-sig", newline="")))
    queue_json = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    assert len(rows) == len(queue_json) == 345
    by_id = {row["queue_id"]: row for row in rows}
    json_by_id = {row["queue_id"]: row for row in queue_json}
    assert set(by_id) == set(json_by_id)
    selected = {qid: by_id[qid] for qid in IDS}
    assert set(selected) == IDS

    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["repository"] == REPOSITORY
    assert raw["scope"]["declared_scope"] == [
        "test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp",
        "test/ra_napi_image/author/include/image_source_taihe.h",
    ]
    assert raw["source_parsing"]["parsing_status"] == {"complete": 2}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 16
    )
    assert run["scope_files"] == 2 and run["scope_loc"] == 316
    diagnostics = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}

    files = {}
    for row in selected.values():
        path = row["path"]
        content = git(source, "show", f"{COMMIT}:{path}")
        blob = git(source, "rev-parse", f"{COMMIT}:{path}").decode().strip()
        digest = hashlib.sha256(content).hexdigest()
        assert row["commit"] == COMMIT and row["tree"] == TREE
        assert row["repository"] == REPOSITORY
        assert (row["blob"], row["source_sha256"]) == (blob, digest)
        files[path] = {"path": path, "blob": blob, "sha256": digest,
                       "bytes": len(content), "lines": len(content.decode("utf-8").splitlines())}

    items = []
    for qid in sorted(IDS):
        row = selected[qid]
        jrow = json_by_id[qid]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob",
                    "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(jrow[key])
        found = diagnostics.get((row["path"], int(row["line"])))
        content = git(source, "show", f"{COMMIT}:{row['path']}").decode("utf-8").splitlines()
        item = {key: row[key] for key in (
            "queue_id", "candidate_id", "repository", "commit", "tree", "path", "line",
            "blob", "source_sha256", "original_status", "queue_status")}
        item["source_line"] = content[int(row["line"]) - 1].strip()
        item["finding"] = ({"matched": True, "rule_id": found["rule_id"],
                            "symbol": found.get("symbol"),
                            "diagnostic_id": found["diagnostic_id"]} if found else
                           {"matched": False, "reason": "no_current_finding_at_a0_line"})
        assert row["original_status"] == jrow["original_status"] == "not_testable"
        assert row["queue_status"] == jrow["queue_status"] == "paused_pending_evidence"
        items.append(item)

    build_content = git(source, "show", f"{COMMIT}:BUILD.gn")
    build_blob = git(source, "rev-parse", f"{COMMIT}:BUILD.gn").decode().strip()
    # There is no GN target definition in this repository commit; only root compiler packaging targets.
    build_text = build_content.decode("utf-8")
    assert "test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp" not in build_text
    assert "test/ra_napi_image/author/include/image_source_taihe.h" not in build_text
    context_path = "test/ra_napi_image/author/src/image_source_taihe.cpp"
    context_content = git(source, "show", f"{COMMIT}:{context_path}")
    context_blob = git(source, "rev-parse", f"{COMMIT}:{context_path}").decode().strip()
    context_lines = context_content.decode("utf-8").splitlines()
    assert "// This file is a test file." in context_lines[:30]
    assert sum("imageSourceCrossThreadMutex_" in line for line in context_lines) == 1

    replay = {
        "schema_version": "d43-taihe-ffi-gen-sharedptr-replay-v1",
        "task": "D43",
        "base_head": BASE,
        "structured_vibe_prompt": {
            "role": "A线 C/C++ shared_ptr_race 开发与源码复核负责人",
            "sustained_goal": "对 A0 固定来源中的共享指针语法候选逐案追踪同一 wrapper 的所有权、读写、同步、构建和线程生命周期；只有存在可证明的产品级同对象未同步并发 root 时才提出规则变化。",
            "inputs": {"a0_ids": "CR-0197–CR-0213", "repository": REPOSITORY,
                       "commit": COMMIT, "tree": TREE,
                       "detector": "ohscanner.cpp.shared_ptr_race 0.5.1"},
            "steps": [
                "绑定每个 A0 ID 的 commit/tree/blob/SHA 并运行当前生产 CLI，记录解析覆盖、规则版本、位置和耗时。",
                "核对 author 文件、组件 GN/build target 与 production inclusion；不要将目录名或 shared_ptr 成员直接当成产品漏洞。",
                "逐个 shared_ptr wrapper 追踪写入/读取/reset/复制、对象别名、锁/原子和调用线程生命周期。",
                "若根因只在测试或作者占位实现，保留语法候选与产品结论 unknown；若有生产漏检，冻结精确源码后才改 detector 并交独立测试线。",
                "原始 A0 状态、缺失修复/线程/产品配置证据均保持，不把未命中或完整解析解读为安全。"
            ],
            "completion_gate": "17 个来源绑定位置均有可复跑 CLI 映射、build/test-only 证据与同对象同步/线程结论；若规则变化则由独立线复验正例及安全/修复对照；A0 与范围检查通过。",
            "boundaries": ["不改 A0 状态、公共 API/schema 或 Catalog。",
                           "语法候选不等于数据竞争；完整解析不代表线程/跨模块上下文完整。",
                           "不据零 finding、test 文件名或 build 缺项宣称产品安全。"]
        },
        "source": {"repository": REPOSITORY, "commit": COMMIT, "tree": TREE,
                   "identity_verified_from_local_git_objects": True,
                   "files": list(files.values()),
                   "build_file": {"path": "BUILD.gn", "blob": build_blob,
                                  "sha256": hashlib.sha256(build_content).hexdigest(),
                                  "result": "no references to either queued author source; tracked source tree has no BUILD.gn beneath either author directory; root targets package Taihe compiler/runtime outputs"},
                   "context_file": {"path": context_path, "blob": context_blob,
                                    "sha256": hashlib.sha256(context_content).hexdigest(),
                                    "result": "explicit test-file comment; async worker context can call GetIncrementalPixelMap; imageSourceCrossThreadMutex_ has one declaration and no visible use"}},
        "cli": {"raw_json": RAW.name, "detector": run["tool"], "version": run["tool_version"],
                "status": run["status"], "parse": raw["source_parsing"]["parsing_status"],
                "scope_files": run["scope_files"], "scope_loc": run["scope_loc"],
                "finding_count": run["diagnostic_count"], "elapsed_seconds": run["elapsed_seconds"],
                "command": "python -m src.cli ohscan-run --repo-dir <local-bare-source-object-store> --repository " + REPOSITORY +
                           " --commit " + COMMIT + " --include test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp" +
                           " --include test/ra_napi_image/author/include/image_source_taihe.h --detector ohscanner.cpp.shared_ptr_race"},
        "queue": {"audited_ids": sorted(IDS), "states_changed": False,
                  "status_counts": {"not_testable": 17, "paused_pending_evidence": 17}},
        "items": items,
        "assessment": {
            "classification": "PARTIAL",
            "summary": "CR-0197–CR-0212 all map to syntax findings on m_pdata in a source file explicitly marked 'This file is a test file.' CR-0213 binds a shared_ptr member in another author header but has no exact current finding. The source objects are under test/.../author and root BUILD.gn contains no references to them or registered test GN target. No concurrent callers, production inclusion, synchronization contract, trusted fixed object, or impact is established.",
            "same_object_facts": [
                "CR-0197–CR-0209 refer to PixelMapImpl::m_pdata or ImageSourceImpl::m_pdata in one test implementation file; operations include member initialization, reads through native PixelMap methods, and reset/release.",
                "CR-0210–CR-0212 map ImageSourceImpl::m_pdata construction/release operations in the same explicit test implementation file.",
                "CR-0213 line 57 is the const GetIncrementalPixelMap() accessor returning navIncPixelMap_; the associated test implementation's async worker helper invokes this accessor, but the shared object setter/initialization path is not present in the inspected author files.",
                "Related image_source_taihe.cpp is also explicitly marked as a test file. It declares imageSourceCrossThreadMutex_ exactly once with no visible use, while thread-local path/buffer state is present. No mutex/atomic synchronization around the queued wrappers or target-derived thread overlap was established; external test/build integration remains unknown."
            ],
            "limitations": ["production inclusion and target-derived callers unbound",
                            "cross-repository callers, external harness registration, and full framework lifecycle not audited",
                            "no trusted fixed source or safe/fixed control for this component case",
                            "CLI syntax locations do not establish dynamic data races"]
        }
    }
    REPLAY.write_text(json.dumps(replay, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Verify generated mapping and all unchanged queue-state identities.
    final = json.loads(REPLAY.read_text(encoding="utf-8"))
    assert len(final["items"]) == 17
    assert sum(item["finding"]["matched"] for item in final["items"]) == 16
    assert sum(not item["finding"]["matched"] for item in final["items"]) == 1
    print("D43 commit/tree, 17 exact A0 source bindings, author BUILD evidence: PASS")
    print("D43 current shared_ptr_race 0.5.1 CLI: PASS (2/2 complete, 16 findings)")
    print("D43 per-ID line map: PASS (16 matched, 1 no current finding)")
    print("A0 queue remains 345 rows; all 17 statuses unchanged: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

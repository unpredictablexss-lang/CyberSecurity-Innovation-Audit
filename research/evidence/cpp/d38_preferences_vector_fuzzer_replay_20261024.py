from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
RAW = HERE / "d38_preferences_vector_fuzzer_20261024.json"
OUT = HERE / "d38_preferences_vector_fuzzer_replay_20261024.json"
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
REPO = "openharmony/distributeddatamgr_preferences"
SRC = "test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferencesvector_fuzzer/BUILD.gn"
IDS = [f"CR-{i:04d}" for i in range(91, 97)]


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def binding(path: str) -> dict[str, str | int]:
    blob = git("show", f"{COMMIT}:{path}")
    return {"path": path, "blob": git("hash-object", "--stdin", data=blob).decode().strip(),
            "sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob)}


def main() -> None:
    rows = list(csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline="")))
    json_rows = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    cmap, jmap = ({r["queue_id"]: r for r in group} for group in (rows, json_rows))
    assert len(rows) == len(json_rows) == len(cmap) == len(jmap) == 345
    assert set(cmap) == set(jmap)
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    src, build = binding(SRC), binding(BUILD)
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE and raw["repository"] == REPO
    assert raw["status"] == "completed" and raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 6)
    diags = {d["line"]: d for d in run["diagnostics"] if d["file"] == SRC}
    assert len(diags) == 6
    items = []
    for qid in IDS:
        row, jrow = cmap[qid], jmap[qid]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(jrow[key]), (qid, key)
        assert (row["repository"], row["commit"], row["tree"], row["path"]) == (REPO, COMMIT, TREE, SRC)
        assert row["blob"] == src["blob"] and row["source_sha256"].lower() == src["sha256"]
        assert (row["original_status"], row["queue_status"]) == ("not_testable", "paused_pending_evidence")
        diag = diags[int(row["line"])]
        items.append({"queue_id": qid, "candidate_id": row["candidate_id"],
                      "source": {**src, "repository": REPO, "commit": COMMIT, "tree": TREE, "line": int(row["line"])},
                      "original_a0": {"original_status": row["original_status"], "queue_status": row["queue_status"]},
                      "replay": {"detector": run["tool"], "version": run["tool_version"], "parse_status": "complete",
                                 "coverage": "syntax_candidate", "finding_line": diag["line"], "symbol": diag["symbol"],
                                 "rule_id": diag["rule_id"], "diagnostic_id": diag["diagnostic_id"]},
                      "disposition": "PARTIAL", "reason": "The exact DBPreferencesVectorFuzzTest is test-only; Put/Get calls in the harness execute sequentially and do not establish overlapping production accesses, product inclusion, reachability or impact.",
                      "queue_preserved": True})
    assert {int(cmap[q]["line"]) for q in IDS} == set(diags)
    report = {
        "schema_version": "d38-preferences-vector-fuzzer-replay-v1", "task": "D38",
        "source": {"repository": REPO, "commit": COMMIT, "tree": TREE, "file": src},
        "build_target": {"file": build, "target": "ohos_fuzztest(DBPreferencesVectorFuzzTest)",
                         "test_group": 'group("fuzztest") [testonly = true]', "harness_entry": "LLVMFuzzerTestOneInput",
                         "production_evidence": False},
        "queue": {"total_rows": 345, "audited_ids": IDS, "a0_status_unchanged": True},
        "cli": {"raw": RAW.name, "detector": run["tool"], "version": run["tool_version"], "status": run["status"],
                "scope_files": run["scope_files"], "scope_loc": run["scope_loc"],
                "parse": raw["source_parsing"]["parsing_status"], "findings": run["diagnostic_count"],
                "elapsed_seconds": run["elapsed_seconds"],
                "command": "python -m src.cli.main ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d37-preferences-source-20261024 --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race"},
        "items": items, "overall_disposition": "PARTIAL", "detector_change": "none; six source-bound harness candidates reproduce, no production-root miss established",
        "queue_states_changed": False,
        "structured_vibe_prompt": {"role": "A 线 Preferences shared_ptr_race 开发负责人",
            "sustained_goal": "区分测试 harness 语法候选与生产可达、确有并发交错的同对象根因；保持精确源码绑定和 A0 状态。",
            "input": "D38 的 exact source/build 身份、raw CLI 输出及 CR-0091–CR-0096 行映射。",
            "steps": ["追踪 production BUILD inclusion 与可达调用链；不得从 fuzz target 依赖推断生产发布。", "核验同一 shared_ptr 对象的并发读写、任务生命周期及锁/原子/join 同步关系。", "只有复现具体生产源码漏检时才改 detector，并补 positive、fixed、safe、unrelated、renamed、partial controls。", "逐次记录 commit/tree/blob/SHA、scope、profile、rule version、覆盖、耗时和可复跑命令。"],
            "completion_gate": "独立复核产品构建/可达性和同对象重叠未同步访问；证据不足则维持 PARTIAL/BLOCK，不把测试候选升级为产品根因。",
            "boundaries": ["不按 CVE、仓库名、函数名或源码哈希硬编码。", "不改 A0 状态、共享 API、Catalog 或 detector schema。", "不得把零结果或 parser partial 解释为安全。"]}}
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.name}: {len(items)} A0 rows; {len(diags)} source candidates")


if __name__ == "__main__":
    main()

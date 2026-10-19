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
RAW = HERE / "d37_preferences_get_fuzzer_20261024.json"
OUT = HERE / "d37_preferences_get_fuzzer_replay_20261024.json"
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
REPO = "openharmony/distributeddatamgr_preferences"
SRC = "test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferencesget_fuzzer/BUILD.gn"
IDS = [f"CR-{i:04d}" for i in range(66, 91)]


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def binding(path: str) -> dict[str, str | int]:
    blob = git("show", f"{COMMIT}:{path}")
    return {
        "path": path,
        "blob": git("hash-object", "--stdin", data=blob).decode().strip(),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "bytes": len(blob),
    }


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
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 25
    )
    diags = {d["line"]: d for d in run["diagnostics"] if d["file"] == SRC}
    assert len(diags) == 25
    items = []
    for qid in IDS:
        row, jrow = cmap[qid], jmap[qid]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(jrow[key]), (qid, key)
        assert (row["repository"], row["commit"], row["tree"], row["path"]) == (REPO, COMMIT, TREE, SRC)
        assert row["blob"] == src["blob"] and row["source_sha256"].lower() == src["sha256"]
        assert (row["original_status"], row["queue_status"]) == ("not_testable", "paused_pending_evidence")
        diag = diags[int(row["line"])]
        items.append({
            "queue_id": qid, "candidate_id": row["candidate_id"],
            "source": {**src, "repository": REPO, "commit": COMMIT, "tree": TREE, "line": int(row["line"])},
            "original_a0": {"original_status": row["original_status"], "queue_status": row["queue_status"]},
            "replay": {"detector": run["tool"], "version": run["tool_version"], "parse_status": "complete",
                       "coverage": "syntax_candidate", "finding_line": diag["line"], "symbol": diag["symbol"],
                       "rule_id": diag["rule_id"], "diagnostic_id": diag["diagnostic_id"]},
            "disposition": "PARTIAL",
            "reason": "The exact GN target is a test-only fuzz harness. It invokes Preferences APIs sequentially; syntax candidates do not establish overlapping production accesses, product inclusion, reachability or impact.",
            "queue_preserved": True,
        })
    assert {int(cmap[q]["line"]) for q in IDS} == set(diags)
    report = {
        "schema_version": "d37-preferences-get-fuzzer-replay-v1", "task": "D37",
        "source": {"repository": REPO, "commit": COMMIT, "tree": TREE, "file": src},
        "build_target": {"file": build, "target": "ohos_fuzztest(DBPreferencesGetFuzzTest)",
                         "test_group": 'group("fuzztest") [testonly = true]',
                         "harness_entry": "LLVMFuzzerTestOneInput", "production_evidence": False},
        "queue": {"total_rows": 345, "audited_ids": IDS, "a0_status_unchanged": True},
        "cli": {"raw": RAW.name, "detector": run["tool"], "version": run["tool_version"],
                "status": run["status"], "scope_files": run["scope_files"], "scope_loc": run["scope_loc"],
                "parse": raw["source_parsing"]["parsing_status"], "findings": run["diagnostic_count"],
                "command": "python -m src.cli.main ohscan-run --repo-dir <pinned-source-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race"},
        "items": items, "overall_disposition": "PARTIAL",
        "detector_change": "none; all 25 source-bound candidates reproduce in a test-only fuzz file, with no demonstrated product-root miss",
        "queue_states_changed": False,
        "structured_vibe_prompt": {
            "role": "A 线 Preferences shared_ptr_race 开发负责人",
            "sustained_goal": "区分测试 harness 语法候选与生产可达、确有并发交错的同对象根因；保持源码绑定和 A0 队列状态不变。",
            "input": "D37 精确 source/build 身份、当前 CLI 原始输出及 CR-0066–CR-0090 对应行。",
            "steps": ["单独追踪 production BUILD inclusion、调用链和可达性，不以 fuzz target 依赖推断产品发布。", "核验 shared_ptr 同对象读写、线程/任务创建与重叠、锁/原子或 join 的同步关系。", "仅在具体产品源码漏检已复现时改 shared_ptr_race；同时提供 positive、fixed、safe、unrelated、renamed 和 partial controls。", "每次复跑记录 commit/tree/blob/SHA、规则版本、scope、解析覆盖和命令。"],
            "completion_gate": "独立复验精确对象和发现；产品构建/可达性及重叠未同步同对象访问均有证据后才能确认产品根因，否则保留 PARTIAL/BLOCK 并列明缺失项。",
            "boundaries": ["不按 CVE、仓库、函数名或哈希硬编码。", "不把测试 harness 候选提升为产品漏洞。", "不改 A0 状态、共享 API 或 Catalog。"],
        },
    }
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.name}: {len(items)} queue rows; {len(diags)} source candidates")


if __name__ == "__main__":
    main()

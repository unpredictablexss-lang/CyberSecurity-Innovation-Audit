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
RAW = HERE / "d39_preferences_fuzzer_cli_20261024.json"
OUT = HERE / "d39_preferences_fuzzer_replay_20261024.json"
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
SOURCE_ROOT = Path(r"D:\openHarmonyScanner\tmp\d37-preferences-source-20261024")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
REPO = "openharmony/distributeddatamgr_preferences"
SRC = "test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp"
BUILD = "test/native/fuzztest/preferences_fuzzer/BUILD.gn"
IDS = [f"CR-{i:04d}" for i in range(97, 116)]


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def binding(path: str) -> dict[str, str | int]:
    content = git("show", f"{COMMIT}:{path}")
    return {"path": path, "blob": git("hash-object", "--stdin", data=content).decode().strip(),
            "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}


def main() -> None:
    cmd = ["python", "-m", "src.cli.main", "ohscan-run", "--repo-dir",
           SOURCE_ROOT.as_posix(), "--repository", REPO, "--commit", COMMIT,
           "--include", SRC, "--detector", "ohscanner.cpp.shared_ptr_race"]
    subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True)
    generated = ROOT / "outputs/reports/ohscanner_m2.json"
    RAW.write_bytes(generated.read_bytes())
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
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 19)
    diags = {d["line"]: d for d in run["diagnostics"] if d["file"] == SRC}
    assert len(diags) == 19
    source_lines = (SOURCE_ROOT / SRC).read_text(encoding="utf-8").splitlines()
    items = []
    for qid in IDS:
        row, jrow = cmap[qid], jmap[qid]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(jrow[key]), (qid, key)
        assert (row["repository"], row["commit"], row["tree"], row["path"]) == (REPO, COMMIT, TREE, SRC)
        assert row["blob"] == src["blob"] and row["source_sha256"].lower() == src["sha256"]
        assert (row["original_status"], row["queue_status"]) == ("not_testable", "paused_pending_evidence")
        line = int(row["line"])
        diag = diags[line]
        items.append({"queue_id": qid, "candidate_id": row["candidate_id"],
                      "source": {**src, "repository": REPO, "commit": COMMIT, "tree": TREE, "line": line,
                                 "line_text": source_lines[line - 1].strip()},
                      "original_a0": {"original_status": row["original_status"], "queue_status": row["queue_status"]},
                      "replay": {"detector": run["tool"], "version": run["tool_version"], "parse_status": "complete",
                                 "coverage": "syntax_candidate", "finding_line": line, "symbol": diag["symbol"],
                                 "rule_id": diag["rule_id"], "diagnostic_id": diag["diagnostic_id"]},
                      "disposition": "PARTIAL", "queue_preserved": True})
    assert {int(cmap[q]["line"]) for q in IDS} == set(diags)
    build_text = (SOURCE_ROOT / BUILD).read_text(encoding="utf-8")
    assert 'ohos_fuzztest("PreferencesFuzzTest")' in build_text and 'group("fuzztest")' in build_text and "testonly = true" in build_text
    report = {
        "schema_version": "d39-preferences-fuzzer-replay-v1", "task": "D39",
        "source": {"repository": REPO, "commit": COMMIT, "tree": TREE, "file": src},
        "build_target": {"file": build, "target": "ohos_fuzztest(PreferencesFuzzTest)",
                         "test_group": 'group("fuzztest") [testonly = true]',
                         "production_evidence": False},
        "behavior": {"entry": "LLVMFuzzerTestOneInput", "api_sequence": ["SetUpTestCase", "GetAllFuzz", "GetAllDataFuzz", "GetAllDatasFuzz", "DeleteFuzz", "ClearFuzz", "FlushFuzz", "FlushSyncFuzz", "TearDownTestCase"],
                      "thread_creation_or_dispatch_in_entry": False,
                      "interpretation": "All harness calls are sequential in this entry; this does not establish thread behavior inside production Preferences implementation."},
        "queue": {"total_rows": 345, "audited_ids": IDS, "a0_status_unchanged": True},
        "cli": {"raw": RAW.name, "detector": run["tool"], "version": run["tool_version"], "status": run["status"],
                "scope_files": run["scope_files"], "scope_loc": run["scope_loc"],
                "parse": raw["source_parsing"]["parsing_status"], "findings": run["diagnostic_count"],
                "elapsed_seconds": run["elapsed_seconds"], "command": " ".join(cmd)},
        "items": items, "overall_disposition": "PARTIAL",
        "detector_change": "none; all 19 findings correspond to a test-only fuzz harness and no labeled product-root miss was established",
        "queue_states_changed": False,
        "structured_vibe_prompt": {"role": "A 线 Preferences shared_ptr_race 开发负责人",
            "sustained_goal": "区分 fuzz harness 语法候选与产品可达、同一对象存在实际并发重叠的根因；继续按精确来源维护回归证据。",
            "input": "D39 固定 source/build 对象、完整 CLI 原始输出、CR-0097–CR-0115 行映射，以及生产 Preferences 实现和构建依赖。",
            "steps": ["先独立核对 PreferencesFuzzTest 的构建依赖、生产目标入口和发布 profile；不能由 testonly fuzz group 推断产品包含或排除生产实现。", "分别追踪同一 Preferences 实例的读写、析构/重置和任务/回调生命周期，核验锁、原子、线程派发及 join/happens-before。", "只有绑定到已标注产品根因的真实漏检才改 detector；补漏洞、修复、安全、无关、改名和 partial controls，并记录 scope、rule、coverage、耗时。", "由独立测试线复验来源、逐行 finding、产品构建上下文、顺序/并发事实和 A0 阻塞原因；没有证据时保持原 A0 状态。"],
            "completion_gate": "仅在产品入口、同对象并发交错、缺失同步及根因标注都被独立证据支持后讨论产品漏洞闭环；否则维持 PARTIAL/BLOCK。",
            "boundaries": ["不将 fuzz harness 告警自动升级为产品漏洞，也不自动标记为误报。", "不按 CVE、仓库、函数名或源码哈希硬编码；不改 A0 队列。", "不把 parser partial、候选或零结果表述为安全结论。"]}}
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"D39 replay: {len(items)} A0 rows; {len(diags)} source candidates; parse complete")


if __name__ == "__main__":
    main()

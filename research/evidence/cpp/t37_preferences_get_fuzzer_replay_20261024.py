from __future__ import annotations
import csv, hashlib, json, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OBJ = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
REPO = "openharmony/distributeddatamgr_preferences"
SRC = "test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferencesget_fuzzer/BUILD.gn"
IDS = [f"CR-{n:04d}" for n in range(66, 91)]
RAW = HERE / "t37_preferences_get_fuzzer_20261024.json"
OUT = HERE / "t37_preferences_get_fuzzer_replay_20261024.json"

def git(*args, data=None):
    return subprocess.check_output(["git", f"--git-dir={OBJ}", *args], input=data)

def bind(path):
    blob = git("show", f"{COMMIT}:{path}")
    return {"path": path, "blob": git("hash-object", "--stdin", data=blob).decode().strip(),
            "sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob)}

def main():
    csv_path = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    json_path = csv_path.with_name("queue.json")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8-sig", newline="")))
    jrows = json.loads(json_path.read_text(encoding="utf-8"))["queue"]
    cmap, jmap = {r["queue_id"]: r for r in rows}, {r["queue_id"]: r for r in jrows}
    assert len(rows) == len(jrows) == len(cmap) == len(jmap) == 345 and set(cmap) == set(jmap)
    assert git("rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    source, build = bind(SRC), bind(BUILD)
    raw = json.loads(RAW.read_text(encoding="utf-8")); run = raw["detector_runs"][0]
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE and raw["repository"] == REPO
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 25)
    ds = [d for d in run["diagnostics"] if d["file"] == SRC]
    by_line = {d["line"]: d for d in ds}
    assert len(by_line) == 25
    items = []
    for qid in IDS:
        q, jq = cmap[qid], jmap[qid]
        for k in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(q[k]) == str(jq[k]), (qid, k)
        assert (q["repository"], q["commit"], q["tree"], q["path"]) == (REPO, COMMIT, TREE, SRC)
        assert q["blob"] == source["blob"] and q["source_sha256"].lower() == source["sha256"]
        assert (q["original_status"], q["queue_status"]) == ("not_testable", "paused_pending_evidence")
        d = by_line[int(q["line"])]
        items.append({"queue_id": qid, "candidate_id": q["candidate_id"],
          "source": {**source, "repository": REPO, "commit": COMMIT, "tree": TREE, "line": int(q["line"])},
          "original_a0": {"original_status": q["original_status"], "queue_status": q["queue_status"]},
          "replay": {"detector": run["tool"], "version": run["tool_version"], "parse_status": "complete",
            "coverage": "syntax_candidate", "finding_line": d["line"], "symbol": d["symbol"], "rule_id": d["rule_id"], "diagnostic_id": d["diagnostic_id"]},
          "disposition": "PARTIAL", "queue_preserved": True})
    assert {int(cmap[q]["line"]) for q in IDS} == set(by_line)
    report = {"schema_version": "t37-preferences-get-fuzz-independent-audit-v1", "task": "T37",
      "source": {"repository": REPO, "commit": COMMIT, "tree": TREE, "file": source},
      "build_target": {"file": build, "target": "ohos_fuzztest(DBPreferencesGetFuzzTest)",
        "test_group": "group(\"fuzztest\") { testonly = true }", "harness_entry": "LLVMFuzzerTestOneInput", "production_evidence": False},
      "queue": {"total_rows": 345, "audited_ids": IDS, "a0_status_unchanged": True},
      "cli": {"raw": RAW.name, "detector": run["tool"], "version": run["tool_version"], "status": run["status"],
        "scope_files": run["scope_files"], "scope_loc": run["scope_loc"], "parse": raw["source_parsing"]["parsing_status"], "findings": run["diagnostic_count"],
        "command": "python -m src.cli.main ohscan-run --repo-dir <pinned-source-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race"},
      "source_review": {"observed_api_calls": ["PreferencesHelper::GetPreferences", "PutInt/PutString/PutBool/PutFloat/PutDouble/PutLong", "GetValue/GetInt/GetString/GetBool/GetFloat/GetDouble/GetLong", "Preferences::Clear", "PreferencesHelper::RemovePreferencesFromCache"],
        "harness_sequence": "Each LLVMFuzzerTestOneInput calls setup, invokes sequential fuzz helpers on one static shared_ptr, then teardown. No thread creation or parallel dispatch is present in this translation unit.",
        "external_evidence_gaps": ["Whether this fuzz target is included in any shipped product build", "Production call paths and object/thread ownership for these API calls", "Concurrent access to this exact Preferences instance and synchronization protocol", "Attacker-reachable production trigger and security impact"],
        "interpretation": "The testonly GN group and fuzz target establish harness context. They neither prove a product race nor prove a false positive."},
      "items": items, "overall_disposition": "PARTIAL", "detector_change": "none", "queue_states_changed": False,
      "structured_vibe_prompt": {"role": "A 线 Preferences shared_ptr_race 独立开发/审查负责人", "sustained_goal": "持续区分 fuzz harness 语法候选与产品可达、同一对象的未同步并发根因，并保持来源可复现。", "input": "T37 固定来源和 25 条 A0 候选映射；CR-0022–CR-0090 同组件候选族证据。", "steps": ["从生产 BUILD 和真实调用方出发，绑定目标版本与产品构建。", "追踪同一 Preferences 实例的读写、锁/原子保护、线程创建和销毁。", "仅在生产源码中复现遗漏根因后调整规则，并覆盖 positive/fixed/safe/unrelated/renamed/partial。", "结果绑定 commit/tree/blob/SHA、CLI 版本和解析范围，A0 记录保持原样。"], "completion_gate": "独立复跑候选并证明具体生产目标、可达路径和未同步并发访问；否则保持 PARTIAL/BLOCK 并列明缺证。", "boundaries": ["不将 testonly harness 告警称作产品漏洞或误报。", "不修改 A0 状态，不按仓库名、CVE、函数名或哈希硬编码。", "不把 parser partial 或零 finding 当安全证据。"]}}
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.name}: {len(items)} A0 rows; {len(ds)} findings; complete parse")

if __name__ == "__main__": main()

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
SOURCE_REPO = Path(r"D:\openHarmonyScanner\tmp\t43-taihe-source-20261026")
COMMIT = "d91f43e80d892bca694c6b0fce8ea27cd644919f"
TREE = "8c5eecdad09e2fe960ce5f3728959a4726f0a91d"
REPO = "openharmony/arkcompiler_taihe_ffi_gen"
RAW = EVIDENCE / "t43_taihe_ffi_cli_20261026.json"
OUT = EVIDENCE / "t43_taihe_ffi_audit_20261026.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
PATHS = [
    "test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp",
    "test/ra_napi_image/author/include/image_source_taihe.h",
]
IDS = [f"CR-{i:04d}" for i in range(197, 214)]


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(SOURCE_REPO), *args], text=True).strip()


def read_pinned(path: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(SOURCE_REPO), "show", f"{COMMIT}:{path}"])


def identity(path: str) -> dict:
    data = read_pinned(path)
    return {"path": path, "blob": git("rev-parse", f"{COMMIT}:{path}"), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "loc": len(data.decode("utf-8").splitlines())}


def main() -> None:
    with QUEUE.open(encoding="utf-8-sig", newline="") as f:
        all_rows = list(csv.DictReader(f))
    rows = {r["queue_id"]: r for r in all_rows}
    assert len(all_rows) == 345 and len(rows) == 345
    assert git("rev-parse", "HEAD") == COMMIT and git("rev-parse", "HEAD^{tree}") == TREE
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert raw["repository"] == REPO and raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["source_parsing"]["parsing_status"] == {"complete": 2}
    assert run["tool"] == "ohscanner.cpp.shared_ptr_race" and run["tool_version"] == "0.5.1"
    diags = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}
    ids_by_path = {p: [qid for qid in IDS if rows[qid]["path"] == p] for p in PATHS}
    sources = {p: identity(p) for p in PATHS}
    # The root BUILD.gn exists but the test author sources are not referenced by it;
    # the only nested test BUILD files are unrelated integer controls.
    build_path = "BUILD.gn"
    build_identity = identity(build_path)
    root_build = read_pinned(build_path).decode("utf-8")
    source_references = {p: p in root_build for p in PATHS}
    items = []
    for qid in IDS:
        row = rows[qid]
        src = sources[row["path"]]
        assert (row["repository"], row["commit"], row["tree"]) == (REPO, COMMIT, TREE)
        assert row["blob"] == src["blob"] and row["source_sha256"].lower() == src["sha256"]
        assert (row["original_status"], row["queue_status"]) == ("not_testable", "paused_pending_evidence")
        line = int(row["line"])
        text = read_pinned(row["path"]).decode("utf-8").splitlines()[line - 1].strip()
        diag = diags.get((row["path"], line))
        items.append({
            "queue_id": qid, "candidate_id": row["candidate_id"], "path": row["path"], "line": line,
            "source_line": text, "source": {**src, "repository": REPO, "commit": COMMIT, "tree": TREE},
            "a0": {"original_status": row["original_status"], "queue_status": row["queue_status"]},
            "cli": None if diag is None else {"diagnostic_id": diag["diagnostic_id"], "rule_id": diag["rule_id"], "source_sha256": diag["source_sha256"], "symbol": diag.get("symbol"), "evidence_type": diag.get("evidence_type")},
            "mapping": "exact_cli_match" if diag else "no_current_cli_diagnostic_at_A0_location",
            "disposition": "PARTIAL",
        })
    qhash = hashlib.sha256(QUEUE.read_bytes()).hexdigest()
    report = {
        "schema_version": "t43-taihe-ffi-independent-audit-v1", "task": "T43",
        "integration_base": "aacc11729e95d19171fdbf70c30859ce2a05e246",
        "source_identity": {"repository": REPO, "commit": COMMIT, "tree": TREE, "files": sources},
        "build_classification": {
            "searched_scope": ["test/ani_image/author", "test/ra_napi_image/author"],
            "root_build_identity": build_identity,
            "nested_test_build_files": ["test/integer/author/BUILD.gn", "test/integer/user/BUILD.gn"],
            "root_build_references_audited_sources": source_references,
            "result": "BLOCK_product_target_not_bound; root BUILD.gn is Taihe tool build and does not reference audited test files",
            "supporting_source_text": {PATHS[1]: "This file is a test file."},
            "product_build_inclusion_proven": False,
            "note": "The only root BUILD.gn builds Taihe tooling and does not name either audited source; the nested test BUILD files are only under test/integer. No product target/installable source set was bound. The header itself labels itself a test file. Do not infer product exposure or non-exposure from path names alone."
        },
        "cli": {"raw": RAW.name, "detector": run["tool"], "version": run["tool_version"], "status": run["status"], "scope_files": run["scope_files"], "scope_loc": run["scope_loc"], "parse": raw["source_parsing"]["parsing_status"], "finding_count": run["diagnostic_count"], "elapsed_seconds": run["elapsed_seconds"], "command": "python -m src.cli.main ohscan-run --repo-dir D:\\openHarmonyScanner\\tmp\\t43-taihe-source-20261026 --repository openharmony/arkcompiler_taihe_ffi_gen --commit d91f43e80d892bca694c6b0fce8ea27cd644919f --include test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp --include test/ra_napi_image/author/include/image_source_taihe.h --detector ohscanner.cpp.shared_ptr_race"},
        "a0": {"row_count": len(all_rows), "queue_csv_sha256": qhash, "audited_ids": IDS, "queue_states_changed": False},
        "items": items,
        "semantics": [
            "The 16 candidates in ohos.multimedia.image.image.impl.cpp all map to exact current CLI findings. They include PixelMapImpl member initialization, null/reset operations, dereferences and shared ImageSourceImpl member operations; these are lexical shared_ptr observations, not proof of concurrent access to the same object.",
            "Those methods are ordinary synchronous wrapper methods in this file; no thread creation, lock protocol, or cross-thread same-object overlap is established by the reviewed translation unit.",
            "CR-0213 is a header member return (`return navIncPixelMap_;`) and has no current CLI finding at line 57. That is a detector/A0 mapping discrepancy, not evidence of safety; whether copying/reading this shared_ptr overlaps a write remains unknown.",
            "The first translation unit is under ani_image/author and the second header explicitly says it is a test file. Build target inclusion, product configuration, actual callers, thread lifecycle, attacker control, and CIA impact are not established. No trustworthy fixed source or security ground truth is bound for these candidate rows."
        ],
        "limitations": ["No product BUILD.gn target could be located in/above the two author subtrees from the pinned source object.", "No same-object cross-thread overlap or unsynchronized conflicting access is shown by the selected source scope.", "A0 identifiers are candidate observations, not 17 separate races or vulnerabilities; 16 map to CLI diagnostics and one does not.", "There is no trusted fixed source/control pair for this candidate family."],
        "overall_disposition": "PARTIAL/BLOCK", "detector_tests_fixtures_or_A0_modified": False
    }
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = ["# T43 独立测试线：Taihe FFI shared_ptr_race CR-0197–CR-0213", "", f"- 源码身份：`{REPO}` commit `{COMMIT}`，tree `{TREE}`。", f"- 当前 CLI：`{run['tool']} {run['tool_version']}`；两文件解析完整，16 条诊断对应 17 条 A0 记录，耗时 {run['elapsed_seconds']:.4f}s。", "- 16 条位于 `ani_image` 实现文件的记录逐条对应 CLI finding；CR-0213 位于 header 的 getter return，没有当前 finding。该差异不是安全结论。", "- 构建证据：根目录 BUILD.gn 构建 Taihe 工具且不引用这两个源文件；测试目录仅找到无关的 integer BUILD.gn。header 自述为 test file；产品目标未绑定。", "- 同一对象的无同步并发读写、线程重叠、有效产品调用路径及安全影响均未证明。无可信修复源/安全真值。", "- 结论：全部保留 `PARTIAL/BLOCK`；17 条 A0 状态保持 `not_testable / paused_pending_evidence`。不修改 detector、测试、fixtures 或 A0。", "", "| A0 ID | 源位置 | 当前 CLI 映射 | 源码行 |", "|---|---|---|---|"]
    for x in items:
        md.append(f"| {x['queue_id']} | `{x['path']}:{x['line']}` | {x['mapping']}" + (f" `{x['cli']['diagnostic_id']}`" if x['cli'] else "") + f" | `{x['source_line'].replace('|', '&#124;')}` |")
    md += ["", "机器记录：`t43_taihe_ffi_audit_20261026.json`；原始 CLI：`t43_taihe_ffi_cli_20261026.json` / `.md`；验证器：`verify_t43_taihe_ffi_audit_20261026.py`。"]
    (EVIDENCE / "t43_taihe_ffi_audit_20261026.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"PASS T43 evidence built: {len(items)} IDs, {len(diags)} exact findings, {sum(x['cli'] is not None for x in items)} mapped")


if __name__ == "__main__":
    main()

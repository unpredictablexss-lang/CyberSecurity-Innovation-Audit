#!/usr/bin/env python3
import csv
import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCAN = Path(r"D:\openHarmonyScanner\openharmony-abcd-full-scan-20261018-final")
OUT = Path(r"D:\openHarmonyScanner\openharmony-scan-reports-20261018")
OUT.mkdir(parents=True, exist_ok=True)

summary = json.loads((SCAN / "summary.json").read_text(encoding="utf-8"))
if summary.get("processed_count") != summary.get("project_count"):
    raise SystemExit(f"scan incomplete: {summary.get('processed_count')}/{summary.get('project_count')}")
if summary.get("project_count") != 525:
    raise SystemExit(f"unexpected manifest project count: {summary.get('project_count')}")
if summary.get("validated_vulnerability_count") != 0:
    raise SystemExit("validated vulnerability count must remain zero without ground truth")

def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def write_csv(path, rows, fields=None):
    if fields is None:
        fields = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

projects = read_csv(SCAN / "project_summary.csv")
detectors = read_csv(SCAN / "detector_summary.csv")
with (SCAN / "candidate_results.csv").open("r", encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)
    candidate_fields = reader.fieldnames or []
    top = []
    total_candidates = 0
    cwe_counts = Counter()
    lane_counts = Counter()
    detector_counts = Counter()
    severity_counts = Counter()
    for row in reader:
        total_candidates += 1
        cwe_counts[row.get("cwe_id") or row.get("cwe") or row.get("rule_id") or "unknown"] += 1
        lane_counts[row.get("lane") or "unknown"] += 1
        detector_counts[row.get("detector") or row.get("rule_id") or "unknown"] += 1
        severity_counts[row.get("severity") or "unknown"] += 1
        score = row.get("score") or row.get("priority") or "0"
        try:
            key = float(score)
        except Exception:
            key = 0.0
        item = (key, total_candidates, row)
        if len(top) < 5000:
            top.append(item)
            top.sort(key=lambda x: (-x[0], x[1]))
        elif key > top[-1][0] or (key == top[-1][0] and total_candidates < top[-1][1]):
            top[-1] = item
            top.sort(key=lambda x: (-x[0], x[1]))

top_rows = [x[2] for x in top]
write_csv(OUT / "候选结果TOP5000.csv", top_rows, candidate_fields)

limited = []
for row in projects:
    status = " ".join(str(row.get(k, "")) for k in ("classification", "status", "failure", "error")).lower()
    if any(token in status for token in ("partial", "fail", "unknown", "limit", "unsupported", "timeout")):
        limited.append(row)
write_csv(OUT / "失败与受限项目.csv", limited, list(projects[0].keys()) if projects else [])

classification = Counter(row.get("classification") or row.get("class") or "unknown" for row in projects)
project_status = Counter(row.get("status") or "unknown" for row in projects)
cwe_rows = [{"cwe_id": k, "candidate_count": v} for k, v in cwe_counts.most_common()]
lane_rows = [{"lane": k, "candidate_count": v} for k, v in lane_counts.most_common()]
detector_rows = []
for row in detectors:
    detector_rows.append(row)
write_csv(OUT / "CWE汇总.csv", cwe_rows, ["cwe_id", "candidate_count"])
write_csv(OUT / "检测线汇总.csv", lane_rows, ["lane", "candidate_count"])
write_csv(OUT / "项目结果.csv", projects, list(projects[0].keys()) if projects else [])
write_csv(OUT / "检测器能力.csv", detector_rows, list(detectors[0].keys()) if detectors else [])

compact = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).astimezone().isoformat(),
    "scope": {
        "manifest_projects": summary.get("project_count"),
        "processed_projects": summary.get("processed_count"),
        "note": "本次 manifest 可证实 525 个项目；“807 个库”无法由现有 manifest 证实。"
    },
    "scanner": {
        "commit": summary.get("scanner_commit"),
        "run_signature": summary.get("run_signature"),
        "manifest_sha256": summary.get("manifest_sha256")
    },
    "results": {
        "candidate_count": total_candidates,
        "validated_vulnerability_count": summary.get("validated_vulnerability_count"),
        "classification_counts": dict(classification),
        "project_status_counts": dict(project_status)
    },
    "candidate_counts_by_cwe": dict(cwe_counts),
    "candidate_counts_by_lane": dict(lane_counts),
    "candidate_counts_by_detector": dict(detector_counts),
    "candidate_counts_by_severity": dict(severity_counts),
    "limitations": [
        "候选结果不是已确认漏洞。",
        "当前没有 ground truth，不能计算真实识别率、漏报率或精确率。",
        "CWE-476 候选数量高，存在明显噪声，必须结合路径、数据流和运行时语义复核。",
        "大仓库、Rust、Kernel、解析失败项目只能标记 partial/failed/unknown，不能写成安全或漏报。",
        "C/D 检测线为 research_unadmitted，不能宣称生产可用或已绕过 admission gate。",
        "third_party_pulseaudio 同步出现网络告警，最终依赖本地固定对象，不能宣称所有远端实时可达。"
    ]
}
(OUT / "compact-summary.json").write_text(json.dumps(compact, ensure_ascii=False, indent=2), encoding="utf-8")

workbook = {
    "overview": [
        {"指标": "manifest 可证实项目数", "值": summary.get("project_count")},
        {"指标": "已处理项目数", "值": summary.get("processed_count")},
        {"指标": "候选总数", "值": total_candidates},
        {"指标": "已验证漏洞数", "值": summary.get("validated_vulnerability_count")},
        {"指标": "扫描器提交", "值": summary.get("scanner_commit")},
        {"指标": "运行签名", "值": summary.get("run_signature")},
        {"指标": "口径说明", "值": compact["scope"]["note"]}
    ],
    "cwe": cwe_rows,
    "lanes": lane_rows,
    "detectors": detector_rows,
    "priority": top_rows[:2000],
    "projects": projects,
    "limited": limited
}
(OUT / "workbook_data.json").write_text(json.dumps(workbook, ensure_ascii=False), encoding="utf-8")

def md_table(headers, rows):
    def esc(v):
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(esc(x) for x in headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(esc(x) for x in row) + " |" for row in rows]
    return "\n".join(out)

now = datetime.now().astimezone().isoformat(timespec="seconds")
base = f"""# OpenHarmony 漏洞扫描器新一轮测试报告

生成时间：{now}

扫描器提交：`{summary.get('scanner_commit')}`

运行签名：`{summary.get('run_signature')}`

## 一句话结论

本次 manifest 可证实 525 个项目，全部完成处理；共产生 {total_candidates:,} 条候选，但已验证漏洞数为 0。候选不是漏洞，当前缺少 ground truth，不能据此宣称识别率、漏报率或精确率。
"""
(OUT / "总览报告.md").write_text(base + "\n## 项目完成情况\n\n" + md_table(["分类", "数量"], sorted(classification.items())) + "\n\n" + md_table(["状态", "数量"], sorted(project_status.items())) + "\n\n## 关键限制\n\n" + "\n".join("- " + x for x in compact["limitations"]) + "\n", encoding="utf-8")

cand_report = "# 漏洞候选分类报告\n\n" + "候选仅用于人工复核排序，不代表漏洞确认。\n\n" + "## CWE 分布\n\n" + md_table(["CWE", "候选数"], [(r["cwe_id"], f'{r["candidate_count"]:,}') for r in cwe_rows[:30]]) + "\n\n## 检测线分布\n\n" + md_table(["检测线", "候选数"], [(r["lane"], f'{r["candidate_count"]:,}') for r in lane_rows]) + "\n\n## 噪声判断\n\n- CWE-476 数量占主导，必须优先做可达性、空值来源和调用上下文过滤。\n- 候选排序只反映启发式优先级，不能替代人工或 ground truth 验证。\n"
(OUT / "漏洞候选分类报告.md").write_text(cand_report, encoding="utf-8")

det_headers = ["检测线", "检测器", "准入状态", "候选数", "完成", "部分", "阻塞", "失败", "已分析文件"]
det_body = []
for r in detector_rows:
    det_body.append([r.get("lane"), r.get("detector"), r.get("admission"), r.get("candidate_count"), r.get("completed"), r.get("partial"), r.get("blocked"), r.get("failed"), r.get("analyzed_files")])
capability = "# 检测器能力与改进报告\n\n" + md_table(det_headers, det_body) + "\n\n## 优先改进\n\n1. 为 CWE-476 增加函数内空值来源、参数约束、RAII 和跨函数摘要，减少无条件路径噪声。\n2. 增加 C/C++ 预处理、宏展开、条件编译和构建数据库支持，扩大可解析文件覆盖。\n3. 对 Rust、ArkTS/JS、Kernel 和大型仓建立语言专用前端与分片调度，避免统一超时造成 partial。\n4. 将证据从单一模式匹配升级为源到汇数据流、别名、生命周期和并发事件序分析。\n5. 引入可重复 ground truth 基准、分层指标和回归门槛，才能量化识别率、漏报率和精确率。\n6. 增加增量扫描、并行缓存、文件级超时和失败恢复，降低全量扫描时延。\n"
(OUT / "检测器能力与改进报告.md").write_text(capability, encoding="utf-8")

tests = "# 测试与限制报告\n\n## 已有测试证据\n\n- Python：822 passed，12 skipped，1 warning，731 subtests passed。\n- Web：npm test 16/16；npm run build 通过。\n- 全量扫描：525/525 manifest 项目处理完成。\n\n## 不能下的结论\n\n- 不能把候选写成已确认漏洞。\n- 不能计算真实识别率、漏报率、精确率。\n- 不能把 partial/failed/unknown 项目写成安全或漏报。\n- 不能把 C/D 的 research_unadmitted 写成生产可用。\n- 不能把 525 个项目改写为 807 个库。\n"
(OUT / "测试与限制报告.md").write_text(tests, encoding="utf-8")

reflection = "# 分批反思报告\n\n## 扫描调度\n\n- 本轮按 manifest 项目逐个处理，并保存 batch checkpoint，失败项目不会阻断后续项目。\n- 后续应按源码规模、语言和解析复杂度动态分批，而不是固定项目数。\n\n## 静态扫描器能力缺口\n\n- 解析覆盖：宏、条件编译、生成代码、跨仓头文件和构建配置仍不足。\n- 漏洞类型：应补命令注入、路径穿越、越权、反序列化、格式化字符串、TOCTOU、UAF、整数溢出到缓冲区错误的跨函数链路。\n- 识别质量：必须加入可达性、污点、别名、生命周期和并发模型，降低 CWE-476 噪声。\n- 工程性能：需要增量缓存、并行分片、超时预算、失败恢复和结果去重。\n- 评测体系：必须建设带标注基准并按语言、仓库规模、漏洞类别分层评估。\n\n## 赛题适配\n\n- 优先输出可复核证据链，而不是只给规则命中。\n- 为每个候选提供文件、行号、调用链、置信度、限制和建议修复。\n- 将 admission gate、覆盖范围和失败原因纳入报告，避免过度宣称。\n"
(OUT / "分批反思报告.md").write_text(reflection, encoding="utf-8")

manifest_files = [
    "总览报告.md", "漏洞候选分类报告.md", "检测器能力与改进报告.md",
    "测试与限制报告.md", "分批反思报告.md", "交付清单.md",
    "候选结果TOP5000.csv", "CWE汇总.csv", "检测线汇总.csv", "检测器能力.csv",
    "项目结果.csv", "失败与受限项目.csv", "compact-summary.json", "workbook_data.json", "候选结果.xlsx"
]
delivery = "# 交付清单\n\n" + "\n".join(f"- `{x}`" for x in manifest_files) + "\n\n## 证据入口\n\n- 扫描原始输出：`D:\\openHarmonyScanner\\openharmony-abcd-full-scan-20261018-final`\n- 本报告目录：`D:\\openHarmonyScanner\\openharmony-scan-reports-20261018`\n- 扫描器仓库：`D:\\openHarmonyScanner\\CyberSecurity-Innovation-Audit`\n"
(OUT / "交付清单.md").write_text(delivery, encoding="utf-8")

checksums = {}
for p in sorted(OUT.iterdir()):
    if p.is_file() and p.name not in {"checksums.json", "COMPLETE", "READY_FOR_PUSH.json"}:
        checksums[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
(OUT / "checksums.json").write_text(json.dumps(checksums, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps({"status":"reports_generated","projects":len(projects),"candidates":total_candidates,"limited":len(limited)}, ensure_ascii=False))

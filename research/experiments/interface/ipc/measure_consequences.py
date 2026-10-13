"""Measure the consequence dimension of IPC candidates on real components.

The mechanism rules say how a trust boundary fails; the consequence dimension
says what the failure can expose. This script tallies both over production code
of the pinned corpus, so the claim "information disclosure is not confined to one
family" is a measurement rather than an assertion.

The consequence is currently carried in the finding message (the public
`DetectorFinding` has no field for it), so it is read back out of the message.
That is deliberate: if the extraction stops working, the format that downstream
review depends on has changed, and the run should fail loudly rather than
silently report zero.

Usage:
  .venv/bin/python research/experiments/interface/ipc/measure_consequences.py \
      --json outputs/reports/consequence_dimension.json \
      --md   outputs/reports/consequence_dimension.md
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit  # noqa: E402
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector  # noqa: E402
from src.parser.ast import parse_source  # noqa: E402

SOURCE_SUFFIXES = (".cpp", ".cc", ".cxx", ".c", ".h", ".hh", ".hpp", ".inl")
SKIPPED_DIRS = ("/test/", "/unittest/", "/fuzztest/")
DEFAULT_CORPUS = Path.home() / "openharmony-audit" / "perf-corpus"
CONSEQUENCE = re.compile(r"\[([a-z_]+)(?: (CWE-\d+))?\]")


def load_units(component_dir):
    """Units plus the shared AST outline the detector's contract requires.

    The detector refuses to run without `shared_facts["ast"]` and returns
    `blocked` rather than reporting zero findings, so the outline has to be built
    here exactly as the platform front end would.
    """
    units, ast = [], {}
    for path in sorted(component_dir.rglob("*")):
        if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
            continue
        relative = "/" + path.relative_to(component_dir).as_posix()
        if any(marker in relative for marker in SKIPPED_DIRS):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        language = "c" if path.suffix == ".c" else "cpp"
        name = relative.lstrip("/")
        index = parse_source(text, language=language)
        units.append(SourceUnit(name, language, text,
                                hashlib.sha256(text.encode()).hexdigest(), index.parse_status))
        ast[name] = index.to_dict()
    return units, ast


def run_component(component_dir):
    units, ast = load_units(component_dir)
    if not units:
        return None
    request = ScanRequest("consequence-measurement", "local/perf-corpus", "0" * 40,
                          "0" * 64, "current-component:local/perf-corpus")
    context = ScanContext(request, tuple(units), {"ast": ast})
    run = IpcInterfaceDetector().detect(context, tuple(units))
    consequences = Counter()
    pairs = Counter()
    unmatched = 0
    for finding in run.findings:
        found = CONSEQUENCE.search(finding.message)
        if not found:
            unmatched += 1
            continue
        impact, cwe = found.groups()
        consequences[impact + ((" " + cwe) if cwe else "")] += 1
        pairs[(finding.rule_id, impact)] += 1
    return {
        "component": component_dir.name,
        "source_files": len(units),
        "analyzed_files": len(run.analyzed_files),
        "detector_status": run.status,
        "findings": len(run.findings),
        "consequences": dict(sorted(consequences.items())),
        "rule_by_impact": {rule + "|" + impact: count
                           for (rule, impact), count in sorted(pairs.items())},
        "findings_without_a_consequence": unmatched,
    }


def render_markdown(document):
    lines = ["# IPC 候选的后果维度实测", "",
             "> 由 `research/experiments/interface/ipc/measure_consequences.py` 生成。",
             "> 机制规则说信任边界怎么失守；后果维度说可能暴露什么。两者是不同的问题。",
             "> 后果是**可能性**，不是已证明的影响；`validated_vulnerability` 恒为 0。", "",
             "## 逐组件", "",
             "| 组件 | 生产源文件 | 已分析 | 检测器状态 | 候选 | 后果分布 |",
             "|---|---:|---:|---|---:|---|"]
    for row in document["components"]:
        consequences = "、".join(f"{k}:{v}" for k, v in row["consequences"].items()) or "—"
        lines.append(f"| {row['component']} | {row['source_files']} | {row['analyzed_files']} | "
                     f"{row['detector_status']} | {row['findings']} | {consequences} |")
    totals = document["totals"]
    lines += [f"| **合计** | **{totals['source_files']}** | | | **{totals['findings']}** | |", "",
              "## 后果 × 规则（跨子类）", "",
              "同一后果类出现在多少个不同规则上，是「信息泄露不属于某一个子类」的直接证据。", "",
              "| 规则 | 后果 | 候选 |", "|---|---|---:|"]
    for key, count in sorted(document["rule_by_impact"].items()):
        rule, impact = key.split("|", 1)
        lines.append(f"| `{rule}` | {impact} | {count} |")
    lines += ["", "## 汇总", "",
              f"- 后果分布：{json.dumps(document['totals']['consequences'], ensure_ascii=False)}",
              f"- 出现在多个规则上的后果类："
              f"{', '.join(document['totals']['impacts_spanning_rules'])}",
              f"- 未能从消息中取回后果的候选：{document['totals']['findings_without_a_consequence']}"
              "（应为 0；非 0 说明消息格式已变，下游解析需要同步改）",
              "", "## 限制", "",
              "- 后果是**尚未证明的可能性**，由已审查的 API 目录（`DISCLOSURE_CALLS`）与规则基线决定，"
              "不是数据流或可达性结论。",
              "- 目录是版本化的人工审查结果：调用一个读类 API 不等于真的把数据返回给了未授权调用者。",
              "- 后果当前只能从 finding 消息里取回，说明公共 `DetectorFinding` 缺一个字段；"
              "已另提契约变更申请，未擅自改契约。",
              "- 输入是工作副本；组件固定提交见 `docs/research/ipc_scanner_v0_2_entry_coverage_2026-10-10.md`。",
              ""]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--component", action="append", default=[])
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--md", type=Path, default=None)
    args = parser.parse_args()

    names = args.component or sorted(p.name for p in args.corpus.iterdir() if p.is_dir())
    components = []
    for name in names:
        directory = args.corpus / name
        if not directory.is_dir():
            continue
        row = run_component(directory)
        if row is None:
            continue
        components.append(row)
        print(f"{row['component']:38s} files={row['source_files']:5d} "
              f"analyzed={row['analyzed_files']:5d} status={row['detector_status']:9s} "
              f"findings={row['findings']:4d} {row['consequences']}", flush=True)

    totals = Counter()
    rule_by_impact = Counter()
    consequences = Counter()
    for row in components:
        for key in ("source_files", "analyzed_files", "findings", "findings_without_a_consequence"):
            totals[key] += row[key]
        rule_by_impact.update(row["rule_by_impact"])
        consequences.update(row["consequences"])
    impacts_by_rule = {}
    for key in rule_by_impact:
        rule, impact = key.split("|", 1)
        impacts_by_rule.setdefault(impact, set()).add(rule)

    document = {
        "schema_version": 1,
        "experiment_kind": "ipc_consequence_dimension_measurement",
        "corpus": str(args.corpus),
        "validated_vulnerability": 0,
        "components": components,
        "rule_by_impact": dict(sorted(rule_by_impact.items())),
        "totals": {
            "source_files": totals["source_files"],
            "analyzed_files": totals["analyzed_files"],
            "findings": totals["findings"],
            "findings_without_a_consequence": totals["findings_without_a_consequence"],
            "consequences": dict(sorted(consequences.items())),
            "impacts_spanning_rules": sorted(
                f"{impact}({len(rules)})" for impact, rules in impacts_by_rule.items()
                if len(rules) > 1),
        },
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
        print("wrote", args.json)
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(render_markdown(document))
        print("wrote", args.md)


if __name__ == "__main__":
    main()

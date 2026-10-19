"""Machine-readable PoC records and their Markdown rendering.

Everything a PoC claims has to be in the record: which revision was compiled,
with which compiler and sanitizers, what each case did, how the replay behaved,
and what the result does not establish.
"""
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Tuple

from .reachability import ReachabilityEvidence, render_markdown as render_reachability


@dataclass(frozen=True)
class BuildRecord:
    revision: str
    commit: str
    source_sha256: Tuple[str, ...]
    compiler: str
    compiler_version: str
    sanitizers: Tuple[str, ...]
    command: Tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    binary: str

    @property
    def ok(self):
        return self.returncode == 0 and Path(self.binary).is_file()


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    role: str
    args: Tuple[str, ...]
    returncode: int
    signals: Mapping[str, int]
    verdict: str
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RevisionRun:
    revision: str
    commit: str
    state: str
    build: BuildRecord
    cases: Tuple[CaseOutcome, ...]
    replay: Mapping[str, object]
    expectations_met: Mapping[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class PocResult:
    schema_version: int
    family: str
    family_name: str
    harness: str
    root_cause_instance_id: str
    repository: str
    pr_url: str
    reported_symbol: str
    candidate_cwe: str
    environment: Mapping[str, object]
    revisions: Mapping[str, RevisionRun]
    state: str
    evidence_level: str
    validated_vulnerability: int
    limitations: Tuple[str, ...]
    reachability: Optional[ReachabilityEvidence] = None

    def to_dict(self):
        return asdict(self)


def _yes_no(value):
    return "是" if value else "否"


def render_markdown(result):
    env = result.environment
    lines = [
        "# PoC 记录：" + result.family + " " + result.family_name,
        "",
        "> 由 `src/ohscanner/poc` 生成。这是一个**本地隔离执行**记录：目标组件的两个固定修订被原样编译并运行。",
        "> `validated_vulnerability` 恒为 " + str(result.validated_vulnerability) + "；**入口可达性没有被证明**，仍是 EvidenceObligation。",
        "",
        "## 0. 结论",
        "",
        "- 根因实例：`" + result.root_cause_instance_id + "`（" + result.repository + "，[PR](" + result.pr_url + ")）",
        "- 家族：`" + result.family + "` " + result.family_name + "，候选 CWE `" + result.candidate_cwe + "`",
        "- 记录符号：`" + result.reported_symbol + "`",
        "- 生命周期状态：**" + result.state + "**；证据等级：**" + result.evidence_level + "**",
        "",
        "## 1. 环境指纹",
        "",
        "| 项 | 值 |",
        "|---|---|",
        "| 编译器 | `" + str(env.get("compiler")) + "` " + str(env.get("compiler_version")) + " |",
        "| sanitizer | " + ", ".join(env.get("sanitizers", ())) + " |",
        "| 平台 | " + str(env.get("platform")) + " |",
        "| Python | " + str(env.get("python")) + " |",
        "| 源码来源 | " + str(env.get("source_origin")) + " |",
        "",
        "## 2. 逐修订结果",
        "",
        "| 修订 | 固定提交 | 编译 | 状态 | 重放 |",
        "|---|---|---|---|---|",
    ]
    for name, run in result.revisions.items():
        lines.append(
            "| " + name + " | `" + run.commit[:12] + "` | "
            + ("成功" if run.build.ok else "失败") + " | " + run.state + " | "
            + str(run.replay.get("label", "")) + " (" + str(run.replay.get("triggered", 0))
            + "/" + str(run.replay.get("attempts", 0)) + ") |")

    for name, run in result.revisions.items():
        lines += ["", "### " + name + " (`" + run.commit[:12] + "`)", "",
                  "编译命令：", "", "```sh", " ".join(run.build.command), "```", "",
                  "| 用例 | 角色 | 参数 | 观测 | 判定 | 符合预期 |",
                  "|---|---|---|---|---|---|"]
        for case in run.cases:
            signals = " ".join(k + "=" + str(v) for k, v in sorted(case.signals.items()))
            expected = run.expectations_met.get(case.case_id)
            lines.append("| " + case.case_id + " | " + case.role + " | `"
                         + " ".join(case.args) + "` | " + (signals or "—") + " | "
                         + case.verdict + " | " + (_yes_no(expected) if expected is not None else "—")
                         + " |")

    if result.reachability is not None:
        lines += ["", render_reachability(result.reachability)]

    lines += ["", "## 4. 没有证明的事", ""]
    for item in result.limitations:
        lines.append("- " + item)
    lines.append("")
    return "\n".join(lines) + "\n"

#!/usr/bin/env python3
"""Enforce the layered documentation context budget without third-party deps."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


DOC_NAMES = (
    "README.md",
    "项目现状与下一步.md",
    "架构与公共协议.md",
    "开发协作与交付指南.md",
    "面板功能与验收.md",
    "Agent方案与对照实验.md",
)

CHARACTER_BUDGETS = {
    "AGENTS.md": 3500,
    "docs/README.md": 2500,
    "docs/项目现状与下一步.md": 10000,
    "docs/架构与公共协议.md": 5500,
    "docs/开发协作与交付指南.md": 5200,
    "docs/面板功能与验收.md": 2800,
    "docs/Agent方案与对照实验.md": 3000,
}

TOTAL_DOCS_BUDGET = 32500
BASE_CONTEXT_BUDGET = 13500
ARCHIVE_MANIFEST = Path("research/status/2026-10-16/archive-manifest.json")
ARCHIVE_DOCUMENT = Path("research/status/2026-10-16/项目状态完整归档.md")

REQUIRED_HEADINGS = {
    "AGENTS.md": (
        "# OHScanner project instructions",
        "## 上下文路由",
        "## Shared architecture",
        "## Evidence gate",
        "## Competition deliverables",
        "## Development and delivery",
    ),
    "docs/README.md": (
        "# OHScanner：新 Agent 从这里开始",
        "## 何时读取",
        "## 项目边界",
    ),
    "docs/项目现状与下一步.md": (
        "# 项目现状与下一步",
        "## 当前基线",
        "## 已验证能力",
        "## Unknown 与阻塞",
        "## 下一步优先级",
        "## 证据入口",
    ),
    "docs/架构与公共协议.md": (
        "# 架构、模块边界与公共协议",
        "## 何时读取",
        "## 一套内核，多个入口",
        "## 当前实际契约",
        "## 状态、覆盖与证据门",
    ),
    "docs/开发协作与交付指南.md": (
        "# 开发、协作、复现与最终打包",
        "## 何时读取",
        "## 每轮验证",
        "## 团队职责与交付",
        "## 打包交付",
    ),
    "docs/面板功能与验收.md": (
        "# 面板功能与产品验收",
        "## 何时读取",
        "## 当前已实现",
        "## 验收路径",
    ),
    "docs/Agent方案与对照实验.md": (
        "# Agent 方案与可复核对照实验",
        "## 何时读取",
        "## 主实验",
        "## 数据集与真值",
        "## 指标与报告",
    ),
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def count_characters(path: Path) -> int:
    """Count normalized Unicode characters; CRLF and LF have equal weight."""
    return len(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_problems(root: Path) -> list[str]:
    root = root.resolve()
    problems: list[str] = []
    docs_dir = root / "docs"

    if not docs_dir.is_dir():
        return [f"missing directory: {docs_dir}"]

    actual_names = {path.relative_to(docs_dir).as_posix() for path in docs_dir.rglob("*.md")}
    expected_names = set(DOC_NAMES)
    for name in sorted(expected_names - actual_names):
        problems.append(f"missing current guide: docs/{name}")
    for name in sorted(actual_names - expected_names):
        problems.append(f"unexpected Markdown in docs/: {name}")

    lengths: dict[str, int] = {}
    for relative, budget in CHARACTER_BUDGETS.items():
        path = root / relative
        if not path.is_file():
            problems.append(f"missing context file: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            problems.append(f"{relative} is not valid UTF-8: {error}")
            continue

        length = len(text)
        lengths[relative] = length
        if length > budget:
            problems.append(f"{relative} has {length} characters; budget is {budget}")

        lines = set(text.splitlines())
        for heading in REQUIRED_HEADINGS.get(relative, ()):
            if heading not in lines:
                problems.append(f"{relative} is missing required heading: {heading}")

    docs_total = sum(lengths.get(f"docs/{name}", 0) for name in DOC_NAMES)
    if docs_total > TOTAL_DOCS_BUDGET:
        problems.append(
            f"six current guides have {docs_total} characters; budget is {TOTAL_DOCS_BUDGET}"
        )

    base_total = lengths.get("AGENTS.md", 0) + lengths.get("docs/项目现状与下一步.md", 0)
    if base_total > BASE_CONTEXT_BUDGET:
        problems.append(
            f"default context pack has {base_total} characters; budget is {BASE_CONTEXT_BUDGET}"
        )

    manifest_path = root / ARCHIVE_MANIFEST
    archive_path = root / ARCHIVE_DOCUMENT
    if not manifest_path.is_file():
        problems.append(f"missing status archive manifest: {ARCHIVE_MANIFEST}")
    if not archive_path.is_file():
        problems.append(f"missing status archive: {ARCHIVE_DOCUMENT}")

    if manifest_path.is_file() and archive_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            problems.append(f"invalid status archive manifest: {error}")
            manifest = None

        if isinstance(manifest, dict):
            expected_fields = {
                "schema": "ohscanner.status-archive.v1",
                "source_path": "docs/项目现状与下一步.md",
                "archive_path": ARCHIVE_DOCUMENT.as_posix(),
            }
            for key, expected in expected_fields.items():
                if manifest.get(key) != expected:
                    problems.append(
                        f"status archive manifest {key} must be {expected!r}, got {manifest.get(key)!r}"
                    )

            source_hash = manifest.get("source_sha256")
            archive_hash = manifest.get("archive_sha256")
            repository_head = manifest.get("repository_head")
            migrated_at = manifest.get("migrated_at")

            if not isinstance(source_hash, str) or not _SHA256_RE.fullmatch(source_hash):
                problems.append("status archive manifest source_sha256 is not a SHA-256 digest")
            if not isinstance(archive_hash, str) or not _SHA256_RE.fullmatch(archive_hash):
                problems.append("status archive manifest archive_sha256 is not a SHA-256 digest")
            if source_hash != archive_hash:
                problems.append("status archive source and archive hashes differ")
            if archive_hash != _sha256(archive_path):
                problems.append("status archive bytes do not match archive_sha256")
            if not isinstance(repository_head, str) or not _COMMIT_RE.fullmatch(repository_head):
                problems.append("status archive manifest repository_head is not a full Git SHA")
            if not isinstance(migrated_at, str) or not migrated_at.strip():
                problems.append("status archive manifest migrated_at is empty")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root; defaults to the parent of scripts/",
    )
    args = parser.parse_args()
    problems = collect_problems(args.root)
    if problems:
        print("Documentation context budget check failed:")
        for problem in problems:
            print(f"- {problem}")
        return 1

    base_total = count_characters(args.root / "AGENTS.md") + count_characters(
        args.root / "docs/项目现状与下一步.md"
    )
    docs_total = sum(count_characters(args.root / "docs" / name) for name in DOC_NAMES)
    print(
        "Documentation context budget OK: "
        f"default={base_total}/{BASE_CONTEXT_BUDGET}, "
        f"docs={docs_total}/{TOTAL_DOCS_BUDGET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

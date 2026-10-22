PRODUCT_LEVEL_VALIDATOR_IDS = frozenset()
_REMEDIATION_DRAFTS = {
    "CWE-20": "在输入边界显式校验类型、范围、编码与长度，并在进入敏感操作前拒绝不满足约束的值；约束应来自接口契约。",
    "CWE-22": "在访问前规范化并解析目标路径，确认最终路径仍位于授权根目录内；同时明确处理符号链接、路径分隔符和编码差异。",
    "CWE-119": "以实际缓冲区容量校验每次读写，使用溢出安全的长度计算；拒绝越界输入并保留边界值控制测试。",
    "CWE-125": "读取前验证索引及长度不超过实际对象边界，采用溢出安全的范围计算，并覆盖空、末端及超界输入。",
    "CWE-131": "按实际元素宽度和溢出安全的乘加计算分配容量，再验证后续索引/长度与该容量一致。",
    "CWE-362": "统一保护共享状态的所有读写：让每条访问路径使用一致的同步协议，或采用满足全部访问方约束的原子/不可变替换方案；复核锁顺序和对象生命周期。",
    "CWE-416": "让借用指针在最后一次解引用前始终由有效所有权保护；优先使用 RAII 所有权并缩短借用期，若有并发访问则统一生命周期与同步协议。",
    "CWE-441": "在分发远程请求前校验接口身份/描述符及适用的调用权限，并确认每条敏感分支都受同一授权边界约束。",
    "CWE-476": "在解引用前处理空值并定义安全失败路径；如果空值表示无效状态，应在进入敏感操作前终止流程。",
    "CWE-787": "写入前根据目标对象的真实容量验证偏移和长度，并采用溢出安全的边界运算；覆盖恰好边界与越界控制。",
    "CWE-862": "在敏感操作入口执行服务端授权检查，核验调用身份、权限和对象范围，并确保绕过其他调用路径不能直达该操作。",
    "CWE-863": "让授权决策使用正确的主体、动作和资源属性，并对允许/拒绝两侧及边界身份执行控制验证。",
}
_SOURCE_NOT_SUPPLIED = object()
import zipfile
from typing import Literal
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .operations import (approved_url, date_selection, enqueue_branch_comparison, enqueue_range,
                         range_plan, multimode_triage_preview, bind_multimode_triage)
from .source_catalog import (CatalogUnavailable, repository_catalog as public_repository_catalog,
                             repository_preview, validate_commit, validate_branch,
                             validate_preview, validate_repository_slug)
"""Typed local API for long-running operations; every input becomes an immutable plan."""
import hashlib
import html as html_lib
from decimal import Decimal, InvalidOperation
from html import escape as html_escape
from io import BytesIO
import json
import re
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from .download_locations import normalize_download_dir
from .operations import (MAX_SOURCE_SYNC_BATCH_REPOSITORIES, approved_url, date_selection,
                         enqueue_branch_comparison, enqueue_range, range_plan,
                         recent_window_selections, source_sync_preflight)
from .operations_store import Operations, END
from .operation_limits import MAX_DETECTOR_IDS
from .store import now
from . import service
from .agent_guidance import recommend_investigation_route
from .validation_catalog import AUTH_ID, CPP_IDS, catalog as validation_catalog, manifest_path
from .triage_limits import (MAX_MANUAL_CANDIDATES_PER_BATCH, DEFAULT_AGENT_OUTPUT_TOKENS, MAX_TRIAGE_CANDIDATES_PER_ENDPOINT,
                            MAX_AUTOMATIC_TRIAGE_ENDPOINTS)


_MARKDOWN_INLINE_SPECIAL_CHARS = frozenset(chr(92) + "*_{}[]()#+-.!|<>~" + chr(96))


def _markdown_inline_untrusted(value):
    """Render model, source, and reviewer text as one safe Markdown inline value."""
    normalized = " ".join(str(value if value is not None else "").split())
    return "".join(chr(92) + char if char in _MARKDOWN_INLINE_SPECIAL_CHARS else char
                   for char in normalized)


def _case_html_text(value, fallback="未记录"):
    if value is None:
        value = fallback
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return html_lib.escape(str(value), quote=True)


def _case_html_list(values, *, empty="未记录"):
    if not isinstance(values, (list, tuple)) or not values:
        return "<p>" + _case_html_text(empty) + "</p>"
    return "<ul>" + "".join("<li>" + _case_html_text(item) + "</li>" for item in values) + "</ul>"


def _case_is_chinese_narrative(value):
    """Treat prose as Chinese only when Chinese text is not overwhelmed by English."""
    han_count = len(re.findall(r"[\u3400-\u9fff]", value))
    english_word_count = len(re.findall(r"\b[A-Za-z]{3,}\b", value))
    return han_count > 0 and not (english_word_count >= 3 and han_count < english_word_count * 2)


def _case_html_narrative(value):
    """Keep historical English text accessible while making the Chinese report readable."""
    value = str(value if value is not None else "").strip()
    if not value:
        return "未记录"
    if _case_is_chinese_narrative(value):
        return _case_html_text(value)
    return ("<span>该说明主要为英文，已折叠原文；展开可查看完整内容。</span>"
            "<details><summary>查看原文（历史记录）</summary><p>" +
            _case_html_text(value) + "</p></details>")


def _case_html_narrative_list(values, *, empty="未记录"):
    if not isinstance(values, (list, tuple)) or not values:
        return "<p>" + _case_html_text(empty) + "</p>"
    return "<ul>" + "".join("<li>" + _case_html_narrative(item) + "</li>" for item in values) + "</ul>"


def _case_md_narrative(value):
    """Render Chinese report prose and keep unlocalized legacy prose in a safe disclosure."""
    value = str(value if value is not None else "").strip()
    if not value:
        return "未记录"
    if _case_is_chinese_narrative(value):
        return _markdown_inline_untrusted(value)
    return ("该说明主要为英文，已折叠原文；展开可查看完整内容。 "
            "<details><summary>查看原文（历史记录）</summary><pre>" +
            html_lib.escape(value, quote=True) + "</pre></details>")


_CASE_STAGE_LABELS = {
    "completed": "已完成", "running": "进行中", "not_authorized": "未授权",
    "not_applicable_single_shot": "单轮研判模式不适用", "not_run_primary_answer_unavailable": "主研判结果不可用，未生成",
    "incomplete": "未完成", "rejected": "未通过校验", "failed": "失败", "interrupted": "已中断",
    "queued": "排队中", "cancelled": "已取消", "canceled": "已取消",
    "completed_with_limitations": "已完成（存在限制）", "not_started": "尚未开始",
}
_CASE_ARTIFACT_LABELS = {
    "draft_unverified": "已生成，尚未验证", "draft_unexecuted": "草案未执行",
    "insufficient_evidence": "证据不足", "unknown": "未知",
}
_CASE_PLAN_STEP_LABELS = {
    "review_entry": "核对入口与调用链", "define_oracle": "明确测试判定标准",
    "prepare_isolated_harness": "准备隔离测试环境", "compare_controls": "对比候选与安全对照",
    "human_interpretation": "人工解释测试结果",
}
_CASE_TRIAGE_LABELS = {
    "candidate": "候选", "unknown": "未知", "confirmed": "已确认",
    "likely_true_positive": "倾向真实候选", "likely_false_positive": "倾向误报",
    "needs_more_evidence": "需要更多证据", "false_positive": "误报",
    "analysis_failed": "分析失败", "single_shot": "单轮模型研判",
    "tool_agent": "工具增强调查", "evidence_found": "找到相关证据",
    "contrary_evidence": "发现相反证据", "unresolved": "尚未解决",
    "unknown_due_to_unavailable_source": "来源不可用，无法判断",
    "accepted": "已通过结构校验", "rejected": "未通过校验",
    "server_generated_from_structured_triage": "由结构化分诊生成",
    "legacy_model_generated_unverified": "历史模型摘要，未经核验",
    "not_checked": "未核对", "all_accurate": "全部准确",
    "some_incorrect": "部分有误", "mostly_incorrect": "大多有误",
    "useful": "有用", "partially_useful": "部分有用", "not_useful": "无用",
    "unsafe": "有误导风险", "estimated_range": "区间估算",
    "estimated_amount": "金额估算", "not_available": "不可用",
    "unassessed": "未评估", "source_bound_unverified": "已绑定源码，语义未核验",
    "not_started": "尚未开始", "stable_reproduced": "稳定复现",
    "not_run": "未运行", "plan_only": "仅生成计划",
    "draft": "草案", "passed": "通过", "failed": "失败",
    "true": "是", "false": "否",
    "partially_completed": "部分完成", "unverified_by_machine": "机器未核验",
    "unverified_model_advice": "模型建议未核验", "not_attested": "未记录证明",
    "queued": "排队中", "running": "进行中", "completed_with_limitations": "已完成（存在限制）",
    "cancelled": "已取消", "canceled": "已取消", "available": "可用", "unavailable": "不可用",
    "not_passed": "未通过", "not_verified": "未验证", "blocked": "受阻",
    "triggered": "已触发", "not_triggered": "未触发",
    "product_level": "产品级验证", "product_level_verified": "产品可达性已验证",
    "component_harness": "组件级隔离验证", "component_harness_only": "仅完成组件级隔离验证",
    "unverified_model_suggestions": "模型建议未经核验", "unverified_model_suggestion": "模型建议未经核验",
    "model_unverified": "模型意见待核验", "not_applicable_single_shot": "单轮研判模式不适用",
    "not_run_primary_answer_unavailable": "主研判结果不可用，未生成",
    "baseline": "基线版本", "patched": "修复后版本", "vulnerable": "漏洞触发样例",
    "control": "安全对照样例", "negative_control": "负向对照样例",
    "pass": "通过", "fail": "失败", "success": "成功", "error": "错误",
    "not_applicable": "不适用", "not_reproduced": "未复现", "reproduced": "已复现",
    "trigger": "触发", "no_trigger": "未触发", "poc_trigger": "PoC 触发样例",
    "no_token": "未提供令牌的样例", "test": "测试", "positive_control": "正向对照样例",
    "negative": "负向对照样例", "security_control": "安全对照样例",
}


def _case_enum_label(value):
    if value is None:
        return "未知"
    label = _CASE_TRIAGE_LABELS.get(str(value))
    if label:
        return label
    text = str(value)
    if re.search("[㐀-鿿]", text) or text.lstrip("-").replace(".", "", 1).isdigit():
        return text
    return "其他状态（待核对）"


def _case_enum_value(value):
    if isinstance(value, (list, tuple)):
        return "、".join(_case_enum_label(item) for item in value) if value else "未记录"
    if isinstance(value, bool):
        return "是" if value else "否"
    return _case_enum_label(value)



def _case_html_citations(citations):
    if not isinstance(citations, list) or not citations:
        return "<p>未提供引用。</p>"
    rows = []
    for citation in citations:
        if not isinstance(citation, dict):
            continue
        location = _case_html_text(citation.get("file", "未知文件"))
        if citation.get("line_start") is not None:
            location += ":" + _case_html_text(citation.get("line_start"))
            if citation.get("line_end") is not None:
                location += "–" + _case_html_text(citation.get("line_end"))
        evidence_id = _case_html_text(citation.get("evidence_id", "未记录证据 ID"))
        quote = citation.get("quote")
        detail = "<p>" + evidence_id + " · " + location + "</p>"
        if quote:
            detail += "<blockquote>" + _case_html_text(quote) + "</blockquote>"
        rows.append("<li>" + detail + "</li>")
    return "<ul>" + "".join(rows) + "</ul>" if rows else "<p>未提供有效引用。</p>"


def _case_report_html_document(data):
    """Render a self-contained report; every untrusted value is HTML escaped."""
    h = _case_html_text
    case_id = h(data.get("case_id"))
    operations = data.get("operations") if isinstance(data.get("operations"), list) else []
    candidates = data.get("candidates") if isinstance(data.get("candidates"), list) else []
    assessments = data.get("assessments") if isinstance(data.get("assessments"), list) else []
    rows = [
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>OHScanner 调查案例报告</title>",
        "<style>body{font:16px/1.65 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1.25rem;color:#172b4d}h1,h2,h3{line-height:1.3}section,article{margin:1.25rem 0;padding:1rem;border:1px solid #dce3ee;border-radius:10px}pre{overflow:auto;padding:1rem;background:#f4f6fa;border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere}blockquote{margin:.5rem 0;padding:.5rem 1rem;border-left:3px solid #9cb5da;background:#f7f9fc}.boundary{padding:.8rem;background:#fff4e5;border-left:4px solid #e79c22}.muted{color:#65758b}.fact{margin:.45rem 0}</style></head><body><main>",
        "<h1>OHScanner 调查案例报告</h1>",
        "<p>案例：<code>" + case_id + "</code></p>",
        "<p class=\"boundary\">候选和智能调查结论不等于漏洞确认。验证用例（PoC）草案未执行、未验证；组件级隔离测试观察不单独证明产品可达性。</p>",
    ]
    operation_scope = data.get("operation_summaries") or {}
    included = operation_scope.get("included", len(operations))
    total = operation_scope.get("total", len(operations))
    rows.append("<section><h2>操作记录范围</h2><p>展示 " + h(included) + " / " + h(total) + " 条结果。</p>")
    if operation_scope.get("truncated"):
        rows.append("<p class=\"boundary\">尚有 " + h(max(0, total - included)) + " 条操作未展开，不能据此推断它们没有结果。</p>")
    rows.append("</section><section><h2>候选与固定证据</h2>")
    if not candidates:
        rows.append("<p>没有关联候选记录。</p>")
    for row in candidates:
        row = row if isinstance(row, dict) else {}
        candidate = row.get("candidate") if isinstance(row.get("candidate"), dict) else {}
        rows.append("<article><h3>" + h(candidate.get("detector_id")) + " / " + h(candidate.get("rule_id")) + "</h3>")
        rows.append("<p><strong>状态：</strong>候选；影响范围未知</p>")
        rows.append("<p class=\"fact\"><strong>来源：</strong>" + h(row.get("repository")) + " @ " + h(row.get("commit")) + "</p>")
        rows.append("<p class=\"fact\"><strong>位置：</strong>" + h(candidate.get("file")) + ":" + h(candidate.get("line")) + "</p>")
        rows.append("<p class=\"fact\"><strong>报告 SHA-256：</strong><code>" + h(row.get("report_sha256")) + "</code></p>")
        if row.get("rationale"):
            rows.append("<p><strong>案例关联理由：</strong>" + _case_html_narrative(row.get("rationale")) + "</p>")
        rows.append("<h4>人工登记源码证据</h4>")
        evidence_rows = row.get("source_evidence") if isinstance(row.get("source_evidence"), list) else []
        if evidence_rows:
            rows.append("<ul>" + "".join(
                "<li>" + h(item.get("file") or candidate.get("file")) + ":" + h(item.get("start_line")) +
                " · " + _case_html_narrative(item.get("note") or item.get("observation") or "未记录说明") + "</li>"
                for item in evidence_rows if isinstance(item, dict)) + "</ul>")
        else:
            rows.append("<p>尚未登记人工源码证据。</p>")
        review_rows = row.get("reviews") if isinstance(row.get("reviews"), list) else []
        rows.append("<h4>候选复核记录</h4>")
        rendered_reviews = [
            "<li>" + h(_case_enum_label(item.get("status") or "unknown")) + " · " +
            h(item.get("reviewer") or "未知复核人") + " · " +
            _case_html_narrative(item.get("notes") or "未记录说明") + "</li>"
            for item in review_rows if isinstance(item, dict)
        ]
        rows.append("<ul>" + "".join(rendered_reviews) + "</ul>" if rendered_reviews
                    else "<p>尚无候选级人工复核记录。</p>")
        rows.append("</article>")
    rows.append("</section><section><h2>智能调查报告、修复建议与验证用例草案</h2>")
    agent_ops = [item for item in operations if isinstance(item, dict)
                 and item.get("kind") == "agent_investigation" and isinstance(item.get("agent_triage"), dict)]
    if not agent_ops:
        rows.append("<p>当前案例没有绑定的智能调查结果；验证用例（PoC）计划未执行，状态未知。</p>")
    for operation in agent_ops:
        triage = operation["agent_triage"]
        rows.append("<article><h3>智能调查 · " + h(operation.get("id")) + "</h3>")
        generation = triage.get("artifact_generation") if isinstance(triage.get("artifact_generation"), dict) else {}
        if generation:
            rows.append("<p><strong>报告与验证用例草案生成阶段：</strong>" +
                        h(_CASE_STAGE_LABELS.get(generation.get("status"), "状态待核对")) +
                        "；模型调用数 " + h(generation.get("calls_used", "未记录")) +
                        "。此阶段状态不代表扫描完成或漏洞确认。</p>")
        report = triage.get("vulnerability_report") if isinstance(triage.get("vulnerability_report"), dict) else None
        if report:
            rows.append("<h4>漏洞报告草案 · " +
                        h(_CASE_ARTIFACT_LABELS.get(report.get("status"), "状态待核对")) + "</h4>")
            for label, key in (("标题", "title"), ("摘要", "summary"), ("根因", "root_cause"),
                               ("潜在影响", "impact"), ("修复建议", "remediation")):
                if report.get(key):
                    rows.append("<p><strong>" + label + "：</strong>" +
                                _case_html_narrative(report.get(key)) + "</p>")
            for label, key in (("前置条件", "preconditions"), ("攻击路径草案", "attack_path")):
                rows.append("<h5>" + label + "</h5>" + _case_html_narrative_list(report.get(key)))
            rows.append("<h5>报告引用（仅展示智能调查模型提供的引用）</h5>" + _case_html_citations(report.get("citations")))
            rows.append("<p class=\"boundary\">报告内容是智能调查生成的候选 / 未知草案，引用存在不等于语义主张已被证实。</p>")
        else:
            rows.append("<p>未记录结构化漏洞报告草案。</p>")
        guidance = triage.get("repair_guidance") if isinstance(triage.get("repair_guidance"), dict) else {}
        rows.append("<h4>其他修复/验证建议（未经验证）</h4>" +
                    _case_html_narrative_list(guidance.get("items"), empty="没有记录其他建议。"))
        poc = triage.get("poc_draft") if isinstance(triage.get("poc_draft"), dict) else None
        if poc:
            poc_status = poc.get("status") or "unknown"
            rows.append("<h4>验证用例（PoC）计划 · 智能调查草案 · 未执行 · 未验证 · 候选 / 未知</h4>")
            rows.append("<p><strong>草案状态：</strong>" +
                        h(_CASE_ARTIFACT_LABELS.get(poc_status, "状态待核对")) +
                        "；这不是执行结果，也不是漏洞确认。</p>")
            for label, key in (("标题", "title"), ("语言", "language"),
                               ("预期观察", "expected_observation"), ("负向对照", "negative_control")):
                if poc.get(key):
                    rows.append("<p><strong>" + label + "：</strong>" +
                                (h(poc.get(key)) if key == "language" else _case_html_narrative(poc.get(key))) + "</p>")
            for label, key in (("前置条件", "prerequisites"), ("人工执行步骤", "run_steps")):
                rows.append("<h5>" + label + "</h5>" + _case_html_narrative_list(poc.get(key)))
            if poc.get("code"):
                rows.append("<h5>未执行的代码草案</h5><pre><code>" + h(poc.get("code")) + "</code></pre>")
            else:
                rows.append("<p>没有可执行验证用例代码；当前记录为证据不足或草案未提供。</p>")
            rows.append("<h5>验证用例（PoC）草案引用（仅展示智能调查模型提供的引用）</h5>" + _case_html_citations(poc.get("citations")))
        else:
            rows.append("<p class=\"boundary\">未生成验证用例草案；验证计划未执行，当前状态未知。</p>")
        rows.append("</article>")
    rows.append("</section><section><h2>固定隔离测试环境 / 验证记录</h2>")
    validation_ops = [item for item in operations if isinstance(item, dict) and item.get("kind") == "validation"]
    if not validation_ops:
        rows.append("<p>没有验证操作记录；验证用例（PoC）计划与产品影响状态均未知。</p>")
    for operation in validation_ops:
        evidence = operation.get("validation_evidence") if isinstance(operation.get("validation_evidence"), dict) else {}
        rows.append("<article><h3>" + h(evidence.get("harness_id", "隔离测试环境未记录")) + "</h3>")
        rows.append("<p>操作状态：" + h(_case_enum_label(operation.get("status"))) + "；验证门控：" +
                    h(_case_enum_label(operation.get("validation_gate"))) + "；产品可达性：" +
                    h(_case_enum_label(operation.get("reachability_status", "unknown"))) + "；计入确认数：" +
                    h(operation.get("validated_vulnerability", 0)) + "</p>")
        for revision_name, revision in (evidence.get("revisions") or {}).items():
            if not isinstance(revision, dict):
                continue
            build = revision.get("build") if isinstance(revision.get("build"), dict) else {}
            replay = revision.get("replay") if isinstance(revision.get("replay"), dict) else {}
            rows.append("<p>版本 " + h(revision_name) + " @ " + h(revision.get("commit")) +
                        "；构建退出码 " + h(build.get("returncode")) + "；重放 " +
                        h(_case_enum_label(replay.get("label"))) + "；所有案例均符合预期 " +
                        h(_case_enum_label(replay.get("all_cases_match"))) + "</p>")
        rows.append("<p class=\"boundary\">组件级隔离测试观察不单独证明产品入口可达或漏洞已确认。</p></article>")
    rows.append("</section><section><h2>人工案例复核</h2>")
    human_assessments = [item for item in assessments if isinstance(item, dict) and item.get("reviewer_kind") == "human"]
    rendered_assessments = [
        "<li>" + h(item.get("reviewer") or "未知复核人") + " · " +
        h(_case_enum_label(item.get("outcome") or "unknown")) + " · 证据 " +
        h("、".join(item.get("evidence_ids") or [])) + " · 未决项 " +
        _case_html_narrative("；".join(item.get("remaining_unknowns") or [])) + "</li>"
        for item in human_assessments
    ]
    rows.append("<ul>" + "".join(rendered_assessments) + "</ul>" if rendered_assessments
                else "<p>尚无人工案例复核记录。</p>")
    rows.append("<p><strong>经门控确认的漏洞数：</strong>" + h(data.get("validated_vulnerability", 0)) +
                "。候选数、智能调查草案和组件级测试结果不会自动升级漏洞状态。</p></section>")
    rows.append("</main></body></html>")
    return "\n".join(rows)


def _aggregate_agent_budget_cost_estimates(estimates):
    items = list(estimates)
    if items and any(item.get("status") == "unbounded_local_usage"
                     for item in items if isinstance(item, dict)):
        return {"status": "unbounded_local_usage", "hard_spend_cap": False,
                "note": "At least one authorized tool_agent has no local cumulative cost cap; actual charge and quota are controlled by the Provider account.",
                "actual_charge_verified": False}
    if not items or any(not isinstance(item, dict)
                        or item.get("status") != "budget_based_upper_estimate"
                        for item in items):
        return None
    rate_cards = {item.get("rate_card_id") for item in items}
    currencies = {item.get("currency") for item in items}
    sources = {item.get("rate_source_url") for item in items}
    if len(rate_cards) != 1 or len(currencies) != 1 or len(sources) != 1:
        return None
    cny_values = [item.get("maximum_cny") for item in items]
    if any(value is not None for value in cny_values) and any(value is None for value in cny_values):
        return None
    try:
        total = sum((Decimal(item["maximum_usd"]) for item in items), Decimal(0))
        cny_total = (sum((Decimal(value) for value in cny_values), Decimal(0))
                     if all(value is not None for value in cny_values) else None)
    except (KeyError, InvalidOperation, TypeError):
        return None
    if (not total.is_finite() or total < 0
            or (cny_total is not None and (not cny_total.is_finite() or cny_total < 0))):
        return None
    result = {
        "status": "budget_based_upper_estimate",
        "currency": next(iter(currencies)),
        "maximum_usd": format(total.quantize(Decimal("0.00000001")), "f"),
        "rate_card_id": next(iter(rate_cards)),
        "rate_source_url": next(iter(sources)),
        "candidate_or_arm_count": len(items),
        "actual_charge_verified": False,
        "hard_spend_cap": False,
    }
    if cny_total is not None:
        result["maximum_cny"] = format(cny_total.quantize(Decimal("0.00000001")), "f")
        result["alternative_currency"] = "CNY"
    return result


def _smart_operation_retry_available(store, ops, task):
    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    if (task.get("kind") != "agent_investigation" or task.get("status") != "interrupted"
            or task.get("result_sha256") or task.get("cancel_requested")):
        return False
    audit_id, report_sha256 = spec.get("job_id"), spec.get("report_sha256")
    authorization_sha256 = spec.get("triage_authorization_sha256")
    batch_id, candidate_id = spec.get("smart_triage_batch_id"), spec.get("candidate_id")
    if not all(isinstance(value, str) and value for value in
               (audit_id, report_sha256, authorization_sha256, batch_id, candidate_id)):
        return False
    try:
        job = store.job(audit_id)
        authorization = store.triage_authorization(audit_id)
        if (job.get("report_sha256") != report_sha256 or not authorization
                or authorization.get("revoked")
                or authorization.get("consent_sha256") != authorization_sha256
                or ops.triage_cancellation(audit_id, report_sha256)):
            return False
        batch = next((item for item in ops.triage_batches_for_job(audit_id, report_sha256)
                      if item["id"] == batch_id
                      and item["authorization_sha256"] == authorization_sha256), None)
        if batch is None:
            return False
        if spec.get("mode") == "single_shot":
            member_ids = batch["operation_ids"]
            manifest = batch["candidate_manifest"]
        elif spec.get("mode") == "tool_agent":
            member_ids = batch["r2_operation_ids"]
            manifest = batch["r2_candidate_manifest"]
        else:
            return False
        if (task["id"] not in member_ids
                or not any(isinstance(row, dict) and row.get("candidate_id") == candidate_id
                           and row.get("state") == "selected" for row in manifest)):
            return False
        return not any(item["id"] != task["id"]
                       and item["spec"].get("candidate_id") == candidate_id
                       and item["status"] in {"queued", "running"}
                       for item in ops.smart_triage_operations(batch_id))
    except (KeyError, ValueError, TypeError):
        return False

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TaskTriageAuthorization(Strict):
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workflow_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    consent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")



class OfficialRepositoryPreviewRequest(Strict):
    slug: str = Field(min_length=1, max_length=100)

    @field_validator("slug")
    @classmethod
    def valid_slug(cls, value):
        return validate_repository_slug(value)


class OfficialRepositoryImportRequest(Strict):
    slug: str = Field(min_length=1, max_length=100)
    branch: str = Field(min_length=1, max_length=200)
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] | None = Field(default=None, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)
    import_timeout_seconds: int = Field(default=1800, ge=30, le=3600)
    destination_dir: str | None = Field(default=None, max_length=4096)

    @field_validator("slug")
    @classmethod
    def valid_slug(cls, value):
        return validate_repository_slug(value)


class EndpointTriageApproval(Strict):
    """Compatibility input for multi-endpoint approvals; rebound to the full local plan."""
    consent_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    consent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class TaskTriageOptions(Strict):
    audit_mode: Literal["standard_review", "static_only"] = "standard_review"
    auto_triage: bool = False
    max_triage_candidates: int = Field(default=5, ge=1, le=MAX_TRIAGE_CANDIDATES_PER_ENDPOINT)
    max_r2_candidates: int = Field(default=0, ge=0, le=MAX_TRIAGE_CANDIDATES_PER_ENDPOINT)
    max_cost_usd: str | None = Field(default=None, min_length=1, max_length=16,
                                     pattern=r"^\d{1,6}(?:\.\d{1,8})?$")
    triage_authorizations: list[TaskTriageAuthorization] = Field(default_factory=list, max_length=MAX_AUTOMATIC_TRIAGE_ENDPOINTS)
    triage_approvals: list[EndpointTriageApproval] = Field(default_factory=list, max_length=MAX_AUTOMATIC_TRIAGE_ENDPOINTS)

    @model_validator(mode="after")
    def default_r2_for_opted_in_triage(self):
        # Keep static-only/default requests free of conditional R2 authorization.
        # Keep the legacy parsed value for compatibility. Route handlers resolve
        # omitted fields from the current policy before hashing source consent.
        # Preserve model_fields_set so an explicit zero remains distinguishable.
        if "max_r2_candidates" not in self.model_fields_set:
            object.__setattr__(self, "max_r2_candidates", (
                min(3, self.max_triage_candidates) if self.auto_triage else 0
            ))
        return self

    @field_validator("max_cost_usd")
    @classmethod
    def positive_cost_cap(cls, value):
        if value is not None and Decimal(value) <= 0:
            raise ValueError("max_cost_usd must be positive")
        return value


class SyncRequest(Strict):
    repository: str = Field(min_length=13, max_length=112)
    url: str = Field(min_length=16, max_length=300)
    timeout_seconds: int = Field(default=900, ge=10, le=3600)
    scan_after_sync: bool = False
    revision: str = Field(default="HEAD", min_length=1, max_length=200)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] | None = Field(default=None, max_length=MAX_DETECTOR_IDS)
    audit_mode: Literal["standard_review", "static_only"] = "static_only"
    scan_timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)
    destination_dir: str | None = Field(default=None, max_length=4096)

    @field_validator("repository")
    @classmethod
    def valid_repository_name(cls, value):
        prefix = "openharmony/"
        if not value.startswith(prefix):
            raise ValueError("repository must name one OpenHarmony repository")
        validate_repository_slug(value[len(prefix):])
        return value

    @field_validator("url")
    @classmethod
    def valid_repository_url(cls, value):
        approved_url(value)
        return value


class SyncBatchRequest(Strict):
    repositories: list[SyncRequest] = Field(
        min_length=1, max_length=MAX_SOURCE_SYNC_BATCH_REPOSITORIES
    )


class RangeRequest(TaskTriageOptions):
    repository_id: str
    baseline: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    endpoint: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class DateRangeRequest(TaskTriageOptions):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    start: str = Field(min_length=10, max_length=40)
    end: str = Field(min_length=10, max_length=40)
    timezone: str = Field(min_length=1, max_length=100)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class DateRangePreviewRequest(Strict):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    start: str = Field(min_length=10, max_length=40)
    end: str = Field(min_length=10, max_length=40)
    timezone: str = Field(min_length=1, max_length=100)


class MatrixRequest(TaskTriageOptions):
    case_id: str
    repository_id: str
    commits: list[str] = Field(min_length=2, max_length=8)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class JointCandidateComparisonSelectors(Strict):
    matrix_operation_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    recent_window_operation_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    from_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    from_candidate_id: str = Field(min_length=1, max_length=200)
    to_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    to_candidate_id: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def exactly_one_parent_operation(self):
        if (self.matrix_operation_id is None) == (self.recent_window_operation_id is None):
            raise ValueError("provide exactly one matrix_operation_id or recent_window_operation_id")
        return self


class JointCandidateComparisonCreateRequest(JointCandidateComparisonSelectors):
    approved: Literal[True]
    consent_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    expected_consent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: str = Field(min_length=20, max_length=40)


class BranchComparisonRequest(TaskTriageOptions):
    repository_id: str
    baseline_ref: str = Field(min_length=1, max_length=200)
    endpoint_ref: str = Field(min_length=1, max_length=200)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class RecentComparisonRequest(TaskTriageOptions):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    lookback_days: int = Field(default=7, ge=2, le=90)
    reference_time: str = Field(min_length=10, max_length=40)
    timezone: str = Field(default="Asia/Shanghai", min_length=1, max_length=100)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class OperationScanPreviewRequest(Strict):
    kind: Literal["date", "branches", "range", "matrix", "recent"]
    payload: dict[str, Any]


class IntelligentOperationPreviewRequest(Strict):
    kind: Literal["date", "branches", "range", "matrix"]
    payload: dict[str, Any]


class ValidationRequest(Strict):
    case_id: str
    harness_id: Literal["auth01_descriptor_bypass", "cpp_lifetime_unique_ptr_alias", "cpp_shared_ptr_delayed_singleton"]
    target_repository_id: str | None = None
    target_commit: str | None = Field(default=None, min_length=40, max_length=64)
    cutils_repository_id: str | None = None
    cutils_commit: str | None = Field(default=None, min_length=40, max_length=64)
    repeats: int = Field(default=3, ge=3, le=3)
    timeout_seconds: int = Field(default=900, ge=60, le=1800)


class InvestigationRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    max_output_bytes: int = Field(default=65536, ge=1024, le=262144)


class CandidateReviewQueueRequest(Strict):
    job_id: str


class TriageAuthorizationRevocationRequest(Strict):
    consent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProviderCheckRequest(Strict):
    confirm_no_source_request: Literal[True]


class ProviderSettingsRequest(Strict):
    api_protocol: Literal["openai-responses", "openai-chat-completions"] = "openai-responses"
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=200)
    proxy_url: str = Field(default="", max_length=500)
    api_key: str = Field(default="", max_length=4096)


class AgentInvestigationRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    case_id: str | None = Field(default=None, min_length=1, max_length=200)
    experiment_id: str | None = Field(default=None, min_length=1, max_length=64,
                                      pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    mode: Literal["single_shot", "tool_agent"] = "tool_agent"
    max_steps: int = Field(default=4, ge=1, le=12)
    max_output_tokens: int = Field(default=1200, ge=128, le=3000)
    max_total_input_tokens: int = Field(default=128000, ge=1000, le=2_000_000)
    max_total_output_tokens: int = Field(default=4000, ge=512, le=500_000)
    max_total_model_calls: int = Field(default=120, ge=1, le=10_000)
    timeout_seconds: int = Field(default=240, ge=60, le=14_400)
    source_submission_approved: bool = False
    consent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class ProgressiveQuickScreenRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    source_submission_approved: bool = False
    consent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    consent_expires_at: str | None = Field(default=None, max_length=40)


class ProgressiveQuickScreenBatchRequest(Strict):
    audit_operation_id: str = Field(min_length=1, max_length=200)
    source_submission_approved: bool = False
    consent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    consent_expires_at: str | None = Field(default=None, max_length=40)


class ProgressiveDeepInvestigationRequest(AgentInvestigationRequest):
    max_steps: int = Field(default=4, ge=1, le=12)
    progressive_quick_screen_operation_id: str = Field(
        min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    progressive_group_id: str | None = Field(default=None, min_length=1, max_length=200)




class ProgressiveDeepInvestigationBatchRequest(Strict):
    progressive_quick_screen_batch_id: str = Field(
        min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    source_submission_approved: bool = False
    consent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    consent_expires_at: str | None = Field(default=None, max_length=40)


class AgentBatchInvestigationRequest(Strict):
    job_id: str
    candidate_ids: list[str] = Field(min_length=1, max_length=MAX_MANUAL_CANDIDATES_PER_BATCH)
    mode: Literal["single_shot", "tool_agent"] = "tool_agent"
    max_steps: int = Field(default=4, ge=1, le=12)
    max_output_tokens: int = Field(default=1200, ge=128, le=3000)
    max_total_input_tokens: int = Field(default=128000, ge=1000, le=2_000_000)
    max_total_output_tokens: int = Field(default=4000, ge=512, le=500_000)
    max_total_model_calls: int = Field(default=120, ge=1, le=10_000)
    timeout_seconds: int = Field(default=240, ge=60, le=14_400)
    source_submission_approved: bool = False
    consent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class AgentPairedInvestigationRequest(AgentInvestigationRequest):
    experiment_id: str = Field(min_length=1, max_length=64,
                               pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _agent_policy_child_request(body, *, candidate_id, mode, experiment_id=None):
    """Keep validated request identity and copy already resolved system budgets.

    Call only after _agent_policy_request: its validated policy supports values
    (including None and 32768 output tokens) outside legacy HTTP input bounds.
    Revalidating those internal budgets as client input breaks batch and paired
    previews. Copy every budget so preview fingerprints match queued specs.
    """
    child = AgentInvestigationRequest(
        job_id=body.job_id, candidate_id=candidate_id, mode=mode,
        experiment_id=experiment_id, consent_nonce=body.consent_nonce)
    return child.model_copy(update={key: getattr(body, key) for key in (
        "max_steps", "max_output_tokens", "max_total_input_tokens",
        "max_total_output_tokens", "max_total_model_calls", "timeout_seconds")})


class AgentBaselineObligationReview(Strict):
    obligation_index: int = Field(ge=0, le=39, strict=True)
    disposition: Literal["evidence_found", "contrary_evidence", "unresolved"]
    source_line: int | None = Field(default=None, ge=1, strict=True)
    quote: str | None = Field(default=None, min_length=8, max_length=500)
    notes: str = Field(default="", max_length=800)


class AgentStaticReviewSourceRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    start_line: int = Field(ge=1, strict=True)
    line_count: int = Field(default=40, ge=1, le=40, strict=True)


class AgentBaselineSourceRange(Strict):
    start_line: int = Field(ge=1, strict=True)
    end_line: int = Field(ge=1, strict=True)


class AgentBaselineReviewRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    experiment_id: str = Field(min_length=1, max_length=64,
                               pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    reviewer: str = Field(min_length=1, max_length=100)
    disposition: Literal["investigate", "likely_noise", "unknown"]
    elapsed_seconds: int | None = Field(default=None, ge=0, le=7200)
    notes: str = Field(default="", max_length=1200)
    reviewer_acknowledged: bool = False
    obligation_reviews: list[AgentBaselineObligationReview] = Field(default_factory=list, max_length=40)
    source_ranges: list[AgentBaselineSourceRange] = Field(default_factory=list, max_length=20)

class AgentObligationAdjudication(Strict):
    obligation_index: int = Field(ge=0, le=29)
    disposition: Literal["evidence_found", "contrary_evidence", "unresolved"]


class AgentClaimAdjudication(Strict):
    claim_index: int = Field(ge=0, le=29, strict=True)
    disposition: Literal["supported", "partially_supported", "unsupported", "unverifiable"]


class AgentHumanReviewRequest(Strict):
    reviewer: str = Field(min_length=1, max_length=100)
    usefulness: Literal["useful", "partially_useful", "not_useful", "unsafe"]
    citation_accuracy: Literal["all_accurate", "some_incorrect", "mostly_incorrect", "not_checked"]
    claim_adjudications: list[AgentClaimAdjudication] = Field(default_factory=list, max_length=30)
    post_review_disposition: Literal["investigate", "likely_noise", "unknown"] | None = None
    elapsed_seconds: int | None = Field(default=None, ge=0, le=7200)
    claims_to_correct: str = Field(default="", max_length=1200)
    missed_evidence: str = Field(default="", max_length=1200)
    notes: str = Field(default="", max_length=1000)


class AgentBlindSessionRequest(Strict):
    experiment_id: str = Field(min_length=1, max_length=64,
                               pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    operation_ids: list[str] = Field(min_length=2, max_length=20)


class AgentBlindReviewSubmission(AgentHumanReviewRequest):
    blind_item_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    obligation_adjudications: list[AgentObligationAdjudication] = Field(default_factory=list, max_length=30)
    claim_adjudications: list[AgentClaimAdjudication] = Field(default_factory=list, max_length=30)
    guessed_arm: Literal["single_shot", "tool_agent", "unknown"] = "unknown"
    guess_confidence: int | None = Field(default=None, ge=0, le=100)


class AgentBlindReviewImportRequest(Strict):
    reviews: list[AgentBlindReviewSubmission] = Field(min_length=1, max_length=20)


class AgentBlindAgreementRequest(Strict):
    session_ids: list[str] = Field(min_length=2, max_length=10)


class AssessmentRequest(Strict):
    outcome: Literal["candidate", "dynamic_reproduced_component_issue", "confirmed", "reportable",
                     "supports_vulnerability_hypothesis", "supports_false_positive_hypothesis",
                     "unknown", "proposed_confirmation"]
    reviewer_kind: Literal["human", "agent"] = "human"
    reviewer: str = Field(min_length=1, max_length=100)
    notes: str = Field(min_length=1, max_length=8000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    validation_operation_ids: list[str] = Field(default_factory=list, max_length=10)
    remaining_unknowns: list[str] = Field(default_factory=list, max_length=50)


class AgentEvidenceCitation(Strict):
    file: str = Field(min_length=1, max_length=500)
    blob: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    observation: str = Field(min_length=1, max_length=2000)


class AgentProposalRequest(Strict):
    candidate_id: str = Field(min_length=1, max_length=200)
    agent_id: str = Field(min_length=1, max_length=100)
    suggestion: Literal["supports_vulnerability_hypothesis", "supports_false_positive_hypothesis",
                        "unknown", "proposed_confirmation"]
    summary: str = Field(min_length=1, max_length=4000)
    source_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_blob: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    supporting_evidence: list[AgentEvidenceCitation] = Field(default_factory=list, max_length=30)
    refuting_evidence: list[AgentEvidenceCitation] = Field(default_factory=list, max_length=30)
    unresolved_obligations: list[str] = Field(default_factory=list, max_length=50)
    provider: str = Field(min_length=1, max_length=100)
    model_version: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=100)
    tool_version: str = Field(min_length=1, max_length=100)
    run_id: str = Field(min_length=1, max_length=100)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    duration_ms: int | None = Field(default=None, ge=0)



_TRIAGE_SUCCESS_STATUSES = {"completed", "completed_with_limitations"}
_TRIAGE_FAILURE_STATUSES = {"failed", "timed_out", "interrupted", "blocked"}
_TRIAGE_TERMINAL_STATUSES = _TRIAGE_SUCCESS_STATUSES | _TRIAGE_FAILURE_STATUSES | {"cancelled"}


def _operation_phase_progress(records, *, phase_state=None):
    """Summarize a fixed R1/R2 operation set without treating failures as completion."""
    statuses = [str(item.get("status") or "unknown") for item in records]
    counts = {}
    for status in statuses:
        counts[status] = counts.get(status, 0) + 1
    completed = counts.get("completed", 0)
    completed_with_limitations = counts.get("completed_with_limitations", 0)
    success = completed + completed_with_limitations
    failed = sum(counts.get(status, 0) for status in _TRIAGE_FAILURE_STATUSES)
    cancelled = counts.get("cancelled", 0)
    queued, running = counts.get("queued", 0), counts.get("running", 0)
    reasons = [
        {"operation_id": item.get("id"), "candidate_id": item.get("spec", {}).get("candidate_id"),
         "status": item.get("status"), "reason": item.get("error") or item.get("status")}
        for item in records if item.get("status") in _TRIAGE_FAILURE_STATUSES | {"cancelled"}
    ]
    if running:
        state = "running"
    elif queued:
        state = "queued"
    elif not records:
        state = phase_state or "not_triaged"
    elif failed and not success and not cancelled and all(status in _TRIAGE_TERMINAL_STATUSES for status in statuses):
        state = "failed"
    elif cancelled and not success and not failed and all(status in _TRIAGE_TERMINAL_STATUSES for status in statuses):
        state = "cancelled"
    elif success and (failed or cancelled or not all(status in _TRIAGE_SUCCESS_STATUSES for status in statuses)):
        state = "partially_completed"
    elif all(status in _TRIAGE_SUCCESS_STATUSES for status in statuses):
        state = "completed_with_limitations" if completed_with_limitations else "completed"
    elif failed:
        state = "failed"
    else:
        state = phase_state or "not_triaged"
    return {
        "state": state, "operation_count": len(records), "status_counts": counts,
        "queued_count": queued, "running_count": running, "completed_count": completed,
        "completed_with_limitations_count": completed_with_limitations,
        "failed_count": failed, "cancelled_count": cancelled,
        "timed_out_count": counts.get("timed_out", 0),
        "interrupted_count": counts.get("interrupted", 0),
        "blocked_count": counts.get("blocked", 0),
        "failure_reasons": reasons,
    }


def _classify_intelligent_review(batch, r1_records, r2_records, *, revoked=False):
    candidate_count = int(batch.get("candidate_count") or 0)
    selected_count = int(batch.get("selected_count") or 0)
    r2_state = batch.get("r2_status", "not_requested")
    r1 = _operation_phase_progress(r1_records)
    r2 = _operation_phase_progress(r2_records, phase_state=r2_state)
    all_records = [*r1_records, *r2_records]
    if revoked:
        state = "revoked"
    elif batch.get("status") == "candidate_limit_exceeded":
        state = "candidate_limit_exceeded"
    elif batch.get("status") == "queue_limit_exceeded":
        state = "queue_limit_exceeded"
    elif batch.get("status") == "blocked_authorization_changed":
        state = "authorization_changed"
    elif batch.get("status") == "no_eligible_candidates" or candidate_count == 0:
        state = "no_eligible_candidates"
    elif any(item.get("status") == "running" for item in all_records):
        state = "running"
    elif any(item.get("status") == "queued" for item in all_records) or r2_state == "awaiting_r1":
        state = "queued"
    elif not all_records:
        state = "not_triaged" if candidate_count else "no_eligible_candidates"
    else:
        successes = sum(item.get("status") in _TRIAGE_SUCCESS_STATUSES for item in all_records)
        failures = sum(item.get("status") in _TRIAGE_FAILURE_STATUSES for item in all_records)
        cancellations = sum(item.get("status") == "cancelled" for item in all_records)
        full_coverage = selected_count >= candidate_count
        all_success = all(item.get("status") in _TRIAGE_SUCCESS_STATUSES for item in all_records)
        if all_success and full_coverage and r2_state not in {
            "candidate_limit_reached", "failed_selection", "queue_limit_exceeded"
        }:
            state = ("completed_with_limitations"
                     if any(item.get("status") == "completed_with_limitations" for item in all_records)
                     else "completed")
        elif successes:
            state = "partially_completed"
        elif failures:
            state = "failed"
        elif cancellations:
            state = "cancelled"
        else:
            state = "not_triaged"
    return {"state": state, "r1": r1, "r2": r2,
            "candidate_count": candidate_count, "authorized_candidate_count": selected_count,
            "not_triaged_count": max(0, candidate_count - selected_count),
            "r2_status": r2_state}


def _operation_scan_plan(settings, store, kind, body):
    """Resolve operation inputs to immutable scan plans before queue insertion."""
    mode = body.audit_mode
    if kind in {"range", "date"}:
        if kind == "date":
            selection = date_selection(settings, store, body.repository_id, body.branch,
                                       body.start, body.end, body.timezone)
            baseline, endpoint = selection["baseline"], selection["endpoint"]
        else:
            selection = None
            baseline, endpoint = body.baseline, body.endpoint
        repo, before, after, commits = range_plan(settings, store, body.repository_id,
            baseline, endpoint, body.include_paths, body.detector_ids,
            body.timeout_seconds, body.memory_mb)
        scans = [{**before, "audit_mode": mode}, {**after, "audit_mode": mode}]
        spec = {"repository_id": repo["id"], "baseline": before["commit"],
            "endpoint": after["commit"], "commits": commits, "audit_mode": mode,
            "timeout_seconds": body.timeout_seconds * 2 + 60, "memory_mb": body.memory_mb,
            "date_selection": selection}
        return "time_incremental_scan" if selection is not None else "revision_range", repo, spec, scans
    if kind == "branches":
        repo = store.repository(body.repository_id)
        service.check_repository(settings, repo["path"])
        before = service.revision(repo, body.baseline_ref)
        after = service.revision(repo, body.endpoint_ref)
        if before["commit"] == after["commit"]:
            raise ValueError("branch comparison refs must resolve to different commits")
        scans = [service.make_spec(repo, item["commit"], body.include_paths, body.detector_ids,
                                  body.timeout_seconds, body.memory_mb)
                 for item in (before, after)]
        scans = [{**scan, "audit_mode": mode} for scan in scans]
        spec = {"repository_id": repo["id"], "audit_mode": mode,
            "baseline_ref": body.baseline_ref, "baseline": before["commit"],
            "endpoint_ref": body.endpoint_ref, "endpoint": after["commit"],
            "timeout_seconds": body.timeout_seconds * 2 + 60, "memory_mb": body.memory_mb}
        return "branch_comparison", repo, spec, scans
    if kind == "matrix":
        if len(set(body.commits)) != len(body.commits):
            raise ValueError("version matrix commits must be unique")
        if any(not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", item) for item in body.commits):
            raise ValueError("version matrix requires complete lowercase Git object IDs")
        with store.connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (body.case_id,)).fetchone():
                raise KeyError("case not found")
        repo = store.repository(body.repository_id)
        service.check_repository(settings, repo["path"])
        links = _case_links(store, body.case_id)
        if not any(store.repository(store.job(link["job_id"])["repository_id"])["name"] == repo["name"] for link in links):
            raise ValueError("version matrix case must already link a candidate from the selected repository")
        scans = [service.make_spec(repo, sha, body.include_paths, body.detector_ids,
                                   body.timeout_seconds, body.memory_mb) for sha in body.commits]
        scans = [{**scan, "audit_mode": mode} for scan in scans]
        spec = {"case_id": body.case_id, "repository_id": repo["id"], "audit_mode": mode,
            "commits": [scan["commit"] for scan in scans],
            "timeout_seconds": body.timeout_seconds * len(scans) + 120,
            "memory_mb": body.memory_mb}
        return "version_matrix", repo, spec, scans
    if kind == "recent":
        selection = recent_window_selections(settings, store, body.repository_id, body.branch,
            body.lookback_days, body.reference_time, body.timezone)
        repo = store.repository(body.repository_id)
        service.check_repository(settings, repo["path"])
        windows = (selection["long_window"], selection["one_day_window"])
        scans = []
        for window in windows:
            for revision in (window["baseline"], window["endpoint"]):
                scan = service.make_spec(repo, revision, body.include_paths, body.detector_ids,
                                         body.timeout_seconds, body.memory_mb)
                scans.append({**scan, "audit_mode": mode})
        spec = {"repository_id": repo["id"], "branch": body.branch,
            "lookback_days": body.lookback_days, "reference_time": selection["reference_time"],
            "timezone": body.timezone, "windows": [selection["long_window"], selection["one_day_window"]],
            "audit_mode": mode, "timeout_seconds": body.timeout_seconds * 4 + 120,
            "memory_mb": body.memory_mb,
            "limitations": ["Each window scans its fixed baseline and endpoint; commits inside the interval are not individually scanned.",
                            "Candidate deltas do not establish vulnerability introduction, remediation, or affected product versions."]}
        return "recent_window_comparison", repo, spec, scans
    raise ValueError("unsupported scan operation preview")


def _prepare_operation_triage(settings, body, scan_specs, *, authorization_inputs=None):
    """Attach per-endpoint consent snapshots only after matching a fresh preview."""
    from .progressive_triage.policy import PolicyStore
    policy_state = PolicyStore(settings.data_dir).read()
    policy_snapshot = {"revision": policy_state["revision"],
                       "policy": policy_state["policy"],
                       "policy_sha256": policy_state["policy_sha256"]}

    def with_policy(scan):
        return {**scan, "progressive_triage_policy": policy_snapshot}

    from .progressive_triage.policy import apply_task_candidate_scope
    apply_task_candidate_scope(body, policy_snapshot["policy"])
    mode = body.audit_mode
    enabled = body.auto_triage
    if body.max_r2_candidates > body.max_triage_candidates:
        raise ValueError("conditional R2 candidate budget cannot exceed the R1 candidate budget")
    if body.max_r2_candidates and not enabled:
        raise ValueError("conditional R2 requires task-level automatic triage authorization")
    if enabled and mode != "standard_review":
        raise ValueError("automatic triage requires standard review mode")
    supplied = authorization_inputs if authorization_inputs is not None else body.triage_authorizations
    approvals = [item.model_dump() for item in body.triage_approvals]
    if approvals and supplied:
        raise ValueError("submit either endpoint approvals or bound authorizations, not both")
    if not enabled:
        if supplied or approvals:
            raise ValueError("triage authorizations cannot be submitted unless automatic triage was selected")
        prepared = []
        for scan in scan_specs:
            workflow = service.audit_workflow_sha256(scan["plan_sha256"], mode)
            prepared.append(with_policy({**scan, "audit_mode": mode, "max_r2_candidates": 0,
                "max_cost_usd": body.max_cost_usd, "workflow_sha256": workflow,
                "workflow": service.audit_workflow_summary(mode)}))
        return prepared
    if not isinstance(supplied, list) or len(supplied) != len(scan_specs):
        if approvals:
            if len(approvals) != len(scan_specs):
                raise ValueError("every fixed endpoint requires a separately reviewed model-egress preview")
            preview = _preview_operation_triage(
                settings, body, scan_specs,
                consent_nonces=[item["consent_nonce"] for item in approvals],
            )
            bound = []
            for item, approval, endpoint in zip(scan_specs, approvals, preview["scans"]):
                if approval["consent_sha256"] != endpoint["consent_sha256"]:
                    raise ValueError("endpoint consent expired or changed; review a fresh preview")
                bound.append({"plan_sha256": endpoint["plan_sha256"],
                              "workflow_sha256": endpoint["workflow_sha256"],
                              "consent_sha256": endpoint["consent_sha256"],
                              "consent_nonce": endpoint["consent_nonce"]})
            supplied = bound
        else:
            raise ValueError("every fixed endpoint requires a separately reviewed model-egress preview")
    from .agent import ProviderConfig, audit_task_consent_preview
    provider = ProviderConfig.from_env(settings.data_dir)
    prepared = []
    for scan, raw in zip(scan_specs, supplied):
        authorization = raw.model_dump() if isinstance(raw, TaskTriageAuthorization) else raw
        workflow = _progressive_workflow_sha256(
            service.audit_workflow_sha256(scan["plan_sha256"], mode, True,
                body.max_triage_candidates, body.max_r2_candidates), policy_snapshot["policy_sha256"])
        if (authorization.get("plan_sha256") != scan["plan_sha256"]
                or authorization.get("workflow_sha256") != workflow):
            raise ValueError("multi-endpoint model authorization no longer matches the fixed scan plan")
        preview = audit_task_consent_preview(scan["audit_plan"], workflow,
            scan["include_paths"], body.max_triage_candidates,
            authorization.get("consent_nonce"), provider,
            body.max_r2_candidates, max_cost_usd=body.max_cost_usd,
            system_policy_snapshot=policy_snapshot)
        if (not preview.get("eligible")
                or preview.get("consent_sha256") != authorization.get("consent_sha256")):
            raise ValueError("model-egress preview expired or changed; review a fresh preview")
        prepared.append(with_policy({**scan, "audit_mode": mode, "max_r2_candidates": body.max_r2_candidates,
            "max_cost_usd": body.max_cost_usd, "workflow_sha256": workflow,
            "workflow": service.audit_workflow_summary(mode, True,
                body.max_triage_candidates, body.max_r2_candidates),
            "triage_authorization": {"authorized": True,
                "consent_sha256": preview["consent_sha256"], "snapshot": preview["manifest"]}}))
    return prepared


def _progressive_workflow_sha256(base_workflow_sha256, policy_sha256):
    import hashlib
    import json
    return hashlib.sha256(json.dumps({
        "base_workflow_sha256": base_workflow_sha256,
        "progressive_policy_sha256": policy_sha256,
        "progressive_workflow_version": "progressive-triage-v1",
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _preview_operation_triage(settings, body, scan_specs, *, consent_nonces=None):
    from .progressive_triage.policy import PolicyStore
    policy_state = PolicyStore(settings.data_dir).read()
    policy_snapshot = {"revision": policy_state["revision"],
                       "policy": policy_state["policy"],
                       "policy_sha256": policy_state["policy_sha256"]}
    from .progressive_triage.policy import apply_task_candidate_scope
    apply_task_candidate_scope(body, policy_snapshot["policy"])
    if not body.auto_triage:
        return {"eligible": False, "model_calls": 0,
                "progressive_policy": policy_snapshot,
                "scans": [{"commit": scan["commit"], "plan_sha256": scan["plan_sha256"]}
                          for scan in scan_specs],
                "message": "No model source egress is authorized; endpoint scans remain static."}
    if body.audit_mode != "standard_review":
        raise ValueError("automatic triage is only available in standard review mode")
    if body.max_r2_candidates > body.max_triage_candidates:
        raise ValueError("conditional R2 candidate limit cannot exceed R1 candidate limit")
    from .agent import ProviderConfig, audit_task_consent_preview
    provider = ProviderConfig.from_env(settings.data_dir)
    if consent_nonces is None:
        consent_nonces = [uuid.uuid4().hex for _ in scan_specs]
    if len(consent_nonces) != len(scan_specs):
        raise ValueError("consent nonce count does not match fixed endpoint count")
    previews = []
    for scan, nonce in zip(scan_specs, consent_nonces):
        workflow = _progressive_workflow_sha256(
            service.audit_workflow_sha256(scan["plan_sha256"], body.audit_mode, True,
                body.max_triage_candidates, body.max_r2_candidates), policy_snapshot["policy_sha256"])
        preview = audit_task_consent_preview(scan["audit_plan"], workflow,
            scan["include_paths"], body.max_triage_candidates, nonce,
            provider, body.max_r2_candidates, max_cost_usd=body.max_cost_usd,
            system_policy_snapshot=policy_snapshot)
        if not preview.get("eligible"):
            raise ValueError("automatic triage cannot be authorized: " + preview.get("reason", "provider unavailable"))
        source_binding = ((scan.get("audit_plan") or {}).get("source") or {})
        previews.append({"commit": scan["commit"], "tree": scan.get("git_tree") or source_binding.get("git_tree"),
            "plan_sha256": scan["plan_sha256"], "workflow_sha256": workflow,
            **preview})
    aggregate = _aggregate_agent_budget_cost_estimates(item.get("estimated_cost") for item in previews)
    return {"eligible": True, "model_calls": None,
            "progressive_policy": policy_snapshot,
            "per_endpoint_candidate_scope": True, "aggregate_estimated_cost": aggregate,
            "scans": previews,
            "consent_required": "Review each source-egress manifest and submit each nonce and digest with the operation. Candidate counts remain bounded by authorization; no platform cumulative token/USD/call/total-time cap is applied. Provider billing and quota apply."}


def _case_links(store, case_id):
    with store.connect() as db:
        return [dict(x) for x in db.execute("SELECT * FROM case_links WHERE case_id=? ORDER BY job_id,candidate_id", (case_id,))]


def _case_review_status(settings, store, ops, case_id):
    assessments = ops.assessments(case_id)
    human_assessments = [item for item in assessments if item.get("reviewer_kind") == "human"]
    latest = human_assessments[-1] if human_assessments else None
    links = _case_links(store, case_id)
    single_candidate = len({(item["job_id"], item["candidate_id"]) for item in links}) == 1
    valid_evidence_ids = {item["id"] for link in links
                          for item in store.source_evidence(link["job_id"], link["candidate_id"])}
    validated_by = None
    # The latest human decision controls current case status. An older confirmation
    # must not survive a later append-only candidate/unknown/refutation assessment.
    assessment = latest
    if (single_candidate and assessment and assessment.get("outcome") in {"confirmed", "reportable"}
            and assessment.get("evidence_ids")
            and assessment.get("remaining_unknowns")
            and set(assessment["evidence_ids"]).issubset(valid_evidence_ids)):
        for operation_id in assessment.get("validation_operation_ids", []):
            if _product_validation_is_bound(settings, store, ops, case_id, operation_id):
                validated_by = {
                    "assessment_id": assessment.get("id"),
                    "validation_operation_id": operation_id,
                    "outcome": assessment["outcome"],
                }
                break
    return {
        "latest_human_assessment": latest,
        "validated_vulnerability": 1 if validated_by else 0,
        "validated_by": validated_by,
        "assessment_count": len(assessments),
    }



def _validated_cases_for_audit(store, ops, audit_id):
    confirmed = []
    for case in store.cases():
        linked = [item for item in case.get("links", []) if item.get("job_id") == audit_id]
        if not linked:
            continue
        status = _case_review_status(settings, store, ops, case["id"])
        if status["validated_vulnerability"]:
            confirmed.append({
                "case_id": case["id"],
                "candidate_ids": sorted({item["candidate_id"] for item in linked}),
                "validation_basis": status["validated_by"],
            })
    return confirmed


def _combined_audit_report_markdown(document):
    md = _markdown_inline_untrusted
    scan = document["scan"]
    risks = document["risk_snapshot"]
    triage = document["triage"]
    authorization = triage.get("authorization") or {}
    cost_budget = authorization.get("cost_budget") or {}
    rows = [
        "# OHScanner 智能安全审计报告",
        "",
        "- 报告快照：`" + md(document["report_snapshot_id"]) + "`",
        "- 快照 SHA-256：`" + md(document["report_snapshot_sha256"]) + "`",
        "- 静态原始报告 SHA-256：`" + md(scan["report_sha256"]) + "`",
        "- 仓库版本：" + md(scan["repository"]) + " @ `" + md(scan["commit"]) + "`",
        "- Tree：`" + md(scan["tree"]) + "`",
        "- 静态扫描：" + md(_case_enum_label(scan["status"])) + "；智能研判：" + md(_case_enum_label(triage["state"])),
        "- 漏洞确认数：" + str(document["validated_vulnerability"]),
        "- 模型费用：" + ("平台不设累计费用上限；实际计费与配额由模型服务商账户决定" if cost_budget else "未授权自动模型研判"),
        "",
        "## 风险分层",
        "",
        "| 层级 | 数量 |",
        "|---|---:|",
    ]
    labels = {
        "high_confidence_candidate": "高可信风险候选（仍为待复核候选）",
        "further_validation": "待进一步验证",
        "low_priority_manual": "低优先级线索（人工标记，不代表安全）",
        "unknown_source_binding": "来源绑定未知",
    }
    for tier, label in labels.items():
        rows.append("| " + md(label) + " | " + str(risks["counts"].get(tier, 0)) + " |")
    rows.extend(["", "## 优先候选", ""])
    all_risk_items = risks.get("items", [])
    all_risk_items = all_risk_items if isinstance(all_risk_items, list) else []
    selected = all_risk_items[:20]
    tier_total = sum(int(value or 0) for value in risks.get("counts", {}).values())
    declared_total = risks.get("candidate_observation_count")
    risk_total = max(len(all_risk_items), tier_total,
                     declared_total if isinstance(declared_total, int) and not isinstance(declared_total, bool) else 0)
    if risk_total > len(selected):
        rows.append("> 风险分层统计覆盖 " + str(risk_total) + " 条候选观测；本节仅展示前 " +
                    str(len(selected)) + " 条明细，另有 " + str(risk_total - len(selected)) +
                    " 条明细未展开。未展开项仍属于本快照，不能据此推断其没有风险。")
        rows.append("")
    if not selected:
        if risk_total:
            rows.append("当前快照未包含候选明细；风险分层统计仍记录 " + str(risk_total) +
                        " 条候选观测，不能将明细缺失理解为没有候选。")
        else:
            rows.append("当前没有静态候选；这不表示整个仓库无漏洞。")
    for item in selected:
        rows.extend([
            "### " + md(item.get("risk_tier_label")) + " — "
            + md(item.get("detector_id")) + " / " + md(item.get("rule_id")),
            "",
            "- 候选：`" + md(item.get("candidate_id")) + "`",
            "- 位置：" + md(item.get("file")) + ":" + md(item.get("line")),
            "- 源码 SHA-256：`" + md(item.get("source_sha256")) + "`",
            "- 研判状态：" + md(_case_enum_label(item.get("triage", {}).get("state"))),
            "- 状态边界：当前仍为候选；该分层不代表漏洞已确认。",
            "- 原因：" + _case_md_narrative("；".join(item.get("reasons", []))),
            "",
        ])
    rows.extend(["## 覆盖与限制", ""])
    rows.append("静态文件解析统计：" + md(json.dumps(document["coverage"].get("source_parsing", {}), ensure_ascii=False, sort_keys=True)))
    for limitation in document.get("limitations", []):
        rows.append("- " + _case_md_narrative(limitation))
    rows.extend([
        "",
        "> 模型研判是候选调查建议。模型自报置信度和引文存在性均不构成漏洞确认；只有现有人工评估与通过的运行时可达性门才能增加已确认漏洞数。",
        "",
    ])
    return "\n".join(rows)


def _blind_packet(result):
    """Create a review packet without arm/provider identifiers or raw operation metadata."""
    initial = result.get("initial_evidence") or {}
    context = initial.get("context") or {}
    assessment = result.get("agent_assessment") or {}
    if not context.get("source_excerpt") or not isinstance(assessment, dict):
        raise ValueError("Agent result lacks the source-bound context needed for blind review")
    evidence = []
    aliases = {}
    private_keys = {"repository", "repository_id", "commit", "tree", "snapshot_sha256",
        "report_sha256", "source_sha256", "git_blob", "candidate_id", "operation_id",
        "experiment_id", "mode", "model", "provider", "tool", "tool_name",
        "prompt_version", "tool_policy_version", "evidence_id"}
    def scrub_metadata(value):
        if isinstance(value, dict):
            return {key: scrub_metadata(item) for key, item in value.items()
                    if str(key).lower() not in private_keys}
        if isinstance(value, list):
            return [scrub_metadata(item) for item in value]
        return value
    initial_id = initial.get("evidence_id")
    if initial_id:
        aliases[initial_id] = "E1"
    evidence.append({"id": "E1", "kind": "candidate_source", "file": context.get("file"),
        "start_line": context.get("source_excerpt_start_line"),
        "end_line": context.get("source_excerpt_end_line"),
        "content": {"source_excerpt": context.get("source_excerpt"),
                    "evidence_obligations": context.get("evidence_obligations", [])}})
    supplemental = []
    for call in result.get("tool_calls", []):
        evidence_id = call.get("evidence_id")
        payload = call.get("result")
        if not evidence_id or payload is None:
            continue
        alias = "E" + str(len(evidence) + 1)
        aliases[evidence_id] = alias
        evidence.append({"id": alias, "kind": "supplemental_source_evidence",
                         "content": scrub_metadata(payload)})
    def scrub_citations(items):
        citations = []
        for citation in items if isinstance(items, list) else []:
            source_id = citation.get("evidence_id")
            if source_id in aliases:
                citations.append({"evidence_id": aliases[source_id], "quote": citation.get("quote", "")})
        return citations
    def scrub_claims(items):
        output = []
        for claim in items if isinstance(items, list) else []:
            if not isinstance(claim, dict):
                continue
            item = {"claim": claim.get("claim", ""),
                    "citations": scrub_citations(claim.get("citations", []))}
            indices = claim.get("obligation_indices")
            if (isinstance(indices, list)
                    and all(isinstance(index, int) and not isinstance(index, bool) and index >= 0
                            for index in indices)):
                item["obligation_indices"] = indices
            output.append(item)
        return output
    packet = {
        "candidate": {"file": context.get("file"), "line": context.get("line"),
                      "symbol": context.get("symbol"), "source_excerpt": context.get("source_excerpt"),
                      "evidence_obligations": context.get("evidence_obligations", []),
                      "evidence_routing": context.get("evidence_routing")},
        "assessment": {"summary": assessment.get("summary", ""),
                       "summary_provenance": result.get("summary_provenance", "legacy_model_generated_unverified"),
                       "model_summary_unverified": assessment.get("model_summary_unverified",
                           assessment.get("summary", "")),
                       "citation_integrity": result.get("citation_integrity", {
                           "quote_presence": "unknown",
                           "semantic_support": "unverified_by_machine",
                           "note": "This result has no recorded server-side verbatim citation check."}),
                       "narrative_integrity": result.get("narrative_integrity", {
                           "unverified_narrative_fields": ["model_summary_unverified", "unsupported_claims", "unknowns", "next_steps"],
                           "narrative_semantics": "unverified_by_machine"}),
                       "assessment": assessment.get("assessment", "unknown"),
                       "supported_claims": scrub_claims(assessment.get("supported_claims", [])),
                       "obligation_reviews": [{
                           "obligation_index": item.get("obligation_index"),
                           "disposition": item.get("disposition", "unresolved"),
                           "citations": scrub_citations(item.get("citations", [])),
                       } for item in assessment.get("obligation_reviews", []) if isinstance(item, dict)],
                       "unsupported_claims": assessment.get("unsupported_claims", []),
                       "unknowns": assessment.get("unknowns", []),
                       "next_steps": assessment.get("next_steps", [])},
        "evidence": evidence,
        "notice": "Review this anonymized investigation output and evidence. Arm and provider details are hidden until the session is closed.",
    }
    return packet


def _experiment_evidence_summary(settings, store, ops):
    """Summarize persisted, source-bound Agent and validation evidence without scoring truth."""
    agent_groups = {}
    validation_runs = []
    agent_operation_count = 0
    agent_bound_count = 0
    agent_unknown_count = 0

    # Keep this inventory explicitly bounded to the same recent operation window as
    # the existing telemetry panel. It is not a complete experiment ledger.
    for operation in ops.list():
        spec = operation.get("spec") if isinstance(operation.get("spec"), dict) else {}
        if operation.get("kind") == "agent_investigation":
            agent_operation_count += 1
            result = {}
            source_state = "unknown"
            if operation.get("result_sha256"):
                try:
                    result = ops.result(operation["id"])
                    if not isinstance(result, dict):
                        raise ValueError("agent result is not a JSON object")
                    binding = result.get("binding") if isinstance(result.get("binding"), dict) else {}
                    job = store.job(spec.get("job_id"))
                    report = service.read_report(settings, job)
                    candidate = service.finding(report, spec.get("candidate_id"))
                    anchor = _fixed_case_source_anchor(settings, store, job, report, candidate)
                    expected_binding = {
                        "job_id": job["id"], "candidate_id": candidate["id"],
                        "repository": report.get("repository"),
                        "report_sha256": job.get("report_sha256"),
                        "commit": job.get("spec", {}).get("commit"),
                        "source_sha256": candidate.get("source_sha256"),
                    }
                    provider = result.get("provider") if isinstance(result.get("provider"), dict) else {}
                    if all((
                        spec.get("candidate_id") == candidate.get("id"),
                        spec.get("report_sha256") == job.get("report_sha256"),
                        spec.get("source_commit") == job.get("spec", {}).get("commit"),
                        spec.get("candidate_source_sha256") == candidate.get("source_sha256"),
                        result.get("mode") == spec.get("mode"),
                        result.get("experiment_id") == spec.get("experiment_id"),
                        provider.get("model") == spec.get("provider_model"),
                        result.get("prompt_version") == spec.get("prompt_version"),
                        result.get("tool_policy_version") == spec.get("tool_policy_version"),
                        result.get("vulnerability_state") == "candidate",
                        result.get("validated_vulnerability") == 0,
                        anchor.get("verified") is True,
                        all(binding.get(key) == value for key, value in expected_binding.items()),
                    )):
                        source_state = "verified_fixed_source"
                except (KeyError, TypeError, ValueError, OSError, UnicodeError,
                        subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
            if source_state == "verified_fixed_source":
                agent_bound_count += 1
            else:
                agent_unknown_count += 1
            provider = result.get("provider") if isinstance(result.get("provider"), dict) else {}
            dimensions = (
                spec.get("experiment_id") or None,
                result.get("mode") or spec.get("mode") or "unknown",
                provider.get("model") or spec.get("provider_model") or "unknown",
                result.get("prompt_version") or spec.get("prompt_version") or "unknown",
                result.get("tool_policy_version") or spec.get("tool_policy_version") or "unknown",
            )
            group = agent_groups.setdefault(dimensions, {
                "experiment_id": dimensions[0], "mode": dimensions[1], "model": dimensions[2],
                "prompt_version": dimensions[3], "tool_policy_version": dimensions[4],
                "operation_count": 0, "status_counts": {},
                "fixed_source_bound_result_count": 0, "unknown_binding_count": 0,
            })
            group["operation_count"] += 1
            status = operation.get("status", "unknown")
            group["status_counts"][status] = group["status_counts"].get(status, 0) + 1
            group["fixed_source_bound_result_count"] += int(source_state == "verified_fixed_source")
            group["unknown_binding_count"] += int(source_state != "verified_fixed_source")

        elif operation.get("kind") == "validation":
            result = {}
            manifest_state = "unknown"
            manifest_reason = "验证尚无可校验的结果清单。"
            if operation.get("result_sha256"):
                try:
                    result = ops.result(operation["id"])
                    if not isinstance(result, dict):
                        raise ValueError("validation result is not a JSON object")
                    manifest_path = ops.directory(operation["id"]) / "input-manifest.json"
                    raw_manifest = manifest_path.read_bytes()
                    if len(raw_manifest) > 256 * 1024:
                        raise ValueError("validation input manifest exceeds limit")
                    manifest_hash = hashlib.sha256(raw_manifest).hexdigest()
                    manifest = json.loads(raw_manifest)
                    if not isinstance(manifest, dict):
                        raise ValueError("validation input manifest is not a JSON object")
                    cpp_harness = spec.get("harness_id") in CPP_IDS
                    cpp_binding = (cpp_harness
                        and manifest.get("harness_id") == spec.get("harness_id")
                        and manifest.get("validation_scope") == spec.get("validation_scope")
                        and manifest.get("harness_manifest_sha256") == spec.get("manifest_sha256"))
                    auth_binding = (not cpp_harness
                        and manifest.get("target_commit") == spec.get("target_commit")
                        and manifest.get("target_repository") == spec.get("target_repository")
                        and manifest.get("cutils_commit") == spec.get("cutils_commit")
                        and isinstance(manifest.get("harness_manifest_sha256"), str)
                        and re.fullmatch(r"[0-9a-f]{64}", manifest["harness_manifest_sha256"]))
                    if manifest_hash == result.get("input_manifest_sha256") and (cpp_binding or auth_binding):
                        manifest_state = "verified_input_manifest"
                        manifest_reason = None
                    else:
                        manifest_reason = "验证结果与持久化输入清单/固定提交不一致。"
                except (KeyError, TypeError, ValueError, OSError, UnicodeError):
                    manifest_reason = "验证输入清单缺失、损坏或与结果摘要不匹配。"

            if spec.get("harness_id") in {AUTH_ID, "cpp_shared_ptr_delayed_singleton"}:
                scope = "component_harness"
            elif spec.get("harness_id") == "cpp_lifetime_unique_ptr_alias":
                scope = "synthetic_harness"
            elif (manifest_state == "verified_input_manifest"
                  and spec.get("validation_scope") == "product_level"
                  and result.get("validation_scope") == "product_level"
                  and result.get("reachability_status") == "verified"):
                scope = "product_level"
            else:
                scope = "unknown"
            validation_runs.append({
                "operation_id": operation["id"], "case_id": spec.get("case_id"),
                "scope": scope, "harness_id": spec.get("harness_id"),
                "status": operation.get("status", "unknown"),
                "target_repository": spec.get("target_repository") or "unknown",
                "target_commit": spec.get("target_commit") or "unknown",
                "input_manifest_state": manifest_state,
                "input_manifest_reason": manifest_reason,
                "validation_gate": result.get("validation_gate", "unknown"),
                "reachability_status": result.get("reachability_status", "unknown"),
                "validated_vulnerability": 0,
            })

    return {
        "schema_version": 1,
        "operation_window": "recent_200_persisted_operations",
        "accuracy_claim": False,
        "agent": {
            "state": "available" if agent_operation_count else "unknown",
            "operation_count": agent_operation_count,
            "fixed_source_bound_result_count": agent_bound_count,
            "unknown_binding_count": agent_unknown_count,
            "groups": [agent_groups[key] for key in sorted(
                agent_groups, key=lambda value: tuple(str(item or "") for item in value))],
            "limitation": "只汇总可重新校验固定扫描报告、候选源码 SHA 与 Agent 结果绑定的运行；不衡量模型正确性。",
        },
        "validation": {
            "state": "available" if validation_runs else "unknown",
            "run_count": len(validation_runs),
            "scope_counts": {
                scope: sum(item["scope"] == scope for item in validation_runs)
                for scope in ("component_harness", "product_level", "unknown")
            },
            "runs": validation_runs,
            "limitation": "验证操作只按显式 Harness 类型与持久化输入清单分类，不自动关联到候选实验；组件级隔离测试结果不代表产品级可达性。",
        },
        "holdout": {
            "state": "unknown",
            "reason": "没有持久化的冻结独立 holdout 清单、样本成员身份与人工真值标签；不计算准确率、Precision 或 Recall。",
        },
    }


def install_routes(app: FastAPI, settings, store):
    ops = Operations(store)
    router = APIRouter(prefix="/api/v1")

    @router.get("/cases/review-statuses")
    def case_review_statuses():
        return {"items": [{"case_id": case["id"], **_case_review_status(settings, store, ops, case["id"])}
                          for case in store.cases()]}

    @router.get("/agent/evaluation-summary")
    def agent_evaluation_summary():
        summary = ops.agent_evaluation_summary()
        summary["evidence_evaluation"] = _experiment_evidence_summary(settings, store, ops)
        return summary

    @router.get("/agent/static-review-preview")
    def agent_static_review_preview(job_id: str, candidate_id: str):
        job = store.job(job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("static review preview requires a completed scan report")
        report = service.read_report(settings, job)
        candidate = service.finding(report, candidate_id)
        source = service.source(settings, store, job, candidate["file"])
        if source.get("sha256") != candidate.get("source_sha256"):
            raise ValueError("static preview source does not match the fixed candidate")
        try:
            line = int(candidate["line"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("static preview candidate has no valid source line") from None
        lines = source["text"].splitlines()
        if line < 1 or line > len(lines):
            raise ValueError("static preview candidate line is outside the fixed source")
        start, end = max(1, line - 20), min(len(lines), line + 20)
        preview_parts = []
        preview_bytes = 0
        truncated = False
        for number in range(start, end + 1):
            encoded = f"{number}: {lines[number - 1]}".encode("utf-8")
            remaining = 32768 - preview_bytes
            if len(encoded) > remaining:
                if remaining > 0:
                    preview_parts.append(encoded[:remaining].decode("utf-8", "ignore"))
                truncated = True
                break
            preview_parts.append(encoded.decode("utf-8"))
            preview_bytes += len(encoded) + 1
        candidate_evidence = candidate.get("evidence")
        if not isinstance(candidate_evidence, dict):
            candidate_evidence = {}
        obligations = candidate_evidence.get("obligations", [])
        if not isinstance(obligations, list):
            obligations = []
        coverage = report.get("detector_coverage")
        if not isinstance(coverage, dict):
            coverage = {}
        detectors = coverage.get("detectors")
        if not isinstance(detectors, dict):
            detectors = {}
        detector_coverage = detectors.get(candidate.get("detector_id"))
        if not isinstance(detector_coverage, dict):
            detector_coverage = {}
        coverage_counts = detector_coverage.get("coverage_counts")
        if not isinstance(coverage_counts, dict):
            coverage_counts = {}
        bounded_obligations = obligations[:40]
        evidence_routing = recommend_investigation_route(
            bounded_obligations,
            scan_status=report.get("status", "unknown"),
            detector_status=detector_coverage.get("status", "unknown"),
            analysis_status=candidate_evidence.get("analysis_status", "unknown"),
        )

        def coverage_count(key, files_key):
            value = coverage_counts.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
            files = detector_coverage.get(files_key)
            return len(files) if isinstance(files, list) else None

        return {
            "schema_version": 1,
            "binding": {"repository": report.get("repository"), "commit": report.get("commit"),
                         "tree": report.get("git_tree", report.get("tree")),
                         "report_sha256": job["report_sha256"]},
            "scan_status": report.get("status", "unknown"),
            "analysis_status": candidate_evidence.get("analysis_status", "unknown"),
            "detector_coverage": {
                "status": detector_coverage.get("status", "unknown"),
                "applicable_files": detector_coverage.get("applicable_files"),
                "analyzed_files": coverage_count("complete", "analyzed_files"),
                "partially_inspected_files": coverage_count("partial", "partially_inspected_files"),
                "not_analyzed_files": coverage_count("not_analyzed", "not_analyzed_files"),
                "failed_files": coverage_count("failed", "failed_files"),
            },
            "evidence_routing": evidence_routing,
            "id": candidate["id"], "file": candidate["file"], "line": line,
            "detector_id": candidate.get("detector_id"),
            "detector_version": candidate.get("detector_version"),
            "rule_id": candidate.get("rule_id"),
            "message": candidate.get("message"),
            "severity": candidate.get("severity"), "confidence": candidate.get("confidence"),
            "source_sha256": candidate.get("source_sha256"),
            "risk_assessment": candidate_evidence.get("risk_assessment"),
            "evidence": {"obligations": obligations[:40],
                          "obligations_truncated": len(obligations) > 40},
            "source": {"sha256": source["sha256"], "blob": source.get("blob"),
                        "start_line": start, "end_line": min(end, start + len(preview_parts) - 1),
                        "text": "\n".join(preview_parts), "truncated": truncated},
            "source_line_count": len(lines),
            "semantics": "Static scanner evidence for human R0 triage only; no Agent output or vulnerability conclusion.",
        }

    @router.post("/agent/static-review-source")
    def agent_static_review_source(body: AgentStaticReviewSourceRequest):
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("fixed-source review requires a completed scan report")
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        source = service.source(settings, store, job, candidate["file"])
        if source.get("sha256") != candidate.get("source_sha256"):
            raise ValueError("fixed-source excerpt no longer matches the candidate source")
        lines = source.get("text", "").splitlines()
        if body.start_line > len(lines):
            raise ValueError("requested source range starts beyond end of file")
        end_line = min(len(lines), body.start_line + body.line_count - 1)
        excerpt = "\n".join(f"{number}: {lines[number - 1]}"
                            for number in range(body.start_line, end_line + 1))
        if len(excerpt.encode("utf-8")) > 32768:
            raise ValueError("requested source excerpt exceeds the 32 KiB limit; request fewer lines")
        return {"job_id": job["id"], "candidate_id": candidate["id"],
                "repository": report["repository"], "commit": report["commit"],
                "report_sha256": job["report_sha256"], "file": candidate["file"],
                "source_sha256": source["sha256"], "start_line": body.start_line,
                "end_line": end_line, "text": excerpt,
                "semantics": "Read-only excerpt from the candidate file at its fixed source SHA; no provider request was made."}

    @router.post("/agent/baseline-reviews", status_code=201)
    def agent_baseline_review(body: AgentBaselineReviewRequest):
        reviewer = body.reviewer.strip()
        if not reviewer:
            raise ValueError("reviewer name must not be blank")
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("R0 baseline requires a completed scan report")
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        source = service.source(settings, store, job, candidate["file"])
        if source.get("sha256") != candidate.get("source_sha256"):
            raise ValueError("R0 baseline source does not match the fixed candidate")
        for task in ops.list():
            spec = task.get("spec") or {}
            if (task["kind"] == "agent_investigation"
                    and spec.get("experiment_id") == body.experiment_id
                    and spec.get("job_id") == body.job_id
                    and spec.get("candidate_id") == body.candidate_id):
                raise ValueError("R0 must be recorded before any LLM operation in this experiment")
        if not body.reviewer_acknowledged:
            raise ValueError("R0 requires explicit reviewer confirmation that each displayed obligation was checked")
        evidence = candidate.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        all_obligations = evidence.get("obligations", [])
        if not isinstance(all_obligations, list):
            all_obligations = []
        obligations = all_obligations[:40]
        reviews = [item.model_dump() for item in body.obligation_reviews]
        indices = [item["obligation_index"] for item in reviews]
        if len(reviews) != len(obligations) or sorted(indices) != list(range(len(obligations))):
            raise ValueError("R0 must record exactly one static review for every displayed evidence obligation")
        source_lines = source.get("text", "").splitlines()
        candidate_line = candidate.get("line")
        if not isinstance(candidate_line, int) or isinstance(candidate_line, bool) or candidate_line < 1:
            raise ValueError("R0 candidate source line is invalid")
        excerpt_start = max(1, candidate_line - 20)
        excerpt_end = min(len(source_lines), candidate_line + 20)
        displayed_lines = set(range(excerpt_start, excerpt_end + 1))
        for source_range in body.source_ranges:
            if (source_range.end_line < source_range.start_line
                    or source_range.end_line - source_range.start_line + 1 > 40
                    or source_range.end_line > len(source_lines)):
                raise ValueError("R0 supplemental source ranges must be valid fixed-file ranges of at most 40 lines")
            displayed_lines.update(range(source_range.start_line, source_range.end_line + 1))
        for review in reviews:
            quote = review.get("quote")
            line = review.get("source_line")
            if review["disposition"] != "unresolved" and (not quote or line is None):
                raise ValueError("R0 evidence_found and contrary_evidence decisions require a quoted source line")
            if quote is not None:
                if line is None or line not in displayed_lines:
                    raise ValueError("R0 source quote line must be inside the initial or supplemental fixed-source excerpt")
                if quote not in source_lines[line - 1]:
                    raise ValueError("R0 source quote does not match the cited fixed-source line")
        record = {
            "experiment_id": body.experiment_id,
            "job_id": body.job_id,
            "candidate_id": body.candidate_id,
            "repository": report["repository"],
            "commit": report["commit"],
            "report_sha256": job["report_sha256"],
            "source_sha256": source["sha256"],
            "source_blob": source.get("blob"),
            "detector_id": candidate.get("detector_id"),
            "detector_version": candidate.get("detector_version"),
            "reviewer": reviewer,
            "disposition": body.disposition,
            "elapsed_seconds": body.elapsed_seconds,
            "notes": body.notes,
            "obligation_reviews": reviews,
            "source_ranges": [item.model_dump() for item in body.source_ranges],
            "obligations_reviewed": len(reviews),
            "obligations_truncated": len(all_obligations) > len(obligations),
            "review_scope": "static_only_r0_triage",
            "vulnerability_state": "candidate",
            "validated_vulnerability": 0,
        }
        return ops.record_agent_baseline_review(record)

    def normalize_source_sync_entries(body):
        entries = []
        seen = {}
        timeout_total = 0
        from urllib.parse import urlsplit
        for item in body.repositories:
            values = item.model_dump()
            repository = values.pop("repository")
            submitted_url = values.pop("url")
            url = approved_url(submitted_url)
            expected = "/" + repository + (".git" if urlsplit(url).path.endswith(".git") else "")
            if urlsplit(url).path != expected:
                raise ValueError("repository URL path must match the approved repository name")
            canonical = repository.casefold()
            values["destination_dir"] = normalize_download_dir(settings, values.get("destination_dir"))
            normalized = {"name": repository, "url": url, **values}
            prior = seen.get(canonical)
            if prior is not None and prior != normalized:
                raise ValueError("duplicate repository entries must use the same URL and scan options")
            if prior is None:
                seen[canonical] = normalized
                timeout_total += values["timeout_seconds"]
            entries.append(normalized)
        if timeout_total > 7200:
            raise ValueError("batch total Git timeout cannot exceed two hours")
        return entries, timeout_total

    @router.post("/operations/source-sync/preview")
    def source_sync_preview(body: SyncBatchRequest):
        entries, _timeout_total = normalize_source_sync_entries(body)
        return source_sync_preflight(settings, entries)

    @router.post("/operations/source-sync/batch", status_code=201)
    def source_sync_batch(body: SyncBatchRequest):
        entries, timeout_total = normalize_source_sync_entries(body)
        return ops.create("source_sync_batch", {
            "repositories": entries,
            "timeout_seconds": timeout_total + 60,
            "max_repositories": MAX_SOURCE_SYNC_BATCH_REPOSITORIES,
        })

    @router.post("/operations/source-sync", status_code=201)
    def source_sync(body: SyncRequest):
        prefix = "openharmony/"
        if not body.repository.startswith(prefix):
            raise ValueError("repository must name one OpenHarmony repository")
        slug = validate_repository_slug(body.repository[len(prefix):])
        url = approved_url(body.url)
        from urllib.parse import quote, urlsplit
        path = urlsplit(url).path
        expected = "/" + prefix + quote(slug, safe="") + (".git" if path.endswith(".git") else "")
        if path != expected:
            raise ValueError("repository URL path must match the approved repository name")
        values = body.model_dump(exclude={"repository", "url"})
        values["destination_dir"] = normalize_download_dir(settings, values.get("destination_dir"))
        return ops.create("source_sync", {"name": body.repository, "url": url, **values})

    @router.post("/operations/scan-previews")
    def operation_scan_preview(body: OperationScanPreviewRequest):
        request_models = {"range": RangeRequest, "date": DateRangeRequest,
                          "branches": BranchComparisonRequest, "matrix": MatrixRequest,
                          "recent": RecentComparisonRequest}
        operation_body = request_models[body.kind].model_validate(body.payload)
        if operation_body.triage_authorizations or operation_body.triage_approvals:
            raise ValueError("preview requests must not contain prior authorization tokens")
        operation_kind, repo, operation_spec, scans = _operation_scan_plan(
            settings, store, body.kind, operation_body)
        return {"operation_kind": operation_kind, "repository": repo["name"],
            "spec": operation_spec,
            "triage_authorization_preview": _preview_operation_triage(
                settings, operation_body, scans)}

    @router.get("/repositories/official-catalog")
    def official_repository_catalog(q: str = "", page: int = 1, per_page: int = 50,
                                    refresh: bool = False):
        try:
            return public_repository_catalog(settings, query=q, page=page,
                                             per_page=per_page, refresh=refresh)
        except CatalogUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None

    @router.post("/repositories/official-catalog/preview")
    def official_repository_preview(body: OfficialRepositoryPreviewRequest):
        try:
            return repository_preview(settings, validate_repository_slug(body.slug))
        except CatalogUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None

    @router.post("/operations/repository-import-scans", status_code=201)
    def import_repository_and_scan(body: OfficialRepositoryImportRequest):
        validate_repository_slug(body.slug)
        branch = validate_branch(body.branch)
        commit = validate_commit(body.commit)
        try:
            preview = validate_preview(settings, body.slug, branch, commit, body.preview_sha256)
        except CatalogUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        from .source_catalog import approved_clone_url
        spec = {
            "slug": body.slug, "name": preview["name"], "branch": branch,
            "destination_dir": normalize_download_dir(settings, body.destination_dir)
                if body.destination_dir else None,
            "commit": commit, "preview_sha256": body.preview_sha256,
            "catalog_sha256": preview.get("catalog_sha256"),
            "clone_url": approved_clone_url(body.slug),
            "estimated_size_kib": preview.get("size_kib"),
            "include_paths": body.include_paths, "detector_ids": body.detector_ids,
            "timeout_seconds": body.import_timeout_seconds,
            "scan_timeout_seconds": body.timeout_seconds, "memory_mb": body.memory_mb,
            "audit_mode": "static_only",
        }
        return ops.create("repository_import_scan", spec)

    @router.post("/operations/intelligent-previews")
    def intelligent_operation_preview(body: IntelligentOperationPreviewRequest):
        """Only preview source egress, never queue scans or invoke a provider."""
        schemas = {"range": RangeRequest, "date": DateRangeRequest,
                   "branches": BranchComparisonRequest, "matrix": MatrixRequest}
        request = schemas[body.kind].model_validate(body.payload)
        if not request.auto_triage or request.audit_mode != "standard_review":
            raise ValueError("select intelligent review before previewing model source disclosure")
        if request.triage_authorizations or request.triage_approvals:
            raise ValueError("preview does not accept previously approved source consent")
        _, repo, operation_spec, specs = _operation_scan_plan(
            settings, store, body.kind, request)
        preview = _preview_operation_triage(settings, request, specs)
        return {
            "kind": body.kind, "endpoint_count": len(preview["scans"]),
            "endpoints": preview["scans"],
            "progressive_policy": preview.get("progressive_policy"),
            "aggregate_estimated_cost": preview.get("aggregate_estimated_cost"),
            "note": ("Each endpoint has a separate fixed-commit model disclosure consent. "
                     "This preview does not send source; approval binds exact scan plan, workflow, progressive-policy digest and provider."),
        }

    @router.post("/operations/revision-ranges", status_code=201)
    def revision_range(body: RangeRequest):
        operation_kind, repo, operation_spec, scans = _operation_scan_plan(
            settings, store, "range", body)
        scans = _prepare_operation_triage(settings, body, scans)
        operation_spec.update({"auto_triage": body.auto_triage,
            "max_triage_candidates": body.max_triage_candidates,
            "max_r2_candidates": body.max_r2_candidates if body.auto_triage else 0,
            "max_cost_usd": body.max_cost_usd})
        operation_spec["progressive_triage_policy"] = scans[0]["progressive_triage_policy"]
        return ops.create_with_scans(operation_kind, operation_spec, repo["id"], scans)

    @router.post("/operations/date-ranges", status_code=201)
    def date_range(body: DateRangeRequest):
        operation_kind, repo, operation_spec, scans = _operation_scan_plan(
            settings, store, "date", body)
        scans = _prepare_operation_triage(settings, body, scans)
        operation_spec.update({"auto_triage": body.auto_triage,
            "max_triage_candidates": body.max_triage_candidates,
            "max_r2_candidates": body.max_r2_candidates if body.auto_triage else 0,
            "max_cost_usd": body.max_cost_usd})
        operation_spec["progressive_triage_policy"] = scans[0]["progressive_triage_policy"]
        return ops.create_with_scans(operation_kind, operation_spec, repo["id"], scans)

    @router.post("/operations/date-ranges/preview")
    def date_range_preview(body: DateRangePreviewRequest):
        return date_selection(settings, store, body.repository_id, body.branch,
                              body.start, body.end, body.timezone)

    @router.post("/operations/recent-comparisons/preview")
    def recent_comparison_preview(body: RecentComparisonRequest):
        return recent_window_selections(settings, store, body.repository_id, body.branch,
                                        body.lookback_days, body.reference_time, body.timezone)

    @router.post("/operations/recent-comparisons", status_code=201)
    def recent_comparison(body: RecentComparisonRequest):
        operation_kind, repo, operation_spec, scans = _operation_scan_plan(
            settings, store, "recent", body)
        scans = _prepare_operation_triage(settings, body, scans)
        operation_spec.update({"auto_triage": body.auto_triage,
            "max_triage_candidates": body.max_triage_candidates,
            "max_r2_candidates": body.max_r2_candidates if body.auto_triage else 0,
            "max_cost_usd": body.max_cost_usd})
        operation_spec["progressive_triage_policy"] = scans[0]["progressive_triage_policy"]
        return ops.create_with_scans(operation_kind, operation_spec, repo["id"], scans)

    @router.post("/operations/branch-comparisons", status_code=201)
    def branch_comparison(body: BranchComparisonRequest):
        operation_kind, repo, operation_spec, scans = _operation_scan_plan(
            settings, store, "branches", body)
        scans = _prepare_operation_triage(settings, body, scans)
        operation_spec.update({"auto_triage": body.auto_triage,
            "max_triage_candidates": body.max_triage_candidates,
            "max_r2_candidates": body.max_r2_candidates if body.auto_triage else 0,
            "max_cost_usd": body.max_cost_usd})
        operation_spec["progressive_triage_policy"] = scans[0]["progressive_triage_policy"]
        return ops.create_with_scans(operation_kind, operation_spec, repo["id"], scans)

    @router.post("/operations/version-matrices", status_code=201)
    def version_matrix(body: MatrixRequest):
        operation_kind, repo, operation_spec, scans = _operation_scan_plan(
            settings, store, "matrix", body)
        scans = _prepare_operation_triage(settings, body, scans)
        operation_spec.update({"auto_triage": body.auto_triage,
            "max_triage_candidates": body.max_triage_candidates,
            "max_r2_candidates": body.max_r2_candidates if body.auto_triage else 0,
            "max_cost_usd": body.max_cost_usd})
        operation_spec["progressive_triage_policy"] = scans[0]["progressive_triage_policy"]
        return ops.create_with_scans(operation_kind, operation_spec, repo["id"], scans)

    @router.post("/operations/joint-candidate-comparisons/preview")
    @router.post("/operations/version-matrix-candidate-comparisons/preview")
    def joint_candidate_comparison_preview(body: JointCandidateComparisonSelectors):
        from .joint_candidate_comparison_runtime import build_joint_preview
        selectors = body.model_dump()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
        preview = build_joint_preview(settings, store, ops, selectors, uuid.uuid4().hex, expires_at)
        binding = preview["binding"]
        linked_children = binding.get("linked_agent_children_observed", {"from": [], "to": []})
        result_binding = {
            "source_operation_id": binding["source_operation_id"],
            "source_operation_kind": binding["source_operation_kind"],
            "source_operation_result_sha256": binding["source_operation_result_sha256"],
            "repository_id": binding["repository_id"],
            "from": binding["from"],
            "to": binding["to"],
        }
        for key in ("matrix_operation_id", "matrix_result_sha256",
                    "recent_window_operation_id", "recent_window_result_sha256"):
            if key in binding:
                result_binding[key] = binding[key]
        limitations = list(preview["disclosure"]["limitations"])
        limitations.append(
            "The server validates citation side, path, line range, and source text, but not whether a quote semantically supports a model claim."
        )
        ops.issue_joint_comparison_preview_ticket(
            preview["consent_nonce"], preview["consent_sha256"], preview["expires_at"])
        return {
            "eligible": True,
            "consent": {
                "purpose": preview["purpose"],
                "consent_nonce": preview["consent_nonce"],
                "consent_sha256": preview["consent_sha256"],
                "expires_at": preview["expires_at"],
                "provider": {
                    "configured": preview["provider"]["configured"],
                    "destination": preview["provider"]["destination_host"],
                    "model": preview["provider"]["model"],
                },
                "binding": result_binding,
            },
            "context_summary": {
                "source_evidence_count": len(preview["citable_fixed_source_evidence"]),
                "linked_agent_result_count": preview["disclosure"]["linked_agent_result_count"],
                "linked_agent_children": {
                    side: [{
                        "operation_id": row["operation_id"], "status": row["status"],
                        "result_sha256": row.get("result_sha256"),
                    } for row in linked_children.get(side, [])]
                    for side in ("from", "to")
                },
                "linked_review_manifest": preview["linked_review_manifest"],
                "evidence_preview": [{
                    "evidence_id": item["evidence_id"],
                    "side": item["side"],
                    "origin": ("smart_investigation_tool" if item["evidence_id"].startswith("ev-joint-agent-")
                               else "fixed_scan_candidate"),
                    "file": item["file"],
                    "line_start": item["line_start"],
                    "line_end": item["line_end"],
                    "source_sha256": item.get("source_sha256"),
                    **({
                        "operation_id": item["operation_id"],
                        "tool_result_sha256": item["tool_result_sha256"],
                    } if item.get("operation_id") else {}),
                    "lines": item["lines"],
                } for item in preview["citable_fixed_source_evidence"]],
                "redaction_policy_version": preview["redaction_policy_version"],
                "redaction_categories": preview["redaction_categories"],
                "limitations": limitations,
            },
        }

    @router.post("/operations/joint-candidate-comparisons", status_code=201)
    @router.post("/operations/version-matrix-candidate-comparisons", status_code=201)
    def joint_candidate_comparison_create(body: JointCandidateComparisonCreateRequest):
        from .joint_candidate_comparison_runtime import create_joint_operation
        return create_joint_operation(
            settings, store, ops, body.model_dump(exclude={
                "approved", "consent_nonce", "expected_consent_sha256", "expires_at"
            }),
            body.approved, body.consent_nonce, body.expected_consent_sha256, body.expires_at)

    def provider_settings_view():
        from .agent import ProviderConfig
        from .provider_settings import environment_overrides, read_last_provider_check, read_settings
        saved = read_settings(settings.data_dir)
        provider = ProviderConfig.from_env(settings.data_dir)
        env_source = environment_overrides()
        last_check = read_last_provider_check(settings.data_dir, saved) if not env_source else None
        if (not isinstance(last_check, dict) or not provider.configured
                or last_check.get("model") != provider.model
                or last_check.get("endpoint_host") != provider.endpoint_host):
            last_check = None
        else:
            last_check = {key: last_check.get(key) for key in (
                "checked_at", "endpoint_host", "model", "duration_ms", "input_tokens", "output_tokens")}
        return {
            "api_protocol": provider.provider if env_source else saved["api_protocol"],
            "base_url": provider.base_url if env_source else saved["base_url"],
            "model": provider.model if env_source else saved["model"],
            "proxy_url": provider.proxy_url if env_source else saved["proxy_url"],
            "api_key_configured": bool(provider.api_key),
            "configured": provider.configured,
            "configuration_source": "environment" if env_source else "local_settings",
            "editable": not env_source,
            "storage": "local_private_file" if not env_source else "environment",
            "last_provider_check": last_check,
        }

    @router.get("/agent/provider-settings")
    def agent_provider_settings():
        return provider_settings_view()

    @router.post("/agent/provider-settings")
    def save_agent_provider_settings(body: ProviderSettingsRequest):
        from .agent import validate_base_url, validate_proxy_url
        from .provider_settings import environment_overrides, read_settings, write_settings
        if environment_overrides():
            raise HTTPException(status_code=409, detail="当前 Provider 由服务环境变量管理；请在服务端修改环境配置")
        current = read_settings(settings.data_dir)
        key = body.api_key if body.api_key else current["api_key"]
        if not key:
            raise ValueError("请填写 API Key；已保存时留空可保留原 Key")
        validate_base_url(body.base_url.strip().rstrip("/"))
        if body.proxy_url.strip():
            validate_proxy_url(body.proxy_url.strip())
        model = body.model.strip()
        if not model or any(ord(ch) < 33 or ord(ch) > 126 for ch in model):
            raise ValueError("模型名称格式无效")
        if len(key) > 4096 or any(ord(ch) < 33 or ord(ch) > 126 for ch in key):
            raise ValueError("API Key 格式无效")
        write_settings({
            "api_protocol": body.api_protocol,
            "base_url": body.base_url.strip().rstrip("/"),
            "model": model,
            "proxy_url": body.proxy_url.strip(),
            "api_key": key,
        }, settings.data_dir)
        return provider_settings_view()

    @router.post("/agent/provider-settings/clear")
    def clear_agent_provider_key():
        from .provider_settings import clear_api_key, environment_overrides
        if environment_overrides():
            raise HTTPException(status_code=409, detail="当前 Provider 由服务环境变量管理；请在服务端修改环境配置")
        clear_api_key(settings.data_dir)
        return provider_settings_view()

    @router.get("/agent/status")
    def agent_status():
        from .agent import public_status
        return public_status(settings.data_dir)


    @router.post("/agent/provider-check")
    def agent_provider_check(body: ProviderCheckRequest):
        from .agent import ProviderConfig, provider_connectivity_check
        from .provider_settings import environment_overrides, record_provider_check
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        try:
            result = provider_connectivity_check(config=provider)
        except ValueError as exc:
            raise HTTPException(status_code=502, detail="Provider 连通性检查失败：" + str(exc)) from None
        persisted = None
        if not environment_overrides():
            try:
                persisted = record_provider_check(settings.data_dir, provider, result)
            except (OSError, ValueError):
                persisted = None
        result["probe_persisted"] = persisted is not None
        result["checked_at"] = persisted.get("checked_at") if persisted else None
        return result

    def _agent_consent_preview(body, provider, *, continuous=None, progressive_bounded=False,
                               system_policy_sha256=None, knowledge_retrieval_enabled=False,
                               source_context=None, prepared_context=None):
        from .agent import consent_preview
        if source_context is None:
            job = store.job(body.job_id)
            if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
                raise ValueError("只允许预览已有完整报告的候选")
            report = service.read_report(settings, job)
            candidate = service.finding(report, body.candidate_id)
        else:
            job, report, candidate = source_context
        preview_spec = body.model_dump()
        preview_spec["knowledge_retrieval_enabled"] = knowledge_retrieval_enabled is True
        # Ordinary tasks inherit budgets from System Settings. Progressive L3
        # retains its ledger-controlled continuous Agent execution semantics.
        preview_spec["continuous_investigation"] = continuous is True
        preview_spec["no_cumulative_token_ceiling"] = (
            False if system_policy_sha256 else
            body.mode == "tool_agent" and (not progressive_bounded or continuous is True))
        preview_spec["provider_request_timeout_seconds"] = 45
        preview_spec["max_provider_retries"] = 0 if progressive_bounded else 1
        if system_policy_sha256:
            preview_spec["system_policy_sha256"] = system_policy_sha256
        preview = consent_preview(settings, store, job, report, candidate, preview_spec, provider,
                                  prepared=prepared_context)
        return job, report, candidate, preview

    def _agent_policy_request(body):
        """Resolve task budgets from the single system-settings policy snapshot."""
        from .progressive_triage.policy import PolicyStore, validate_policy
        state = PolicyStore(settings.data_dir).read()
        policy = validate_policy(state["policy"])
        limits = policy["limits"]
        output_cap = policy.get("request_output_tokens", limits.get(
            "max_output_tokens_per_request", min(1200, limits["max_output_tokens_per_audit"])))
        if ("max_output_tokens" in getattr(body, "model_fields_set", set())
                and body.max_output_tokens != output_cap):
            raise HTTPException(status_code=409, detail="Single output cap is configured in System Settings.")
        bounded = body.model_copy(update={
            "max_steps": limits["max_tool_steps_per_group"],
            "max_output_tokens": output_cap,
            "max_total_input_tokens": limits["max_input_tokens_per_audit"],
            "max_total_output_tokens": limits["max_output_tokens_per_audit"],
            "max_total_model_calls": limits["max_model_calls_per_audit"],
            "timeout_seconds": limits["max_ai_wall_seconds"],
        })
        snapshot = {"revision": state["revision"], "policy": policy,
                    "policy_sha256": state["policy_sha256"]}
        return bounded, snapshot

    def _r0_review_complete(item, job, report, candidate):
        if not (item.get("job_id") == job["id"]
                and item.get("candidate_id") == candidate["id"]
                and item.get("repository") == report["repository"]
                and item.get("commit") == report["commit"]
                and item.get("report_sha256") == job["report_sha256"]
                and item.get("source_sha256") == candidate.get("source_sha256")):
            return False
        evidence = candidate.get("evidence")
        obligations = evidence.get("obligations", []) if isinstance(evidence, dict) else []
        count = min(len(obligations), 40) if isinstance(obligations, list) else 0
        reviews = item.get("obligation_reviews")
        if not isinstance(reviews, list) or len(reviews) != count:
            return False
        indices = [review.get("obligation_index") for review in reviews if isinstance(review, dict)]
        return len(indices) == count and sorted(indices) == list(range(count))

    def _fresh_consent_nonce(body):
        return body if body.consent_nonce else body.model_copy(update={"consent_nonce": uuid.uuid4().hex})

    def _require_consent_nonce(body):
        if not body.consent_nonce:
            raise HTTPException(status_code=428, detail="缺少本次预览 nonce；请重新预览后再授权提交")

    def _quick_screen_preview(body, provider):
        from .progressive_triage.quick_screen_operation import prepare_quick_screen
        parent = ops.audit_parent_for_scan(body.job_id)
        parent_plan = None
        if parent:
            parent_result = ops.result(parent["id"])
            parent_plan = parent_result.get("progressive_triage")
        return prepare_quick_screen(settings, store, body.job_id, body.candidate_id,
                                    provider, body.consent_nonce, body.consent_expires_at,
                                    audit_parent=parent, audit_parent_plan=parent_plan)

    def _quick_screen_batch_preview(body, provider):
        from .progressive_triage.quick_screen_batch import prepare_quick_screen_batch
        return prepare_quick_screen_batch(
            settings, store, ops, body.audit_operation_id, provider,
            body.consent_nonce, body.consent_expires_at,
        )

    @router.post("/operations/progressive-quick-screen-batches/preview")
    def progressive_quick_screen_batch_preview(body: ProgressiveQuickScreenBatchRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        body = _fresh_consent_nonce(body)
        try:
            preview = _quick_screen_batch_preview(body, provider)
            return {**preview, "items": [
                {"group_id": item["group_id"], "candidate_id": item["spec"]["candidate_id"],
                 "job_id": item["spec"]["job_id"]}
                for item in preview["items"]
            ]}
        except (KeyError, ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @router.post("/operations/progressive-quick-screen-batches", status_code=201)
    def progressive_quick_screen_batch(body: ProgressiveQuickScreenBatchRequest):
        from .agent import ProviderConfig
        if not body.source_submission_approved:
            raise HTTPException(status_code=428, detail="请先查看本任务所有 L2 源码片段并明确授权")
        if not body.consent_sha256 or not body.consent_expires_at:
            raise HTTPException(status_code=428, detail="缺少本次任务级 L2 预览摘要或有效期")
        _require_consent_nonce(body)
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        try:
            preview = _quick_screen_batch_preview(body, provider)
        except (KeyError, ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="任务级 L2 外发清单、源码、策略或 Provider 已变化；请重新预览")
        spec = {
            "source_submission_approved": True,
            "audit_operation_id": preview["audit_operation_id"],
            "progressive_policy": preview["progressive_policy"],
            "consent_nonce": preview["consent_nonce"],
            "consent_sha256": preview["consent_sha256"],
            "consent_expires_at": preview["consent_expires_at"],
            "consent_manifest": preview["batch_manifest"],
            "items": preview["items"],
            "provider_fingerprint": provider.fingerprint,
            "provider_model": provider.model,
        }
        try:
            return ops.create("progressive_quick_screen_batch", spec)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @router.post("/operations/progressive-quick-screens/preview")
    def progressive_quick_screen_preview(body: ProgressiveQuickScreenRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        body = _fresh_consent_nonce(body)
        try:
            return _quick_screen_preview(body, provider)
        except (KeyError, ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @router.post("/operations/progressive-quick-screens", status_code=201)
    def progressive_quick_screen(body: ProgressiveQuickScreenRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428, detail="请先查看本次 L2 源码外发预览并明确授权")
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少本次 L2 预览指纹，请重新预览")
        if not body.consent_expires_at:
            raise HTTPException(status_code=428, detail="缺少本次 L2 预览有效期，请重新预览")
        _require_consent_nonce(body)
        try:
            preview = _quick_screen_preview(body, provider)
        except (KeyError, ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="L2 外发预览已过期或固定来源发生变化；请重新预览")
        spec = {
            "source_submission_approved": True,
            "job_id": body.job_id,
            "audit_operation_id": preview["audit_operation_id"],
            "candidate_id": body.candidate_id,
            "progressive_policy": preview["progressive_policy"],
            "ranking": preview["ranking"],
            "consent_nonce": body.consent_nonce,
            "consent_sha256": preview["consent_sha256"],
            "consent_expires_at": preview["consent_expires_at"],
            "consent_manifest": preview["consent_manifest"],
            "group": preview["group"],
            "evidence": preview["evidence"],
            "authorization": preview["authorization"],
            "provider_fingerprint": provider.fingerprint,
            "provider_model": provider.model,
        }
        try:
            return ops.create("progressive_quick_screen", spec)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    def _progressive_quick_result(operation_id, job_id, candidate_id, group_id=None):
        quick_task = ops.get(operation_id)
        if (quick_task.get("status") not in {"completed", "completed_with_limitations"}
                or not quick_task.get("result_sha256")):
            raise HTTPException(status_code=409, detail="L2 快筛任务尚未完成或没有可核验结果")
        result = ops.result(operation_id)
        if quick_task.get("kind") == "progressive_quick_screen_batch":
            if not isinstance(group_id, str) or not group_id:
                raise HTTPException(status_code=422, detail="批量 L2 结果需要指定候选组")
            spec = quick_task.get("spec") if isinstance(quick_task.get("spec"), dict) else {}
            item = next((row for row in spec.get("items", [])
                         if isinstance(row, dict) and row.get("group_id") == group_id), None)
            group_result = next((row for row in result.get("groups", [])
                                 if isinstance(row, dict) and row.get("group_id") == group_id), None)
            child_spec = item.get("spec") if isinstance(item, dict) else None
            child_result = group_result.get("result") if isinstance(group_result, dict) else None
            if (not isinstance(child_spec, dict) or not isinstance(group_result, dict)
                    or group_result.get("state") != "completed" or not isinstance(child_result, dict)
                    or group_result.get("candidate_id") != candidate_id
                    or child_spec.get("job_id") != job_id
                    or child_spec.get("candidate_id") != candidate_id):
                raise HTTPException(status_code=409, detail="候选组没有匹配的已完成 L2 结果")
            quick_task = {**quick_task, "spec": child_spec,
                          "progressive_batch_group_id": group_id}
            result = child_result
        elif quick_task.get("kind") != "progressive_quick_screen":
            raise HTTPException(status_code=409, detail="operation 不是可用的渐进式 L2 快筛")
        assessment = result.get("quick_screen") if isinstance(result, dict) else None
        if (not isinstance(assessment, dict) or assessment.get("state") != "completed"
                or assessment.get("quick_assessment") != "investigate"):
            raise HTTPException(status_code=409, detail="只有完成且建议 investigate 的 L2 结果可以进入深度调查")
        source_binding = result.get("source_binding") if isinstance(result, dict) else None
        quick_spec = quick_task.get("spec") if isinstance(quick_task.get("spec"), dict) else {}
        authorization = quick_spec.get("authorization") if isinstance(quick_spec.get("authorization"), dict) else {}
        if (quick_spec.get("job_id") != job_id or quick_spec.get("candidate_id") != candidate_id
                or not isinstance(source_binding, dict)
                or source_binding.get("report_sha256") != authorization.get("report_sha256")):
            raise HTTPException(status_code=409, detail="L2 结果与本次固定候选/报告不匹配")
        return quick_task, result

    def _progressive_deep_preview(body, provider):
        from .progressive_triage.contracts import content_sha256
        from .progressive_triage.policy import validate_policy
        if body.mode != "tool_agent":
            raise HTTPException(status_code=422, detail="L3 仅复用现有只读跨文件 tool-agent 工作流")
        quick_task, quick_result = _progressive_quick_result(
            body.progressive_quick_screen_operation_id, body.job_id, body.candidate_id,
            body.progressive_group_id)
        quick_spec = quick_task["spec"]
        audit_id = quick_spec.get("audit_operation_id")
        if not isinstance(audit_id, str) or not audit_id:
            raise HTTPException(status_code=409, detail="L2 缺少父审计预算绑定")
        parent = ops.get(audit_id) if audit_id != body.job_id else None
        if parent and (parent.get("cancel_requested") or parent.get("status") in
                       {"cancelled", "failed", "timed_out", "interrupted"}):
            raise HTTPException(status_code=409, detail="父审计已取消或不可继续")
        frozen = quick_spec.get("progressive_policy")
        if not isinstance(frozen, dict):
            raise HTTPException(status_code=409, detail="L2 结果没有冻结策略")
        policy = validate_policy(frozen.get("policy"))
        policy_sha = content_sha256(policy)
        if frozen.get("policy_sha256") != policy_sha:
            raise HTTPException(status_code=409, detail="冻结策略摘要校验失败")
        # Each task inherits the immutable system policy captured by the parent
        # audit. Token and tool limits are configured once in System Settings.
        limits = policy["limits"]
        max_steps = min(limits["max_tool_steps_per_group"], 12)
        output_cap = policy.get("request_output_tokens", limits.get(
            "max_output_tokens_per_request", body.max_output_tokens))
        bounded = body.model_copy(update={
            "max_steps": max_steps,
            "max_output_tokens": output_cap,
        })
        _, _, _, preview = _agent_consent_preview(
            bounded, provider, continuous=True, progressive_bounded=True)
        if not preview["agent_execution"]["eligible"]:
            raise HTTPException(status_code=409, detail=preview["agent_execution"]["reason"])
        group = quick_spec.get("group") if isinstance(quick_spec.get("group"), dict) else {}
        source_binding = quick_result.get("source_binding") or {}
        binding = {
            "quick_screen_operation_id": quick_task["id"],
            "quick_screen_result_sha256": quick_task["result_sha256"],
            "quick_screen_batch_group_id": quick_task.get("progressive_batch_group_id"),
            "quick_assessment": "investigate", "audit_operation_id": audit_id,
            "group_id": group.get("group_id"), "policy_sha256": frozen["policy_sha256"],
            "candidate_id": body.candidate_id,
            "report_sha256": source_binding.get("report_sha256"),
            "commit": source_binding.get("commit"),
        }
        if not all(isinstance(binding[key], str) and binding[key]
                   for key in ("group_id", "report_sha256", "commit")):
            raise HTTPException(status_code=409, detail="L2 固定来源或候选组绑定不完整")
        agent_consent_sha256 = preview["consent_sha256"]
        progressive_consent_sha256 = content_sha256({
            "agent_consent_sha256": agent_consent_sha256,
            "progressive_binding": binding,
        })
        preview.update({
            "agent_consent_sha256": agent_consent_sha256,
            "consent_sha256": progressive_consent_sha256,
            "progressive_binding": binding, "progressive_policy": frozen,
            "budgets": {**preview["budgets"],
                        "progressive_task_shared_input_tokens": limits["max_input_tokens_per_audit"],
                        "progressive_task_shared_output_tokens": limits["max_output_tokens_per_audit"],
                        "progressive_task_shared_model_calls": limits["max_model_calls_per_audit"],
                        "progressive_task_shared_wall_seconds": limits["max_ai_wall_seconds"],
                        "max_output_tokens_per_request": output_cap,
                        "local_cumulative_token_budget": "bounded_by_frozen_progressive_policy",
                        "local_total_model_call_budget": "bounded_by_frozen_progressive_policy",
                        "local_total_wall_time_budget": "bounded_by_frozen_progressive_policy",
                        "cumulative_usage_limits_enforced": True,
                        "max_steps": bounded.max_steps},
        })
        return bounded, quick_task, preview

    @router.post("/operations/progressive-deep-investigations/preview")
    def progressive_deep_investigation_preview(body: ProgressiveDeepInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        body = _fresh_consent_nonce(body)
        return _progressive_deep_preview(body, provider)[2]

    @router.post("/operations/progressive-deep-investigations", status_code=201)
    def progressive_deep_investigation(body: ProgressiveDeepInvestigationRequest):
        from .agent import (CONSENT_PREVIEW_VERSION, PROMPT_VERSION,
                            REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION, ProviderConfig)
        if body.source_submission_approved is not True:
            raise HTTPException(status_code=428, detail="请先查看完整 L3 源码/工具范围并明确授权")
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少 L3 预览摘要，请重新预览")
        _require_consent_nonce(body)
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        bounded, quick_task, preview = _progressive_deep_preview(body, provider)
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="L2 结果、源码范围、模型或策略已变化；请重新预览授权")
        binding = preview["progressive_binding"]
        spec = {
            "job_id": bounded.job_id, "candidate_id": bounded.candidate_id,
            "case_id": None, "experiment_id": None, "mode": "tool_agent",
            "max_output_tokens": bounded.max_output_tokens, "max_steps": bounded.max_steps,
            "max_total_input_tokens": bounded.max_total_input_tokens,
            "max_total_output_tokens": bounded.max_total_output_tokens,
            "timeout_seconds": bounded.timeout_seconds,
            "provider_request_timeout_seconds": 45, "max_provider_retries": 0,
            "continuous_investigation": True, "no_cumulative_token_ceiling": True,
            "source_submission_approved": True, "source_submission_approved_at": now(),
            "source_consent_sha256": preview["agent_consent_sha256"],
            "progressive_consent_sha256": preview["consent_sha256"],
            "progressive_quick_screen_operation_id": quick_task["id"],
            "progressive_quick_screen_result_sha256": binding["quick_screen_result_sha256"],
            "progressive_quick_screen_batch_group_id": binding.get("quick_screen_batch_group_id"),
            "progressive_audit_operation_id": binding["audit_operation_id"],
            "progressive_group_id": binding["group_id"],
            "progressive_policy": preview["progressive_policy"],
            "progressive_policy_sha256": binding["policy_sha256"],
            "consent_nonce": body.consent_nonce,
            "consent_preview_version": CONSENT_PREVIEW_VERSION,
            "redaction_policy_version": REDACTION_POLICY_VERSION,
            "provider": provider.provider, "provider_model": provider.model,
            "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
            "prompt_version": PROMPT_VERSION, "tool_policy_version": TOOL_POLICY_VERSION,
            "candidate_source_sha256": preview["binding"]["source_sha256"],
            "source_commit": preview["binding"]["commit"],
            "report_sha256": preview["binding"]["report_sha256"],
        }
        item = ops.create("agent_investigation", spec)
        ops.event(item["id"], "progressive_deep_consent",
                  "User approved L3 fixed-source preview sha256=" + preview["consent_sha256"])
        return ops.get(item["id"])

    def _progressive_deep_batch_preview(body, provider):
        from datetime import datetime, timedelta, timezone
        from .progressive_triage.contracts import content_sha256
        from .progressive_triage.policy import validate_policy
        from .progressive_triage.ledger import BudgetLedger
        from .progressive_triage.deep_agent_batch import MAX_BATCH_ITEMS

        l2 = ops.get(body.progressive_quick_screen_batch_id)
        if (l2.get("kind") != "progressive_quick_screen_batch"
                or l2.get("status") not in {"completed", "completed_with_limitations"}
                or not l2.get("result_sha256")):
            raise HTTPException(status_code=409, detail="L2 批次尚未完成或结果不可核验")
        l2_result = ops.result(l2["id"])
        l2_spec = l2.get("spec") if isinstance(l2.get("spec"), dict) else {}
        audit_id = l2_spec.get("audit_operation_id")
        frozen = l2_spec.get("progressive_policy")
        if not isinstance(audit_id, str) or not isinstance(frozen, dict):
            raise HTTPException(status_code=409, detail="L2 批次缺少任务或策略绑定")
        policy = validate_policy(frozen.get("policy"))
        if frozen.get("policy_sha256") != content_sha256(policy):
            raise HTTPException(status_code=409, detail="L2 冻结策略摘要无效")

        batch_rows = {row.get("group_id"): row for row in l2_result.get("groups", [])
                      if isinstance(row, dict)}
        existing_groups = set()
        for operation in ops.progressive_operations_for_audit(audit_id):
            child_spec = operation.get("spec") if isinstance(operation.get("spec"), dict) else {}
            if operation.get("kind") == "agent_investigation":
                group = child_spec.get("progressive_group_id")
                if isinstance(group, str):
                    existing_groups.add(group)
            elif operation.get("kind") == "progressive_deep_agent_batch":
                existing_groups.update(row.get("group_id") for row in child_spec.get("items", [])
                                       if isinstance(row, dict) and isinstance(row.get("group_id"), str))

        ledger_path = settings.data_dir / "progressive-triage-budget.sqlite3"
        deep_dispatched = 0
        if ledger_path.is_file():
            try:
                deep_dispatched = BudgetLedger(ledger_path).get(audit_id)["phase_counts"]["deep_agent_groups"]
            except (OSError, ValueError):
                pass
        slots = max(0, policy["limits"]["deep_groups_per_audit"] - max(deep_dispatched, len(existing_groups)))
        expiry = body.consent_expires_at or (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        selected = []
        skipped = []
        for l2_item in l2_spec.get("items", []):
            if not isinstance(l2_item, dict):
                continue
            group_id = l2_item.get("group_id")
            row = batch_rows.get(group_id)
            child_l2 = l2_item.get("spec") if isinstance(l2_item.get("spec"), dict) else {}
            if group_id in existing_groups:
                skipped.append({"group_id": group_id, "reason": "already_scheduled"})
                continue
            if (not isinstance(row, dict) or row.get("state") != "completed"
                    or row.get("quick_assessment") != "investigate"):
                continue
            if len(selected) >= min(MAX_BATCH_ITEMS, slots):
                skipped.append({"group_id": group_id, "reason": "task_deep_group_budget_exhausted"})
                continue
            request = ProgressiveDeepInvestigationRequest(
                job_id=child_l2["job_id"], candidate_id=child_l2["candidate_id"],
                mode="tool_agent", max_steps=min(policy["limits"]["max_tool_steps_per_group"], 12),
                progressive_quick_screen_operation_id=l2["id"], progressive_group_id=group_id,
                consent_nonce=body.consent_nonce,
            )
            bounded, quick_task, preview = _progressive_deep_preview(request, provider)
            binding = preview["progressive_binding"]
            from .agent import (CONSENT_PREVIEW_VERSION, PROMPT_VERSION,
                                REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION)
            child_spec = {
                "job_id": bounded.job_id, "candidate_id": bounded.candidate_id,
                "case_id": None, "experiment_id": None, "mode": "tool_agent",
                "max_output_tokens": bounded.max_output_tokens, "max_steps": bounded.max_steps,
                "max_total_input_tokens": bounded.max_total_input_tokens,
                "max_total_output_tokens": bounded.max_total_output_tokens,
                "timeout_seconds": bounded.timeout_seconds,
                "provider_request_timeout_seconds": 45, "max_provider_retries": 0,
                "continuous_investigation": True, "no_cumulative_token_ceiling": True,
                "source_submission_approved": True,
                "source_consent_sha256": preview["agent_consent_sha256"],
                "progressive_consent_sha256": preview["consent_sha256"],
                "progressive_quick_screen_operation_id": quick_task["id"],
                "progressive_quick_screen_result_sha256": binding["quick_screen_result_sha256"],
                "progressive_quick_screen_batch_group_id": binding.get("quick_screen_batch_group_id"),
                "progressive_audit_operation_id": binding["audit_operation_id"],
                "progressive_group_id": binding["group_id"],
                "progressive_policy": preview["progressive_policy"],
                "progressive_policy_sha256": binding["policy_sha256"],
                "consent_nonce": body.consent_nonce,
                "consent_preview_version": CONSENT_PREVIEW_VERSION,
                "redaction_policy_version": REDACTION_POLICY_VERSION,
                "provider": provider.provider, "provider_model": provider.model,
                "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
                "prompt_version": PROMPT_VERSION, "tool_policy_version": TOOL_POLICY_VERSION,
                "candidate_source_sha256": preview["binding"]["source_sha256"],
                "source_commit": preview["binding"]["commit"],
                "report_sha256": preview["binding"]["report_sha256"],
            }
            selected.append({"group_id": group_id, "spec": child_spec,
                             "disclosure": {
                                 "group_id": group_id, "job_id": child_spec["job_id"],
                                 "candidate_id": child_spec["candidate_id"],
                                 "repository": preview["binding"].get("repository"),
                                 "commit": child_spec["source_commit"],
                                 "report_sha256": child_spec["report_sha256"],
                                 "source_sha256": child_spec["candidate_source_sha256"],
                                 "file": preview["binding"].get("file"),
                                 "allowed_tools": preview.get("allowed_tools", []),
                                 "initial_context": preview.get("initial_context"),
                                 "additional_tool_data_scope": preview.get("additional_tool_data_scope", []),
                                 "disclosure": preview.get("disclosure", []),
                                 "budgets": preview.get("budgets", {}),
                                 "consent_sha256": preview["consent_sha256"],
                             }})
            existing_groups.add(group_id)
        if not selected:
            raise HTTPException(status_code=409, detail="没有剩余预算内可继续的 investigate 组")
        expiry = expiry.replace("Z", "+00:00") if expiry.endswith("Z") else expiry
        consent_manifest = {
            "schema_version": 1, "audit_operation_id": audit_id,
            "l2_batch_operation_id": l2["id"], "l2_batch_result_sha256": l2["result_sha256"],
            "policy_sha256": frozen["policy_sha256"],
            "consent_nonce": body.consent_nonce, "consent_expires_at": expiry,
            "provider_fingerprint": provider.fingerprint, "model": provider.model,
            "selected_group_count": len(selected), "skipped": skipped,
            "items": [{
                "group_id": item["group_id"],
                "progressive_consent_sha256": item["spec"]["progressive_consent_sha256"],
                "source_consent_sha256": item["spec"]["source_consent_sha256"],
                "job_id": item["spec"]["job_id"], "candidate_id": item["spec"]["candidate_id"],
                "report_sha256": item["spec"]["report_sha256"],
                "source_commit": item["spec"]["source_commit"],
            } for item in selected],
        }
        digest = content_sha256(consent_manifest)
        disclosures = [item["disclosure"] for item in selected]
        items = [{"group_id": item["group_id"], "spec": item["spec"]} for item in selected]
        return {
            "eligible": True, "audit_operation_id": audit_id,
            "l2_batch_operation_id": l2["id"], "l2_batch_result_sha256": l2["result_sha256"],
            "progressive_policy": frozen, "provider": provider.public,
            "consent_nonce": body.consent_nonce, "consent_expires_at": expiry,
            "consent_sha256": digest, "consent_manifest": consent_manifest,
            "items": items, "disclosures": disclosures,
            "selected_group_count": len(selected), "skipped": skipped,
            "budget_limits": {
                "deep_groups_per_audit": policy["limits"]["deep_groups_per_audit"],
                "max_model_concurrency": policy["limits"]["max_model_concurrency"],
                "max_cost_usd": policy["limits"]["max_cost_usd"],
                "max_model_calls_per_audit": policy["limits"]["max_model_calls_per_audit"],
                "max_input_tokens_per_audit": policy["limits"]["max_input_tokens_per_audit"],
                "max_output_tokens_per_audit": policy["limits"]["max_output_tokens_per_audit"],
                "max_output_tokens_per_request": policy["limits"].get("max_output_tokens_per_request"),
                "max_tool_steps_per_group": min(policy["limits"]["max_tool_steps_per_group"], 12),
                "max_ai_wall_seconds": policy["limits"]["max_ai_wall_seconds"],
                "cumulative_usage_limits_enforced": True,
            }, "vulnerability_state_after_review": "candidate",
        }

    @router.post("/operations/progressive-deep-investigation-batches/preview")
    def progressive_deep_investigation_batch_preview(body: ProgressiveDeepInvestigationBatchRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        body = _fresh_consent_nonce(body)
        try:
            preview = _progressive_deep_batch_preview(body, provider)
            return {**preview, "items": [{"group_id": row["group_id"],
                                           "candidate_id": row["spec"]["candidate_id"]}
                                          for row in preview["items"]]}
        except HTTPException:
            raise
        except (KeyError, ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @router.post("/operations/progressive-deep-investigation-batches", status_code=201)
    def progressive_deep_investigation_batch(body: ProgressiveDeepInvestigationBatchRequest):
        from datetime import datetime
        from .agent import ProviderConfig
        if body.source_submission_approved is not True:
            raise HTTPException(status_code=428, detail="请先检查本任务全部 L3 范围并明确授权")
        if not body.consent_sha256 or not body.consent_expires_at:
            raise HTTPException(status_code=428, detail="缺少任务级 L3 清单摘要或有效期")
        _require_consent_nonce(body)
        try:
            l2 = ops.get(body.progressive_quick_screen_batch_id)
            audit_id = l2.get("spec", {}).get("audit_operation_id")
            if isinstance(audit_id, str) and audit_id:
                for prior in ops.progressive_operations_for_audit(audit_id):
                    prior_spec = prior.get("spec") if isinstance(prior.get("spec"), dict) else {}
                    if (prior.get("kind") != "progressive_deep_agent_batch"
                            or prior_spec.get("consent_sha256") != body.consent_sha256):
                        continue
                    try:
                        expires = datetime.fromisoformat(body.consent_expires_at.replace("Z", "+00:00"))
                    except (AttributeError, TypeError, ValueError):
                        raise HTTPException(status_code=409, detail="L3 授权有效期无效；请重新预览") from None
                    if (expires.tzinfo is None
                            or prior_spec.get("consent_nonce") != body.consent_nonce
                            or prior_spec.get("consent_expires_at") != body.consent_expires_at
                            or prior_spec.get("audit_operation_id") != audit_id
                            or prior_spec.get("l2_batch_operation_id") != l2.get("id")
                            or prior_spec.get("l2_batch_result_sha256") != l2.get("result_sha256")
                            or not isinstance(prior_spec.get("consent_manifest"), dict)):
                        raise HTTPException(status_code=409, detail="相同 L3 授权已存在但当前绑定已变化；请重新预览")
                    return prior
        except HTTPException:
            raise
        except (KeyError, ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        try:
            preview = _progressive_deep_batch_preview(body, provider)
        except HTTPException:
            raise
        except (KeyError, ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="L2 结果、候选范围、源码、策略或 Provider 已变化；请重新预览")
        spec = {
            "source_submission_approved": True,
            "audit_operation_id": preview["audit_operation_id"],
            "l2_batch_operation_id": preview["l2_batch_operation_id"],
            "l2_batch_result_sha256": preview["l2_batch_result_sha256"],
            "progressive_policy": preview["progressive_policy"],
            "consent_nonce": preview["consent_nonce"],
            "consent_expires_at": preview["consent_expires_at"],
            "consent_sha256": preview["consent_sha256"],
            "consent_manifest": preview["consent_manifest"],
            "items": [{"group_id": item["group_id"],
                       "spec": {**item["spec"], "source_submission_approved_at": now()}}
                      for item in preview["items"]],
            "provider_fingerprint": provider.fingerprint, "provider_model": provider.model,
        }
        try:
            return ops.create("progressive_deep_agent_batch", spec)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @router.post("/operations/agent-investigations/preview")
    def agent_investigation_preview(body: AgentInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        body, policy_snapshot = _agent_policy_request(body)
        body = _fresh_consent_nonce(body)
        _, _, _, preview = _agent_consent_preview(
            body, provider, system_policy_sha256=policy_snapshot["policy_sha256"],
            knowledge_retrieval_enabled=True)
        preview["system_policy"] = policy_snapshot
        preview_budgets = preview.setdefault("budgets", {})
        preview_budgets["max_output_tokens"] = body.max_output_tokens
        preview_budgets["max_output_tokens_per_request"] = body.max_output_tokens
        return preview

    @router.post("/operations/agent-investigations", status_code=201)
    def agent_investigation(body: AgentInvestigationRequest):
        from .agent import CONSENT_PREVIEW_VERSION, PROMPT_VERSION, REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION, ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428,
                                detail="请先查看本次源码外发预览并明确授权：" + provider.endpoint_host)
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少本次源码外发预览指纹，请重新预览")
        _require_consent_nonce(body)
        body, policy_snapshot = _agent_policy_request(body)
        job, report, candidate, preview = _agent_consent_preview(
            body, provider, system_policy_sha256=policy_snapshot["policy_sha256"],
            knowledge_retrieval_enabled=True)
        preview["system_policy"] = policy_snapshot
        if not preview["agent_execution"]["eligible"]:
            raise HTTPException(status_code=409, detail=preview["agent_execution"]["reason"])
        if body.experiment_id:
            baselines = ops.agent_baseline_reviews(body.experiment_id)
            if not any(_r0_review_complete(item, job, report, candidate) for item in baselines):
                raise HTTPException(status_code=409,
                                    detail="实验批次需先为同一固定候选记录 R0 静态人工基线")
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="源码外发预览已过期；模型、候选、模式或预算发生变化，请重新预览")
        if body.case_id:
            if not any(case["id"] == body.case_id for case in store.cases()):
                raise KeyError("case not found")
            linked = any(link["job_id"] == body.job_id and link["candidate_id"] == body.candidate_id
                         for link in _case_links(store, body.case_id))
            if not linked:
                raise ValueError("Agent case binding must already contain this exact job and candidate")
        spec = {
            "job_id": body.job_id, "candidate_id": body.candidate_id, "case_id": body.case_id,
            "experiment_id": body.experiment_id,
            "mode": body.mode, "max_output_tokens": body.max_output_tokens,
            "max_steps": body.max_steps, "max_total_input_tokens": body.max_total_input_tokens,
            "max_total_output_tokens": body.max_total_output_tokens,
            "max_total_model_calls": body.max_total_model_calls, "timeout_seconds": body.timeout_seconds,
            "provider_request_timeout_seconds": 45, "max_provider_retries": 1,
            "continuous_investigation": False,
            "no_cumulative_token_ceiling": False,
            "system_policy": policy_snapshot,
            "system_policy_sha256": policy_snapshot["policy_sha256"],
            "source_submission_approved": True, "source_submission_approved_at": now(),
            "source_consent_sha256": preview["consent_sha256"], "consent_nonce": body.consent_nonce,
            "consent_preview_version": CONSENT_PREVIEW_VERSION,
            "redaction_policy_version": REDACTION_POLICY_VERSION,
            "provider": provider.provider, "provider_model": provider.model,
            "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
            "prompt_version": PROMPT_VERSION,
            "tool_policy_version": TOOL_POLICY_VERSION,
            "knowledge_retrieval_enabled": True,
            "candidate_source_sha256": candidate.get("source_sha256"),
            "source_commit": report["commit"], "report_sha256": job["report_sha256"],
        }
        item = ops.create("agent_investigation", spec)
        if item["spec"].get("source_submission_approved_at") == spec["source_submission_approved_at"]:
            ops.event(item["id"], "source_consent",
                      "User approved preview sha256=" + preview["consent_sha256"] +
                      " for " + provider.endpoint_host)
        return ops.get(item["id"])

    def _agent_batch_preview(body, provider, *, system_policy_sha256=None, system_policy=None):
        from .progressive_triage.policy import PolicyStore, manual_candidate_batch_limit
        scope_snapshot = (system_policy if isinstance(system_policy, dict)
                          else PolicyStore(settings.data_dir).read())
        scope_policy = scope_snapshot.get("policy", scope_snapshot)
        scope_limit = manual_candidate_batch_limit(scope_policy, body.mode)
        if len(body.candidate_ids) > scope_limit:
            raise HTTPException(status_code=409, detail=(
                f"本次最多选择 {scope_limit} 条候选，范围来自系统设置的智能审计策略；请调整选择或修改设置后重新预览"))
        if len(set(body.candidate_ids)) != len(body.candidate_ids):
            raise ValueError("候选列表包含重复 ID")
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("只允许预览已有完整报告的候选")
        report = service.read_report(settings, job)
        children = []
        for candidate_id in body.candidate_ids:
            child = _agent_policy_child_request(
                body, candidate_id=candidate_id, mode=body.mode)
            _, _, candidate, preview = _agent_consent_preview(
                child, provider, system_policy_sha256=system_policy_sha256)
            children.append({"candidate_id": candidate_id, "file": candidate["file"],
                             "line": candidate.get("line"), "preview": preview})
        tool_agent = body.mode == "tool_agent"
        manifest = {"version": 2, "job_id": body.job_id, "report_sha256": job["report_sha256"],
                    "candidate_scope_policy_sha256": system_policy_sha256,
                    "candidate_scope_limit": scope_limit,
                    "consent_nonce": body.consent_nonce,
                    "provider_fingerprint": provider.fingerprint,
                    "candidates": [{"candidate_id": item["candidate_id"],
                                    "consent_sha256": item["preview"]["consent_sha256"]} for item in children],
                    "mode": body.mode,
                    "continuous_investigation": False,
                    "no_cumulative_token_ceiling": False,
                    "local_cumulative_token_budget": "bounded_by_system_policy",
                    "local_cumulative_usd_budget": "token_bound_advisory_only",
                    "local_total_model_call_budget": "bounded_by_system_policy",
                    "local_total_tool_call_budget": "bounded_by_system_policy",
                    "local_total_wall_time_budget": "bounded_by_system_policy",
                    "max_output_tokens_per_request": body.max_output_tokens,
                    "provider_request_timeout_seconds": 45,
                    "max_validation_repairs_per_tool_agent": 2 if tool_agent else 0,
                    "max_skeptic_requests_per_tool_agent": 1 if tool_agent else 0}
        consent = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        blocked_candidate_ids = [item["candidate_id"] for item in children
                                 if not item["preview"]["agent_execution"]["eligible"]]
        repair_limits = [item["preview"].get("budgets", {}).get("max_validation_repairs", 0)
                         for item in children]
        max_repairs_per_candidate = (
            None if any(limit is None for limit in repair_limits)
            else max(repair_limits, default=0))
        max_skeptic_per_candidate = max(
            (item["preview"].get("budgets", {}).get("max_skeptic_calls", 0)
             for item in children), default=0)
        aggregate_cost_estimate = _aggregate_agent_budget_cost_estimates(
            item["preview"].get("budget_cost_estimate") for item in children)
        model_call_limits = [item["preview"]["budgets"]["max_total_model_calls"] for item in children]
        aggregate_model_call_limit = (
            None if any(limit is None for limit in model_call_limits) else sum(model_call_limits))
        aggregate_budget = {
            "authorized_candidate_count": len(children),
            "candidate_scope_limit": scope_limit,
            "max_total_model_calls": aggregate_model_call_limit,
            "single_shot_candidate_request_count": len(children) if body.mode == "single_shot" else 0,
            "requests_per_candidate": 1 if body.mode == "single_shot" else None,
            "continuous_until_terminal_condition": False,
            "max_output_tokens_per_provider_request": body.max_output_tokens,
            "provider_request_timeout_seconds": 45,
            "local_cumulative_token_budget": "bounded_by_system_policy",
            "local_cumulative_cost_budget": "token_bound_advisory_only",
            "local_total_model_call_budget": "bounded_by_system_policy",
            "local_total_tool_call_budget": "bounded_by_system_policy",
            "local_total_wall_time_budget": "bounded_by_system_policy",
            "max_validation_repair_attempts_per_candidate": max_repairs_per_candidate,
            "max_skeptic_requests_per_candidate": max_skeptic_per_candidate,
            "tool_agent_continuous": False,
        }
        return {"schema_version": 1, "consent_sha256": consent,
                "consent_nonce": body.consent_nonce, "provider": provider.public,
                "job_id": body.job_id, "report_sha256": job["report_sha256"],
                "candidate_count": len(children), "candidates": children,
                "aggregate_budget_cost_estimate": aggregate_cost_estimate,
                "blocked_candidate_ids": blocked_candidate_ids,
                "aggregate_budget": aggregate_budget,
                "disclosure": ["Each selected candidate creates one independent Agent operation.",
                               ("The candidate count is bounded by this explicitly authorized list. Each task inherits cumulative token, call, tool-step, and wall-time caps from System Settings; USD is advisory and Provider billing/account quota still apply."),
                               *( [children[0]["preview"].get("stage_disclosure", "")] if children else [] ),
                               "Exact candidate metadata, bounded source excerpt, and approved fixed-commit tool data may be sent.",
                               "No operation is created until this aggregate preview is approved; batch creation is atomic.",
                               "A model assessment remains a candidate and requires human review."]}

    @router.post("/operations/agent-investigations/batch/preview")
    def agent_investigation_batch_preview(body: AgentBatchInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        body, policy_snapshot = _agent_policy_request(body)
        body = _fresh_consent_nonce(body)
        preview = _agent_batch_preview(
            body, provider, system_policy_sha256=policy_snapshot["policy_sha256"],
            system_policy=policy_snapshot)
        preview["system_policy"] = policy_snapshot
        return preview

    @router.post("/operations/agent-investigations/batch", status_code=201)
    def agent_investigation_batch(body: AgentBatchInvestigationRequest):
        from .agent import CONSENT_PREVIEW_VERSION, PROMPT_VERSION, REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION, ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428, detail="请先查看整批源码外发预览并明确授权：" + provider.endpoint_host)
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少整批预览指纹，请重新预览")
        _require_consent_nonce(body)
        body, policy_snapshot = _agent_policy_request(body)
        preview = _agent_batch_preview(
            body, provider, system_policy_sha256=policy_snapshot["policy_sha256"],
            system_policy=policy_snapshot)
        preview["system_policy"] = policy_snapshot
        if preview["blocked_candidate_ids"]:
            raise HTTPException(status_code=409, detail=(
                "批次包含缺少可读取固定源码片段的候选，请核对文件、行号与源码快照：" +
                ", ".join(preview["blocked_candidate_ids"])))
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="整批源码外发预览已过期，请重新预览")
        batch_id = hashlib.sha256((preview["consent_sha256"] + now()).encode()).hexdigest()[:32]
        count = len(preview["candidates"])
        specs = []
        for index, item in enumerate(preview["candidates"], 1):
            child_preview = item["preview"]
            binding = child_preview["binding"]
            specs.append({
                "job_id": body.job_id, "candidate_id": item["candidate_id"], "case_id": None,
                "experiment_id": None, "mode": body.mode,
                "max_output_tokens": body.max_output_tokens,

                "max_steps": body.max_steps, "max_total_input_tokens": body.max_total_input_tokens,

                "max_total_output_tokens": body.max_total_output_tokens, "timeout_seconds": body.timeout_seconds,
                "max_total_model_calls": body.max_total_model_calls,
                "provider_request_timeout_seconds": 45, "max_provider_retries": 1,
                "continuous_investigation": False,
                "no_cumulative_token_ceiling": False,
                "system_policy": policy_snapshot,
                "system_policy_sha256": policy_snapshot["policy_sha256"],
                "source_submission_approved": True, "source_submission_approved_at": now(),
                "source_consent_sha256": child_preview["consent_sha256"], "consent_nonce": body.consent_nonce,
                "consent_preview_version": CONSENT_PREVIEW_VERSION,
                "redaction_policy_version": REDACTION_POLICY_VERSION,
                "provider": provider.provider, "provider_model": provider.model,
                "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
                "prompt_version": PROMPT_VERSION, "tool_policy_version": TOOL_POLICY_VERSION,
                "candidate_source_sha256": binding.get("source_sha256"),
                "source_commit": binding["commit"], "report_sha256": binding["report_sha256"],
                "batch_id": batch_id, "batch_consent_sha256": preview["consent_sha256"],
                "batch_index": index, "batch_count": count,
            })
        items = ops.create_agent_batch(specs)
        batch_id = items[0]["spec"].get("batch_id", batch_id)
        return {"batch_id": batch_id, "batch_consent_sha256": preview["consent_sha256"],
                "created_count": len(items), "operations": items,
                "note": "每个候选一个独立任务；结论仍为候选，等待人工审核。"}

    def _agent_pair_previews(body, provider, *, system_policy_sha256=None):
        from .agent import _prepare_candidate_context
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("只允许预览已有完整报告的候选")
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        source_context = (job, report, candidate)
        prepared = _prepare_candidate_context(
            settings, store, job, report, candidate, include_knowledge=True)
        previews = []
        for mode in ("single_shot", "tool_agent"):
            child = _agent_policy_child_request(
                body, candidate_id=body.candidate_id, mode=mode,
                experiment_id=body.experiment_id)
            job, report, candidate, preview = _agent_consent_preview(
                child, provider, system_policy_sha256=system_policy_sha256,
                knowledge_retrieval_enabled=True, source_context=source_context,
                prepared_context=prepared)
            if not preview["agent_execution"]["eligible"]:
                raise HTTPException(status_code=409, detail=preview["agent_execution"]["reason"])
            baselines = ops.agent_baseline_reviews(body.experiment_id)
            if not any(_r0_review_complete(item, job, report, candidate) for item in baselines):
                raise HTTPException(status_code=409,
                                    detail="配对实验需先为同一固定候选记录 R0 静态人工基线")
            previews.append({"mode": mode, "preview": preview,
                             "candidate": candidate, "job": job, "report": report})
        manifest = {"version": 2, "experiment_id": body.experiment_id, "case_id": body.case_id,
                    "consent_nonce": body.consent_nonce,
                    "provider_fingerprint": provider.fingerprint,
                    "arms": [{"mode": item["mode"],
                              "consent_sha256": item["preview"]["consent_sha256"]} for item in previews],
                    "single_shot_request_count": 1,
                    "tool_agent_continuous": False,
                    "tool_agent_no_cumulative_token_ceiling": False,
                    "tool_agent_max_output_tokens_per_request": body.max_output_tokens,
                    "provider_request_timeout_seconds": 45}
        consent = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        r2_repair_limit = previews[1]["preview"].get("budgets", {}).get("max_validation_repairs", 0)
        r2_skeptic_limit = previews[1]["preview"].get("budgets", {}).get("max_skeptic_calls", 0)
        aggregate_cost_estimate = _aggregate_agent_budget_cost_estimates(
            item["preview"].get("budget_cost_estimate") for item in previews)
        aggregate_budget = {
            "single_shot_model_calls": 1,
            "tool_agent_max_total_model_calls": previews[1]["preview"]["budgets"]["max_total_model_calls"],
            "tool_agent_max_output_tokens_per_request": body.max_output_tokens,
            "provider_request_timeout_seconds": 45,
            "tool_agent_local_cumulative_token_budget": "bounded_by_system_policy",
            "tool_agent_local_cumulative_cost_budget": "token_bound_advisory_only",
            "tool_agent_local_total_wall_time_budget": "bounded_by_system_policy",
            "tool_agent_max_validation_repair_attempts": r2_repair_limit,
            "tool_agent_max_skeptic_requests": r2_skeptic_limit,
        }
        return {"schema_version": 1, "consent_sha256": consent,
                "consent_nonce": body.consent_nonce, "experiment_id": body.experiment_id,
                "case_id": body.case_id, "provider": provider.public,
                "candidate": previews[0]["preview"]["binding"],
                "arms": [{"mode": item["mode"], "preview": item["preview"]} for item in previews],
                "aggregate_budget_cost_estimate": aggregate_cost_estimate,
                "aggregate_budget": aggregate_budget,
                "disclosure": ["This creates exactly one R1 and one R2 task for the same fixed candidate.",
                               "R0 static triage is already recorded and matched to this report and source.",
                               "Each arm receives its own consent-bound initial context; R2 may additionally use only the fixed-commit tools shown in its preview.",
                               previews[1]["preview"].get("stage_disclosure", ""),
                               "R1 uses one request. R2 inherits cumulative token, call, tool-step, and wall-time caps from System Settings. USD remains advisory; actual billing/account quota is controlled by the Provider.",
                               "All operation rows are created atomically.",
                               "Both model outputs remain candidate-only and must receive blind human review."]}

    @router.post("/operations/agent-investigations/paired/preview")
    def agent_investigation_pair_preview(body: AgentPairedInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        body, policy_snapshot = _agent_policy_request(body)
        body = _fresh_consent_nonce(body)
        preview = _agent_pair_previews(
            body, provider, system_policy_sha256=policy_snapshot["policy_sha256"])
        preview["system_policy"] = policy_snapshot
        return preview

    @router.post("/operations/agent-investigations/paired", status_code=201)
    def agent_investigation_pair(body: AgentPairedInvestigationRequest):
        from .agent import CONSENT_PREVIEW_VERSION, PROMPT_VERSION, REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION, ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428, detail="请先查看 R1/R2 整组源码外发预览并明确授权：" + provider.endpoint_host)
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少配对预览指纹，请重新预览")
        _require_consent_nonce(body)
        body, policy_snapshot = _agent_policy_request(body)
        preview = _agent_pair_previews(
            body, provider, system_policy_sha256=policy_snapshot["policy_sha256"])
        preview["system_policy"] = policy_snapshot
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="R1/R2 配对预览已过期，请重新预览")
        if body.case_id:
            if not any(case["id"] == body.case_id for case in store.cases()):
                raise KeyError("case not found")
            linked = any(link["job_id"] == body.job_id and link["candidate_id"] == body.candidate_id
                         for link in _case_links(store, body.case_id))
            if not linked:
                raise ValueError("Agent case binding must already contain this exact job and candidate")
        pair_id = hashlib.sha256((preview["consent_sha256"] + now()).encode()).hexdigest()[:32]
        specs = []
        for index, arm in enumerate(preview["arms"], 1):
            arm_preview = arm["preview"]
            binding = arm_preview["binding"]
            specs.append({
                "job_id": body.job_id, "candidate_id": body.candidate_id, "case_id": body.case_id,
                "experiment_id": body.experiment_id, "mode": arm["mode"],
                "max_output_tokens": body.max_output_tokens,

                "max_steps": body.max_steps, "max_total_input_tokens": body.max_total_input_tokens,

                "max_total_output_tokens": body.max_total_output_tokens,
                "max_total_model_calls": body.max_total_model_calls, "timeout_seconds": body.timeout_seconds,
                "provider_request_timeout_seconds": 45, "max_provider_retries": 1,
                "continuous_investigation": False,
                "no_cumulative_token_ceiling": False,
                "system_policy": policy_snapshot,
                "system_policy_sha256": policy_snapshot["policy_sha256"],
                "source_submission_approved": True, "source_submission_approved_at": now(),
                "source_consent_sha256": arm_preview["consent_sha256"], "consent_nonce": body.consent_nonce,
                "consent_preview_version": CONSENT_PREVIEW_VERSION,
                "redaction_policy_version": REDACTION_POLICY_VERSION,
                "provider": provider.provider, "provider_model": provider.model,
                "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
                "prompt_version": PROMPT_VERSION, "tool_policy_version": TOOL_POLICY_VERSION,
                "knowledge_retrieval_enabled": True,
                "candidate_source_sha256": binding.get("source_sha256"),
                "source_commit": binding["commit"], "report_sha256": binding["report_sha256"],
                "pair_id": pair_id, "pair_consent_sha256": preview["consent_sha256"],
                "pair_index": index, "pair_count": 2,
            })
        items = ops.create_agent_batch(specs)
        pair_id = items[0]["spec"].get("pair_id", pair_id)
        return {"pair_id": pair_id, "pair_consent_sha256": preview["consent_sha256"],
                "created_count": len(items), "operations": items,
                "note": "R1/R2 各一个固定候选任务；仅完成配对运行，不代表实验效果。"}

    @router.post("/operations/validations", status_code=201)
    def validation(body: ValidationRequest):
        case = store.cases()
        if not any(c["id"] == body.case_id for c in case):
            raise KeyError("case not found")
        if body.harness_id in CPP_IDS:
            if any((body.target_repository_id, body.target_commit,
                    body.cutils_repository_id, body.cutils_commit)):
                raise ValueError("C++ component tests do not accept target repository or commit overrides")
            test = next(item for item in validation_catalog() if item["id"] == body.harness_id)
            if test["source_status"] != "available":
                raise ValueError(test["source_reason"] or "fixed harness inputs are unavailable")
            manifest_file = manifest_path(body.harness_id)
            return ops.create("validation", {
                **body.model_dump(), "validation_scope": test["scope"],
                "manifest_sha256": hashlib.sha256(manifest_file.read_bytes()).hexdigest(),
                "timeout_seconds": body.timeout_seconds, "memory_mb": 2048,
            })
        if not all((body.target_repository_id, body.target_commit,
                    body.cutils_repository_id, body.cutils_commit)):
            raise ValueError("AUTH-01 requires a target revision and commonlibrary_c_utils support revision")
        target = store.repository(body.target_repository_id)
        cutils = store.repository(body.cutils_repository_id)
        service.check_repository(settings, target["path"])
        service.check_repository(settings, cutils["path"])
        if target["name"] != "openharmony/inputmethod_imf":
            raise ValueError("AUTH-01 harness is pinned to openharmony/inputmethod_imf")
        pinned_target = {"e663b47013d534a56165ab7467fbb3e14bf7172b", "5eaddcab19bc4b22544f4bee1e8894fc2d6505dc"}
        target_commit = service.revision(target, body.target_commit)["commit"]
        if target_commit not in pinned_target:
            raise ValueError("AUTH-01 only accepts its two fixed source revisions")
        links = _case_links(store, body.case_id)
        manifest_file = manifest_path(AUTH_ID)
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        expected_source = manifest["sources"][0]["path"]
        linked = False
        for link in links:
            linked_job = store.job(link["job_id"])
            linked_repo = store.repository(linked_job["repository_id"])
            if linked_repo["name"] == target["name"] and linked_job["spec"]["commit"] == target_commit:
                candidate = service.finding(service.read_report(settings, linked_job), link["candidate_id"])
                if candidate["file"] == expected_source:
                    linked = True
        if not linked:
            raise ValueError("case must link a candidate from the pinned AUTH-01 source at the selected commit")
        if cutils["name"] != "openharmony/commonlibrary_c_utils":
            raise ValueError("AUTH-01 requires the registered commonlibrary_c_utils repository")
        cutils_commit = service.revision(cutils, body.cutils_commit)["commit"]
        return ops.create("validation", {**body.model_dump(), "target_commit": target_commit,
            "target_repository": target["name"], "target_path": target["path"], "cutils_path": cutils["path"],
            "cutils_commit": cutils_commit, "validation_scope": "component_harness",
            "manifest_sha256": hashlib.sha256(manifest_file.read_bytes()).hexdigest(),
            "timeout_seconds": body.timeout_seconds, "memory_mb": 2048})

    @router.get("/validation-tests")
    def validation_tests():
        return {"tests": validation_catalog()}

    @router.post("/operations/investigations", status_code=201)
    def investigation(body: InvestigationRequest):
        job = store.job(body.job_id)
        report = service.read_report(settings, job)
        service.finding(report, body.candidate_id)
        return ops.create("investigation", {**body.model_dump(), "timeout_seconds": 60,
                                             "memory_mb": 512})

    @router.get("/scans/{key}/investigation-priority")
    def scan_investigation_priority(key: str):
        from .investigation_priority import investigation_priority
        job = store.job(key)
        if not job.get("report_sha256"):
            raise ValueError("No committed report; initial analysis is not available")
        report = service.read_report(settings, job)
        return investigation_priority(report, key, job["report_sha256"],
            ops.agent_investigations_for_job(key, job["report_sha256"]), ops.result)

    @router.get("/scans/{key}/triage")
    def scan_triage_summary(key: str):
        job = store.job(key)
        authorization = store.triage_authorization(key)
        auth_view = None
        if authorization:
            snapshot = authorization["snapshot"]
            auth_view = {
                "authorized": True,
                "revoked": authorization["revoked"],
                "consent_sha256": authorization["consent_sha256"],
                "created_at": authorization["created_at"],
                "revoked_at": authorization["revoked_at"],
                "provider": snapshot.get("provider"),
                "candidate_selection": "all eligible candidates in the fixed scope",
                "conditional_r2_selection": "all critical/high candidates with unresolved source obligations",
                "budget": snapshot.get("budgets"),
                "estimated_cost": snapshot.get("estimated_cost"),
                "cost_budget": snapshot.get("cost_budget"),
                "platform_cost_budget_enforced": bool(
                    (snapshot.get("cost_budget") or {}).get("platform_enforced")),
                "hard_spend_cap": False,
            }
        cancellation = ops.triage_cancellation(key, job.get("report_sha256"))
        if not job.get("report_sha256"):
            waiting_state = ("cancelled" if cancellation else "stopped"
                             if authorization and authorization["revoked"] else "waiting_for_scan")
            return {
                "schema_version": 2,
                "audit_id": key,
                "job_id": key,
                "state": waiting_state,
                "scan_status": job["status"],
                "triage_status": waiting_state,
                "report_status": "not_ready",
                "scan_progress": {"status": job["status"], "stage": job.get("stage"),
                                  "report_ready": False},
                "triage_progress": {"state": "cancelled" if cancellation else "stopped" if authorization and authorization["revoked"] else "waiting_for_scan",
                                     "candidate_count": None,
                                     "authorized_candidate_count": int((auth_view or {}).get("candidate_limit") or 0),
                                     "created_count": 0, "queued_count": 0, "running_count": 0,
                                     "planned_count": 0, "completed_count": 0,
                                     "completed_with_limitations_count": 0, "failed_count": 0,
                                     "pending_count": 0, "cancelled_count": 0,
                                     "stop_requested_count": 0, "not_triaged_count": None},
                "report_sha256": None,
                "counts": {},
                "items": [],
                "batches": [],
                "authorization": auth_view or {"authorized": False, "revoked": False},
                "limitation": "静态报告尚未提交，模型研判未开始。",
            }
        items = ops.agent_investigations_for_job(key, job["report_sha256"])
        for summary in items:
            operation_item = ops.get(summary["id"])
            summary["retry_available"] = _smart_operation_retry_available(
                store, ops, operation_item)
            summary["investigation_limitations"] = []
            if operation_item.get("result_sha256"):
                try:
                    operation_result = ops.result(summary["id"])
                    summary["assessment"] = (operation_result.get("agent_assessment") or {}).get(
                        "assessment", "unknown")
                    artifact = operation_result.get("artifact_generation") or {}
                    summary["artifact_generation"] = {key: artifact.get(key) for key in ("status", "reason_code")}
                    summary["validation_status"] = operation_result.get("structured_answer_validation")
                    summary["failure_code"] = operation_result.get("structured_answer_validation_error_code")
                    summary["validation_diagnostic"] = operation_result.get("validation_diagnostic") or (
                        operation_result.get("skeptic_review") or {}).get("validation_diagnostic")
                    summary["investigation_limitations"] = [
                        str(value) for value in operation_result.get("limitations", [])
                        if isinstance(value, str) and any(
                            marker in value.lower()
                            for marker in ("24 kib", "per-request", "single-request", "unknown-outcome")
                        )
                    ]
                except (KeyError, ValueError):
                    summary["assessment"] = "unknown"
                    summary["investigation_limitations"] = [
                        "调查结果不可读取；候选保持未知。"
                    ]
        batches = ops.triage_batches_for_job(key, job["report_sha256"])
        counts = {}
        for item in items:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        batch_views = []
        for batch in batches:
            operations = ops.smart_triage_operations(batch["id"])
            stopping = any(item["status"] == "running" and item.get("cancel_requested") for item in operations)
            r1_ids = set(batch.get("operation_ids", []))
            r2_ids = set(batch.get("r2_operation_ids", []))
            r1_operations = [item for item in operations if item["id"] in r1_ids]
            r2_operations = [item for item in operations if item["id"] in r2_ids]
            progress = _classify_intelligent_review(
                batch, r1_operations, r2_operations,
                revoked=bool(authorization and authorization["revoked"]),
            )
            batch_state = "stopping" if stopping else "cancelled" if cancellation else progress["state"]
            created_operations = operations
            batch_views.append({
                "id": batch["id"], "state": batch_state,
                "candidate_count": batch["candidate_count"],
                "authorized_candidate_count": int((auth_view or {}).get("candidate_limit") or 0),
                "created_count": len(created_operations),
                "queued_count": sum(1 for item in created_operations if item["status"] == "queued"),
                "running_count": sum(1 for item in created_operations if item["status"] == "running"),
                "not_triaged_count": max(0, int(batch["candidate_count"]) - int(batch.get("selected_count") or 0)),
                "r1_progress": progress["r1"], "r2_progress": progress["r2"],
                "selected_count": batch["selected_count"],
                "candidate_manifest": batch["candidate_manifest"],
                "operation_ids": batch["operation_ids"],
                "conditional_r2": {
                    "state": batch.get("r2_status", "not_requested"),
                    "operation_ids": batch.get("r2_operation_ids", []),
                    "candidate_manifest": batch.get("r2_candidate_manifest", []),
                    "decision_sha256": batch.get("r2_decision_sha256"),
                    "error": batch.get("r2_error"),
                },
                "error": batch["error"],
            })
        r2_waiting = any(batch.get("r2_status") == "awaiting_r1" for batch in batches)
        stop_requested_count = sum(
            1 for item in items if item["status"] == "running" and item.get("cancel_requested")
        )
        cancelled_count = sum(1 for item in items if item["status"] == "cancelled")
        if cancellation and stop_requested_count:
            state = "stopping"
        elif cancellation:
            state = "cancelled"
        elif authorization and authorization["revoked"] and stop_requested_count:
            state = "stopping"
        elif job["spec"].get("audit_mode") == "static_only":
            state = "not_requested"
        elif r2_waiting:
            state = "in_progress"
        elif items:
            if any(item["status"] in {"queued", "running"} for item in items):
                state = "stopped" if authorization and authorization["revoked"] else "in_progress"
            elif all(item["status"] in END for item in items):
                if all(item["status"] in {"completed", "completed_with_limitations"} for item in items):
                    state = ("completed_with_limitations"
                             if any(item["status"] == "completed_with_limitations" for item in items)
                             else "completed")
                else:
                    state = "partially_completed"
            else:
                state = "in_progress"
        elif authorization and authorization["revoked"]:
            state = "stopped"
        elif batch_views:
            state = batch_views[-1]["state"]
        elif authorization:
            state = "queued"
        else:
            state = "waiting_for_authorization"
        candidate_count = sum(batch.get("candidate_count", 0) for batch in batches) or None
        planned_count = len(items)
        if candidate_count is None and items:
            candidate_count = len({item.get("candidate_id") for item in items if item.get("candidate_id")})
        if candidate_count is None and not items:
            try:
                candidate_count = len(service.findings(service.read_report(settings, job)))
            except FileNotFoundError:
                # Some focused API tests stub a report hash without publishing an artifact.
                # Production report-integrity errors remain visible and fail closed.
                candidate_count = None
        if (candidate_count == 0 and not batches and not items
                and job["spec"].get("audit_mode") == "standard_review"):
            state = "no_eligible_candidates"
        completed_count = sum(1 for item in items if item["status"] == "completed")
        completed_with_limitations_count = sum(
            1 for item in items if item["status"] == "completed_with_limitations"
        )
        failed_count = sum(1 for item in items if item["status"] in {"failed", "timed_out", "interrupted"})
        pending_count = sum(1 for item in items if item["status"] in {"queued", "running"})
        manifest_not_triaged = sum(
            1 for batch in batches for row in batch.get("candidate_manifest", [])
            if isinstance(row, dict) and row.get("state") == "not_triaged"
        )
        not_triaged_count = (max(candidate_count - planned_count, manifest_not_triaged)
                             if candidate_count is not None else None)
        return {
            "schema_version": 2,
            "audit_id": key,
            "job_id": key,
            "state": state,
            "scan_status": job["status"],
            "triage_status": state,
            "report_status": ("ready_with_limitations"
                              if job["status"] == "completed_with_limitations"
                              else "ready" if job["status"] == "completed" else "available"),
            "scan_progress": {"status": job["status"], "stage": job.get("stage"),
                              "report_ready": True, "report_sha256": job["report_sha256"]},
            "triage_progress": {
                "state": state, "candidate_count": candidate_count,
                "authorized_candidate_count": int((auth_view or {}).get("candidate_limit") or 0),
                "created_count": planned_count,
                "queued_count": counts.get("queued", 0),
                "running_count": counts.get("running", 0),
                "planned_count": planned_count, "completed_count": completed_count,
                "completed_with_limitations_count": completed_with_limitations_count,
                "failed_count": failed_count, "pending_count": pending_count,
                "cancelled_count": cancelled_count,
                "stop_requested_count": stop_requested_count,
                "r2_waiting_count": sum(1 for batch in batches if batch.get("r2_status") == "awaiting_r1"),
                "not_triaged_count": not_triaged_count,
            },
            "report_sha256": job["report_sha256"],
            "counts": counts,
            "items": items,
            "batches": batch_views,
            "authorization": auth_view or {"authorized": False, "revoked": False},
            "authorization_required": not bool(authorization),
            "limitation": "模型辅助研判输出仍为待复核候选或未知状态；高优先级或模型倾向不能自动确认漏洞。未入选、未授权、超出候选授权数或队列保护上限的候选仍是未研判，不代表安全。",
        }

    @router.post("/scans/{key}/triage/cancel")
    def cancel_scan_triage(key: str):
        job = store.job(key)
        cancellation = ops.cancel_triage_for_job(key, job.get("report_sha256"))
        return {**scan_triage_summary(key), "cancellation": cancellation}

    @router.post("/scans/{key}/triage/revoke")
    def revoke_scan_triage_authorization(key: str, body: TriageAuthorizationRevocationRequest):
        job = store.job(key)
        authorization = store.revoke_triage_authorization(key, body.consent_sha256)
        for operation in ops.list():
            spec = operation.get("spec", {})
            if (spec.get("job_id") == key
                    and spec.get("triage_authorization_sha256") == body.consent_sha256
                    and operation["status"] in {"queued", "running"}):
                ops.cancel(operation["id"])
        return scan_triage_summary(job["id"])

    @router.get("/scans/{key}/risks")
    def scan_risks(key: str, offset: int = 0, limit: int = 100,
                   candidate_id: str | None = None):
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("invalid pagination")
        if candidate_id is not None and (not candidate_id.strip() or len(candidate_id) > 200):
            raise ValueError("candidate_id must contain 1 to 200 characters")
        job = store.job(key)
        if not job.get("report_sha256"):
            return {"audit_id": key, "state": "waiting_for_scan", "items": [], "counts": {}}
        report = service.read_report(settings, job)
        from .smart_audit import risk_snapshot as build_risk_snapshot
        snapshot = build_risk_snapshot(settings, store, ops, job, report)
        confirmed_cases = _validated_cases_for_audit(store, ops, key)
        snapshot["validated_vulnerability"] = len(confirmed_cases)
        snapshot["confirmed_cases"] = confirmed_cases
        items = snapshot["items"]
        if candidate_id is not None:
            items = [item for item in items if item.get("candidate_id") == candidate_id]
        return {**{name: value for name, value in snapshot.items() if name != "items"},
                "total": len(items), "items": items[offset:offset + limit]}

    @router.get("/scans/{key}/coverage")
    def scan_coverage(key: str):
        job = store.job(key)
        if not job.get("report_sha256"):
            return {"audit_id": key, "state": "waiting_for_scan", "scan_status": job["status"]}
        report = service.read_report(settings, job)
        from .smart_audit import coverage_snapshot
        triage = scan_triage_summary(key)
        return {"schema_version": 1, "audit_id": key,
                "report_sha256": job["report_sha256"],
                "coverage": coverage_snapshot(job, report),
                "scan_progress": triage["scan_progress"],
                "triage_progress": triage["triage_progress"]}

    @router.get("/overview/risks")
    def audit_risk_overview(
        scan_limit: int = 10,
        offset: int = 0,
        limit: int = 12,
        risk_tier: str | None = None,
        triage_state: str | None = None,
        repository: str | None = None,
        detector_id: str | None = None,
        q: str = "",
    ):
        if not 1 <= scan_limit <= 20:
            raise ValueError("scan_limit must be between 1 and 20")
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("offset must be non-negative and limit between 1 and 100")
        tier_names = ("high_confidence_candidate", "further_validation",
                      "low_priority_manual", "unknown_source_binding")
        triage_states = {
            "not_requested", "not_triaged", "waiting_for_authorization", "waiting_for_scan",
            "not_started", "queued", "running", "in_progress", "stopping", "cancelled",
            "completed", "completed_with_limitations", "partially_completed", "blocked",
            "blocked_authorization_changed", "no_eligible_candidates", "stopped", "failed",
            "timed_out", "interrupted", "awaiting_r1", "candidate_limit_reached", "budget_limited",
            "candidate_limit_exceeded", "queue_limit_exceeded", "not_needed",
            "failed_selection", "selected", "not_selected", "unresolved",
        }
        if risk_tier is not None and risk_tier not in tier_names:
            raise ValueError("unsupported risk_tier")
        if triage_state is not None and triage_state not in triage_states:
            raise ValueError("unsupported triage_state")
        if repository is not None and (len(repository) > 200 or not repository.strip()):
            raise ValueError("repository filter must contain 1 to 200 characters")
        if detector_id is not None and (len(detector_id) > 200 or not detector_id.strip()):
            raise ValueError("detector_id filter must contain 1 to 200 characters")
        query = q.strip()
        if len(query) > 160:
            raise ValueError("q must be at most 160 characters")
        jobs = [job for job in store.jobs() if job.get("report_sha256")]
        selected = jobs[:scan_limit]
        from .smart_audit import risk_snapshot as build_risk_snapshot
        tier_counts = {name: 0 for name in tier_names}
        triage_counts = {}
        candidate_items = []
        limitations = []
        evaluated = 0
        validated_count = 0
        for job in selected:
            try:
                report = service.read_report(settings, job)
                risk = build_risk_snapshot(settings, store, ops, job, report)
                confirmed_cases = _validated_cases_for_audit(store, ops, job["id"])
            except Exception as exc:
                limitations.append({
                    "audit_id": job["id"],
                    "reason": "saved report could not be verified: " + type(exc).__name__,
                })
                continue
            evaluated += 1
            for tier in tier_names:
                tier_counts[tier] += int(risk.get("counts", {}).get(tier, 0))
            for state, count in risk.get("triage_counts", {}).items():
                triage_counts[state] = triage_counts.get(state, 0) + int(count)
            validated_count += len(confirmed_cases)
            confirmed_case_links = {}
            for validated_case in confirmed_cases:
                for candidate_id in validated_case["candidate_ids"]:
                    confirmed_case_links.setdefault(candidate_id, []).append(validated_case["case_id"])
            for item in risk.get("items", []):
                candidate_items.append({
                    "audit_id": job["id"],
                    "repository": job["spec"].get("repository"),
                    "commit": job["spec"].get("commit"),
                    "created_at": job.get("created_at"),
                    "candidate_id": item.get("candidate_id"),
                    "detector_id": item.get("detector_id"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "rule_id": item.get("rule_id"),
                    "severity": item.get("severity", "unknown"),
                    "vulnerability_state": item.get("vulnerability_state", "candidate"),
                    "risk_tier": item.get("risk_tier"),
                    "risk_tier_label": item.get("risk_tier_label"),
                    "confidence_basis": item.get("confidence_basis"),
                    "severity": item.get("severity", "unknown"),
                    "severity_label": item.get("severity_label", "未分级"),
                    "severity_evidence": item.get("severity_evidence", "insufficient_evidence"),
                    "severity_basis": item.get("severity_basis"),
                    # A validated investigation case can link multiple observations;
                    # link it for navigation, but do NOT claim each observation was
                    # individually proven a product vulnerability.
                    "vulnerability_state": item.get("vulnerability_state", "candidate"),
                    "validated_case_ids": sorted(confirmed_case_links.get(item["candidate_id"], [])),
                    "human_review_status": item.get("human_review_status", "unassessed"),
                    "triage_state": item.get("triage", {}).get("state"),
                    # Pass only the source-bound, candidate-only assessment
                    # signal produced by smart_audit after result SHA and
                    # report inventory binding checks. Keep operation_id for
                    # direct navigation to the exact immutable Agent result.
                    "agent_signal": item.get("agent_signal"),
                    "reason": "；".join(item.get("reasons", [])),
                })
        order = {"high_confidence_candidate": 0, "further_validation": 1,
                 "unknown_source_binding": 2, "low_priority_manual": 3}
        candidate_items.sort(key=lambda row: (
            order.get(row["risk_tier"], 4),
            row.get("created_at") or "", row.get("repository") or "",
            row.get("file") or "", int(row.get("line") or 0), row.get("candidate_id") or "",
        ))
        repository_key = repository.casefold() if repository else None
        query_key = query.casefold()
        base_filtered_items = [
            row for row in candidate_items
            if (risk_tier is None or row.get("risk_tier") == risk_tier)
            and (triage_state is None
                 or (triage_state == "unresolved"
                     and row.get("triage_state") not in {"completed", "completed_with_limitations"})
                 or row.get("triage_state") == triage_state)
            and (repository_key is None or str(row.get("repository") or "").casefold() == repository_key)
            and (not query_key or any(query_key in str(row.get(field) or "").casefold()
                                      for field in ("repository", "commit", "candidate_id", "file", "rule_id", "detector_id")))
        ]
        detector_counts = {}
        for row in base_filtered_items:
            detector = row.get("detector_id")
            if isinstance(detector, str) and detector:
                detector_counts[detector] = detector_counts.get(detector, 0) + 1
        filtered_items = [
            row for row in base_filtered_items
            if detector_id is None or row.get("detector_id") == detector_id
        ]
        total = sum(tier_counts.values())
        return {
            "schema_version": 1,
            "scope": "Most recent report-bearing scans, bounded to 20 and up to the latest 200 retained scan tasks.",
            "scan_limit": scan_limit,
            "available_report_count": len(jobs),
            "evaluated_scan_count": evaluated,
            "unavailable_report_count": len(limitations),
            "candidate_observation_count": total,
            "counts": tier_counts,
            "triage_counts": triage_counts,
            "detector_counts": [
                {"detector_id": detector, "candidate_count": count}
                for detector, count in sorted(detector_counts.items())
            ],
            "not_triaged_candidate_count": sum(
                count for state, count in triage_counts.items()
                if state not in {"completed", "completed_with_limitations"}
            ),
            "validated_vulnerability": validated_count,
            "offset": offset,
            "limit": limit,
            "filtered_candidate_count": len(filtered_items),
            "items": filtered_items[offset:offset + limit],
            "limitations": limitations,
            "semantics": "Counts are candidate observations across selected scans, not deduplicated root causes, vulnerability totals, recall, or proof that unobserved code is safe.",
        }

    @router.get("/scans/{key}/reports/snapshots")
    def audit_report_snapshots(key: str):
        store.job(key)
        return {"audit_id": key, "items": ops.audit_report_snapshots(key)}

    @router.post("/scans/{key}/reports/snapshots", status_code=201)
    def create_audit_report_snapshot(key: str):
        job = store.job(key)
        report = service.read_report(settings, job)
        from .smart_audit import coverage_snapshot, risk_snapshot as build_risk_snapshot
        risk = build_risk_snapshot(settings, store, ops, job, report)
        coverage = coverage_snapshot(job, report)
        triage = scan_triage_summary(key)
        confirmed_cases = _validated_cases_for_audit(store, ops, key)
        validated_count = sum(1 for item in confirmed_cases)
        risk["validated_vulnerability"] = validated_count
        risk["confirmed_cases"] = confirmed_cases
        batch_views = [{key_name: batch.get(key_name) for key_name in
                        ("id", "state", "candidate_count", "selected_count", "operation_ids", "error")}
                       for batch in triage.get("batches", [])]
        operation_views = [{key_name: item.get(key_name) for key_name in
                            ("id", "status", "candidate_id", "mode", "created_at", "finished_at", "result_sha256")}
                           for item in triage.get("items", [])]
        report_payload = {
            "schema_version": 1,
            "audit_id": key,
            "source_report_sha256": job["report_sha256"],
            "scan": {
                "repository": report["repository"], "commit": report["commit"],
                "tree": report.get("git_tree"), "include_paths": job["spec"].get("include_paths", []),
                "status": job["status"], "stage": job.get("stage"),
                "created_at": job.get("created_at"), "finished_at": job.get("finished_at"),
                "report_sha256": job["report_sha256"],
                "snapshot_sha256": report.get("snapshot_sha256"),
                "detector_versions": job["spec"].get("detector_versions", {}),
            },
            "scan_progress": triage.get("scan_progress"),
            "triage": {
                "state": triage["state"], "progress": triage.get("triage_progress"),
                "authorization": triage.get("authorization"),
                "batches": batch_views, "operations": operation_views,
            },
            "coverage": coverage,
            "risk_snapshot": risk,
            "confirmed_cases": confirmed_cases,
            "validated_vulnerability": validated_count,
            "limitations": list(dict.fromkeys(
                list(report.get("limitations", [])) + risk["limitations"]
                + ([triage["limitation"]] if triage.get("limitation") else [])
            )),
            "evidence_boundary": "静态与模型辅助发现均保持待复核候选或未知状态。只有现行人工评估关联有效源码证据，且通过运行时验证门确认产品可达性时，才计为已验证漏洞。",
        }
        snapshot = ops.create_audit_snapshots(
            risk, report_payload, _combined_audit_report_markdown,
        )
        return {key_name: snapshot[key_name] for key_name in
                ("id", "audit_id", "report_sha256", "risk_snapshot_id", "content_sha256",
                 "json_sha256", "markdown_sha256", "created_at")}

    @router.get("/scans/{key}/reports/snapshots/{snapshot_id}/json")
    def download_audit_report_json(key: str, snapshot_id: str):
        snapshot = ops.audit_report_snapshot(key, snapshot_id)
        return Response(snapshot["json_content"], media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="ohscanner-report-{snapshot_id}.json"',
                                 "X-Content-SHA256": snapshot["json_sha256"]})

    @router.get("/scans/{key}/reports/snapshots/{snapshot_id}/markdown")
    def download_audit_report_markdown(key: str, snapshot_id: str):
        snapshot = ops.audit_report_snapshot(key, snapshot_id)
        return Response(snapshot["markdown_content"], media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="ohscanner-report-{snapshot_id}.md"',
                                 "X-Content-SHA256": snapshot["markdown_sha256"]})

    @router.get("/operations/agent-review-queue/status")
    def agent_review_queue_status():
        return ops.candidate_review_queue()

    @router.post("/operations/agent-review-queue", status_code=201)
    def agent_review_queue(body: CandidateReviewQueueRequest):
        """Queue every candidate in one immutable report; never Top-K truncate."""
        job = store.job(body.job_id)
        report = service.read_report(settings, job)
        candidates = service.findings(report)
        spec = {"job_id": job["id"], "report_sha256": job["report_sha256"],
                "candidate_count_at_enqueue": len(candidates), "timeout_seconds": 60,
                "memory_mb": 512}
        operation = ops.create("candidate_review_batch", spec)
        return {**operation, "candidate_count": len(candidates),
                "review_mode": "candidate_only", "model_available": False,
                "note": "Candidates remain queued until a configured, source-bound review provider is available; no conclusion was inferred."}

    @router.get("/operations")
    def list_operations(limit: int = Query(default=100, ge=1, le=1000)):
        return ops.list()[:limit]

    def _progressive_status(audit_id):
        from .progressive_triage.status import build_progressive_status
        try:
            return build_progressive_status(settings, ops, audit_id, store=store)
        except KeyError:
            raise HTTPException(status_code=404, detail="audit operation not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @router.get("/audits/{audit_id}/ai-usage")
    def progressive_ai_usage(audit_id: str):
        status = _progressive_status(audit_id)
        return {
            "audit_operation_id": audit_id,
            "phase": status["phase"],
            "phase_counts": status["phase_counts"],
            "budget": status["budget"],
            "cost_enforcement": status["cost_enforcement"],
            "stop_reason": status["stop_reason"],
            "policy_revision": status["policy_revision"],
            "policy_sha256": status["policy_sha256"],
            "candidate_disposition_changed": False,
            "validated_vulnerability": 0,
        }

    @router.get("/audits/{audit_id}/triage-groups")
    def progressive_triage_groups(audit_id: str, offset: int = 0, limit: int = 50):
        if (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0
                or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200):
            raise HTTPException(status_code=422, detail="offset must be non-negative and limit must be 1..200")
        status = _progressive_status(audit_id)
        groups = status["groups"]
        return {
            **{key: value for key, value in status.items() if key != "groups"},
            "group_total": len(groups),
            "offset": offset,
            "limit": limit,
            "groups": groups[offset:offset + limit],
        }

    @router.get("/operations/{key}")
    def operation(key: str):
        item = ops.get(key)
        item["retry_available"] = _smart_operation_retry_available(store, ops, item)
        item["events"] = ops.events(key)
        if item["kind"] == "repository_import_scan":
            for event in reversed(item["events"]):
                if event.get("stage") != "repository_import_progress":
                    continue
                try:
                    progress = json.loads(event.get("message", ""))
                except (TypeError, ValueError):
                    break
                if isinstance(progress, dict) and isinstance(progress.get("phase"), str):
                    item["download_progress"] = {**progress, "updated_at": event["created_at"]}
                break
        if item["result_sha256"]:
            item["result"] = ops.result(key)
        item["agent_reviews"] = ops.agent_reviews(key) if item["kind"] == "agent_investigation" else []
        if item["kind"] in {"revision_range", "time_incremental_scan", "branch_comparison", "version_matrix",
                            "recent_window_comparison"}:
            endpoint_progress = []
            for job_id in item["spec"].get("scan_ids", []):
                job = store.job(job_id)
                authorized = store.triage_authorization(job_id)
                batches = (ops.triage_batches_for_job(job_id, job.get("report_sha256"))
                           if job.get("report_sha256") else [])
                batch = batches[-1] if batches else {}
                if job["spec"].get("audit_mode") == "static_only":
                    state = "static_only"
                elif job["status"] not in {"completed", "completed_with_limitations"}:
                    state = ("awaiting_static" if job["status"] in {"queued", "running"}
                             else "static_incomplete")
                elif authorized is None:
                    state = "awaiting_individual_consent"
                elif authorized["revoked"]:
                    state = "revoked"
                elif not batches:
                    state = "awaiting_model_schedule"
                elif batch.get("status") == "candidate_limit_exceeded":
                    state = "candidate_limit_exceeded"
                elif batch.get("status") == "queue_limit_exceeded":
                    state = "queue_limit_exceeded"
                else:
                    ids = batch["operation_ids"] + batch["r2_operation_ids"]
                    statuses = [ops.get(operation_id)["status"] for operation_id in ids]
                    candidate_count = int(batch.get("candidate_count") or 0)
                    selected_count = int(batch.get("selected_count") or 0)
                    r2_status = batch.get("r2_status", "not_requested")
                    if batch["status"] == "blocked_authorization_changed":
                        state = "authorization_changed"
                    elif batch["status"] == "no_eligible_candidates":
                        state = "no_eligible_candidates"
                    elif (statuses and all(status in END for status in statuses)
                          and r2_status != "awaiting_r1"):
                        execution_completed = all(
                            status in {"completed", "completed_with_limitations"}
                            for status in statuses
                        )
                        coverage_incomplete = (
                            selected_count < candidate_count
                            or r2_status in {"candidate_limit_reached", "budget_limited", "failed_selection"}
                        )
                        state = ("completed" if execution_completed and not coverage_incomplete
                                 else "partially_completed")
                    else:
                        state = "agent_in_progress"
                r1_operations = ([ops.get(operation_id) for operation_id in batch.get("operation_ids", [])]
                                 if batches else [])
                r2_operations = ([ops.get(operation_id) for operation_id in batch.get("r2_operation_ids", [])]
                                 if batches else [])
                if batches:
                    progress = _classify_intelligent_review(
                        batch, r1_operations, r2_operations,
                        revoked=bool(authorized and authorized["revoked"]),
                    )
                    state = progress["state"]
                else:
                    progress = {
                        "r1": _operation_phase_progress([], phase_state="not_triaged"),
                        "r2": _operation_phase_progress([], phase_state="not_requested"),
                    }
                    if authorized and authorized["revoked"]:
                        state = "revoked"
                def operation_summary(record):
                    child_spec = record.get("spec") if isinstance(record.get("spec"), dict) else {}
                    return {
                        "id": record.get("id"), "status": record.get("status"),
                        "result_sha256": record.get("result_sha256"),
                        "candidate_id": child_spec.get("candidate_id"),
                        "commit": job["spec"].get("commit"),
                        "report_sha256": job.get("report_sha256"),
                    }

                if batches:
                    endpoint_candidate_count = int(batch.get("candidate_count") or 0)
                elif job.get("report_sha256"):
                    try:
                        endpoint_candidate_count = len(service.findings(service.read_report(settings, job)))
                    except FileNotFoundError:
                        endpoint_candidate_count = None
                else:
                    endpoint_candidate_count = None

                endpoint_progress.append({
                    "scan_id": job_id, "commit": job["spec"].get("commit"),
                    "scan_status": job["status"], "agent_status": state,
                    "agent_authorized": bool(authorized and not authorized["revoked"]),
                    "report_available": bool(job.get("report_sha256")),
                    "candidate_count": endpoint_candidate_count,
                    "r1_authorized_count": int((authorized or {}).get("snapshot", {}).get("candidate_limit") or 0),
                    "r1_created_count": len(r1_operations),
                    "r1_queued_count": sum(1 for operation in r1_operations if operation["status"] == "queued"),
                    "r1_running_count": sum(1 for operation in r1_operations if operation["status"] == "running"),
                    "r1_selected_count": int(batch.get("selected_count") or 0) if batches else 0,
                    "r1_not_selected_count": max(
                        0, int(batch.get("candidate_count") or 0)
                        - int(batch.get("selected_count") or 0),
                    ) if batches else 0,
                    "r2_status": batch.get("r2_status", "not_requested") if batches else "not_requested",
                    "r1_progress": progress["r1"],
                    "r2_progress": progress["r2"],
                    "r1_operations": [operation_summary(record) for record in r1_operations],
                    "r2_operations": [operation_summary(record) for record in r2_operations],
                    "triage_state_reason": (
                        "Authorization was revoked; pending work must stop and candidates remain untriaged."
                        if state == "revoked"
                        else "Every authorized operation failed or was interrupted; no candidate review completed."
                        if state == "failed"
                        else "Only part of the selected or eligible candidate set completed; remaining candidates are untriaged."
                        if state == "partially_completed"
                        else "All eligible candidates completed their authorized review."
                        if state == "completed"
                        else None
                    ),
                    "model_result_is_product_vulnerability_confirmation": False,
                })
            item["intelligent_review_progress"] = endpoint_progress
        return item


    @router.post("/operations/{key}/agent-reviews", status_code=201)
    def agent_human_review(key: str, body: AgentHumanReviewRequest):
        task = ops.get(key)
        if task["kind"] != "agent_investigation":
            raise ValueError("human Agent review requires an Agent investigation")
        record = body.model_dump()
        record["reviewer"] = record["reviewer"].strip()
        if not record["reviewer"]:
            raise ValueError("reviewer name must not be blank")
        return ops.record_agent_review(key, record)

    @router.post("/agent/blind-sessions", status_code=201)
    def create_agent_blind_session(body: AgentBlindSessionRequest):
        if len(set(body.operation_ids)) != len(body.operation_ids):
            raise HTTPException(status_code=422, detail="operation_ids must be unique")
        grouped = {}
        experiment_profiles = set()
        packets = []
        paired_budget_keys = ("max_output_tokens", "provider_request_timeout_seconds")
        for operation_id in body.operation_ids:
            task = ops.get(operation_id)
            if task["kind"] != "agent_investigation" or task["status"] not in {"completed", "completed_with_limitations"}:
                raise HTTPException(status_code=409, detail="blind review requires completed Agent results")
            result = ops.result(operation_id)
            if result.get("experiment_id") != body.experiment_id:
                raise HTTPException(status_code=409, detail="operation is outside the requested experiment")
            if result.get("vulnerability_state") != "candidate" or result.get("validated_vulnerability") != 0:
                raise HTTPException(status_code=409, detail="only candidate-only results may enter blind review")
            binding = result.get("binding") or {}
            spec = task.get("spec") or {}
            mode = result.get("mode")
            if mode not in {"single_shot", "tool_agent"} or spec.get("mode") != mode:
                raise HTTPException(status_code=409, detail="unsupported or mismatched Agent experiment arm")
            candidate_key = (binding.get("repository"), binding.get("commit"),
                             binding.get("report_sha256"), binding.get("candidate_id"),
                             binding.get("source_sha256"))
            if any(value is None for value in candidate_key):
                raise HTTPException(status_code=409, detail="result lacks a fixed source and report binding")
            provider_result = result.get("provider") or {}
            required_profile = (spec.get("provider_fingerprint"), spec.get("provider_model"),
                                spec.get("prompt_version"), spec.get("tool_policy_version"),
                                result.get("implementation_sha256"),
                                *(spec.get(key) for key in paired_budget_keys))
            if any(value is None for value in required_profile):
                raise HTTPException(status_code=409, detail="result lacks the immutable model, implementation, or budget profile")
            if (provider_result.get("model") != spec.get("provider_model")
                    or result.get("prompt_version") != spec.get("prompt_version")
                    or result.get("tool_policy_version") != spec.get("tool_policy_version")):
                raise HTTPException(status_code=409, detail="stored Agent profile does not match the executed result")
            experiment_profiles.add(required_profile)
            modes = grouped.setdefault(candidate_key, {})
            if mode in modes:
                raise HTTPException(status_code=409, detail="experiment has duplicate results for a candidate arm")
            modes[mode] = required_profile
            packets.append({"operation_id": operation_id, "result_sha256": task["result_sha256"],
                            "packet": _blind_packet(result)})
        if not grouped or any(set(modes) != {"single_shot", "tool_agent"} for modes in grouped.values()):
            raise HTTPException(status_code=409, detail="select complete R1/R2 pairs for each candidate")
        if len(experiment_profiles) != 1 or any(len(set(modes.values())) != 1 for modes in grouped.values()):
            raise HTTPException(status_code=409,
                                detail="R1/R2 results must use the same provider, model, implementation, prompt, and budget profile")
        baselines = ops.agent_baseline_reviews(body.experiment_id)
        baseline_keys = {(item["repository"], item["commit"], item["report_sha256"],
                          item["candidate_id"], item["source_sha256"]) for item in baselines}
        if any(candidate_key not in baseline_keys for candidate_key in grouped):
            raise HTTPException(status_code=409, detail="every candidate needs a source-matched R0 review")
        return ops.create_agent_blind_session(body.experiment_id, packets)

    @router.get("/agent/blind-sessions/{session_id}")
    def get_agent_blind_session(session_id: str):
        return ops.agent_blind_session(session_id)

    @router.post("/agent/blind-review-agreement")
    def agent_blind_review_agreement(body: AgentBlindAgreementRequest):
        return ops.agent_blind_review_agreement(body.session_ids)

    @router.get("/agent/blind-reviewer.html")
    def agent_blind_reviewer_page():
        path = Path(__file__).resolve().parents[2] / "web" / "agent-blind-reviewer.html"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="offline blind review form is not installed")
        return FileResponse(path, media_type="text/html")

    @router.get("/agent/blind-sessions/{session_id}/export")
    def export_agent_blind_session(session_id: str):
        data = ops.agent_blind_export(session_id)
        return Response(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=ohscanner-blind-session.json"})

    @router.get("/agent/blind-sessions/{session_id}/evidence-bundle")
    def export_agent_blind_evidence_bundle(session_id: str):
        data = ops.agent_blind_evidence_bundle(session_id)
        return Response(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition":
                                 "attachment; filename=ohscanner-agent-evidence-bundle.json"})

    @router.post("/agent/blind-sessions/{session_id}/import", status_code=201)
    def import_agent_blind_reviews(session_id: str, body: AgentBlindReviewImportRequest):
        records = []
        for item in body.reviews:
            record = item.model_dump(exclude={"blind_item_id"})
            record["reviewer"] = record["reviewer"].strip()
            if not record["reviewer"]:
                raise ValueError("reviewer name must not be blank")
            records.append({"blind_item_id": item.blind_item_id, "record": record})
        return ops.import_agent_blind_reviews(session_id, records)

    @router.post("/agent/blind-sessions/{session_id}/close")
    def close_agent_blind_session(session_id: str):
        return ops.close_agent_blind_session(session_id)


    @router.get("/operations/{key}/result")
    def operation_result(key: str):
        return ops.result(key)

    @router.get("/operations/{key}/log")
    def operation_log(key: str):
        path = ops.directory(key) / "worker.log"
        if not path.is_file():
            raise KeyError("operation log not available")
        return Response(path.read_bytes()[-256 * 1024:], media_type="text/plain")

    @router.post("/operations/{key}/cancel")
    def cancel(key: str):
        return ops.cancel(key)

    @router.get("/cases/{case_id}/report.json")
    def download_case_report_json(case_id: str):
        return Response(_case_report_exports(case_id)["json"], media_type="application/json")


    def case_report_json(case_id: str):
        links = _case_links(store, case_id)
        if not links:
            raise KeyError("case not found or empty")
        records = []
        records_by_candidate = {}
        risk_by_job = {}
        risk_snapshot_unavailable = set()
        fixed_source_cache = {}
        for link in links:
            job = store.job(link["job_id"])
            report = service.read_report(settings, job)
            item = service.finding(report, link["candidate_id"])
            if job["id"] not in risk_by_job:
                try:
                    from .smart_audit import risk_snapshot as build_risk_snapshot
                    snapshot = build_risk_snapshot(settings, store, ops, job, report)
                    risk_by_job[job["id"]] = {
                        risk["candidate_id"]: risk
                        for risk in snapshot.get("items", [])
                        if isinstance(risk, dict) and risk.get("candidate_id")
                    }
                except (KeyError, TypeError, ValueError):
                    # Keep the fixed-source case report readable if an older or
                    # incomplete saved report cannot support risk-tier enrichment.
                    risk_by_job[job["id"]] = {}
                    risk_snapshot_unavailable.add(job["id"])
            risk = risk_by_job[job["id"]].get(item["id"], {})
            record = {"job_id": job["id"], "report_sha256": job["report_sha256"],
                "repository": report["repository"], "commit": report["commit"],
                "candidate": item, "rationale": link["rationale"],
                "risk": {"severity": item.get("severity", "unknown"),
                         "confidence": item.get("confidence", "unknown"),
                         "risk_tier": risk.get("risk_tier", "unknown"),
                         "risk_tier_label": risk.get("risk_tier_label", "风险分层不可用"),
                         "risk_snapshot_available": job["id"] not in risk_snapshot_unavailable,
                         "reasons": risk.get("reasons", []),
                         "vulnerability_state": "candidate"},
                "reviews": store.reviews(job["id"], item["id"]),
                "source_evidence": store.source_evidence(job["id"], item["id"])}
            source_key = (job["id"], item.get("file"))
            if source_key not in fixed_source_cache:
                try:
                    fixed_source_cache[source_key] = service.source(settings, store, job, item.get("file"))
                except (KeyError, TypeError, ValueError, OSError, UnicodeError, subprocess.CalledProcessError):
                    fixed_source_cache[source_key] = None
            source_anchor = _fixed_case_source_anchor(settings, store, job, report, item,
                                                      fixed_source_cache[source_key])
            record["source_anchor"] = source_anchor
            record["remediation_draft"] = _candidate_remediation_draft(item, source_anchor)
            record["poc_plan"] = _candidate_poc_plan(item, source_anchor)
            record["reviewer_checklist"] = _candidate_reviewer_checklist(source_anchor)
            records.append(record)
            records_by_candidate[(job["id"], item["id"])] = record

        # A case may be created after an Agent investigation. Recover that result only
        # when the immutable operation plan and committed result bind to the exact
        # candidate/report/source now linked to this case. Never share explicitly
        # case-bound operations with another case.
        case_page = ops.report_operations_for_case(case_id, limit=20)
        operations = []
        seen_operation_ids = set()
        recovered_operation_count = 0
        for operation in [*case_page["items"], *ops.list()]:
            if operation["id"] in seen_operation_ids:
                continue
            seen_operation_ids.add(operation["id"])
            spec = operation["spec"]
            linked = records_by_candidate.get((spec.get("job_id"), spec.get("candidate_id")))
            case_bound = spec.get("case_id") == case_id
            if operation["kind"] == "agent_investigation":
                if spec.get("case_id") not in (None, case_id) or not linked:
                    continue
                candidate = linked["candidate"]
                if (spec.get("report_sha256") != linked["report_sha256"]
                        or spec.get("source_commit") != linked["commit"]
                        or spec.get("candidate_source_sha256") != candidate.get("source_sha256")):
                    continue
                if operation["result_sha256"]:
                    try:
                        committed = ops.result(operation["id"])
                    except (KeyError, ValueError):
                        continue
                    binding = committed.get("binding")
                    if not isinstance(binding, dict) or any((
                            binding.get("job_id") != linked["job_id"],
                            binding.get("candidate_id") != candidate["id"],
                            binding.get("report_sha256") != linked["report_sha256"],
                            binding.get("commit") != linked["commit"],
                            binding.get("source_sha256") != candidate.get("source_sha256"),
                    )):
                        continue
                operations.append(operation)
                if not case_bound:
                    recovered_operation_count += 1
            elif case_bound:
                operations.append(operation)
        total_operations = case_page["total"] + recovered_operation_count
        operation_page = {"total": total_operations, "truncated": total_operations > 20, "limit": 20}
        operations = operations[:20]
        operation_summaries = []
        for x in operations:
            linked = records_by_candidate.get((x.get("spec", {}).get("job_id"),
                                               x.get("spec", {}).get("candidate_id")))
            result = ops.result(x["id"]) if x["result_sha256"] else {}
            summary = {"id": x["id"], "kind": x["kind"], "status": x["status"],
                "result_sha256": x["result_sha256"], "validation_gate": result.get("validation_gate"),
                "gate_reason": result.get("gate_reason"), "reachability_status": result.get("reachability_status"),
                "validated_vulnerability": result.get("validated_vulnerability", 0),
                "commit": result.get("commit"), "commits": result.get("commits"), "case_id": x["spec"].get("case_id"), "job_id": x["spec"].get("job_id"), "candidate_id": x["spec"].get("candidate_id")}
            if x["kind"] == "validation":
                harness_result = result.get("result") if isinstance(result.get("result"), dict) else {}
                revisions = {}
                for name, revision in (harness_result.get("revisions") or {}).items():
                    if not isinstance(revision, dict):
                        continue
                    build = revision.get("build") if isinstance(revision.get("build"), dict) else {}
                    replay = revision.get("replay") if isinstance(revision.get("replay"), dict) else {}
                    replay_cases = []
                    for case in replay.get("cases", []) if isinstance(replay.get("cases"), list) else []:
                        if not isinstance(case, dict):
                            continue
                        replay_cases.append({key: case.get(key) for key in
                            ("case_id", "role", "expected", "observed", "matches_expectation", "label")
                            if key in case})
                    revisions[name] = {
                        "commit": revision.get("commit"), "state": revision.get("state"),
                        "build": {key: build.get(key) for key in
                                  ("compiler", "compiler_version", "sanitizers", "returncode") if key in build},
                        "replay": {key: replay.get(key) for key in
                                   ("label", "attempts", "triggered", "all_cases_match") if key in replay},
                        "replay_cases": replay_cases,
                        "expectations_met": revision.get("expectations_met", {}),
                    }
                summary["validation_evidence"] = {
                    "harness_id": x.get("spec", {}).get("harness_id") or harness_result.get("harness"),
                    "family": harness_result.get("family"),
                    "target_repository": x.get("spec", {}).get("target_repository") or harness_result.get("repository"),
                    "target_commit": x.get("spec", {}).get("target_commit"),
                    "cutils_commit": x.get("spec", {}).get("cutils_commit"),
                    "docker_exit_code": result.get("docker_exit_code"),
                    "input_manifest_sha256": result.get("input_manifest_sha256"),
                    "validation_command_sha256": result.get("validation_command_sha256"),
                    "docker_log_sha256": result.get("docker_log_sha256"),
                    "revisions": revisions,
                    "patched_revision": result.get("patched_revision"),
                    "validation_scope": result.get("validation_scope") or x.get("spec", {}).get("validation_scope"),
                    "outcome": result.get("outcome"),
                    "source_binding_status": result.get("source_binding_status"),
                    "source_provenance": result.get("source_provenance"),
                    "environment": result.get("environment"),
                    "builds": result.get("builds"),
                    "runs": result.get("runs"),
                    "result_file": result.get("result_file"),
                    "report_file": result.get("report_file"),
                    "report_markdown": result.get("report_markdown"),
                    "scope_explanation": result.get("scope_explanation"),
                    "limitations": result.get("limitations", harness_result.get("limitations", [])),
                }
            if x["kind"] == "agent_investigation":
                assessment = result.get("agent_assessment", {})
                linked_job = store.job(linked["job_id"]) if linked else None
                citation_state = (_agent_citation_state(settings, store, result, linked_job, linked["candidate"],
                                                        linked.get("source_anchor", {}))
                                  if linked_job else {"state": "unknown", "reason": "候选固定绑定不可用。"})
                advice_verified_for_display = citation_state["state"] == "unverified_model_advice"
                if linked and isinstance(linked.get("remediation_draft"), dict):
                    linked["remediation_draft"]["ai_basis"] = {
                        "state": "source_bound_unverified" if advice_verified_for_display else "unknown",
                        "citations": citation_state.get("citations", []),
                        "note": ("这些是智能调查在同一固定提交中引用的源码上下文；引用与修复草案没有机器验证的因果映射，需人工判断。"
                                 if advice_verified_for_display else citation_state.get("reason")),
                    }
                model_suggestions = [{
                    "text": step,
                    "state": "unverified_model_suggestion",
                    "source_anchor": linked.get("source_anchor"),
                    "semantic_support": "unverified_by_machine",
                } for step in assessment.get("next_steps", [])
                    if advice_verified_for_display and isinstance(step, str) and step.strip()]
                summary["agent_triage"] = {
                    "triage_only": True,
                    "assessment": assessment.get("assessment", "unknown") if advice_verified_for_display else "unknown",
                    "summary": assessment.get("summary", "") if advice_verified_for_display else "",
                    "summary_provenance": result.get("summary_provenance", "legacy_model_generated_unverified"),
                    "model_summary_unverified": assessment.get("model_summary_unverified",
                        assessment.get("summary", "")) if advice_verified_for_display else "",
                    "experiment_id": result.get("experiment_id"),
                    "supported_claims": assessment.get("supported_claims", []) if advice_verified_for_display else [],
                    "obligation_reviews": assessment.get("obligation_reviews", []) if advice_verified_for_display else [],
                    "vulnerability_report": assessment.get("vulnerability_report"),
                    "poc_draft": assessment.get("poc_draft"),
                    "artifact_generation": result.get("artifact_generation"),
                    "citation_integrity": result.get("citation_integrity"),
                    "citation_review": citation_state,
                    "model_suggestions": model_suggestions,
                    "narrative_integrity": result.get("narrative_integrity", {
                        "unverified_narrative_fields": ["model_summary_unverified", "unsupported_claims", "unknowns", "next_steps"],
                        "narrative_semantics": "unverified_by_machine"}),
                    "unsupported_claims": assessment.get("unsupported_claims", []) if advice_verified_for_display else [],
                    "unknowns": assessment.get("unknowns", []) if advice_verified_for_display else [],
                    "next_steps": [item["text"] for item in model_suggestions],
                    "repair_guidance": {"status": "unverified_model_suggestions", "items": [item["text"] for item in model_suggestions], "patch_generated": False, "human_review_required": True},
                    "mode": result.get("mode"),
                    "model": (result.get("provider") or {}).get("model"),
                    "model_usage": result.get("model_usage"),
                    "model_calls": result.get("model_calls", []),
                    "initial_evidence": result.get("initial_evidence"),
                    "knowledge_references": result.get("knowledge_references", []),
                    "knowledge_retrieval": result.get("knowledge_retrieval"),
                    "tool_calls": result.get("tool_calls", []),
                    "prompt_version": result.get("prompt_version"),
                    "tool_policy_version": result.get("tool_policy_version"),
                    "source_submission": result.get("source_submission"),
                    "human_reviews": ops.agent_reviews(x["id"]),
                    "binding": result.get("binding"),
                    "limitations": result.get("limitations", []),
                    "vulnerability_state": result.get("vulnerability_state", "candidate"),
                }
            operation_summaries.append(summary)
        review_status = _case_review_status(settings, store, ops, case_id)
        validation_operations = [item for item in operation_summaries if item.get("kind") == "validation"]
        if not validation_operations:
            plans_ready = bool(records) and all(row.get("poc_plan", {}).get("state") == "plan_only"
                                                for row in records)
            poc_status = {"state": "not_run" if plans_ready else "unknown",
                          "label": "计划已生成 · 未执行" if plans_ready else "材料不足 · 未生成可审查计划",
                          "detail": ("已生成绑定固定源码的安全验证计划；本操作不会创建任务或执行验证用例。"
                                     if plans_ready else "固定源码或候选位置材料缺失，保持未知；没有虚构验证步骤。")}
        elif any(item.get("status") == "running" for item in validation_operations):
            poc_status = {"state": "running", "label": "验证执行中",
                          "detail": "请等待受控验证操作完成；运行中不代表漏洞已确认。"}
        elif any(item.get("status") == "queued" for item in validation_operations):
            poc_status = {"state": "queued", "label": "验证计划已登记，尚未运行",
                          "detail": "排队状态不代表 PoC 已执行或漏洞已复现。"}
        else:
            poc_status = {"state": "completed", "label": "验证操作已结束，需查看门控结果",
                          "detail": "组件级隔离测试结果不能单独证明产品可达性；确认状态仍以人工结论和验证门控为准。"}
        for record in records:
            record.get("source_anchor", {}).pop("_source_lines", None)
        return {"schema_version": 2, "case_id": case_id, "candidates": records,
                "operations": operation_summaries,
                "operation_summaries": {
                    "total": operation_page["total"],
                    "included": len(operation_summaries),
                    "truncated": operation_page["truncated"],
                    "limit": operation_page["limit"],
                },
                "assessments": ops.assessments(case_id),
                "latest_human_assessment": review_status["latest_human_assessment"],
                "validation_basis": review_status["validated_by"],
                "validated_vulnerability": review_status["validated_vulnerability"],
                "poc_status": poc_status,
                "limitations": ["静态候选和组件级隔离测试观察不能证明产品入口可达或达到漏洞报告标准。", "除非产品级验证器绑定当前候选和源码，否则产品入口可达性保持未知。",
                                "计入已确认案例需要追加记录的人工结论、匹配的运行时验证门通过结果，以及已核验的产品入口可达性。",
                                "智能调查后续建议是未经核验的调查建议，不是已复核的修复补丁或已执行的 验证用例（PoC）计划。"] +
                    (["部分已保存报告缺少风险分层所需字段；未知表示信息不可用，不表示安全。"]
                     if risk_snapshot_unavailable else [])}



    @router.get("/cases/{case_id}/report.md")
    def case_report_md(case_id: str):
        exports = _case_report_exports(case_id)
        return Response(exports["markdown"], media_type="text/markdown; charset=utf-8")



    def _case_report_markdown(data, case_id):
        md = _markdown_inline_untrusted
        case_state = ("人工确认（运行时门控通过）" if data["validated_vulnerability"]
                      else "候选（尚未确认）")
        rows = ["# OHScanner 调查案例报告", "", "案例 ID：" + md(case_id),
                "", "- 当前结论：" + md(case_state),
                "- 确认漏洞数：" + md(data["validated_vulnerability"]),
                "- 验证用例 / 受控验证：" + md(data["poc_status"]["label"]),
                "", "## 候选与证据"]
        operation_summary = data.get("operation_summaries") or {}
        if operation_summary.get("truncated"):
            rows += ["", "- 操作记录范围：展示 " + md(operation_summary.get("included")) + " / " + md(operation_summary.get("total")) + " 条；本文仅展示最近 20 条结果。", "- 未展开的 " + md(operation_summary.get("total", 0) - operation_summary.get("included", 0)) + " 条操作仍存在，不能据此推断没有结果。"]
        for row in data["candidates"]:
            c = row["candidate"]
            risk = row.get("risk") or {}
            rows += ["", "### " + md(c.get("detector_id", "未知检测器")) + " / " + md(c.get("rule_id", "未知规则")),
                     "", "- 来源：" + md(row["repository"]) + " @ " + md(row["commit"]),
                     "- 固定来源文件：" + md(c.get("file", "未记录")) + ":" + md(c.get("line", "未记录")),
                     "- 静态规则消息：" + _case_md_narrative(c.get("message", "未提供")),
                     "- 静态严重性 / 置信度：" + md(_case_enum_label(risk.get("severity", "unknown"))) + " / " + md(_case_enum_label(risk.get("confidence", "unknown"))),
                     "- 风险分层：" + md(risk.get("risk_tier_label", "来源绑定未知")),
                     "- 分层依据：" + _case_md_narrative("；".join(risk.get("reasons", [])) or "暂无可用依据"),
                     "- 报告 SHA-256：" + md(row["report_sha256"]),
                     "- 观测状态：候选（单条观测保持候选；案例人工结论单独记录）",
                     "- 来源证据 SHA-256：" + md(c.get("source_sha256", "未记录")),
                     "- 建立案例的理由：" + _case_md_narrative(row.get("rationale", "未填写"))]
            for evidence in row.get("source_evidence", []):
                rows += ["- 人工登记源码证据：" + md(evidence.get("file") or c.get("file")) + ":" + md(evidence.get("start_line")) + "；" + _case_md_narrative(evidence.get("note") or evidence.get("observation") or "未记录说明")]
            for review in row.get("reviews", []):
                rows += ["- 候选复核：" + md(_case_enum_label(review.get("status"))) + "；" + md(review.get("reviewer")) + "；" + _case_md_narrative(review.get("notes") or "未记录说明")]
            anchor = row.get("source_anchor") or {}
            if anchor.get("verified"):
                rows += ["- 固定源码锚点：" + md(anchor.get("anchor_id")) + "；" +
                         md(anchor.get("repository")) + " @ " + md(anchor.get("commit")) + "；" +
                         md(anchor.get("file")) + ":" + md(anchor.get("line")) +
                         "；源码 SHA-256 " + md(anchor.get("source_sha256"))]
            else:
                rows += ["- 固定源码锚点：未知（" + _case_md_narrative(anchor.get("reason", "来源材料不可用")) + "）"]
            remediation_draft = row.get("remediation_draft") or {}
            if remediation_draft.get("draft"):
                rows += ["- 修复建议草案（未验证，非补丁/非确认结论）：" + _case_md_narrative(remediation_draft["draft"]),
                         "- 草案依据：" + md(remediation_draft.get("provenance")) +
                         "；固定源码锚点 " + md((remediation_draft.get("source_anchor") or {}).get("anchor_id", "未知"))]
                for check in remediation_draft.get("review_checks", []):
                    rows += ["  - 人工复核：" + md(check)]
            else:
                rows += ["- 修复建议：未知（" + _case_md_narrative(remediation_draft.get("reason", "尚无可审查的 CWE 修复草案")) + "）"]
            evidence = c.get("evidence") if isinstance(c.get("evidence"), dict) else {}
            obligations = evidence.get("obligations") if isinstance(evidence.get("obligations"), list) else []
            if obligations:
                rows += ["- 静态分析义务与证据："]
                for obligation in obligations[:40]:
                    if isinstance(obligation, dict):
                        description = obligation.get("description") or obligation.get("kind") or "未命名义务"
                        state = _case_enum_label(obligation.get("status", "unknown"))
                        rows += ["  - " + _case_md_narrative(description) + "（" + md(state) + "）"]
                    else:
                        rows += ["  - " + _case_md_narrative(obligation)]
            ai_basis = remediation_draft.get("ai_basis") or {"state": "unknown", "citations": [],
                "note": "没有绑定到本候选的已核验智能调查引用。"}
            rows += ["- 智能调查源码依据状态：" + md(_case_enum_label(ai_basis.get("state", "unknown"))) + "；" +
                     _case_md_narrative(ai_basis.get("note", "语义支持未知"))]
            for citation in ai_basis.get("citations", []):
                rows += ["  - 固定源码引文：" + md(citation.get("evidence_id")) + "；" +
                         md(citation.get("file", "未记录文件")) + ":" +
                         md(citation.get("line_start", "?")) + "-" + md(citation.get("line_end", "?")) +
                         "；“" + md(citation.get("quote", "")) + "”"]
            rows += ["- 已人工复核的修复补丁：未提供；以上草案需人工检查并经补丁测试。"]
            plan = row.get("poc_plan") or {}
            rows += ["", "#### " + _case_md_narrative(plan.get("label", "状态未知"))]
            if plan.get("state") == "plan_only":
                rows += ["- 执行状态：未请求、未排队、未执行；预期结果：未知，需人工先定义测试判定标准。",
                         "- 计划依据：固定源码锚点 " + md((plan.get("source_anchor") or {}).get("anchor_id", "未知"))]
                for step in plan.get("steps", []):
                    step_anchor = step.get("source_anchor") or {}
                    rows += ["- " + md(_CASE_PLAN_STEP_LABELS.get(step.get("id"), "验证步骤")) + "（" + md(_case_enum_label(step.get("status"))) + "）：" +
                             _case_md_narrative(step.get("action")) + "；源码 " + md(step_anchor.get("file", "未记录")) +
                             ":" + md(step_anchor.get("line", "未记录")) + " @ " +
                             md(step_anchor.get("commit", "未记录")) + " SHA-256 " +
                             md(step_anchor.get("source_sha256", "未记录"))]
            else:
                rows += ["- 验证计划状态：未知；" + _case_md_narrative(plan.get("reason", "固定源码证据不可用；没有生成伪造步骤。"))]
            checklist = row.get("reviewer_checklist") or {}
            rows += ["", "#### 比赛审阅清单（材料完整性，不是漏洞判定）"]
            for item in checklist.get("items", []):
                rows += ["- " + md(item.get("label", item.get("id", "审阅项"))) + "：" +
                         md(_case_enum_label(item.get("state", "unknown"))) + "；" +
                         _case_md_narrative(item.get("note", "尚无完整材料。"))]
        agent_ops = [item for item in data["operations"] if item.get("kind") == "agent_investigation"
                     and item.get("agent_triage")]
        if agent_ops:
            rows += ["", "## 智能调查研判建议（不代表漏洞确认）", "", "> 引用校验只确认引句逐字出现在绑定证据中；不验证引句是否支持模型陈述，语义推理仍需人工复核。"]
            for operation in agent_ops:
                triage = operation["agent_triage"]
                binding = triage["binding"] or {}
                usage = triage["model_usage"] or {}
                rows += ["", "- 操作：" + md(operation["id"]) + "；结果 SHA-256：" + md(operation["result_sha256"]),
                         "- 模式：" + md(_case_enum_label(triage["mode"] or "unknown")) + "；模型倾向：" + md(_case_enum_label(triage["assessment"])) + "；漏洞状态：" + md(_case_enum_label(triage["vulnerability_state"])),
                         "- 模型：" + md(triage["model"] or "未记录") + "；提示词 / 工具策略版本：" + md(triage["prompt_version"] or "未记录") + " / " + md(triage["tool_policy_version"] or "未记录"),
                         "- 来源绑定：" + md(binding.get("repository") or "未记录") + " @ " + md(binding.get("commit") or "未记录") +
                         "；" + md(binding.get("file") or "未记录") + "；候选 ID " + md(binding.get("candidate_id") or "未记录"),
                         "- 摘要（" + md(_case_enum_label(triage.get("summary_provenance", "legacy_model_generated_unverified"))) + "）：“" + _case_md_narrative(triage["summary"]) + "”",
                         "- 模型用量（令牌）：输入 " + md(usage.get("input_tokens") if usage.get("input_tokens") is not None else "未记录") +
                         " / 输出 " + md(usage.get("output_tokens") if usage.get("output_tokens") is not None else "未记录") +
                         "；缓存命中输入（输入内） " + md(usage.get("cached_input_tokens") if usage.get("cached_input_tokens") is not None else "未记录") +
                         "；推理令牌（已计入输出） " + md(usage.get("reasoning_tokens") if usage.get("reasoning_tokens") is not None else "未记录") +
                         "；模型服务商实际费用 " + md("未知" if usage.get("cost") == "unknown" else usage.get("cost", "未记录"))]
                estimate = usage.get("cost_estimate") if isinstance(usage.get("cost_estimate"), dict) else None
                if estimate and estimate.get("status") == "estimated_range":
                    rows += ["- 估算费用区间（非实账）：" + md(estimate.get("currency", "未记录")) + " " +
                             md(estimate.get("minimum_usd", "未记录")) + "–" +
                             md(estimate.get("maximum_usd", "未记录")) +
                             "；费率快照 " + md(estimate.get("rate_card_id", "未记录")) +
                             "；来源 " + md(estimate.get("rate_source_url", "未记录"))]
                elif estimate and estimate.get("status") == "estimated_amount":
                    amount_text =  "美元 " + md(estimate.get("amount_usd", "未记录"))
                    if estimate.get("amount_cny") is not None:
                        amount_text += " / 人民币 " + md(estimate["amount_cny"])
                    rows += ["- 估算费用（非实账）：" + amount_text +
                             "；费率快照 " + md(estimate.get("rate_card_id", "未记录")) +
                             "；来源 " + md(estimate.get("rate_source_url", "未记录"))]
                if triage.get("model_summary_unverified"):
                    rows += ["- 历史模型摘要（未经核验）：“" + _case_md_narrative(triage["model_summary_unverified"]) + "”"]
                if triage["initial_evidence"]:
                    rows += ["- 初始证据：" + md(triage["initial_evidence"].get("evidence_id")) +
                             "；上下文 SHA-256 " + md(triage["initial_evidence"].get("context_sha256"))]
                knowledge = triage.get("knowledge_retrieval") or {}
                knowledge_refs = triage.get("knowledge_references", [])
                if knowledge:
                    rows += ["", "### 知识库参考资料（不属于当前源码证据）", "",
                             "- 检索状态：" + md(knowledge.get("status", "unknown")) +
                             "；索引文件数：" + md(knowledge.get("indexed_files", 0)) +
                             "；语料 SHA-256：" + md(knowledge.get("corpus_sha256") or "不可用"),
                             "- 边界：这些资料只供类比参考，不能证明当前候选、满足源码证据义务或作为漏洞结论引用。"]
                    for reference in knowledge_refs if isinstance(knowledge_refs, list) else []:
                        if not isinstance(reference, dict):
                            continue
                        rows += ["- " + md(reference.get("path", "未知路径")) + ":" +
                                 md(reference.get("start_line", "?")) + "–" +
                                 md(reference.get("end_line", "?")) + "；" +
                                 md(reference.get("summary", "参考资料")) +
                                 "；SHA-256 " + md(reference.get("sha256", "未记录")),
                                 "  - 片段：" + md(reference.get("excerpt", ""))]
                for review in triage.get("human_reviews", []):
                    rows += ["- 人工评价（仅评价智能调查意见，不是漏洞结论）：" +
                             md(review.get("reviewer")) + "；有用性 " + md(_case_enum_label(review.get("usefulness"))) +
                             "；引文准确性 " + md(_case_enum_label(review.get("citation_accuracy"))) +
                             "；复核耗时秒 " + md(review.get("elapsed_seconds") if review.get("elapsed_seconds") is not None else "未记录")]
                    if review.get("claims_to_correct"):
                        rows += ["  - 需更正陈述：" + _case_md_narrative(review["claims_to_correct"])]
                    if review.get("missed_evidence"):
                        rows += ["  - 遗漏证据：" + _case_md_narrative(review["missed_evidence"])]
                    if review.get("notes"):
                        rows += ["  - 复核备注：" + _case_md_narrative(review["notes"])]
                for claim in triage["supported_claims"]:
                    citations = claim.get("citations", [])
                    if citations:
                        citation_text = "；".join(md(item["evidence_id"]) + "（源码原文）：“" + md(item["quote"]) + "”"
                                                  for item in citations)
                    else:
                        citation_text = md("；".join(claim.get("evidence_ids", [])))
                    mapping = claim.get("obligation_indices")
                    mapping_text = ("关联源码核查项 " + "、".join("#" + str(index) for index in mapping)
                                    if isinstance(mapping, list) and mapping else "历史结果未记录义务关联")
                    rows += ["- 模型列出的源码主张：" + _case_md_narrative(claim["claim"]) + "（" + md(mapping_text) +
                             "；引用证据：" + citation_text + "）"]
                initial_context = (triage.get("initial_evidence") or {}).get("context") or {}
                obligations = initial_context.get("evidence_obligations", [])
                if triage.get("obligation_reviews"):
                    rows += ["- 证据义务逐项分诊（引文存在性已核验；语义是否支持仍需人工判断）："]
                    for item in triage["obligation_reviews"]:
                        index = item.get("obligation_index", -1)
                        obligation = obligations[index] if isinstance(index, int) and 0 <= index < len(obligations) else "未记录的核查项"
                        if isinstance(obligation, dict):
                            obligation = obligation.get("description") or obligation.get("kind") or str(obligation)
                        citations = item.get("citations", [])
                        citation_text = "；".join(
                            md(citation.get("evidence_id", "未记录证据")) + "（源码原文）：“" + md(citation.get("quote", "")) + "”"
                            for citation in citations) or "无引文；保持未决"
                        rows += ["  - #" + md(index) + " " + md(_case_enum_label(item.get("disposition", "unresolved"))) +
                                 " · " + _case_md_narrative(obligation) + "（" + citation_text + "）"]
                if triage["unsupported_claims"]:
                    rows += ["- 尚无证据支持的模型陈述：" + _case_md_narrative("；".join(triage["unsupported_claims"]))]
                if triage["unknowns"]:
                    rows += ["- 仍待核实：" + _case_md_narrative("；".join(triage["unknowns"]))]
                if triage["next_steps"]:
                    rows += ["- 建议后续核查：" + _case_md_narrative("；".join(triage["next_steps"]))]
                if triage["limitations"]:
                    rows += ["- 调查范围说明：" + _case_md_narrative("；".join(triage["limitations"]))]
                if triage.get("model_suggestions"):
                    rows += ["- 智能调查建议（未经验证，仅供人工复核，不代表修复结论或漏洞事实）："]
                    for suggestion in triage["model_suggestions"]:
                        anchor = suggestion.get("source_anchor") or {}
                        rows += ["  - " + _case_md_narrative(suggestion.get("text")) + "；上下文锚点 " +
                                 md(anchor.get("file", "未知")) + ":" + md(anchor.get("line", "未知")) +
                                 " @ " + md(anchor.get("commit", "未记录")) +
                                 "；语义支持仍待人工判断"]
                elif triage.get("citation_review", {}).get("state") == "unknown":
                    rows += ["- 智能调查建议：未知（" + _case_md_narrative(triage["citation_review"].get("reason")) + "）；未展示未绑定建议"]
                if triage["source_submission"]:
                    consent = triage["source_submission"]
                    rows += ["- 源码外发目的地：" + md(consent.get("destination_host") or "未记录") +
                             "；授权预览 SHA-256 " + md(consent.get("consent_sha256") or "未记录") +
                             "；预览版本 " + md(consent.get("consent_preview_version") or "未记录")]
        rows += ["", "## 智能调查漏洞报告草案与验证用例（PoC）计划", "",
                 "> 以下内容均为待复核的候选或未知草案；验证用例（PoC）草案尚未执行或验证。固定隔离测试结果另列，不与草案混同。"]
        if not agent_ops:
            rows += ["- 本案例没有绑定的智能调查结果；未生成验证用例草案，验证用例（PoC）计划未执行，状态未知。"]
        for operation in agent_ops:
            triage = operation["agent_triage"]
            generation = triage.get("artifact_generation")
            if isinstance(generation, dict):
                rows += ["", "### 报告与验证用例草案生成阶段",
                         "- 阶段状态：" + md(_CASE_STAGE_LABELS.get(generation.get("status"), "状态待核对")) +
                         "；模型调用数：" + md(generation.get("calls_used", "未记录")) +
                         "。该状态不代表扫描完成、验证用例执行或漏洞确认。"]
            report = triage.get("vulnerability_report")
            if isinstance(report, dict):
                rows += ["", "### " + _case_md_narrative(report.get("title") or "漏洞报告草案") +
                         "（" + md(_CASE_ARTIFACT_LABELS.get(report.get("status"), "状态待核对")) + "；候选 / 未知）"]
                for label, key in (("摘要", "summary"), ("根因", "root_cause"),
                                   ("潜在影响", "impact"), ("修复建议", "remediation")):
                    if report.get(key):
                        rows += ["- " + label + "：" + _case_md_narrative(report.get(key))]
                for label, key in (("前置条件", "preconditions"), ("攻击路径草案", "attack_path")):
                    rows += ["- " + label + "："]
                    values = report.get(key) if isinstance(report.get(key), list) else []
                    rows.extend(["  - " + _case_md_narrative(value) for value in values] or ["  - 未记录"])
                rows += ["- 报告引用（只展示模型结果中已有的引用）："]
                citations = report.get("citations") if isinstance(report.get("citations"), list) else []
                if citations:
                    for citation in citations:
                        if not isinstance(citation, dict):
                            continue
                        location = md(citation.get("file", "未知文件"))
                        if citation.get("line_start") is not None:
                            location += ":" + md(citation.get("line_start"))
                            if citation.get("line_end") is not None:
                                location += "–" + md(citation.get("line_end"))
                        citation_text = "  - " + md(citation.get("evidence_id", "未记录证据 ID")) + " · " + location
                        if citation.get("quote"):
                            citation_text += "：“" + md(citation.get("quote")) + "”"
                        rows.append(citation_text)
                else:
                    rows.append("  - 未提供引用。")
            else:
                rows += ["", "### 漏洞报告草案", "- 未记录结构化漏洞报告。"]

            poc = triage.get("poc_draft")
            if isinstance(poc, dict):
                poc_status = poc.get("status") or "unknown"
                if poc_status == "draft_unexecuted":
                    status_text = "智能调查草案，未执行"
                elif poc_status == "insufficient_evidence":
                    status_text = "证据不足，未生成可执行草案"
                else:
                    status_text = "状态未知"
                rows += ["", "### 验证用例（PoC）计划（" + md(status_text) + "）",
                         "> 智能调查草案 · 未执行 · 未验证 · 候选 / 未知", "> 未执行、未验证；当前仍为候选 / 未知。这里展示的是验证计划，不是漏洞确认。"]
                for label, key in (("标题", "title"), ("语言", "language"),
                                   ("预期观察", "expected_observation"), ("负向对照", "negative_control")):
                    if poc.get(key):
                        rows += ["- " + label + "：" +
                                 (md(poc.get(key)) if key == "language" else _case_md_narrative(poc.get(key)))]
                for label, key in (("前置条件", "prerequisites"), ("建议步骤", "run_steps")):
                    rows += ["- " + label + "："]
                    values = poc.get(key) if isinstance(poc.get(key), list) else []
                    rows.extend(["  - " + _case_md_narrative(value) for value in values] or ["  - 未记录"])
                code = poc.get("code")
                if isinstance(code, str) and code.strip():
                    language = str(poc.get("language") or "text")
                    if not re.fullmatch(r"[A-Za-z0-9_+.-]{1,48}", language):
                        language = "text"
                    longest_fence = max((len(match.group(0)) for match in re.finditer(r"`+", code)), default=2)
                    fence = "`" * max(3, longest_fence + 1)
                    rows += ["", "未执行代码草案（代码原文）：", fence + language, code, fence]
                else:
                    rows += ["- 没有可执行验证用例代码；当前草案为空或证据不足。"]
                rows += ["- 验证用例引用（只展示模型结果中已有的引用）："]
                citations = poc.get("citations") if isinstance(poc.get("citations"), list) else []
                if citations:
                    for citation in citations:
                        if not isinstance(citation, dict):
                            continue
                        location = md(citation.get("file", "未知文件"))
                        if citation.get("line_start") is not None:
                            location += ":" + md(citation.get("line_start"))
                            if citation.get("line_end") is not None:
                                location += "–" + md(citation.get("line_end"))
                        citation_text = "  - " + md(citation.get("evidence_id", "未记录证据 ID")) + " · " + location
                        if citation.get("quote"):
                            citation_text += "：“" + md(citation.get("quote")) + "”"
                        rows.append(citation_text)
                else:
                    rows.append("  - 未提供引用。")
            else:
                rows += ["", "### 验证用例（PoC）计划（未执行）",
                         "- 未生成验证用例草案；验证计划未执行，当前状态未知。"]

        rows += ["", "## 智能调查修复与验证建议（未经验证）"]
        suggestions = [(operation["id"], item)
                       for operation in agent_ops
                       for item in (operation["agent_triage"].get("repair_guidance", {}).get("items") or [])]
        if suggestions:
            for operation_id, suggestion in suggestions:
                rows += ["- 智能调查建议（操作 " + md(operation_id) + "，待人工复核）：“" + _case_md_narrative(suggestion) + "”"]
        else:
            rows += ["- 当前没有绑定到本案例的智能调查修复建议。"]
        rows += ["- 系统未生成或应用补丁；建议文本不构成修复证明，必须单独审查补丁并在固定版本上重新扫描和验证。"]
        validation_ops = [item for item in data["operations"] if item.get("kind") == "validation"]
        rows += ["", "## 概念验证 / 隔离验证记录"]
        if validation_ops:
            for operation in validation_ops:
                rows += ["- 操作 " + md(operation["id"]) + "；状态 " + md(_case_enum_label(operation.get("status"))) +
                         "；验证门控 " + md(_case_enum_label(operation.get("validation_gate") or "unknown")) +
                         "；产品可达性 " + md(_case_enum_label(operation.get("reachability_status") or "unknown")) +
                         "；计入确认数 " + md(operation.get("validated_vulnerability", 0)) +
                         "；结果 SHA-256 " + md(operation.get("result_sha256"))]
                if operation.get("gate_reason"):
                    rows += ["  - 门控说明：" + _case_md_narrative(operation["gate_reason"])]
                evidence = operation.get("validation_evidence") or {}
                if evidence:
                    rows += ["  - 固定隔离测试环境：" + md(evidence.get("harness_id") or "结果未记录") +
                             "；目标仓库 " + md(evidence.get("target_repository") or "结果未记录") +
                             " @ " + md(evidence.get("target_commit") or "结果未记录") +
                             "；支持库提交 " + md(evidence.get("cutils_commit") or "结果未记录")]
                    for revision_name, revision in evidence.get("revisions", {}).items():
                        build = revision.get("build") or {}
                        replay = revision.get("replay") or {}
                        rows += ["  - 修订 " + md(revision_name) + " @ " + md(revision.get("commit") or "未记录") +
                                 "；编译退出码 " + md(build.get("returncode", "未知")) +
                                 "；重放结果 " + md(_case_enum_label(replay.get("label", "unknown"))) +
                                 "；所有测试案例均符合预期 " + md(_case_enum_label(replay.get("all_cases_match", "unknown")))]
                        for case in revision.get("replay_cases", []):
                            rows += ["    - 案例 " + md(case.get("case_id", "未记录")) +
                                     "（" + md(_case_enum_value(case.get("role"))) + "）：预期 " +
                                     md(_case_enum_value(case.get("expected"))) + "；观察 " +
                                     md(_case_enum_value(case.get("observed"))) + "；符合预期 " +
                                     md(_case_enum_value(case.get("matches_expectation")))]
                    for label, digest in (("输入清单", evidence.get("input_manifest_sha256")),
                                          ("运行命令", evidence.get("validation_command_sha256")),
                                          ("Docker 日志", evidence.get("docker_log_sha256"))):
                        if digest:
                            rows += ["  - " + label + " SHA-256：" + md(digest)]
                    for limitation in evidence.get("limitations", []):
                        rows += ["  - 隔离测试限制：" + _case_md_narrative(limitation)]
            rows += ["> 固定隔离测试的组件级结果不自动证明产品受影响；只有验证门通过、产品可达性已验证且存在匹配人工评估时才计为确认。"]
        else:
            rows += ["- 尚无已完成的隔离验证操作；验证用例（PoC）计划与产品影响状态均未知。"]
        rows += ["", "## 智能调查实验与人工评价",
                 "",
                 "> 本节按案例中已包含的智能调查操作展示人工研判反馈；它不等于独立盲评、模型准确率或漏洞真值。"]
        if agent_ops:
            for operation in agent_ops:
                triage = operation["agent_triage"]
                rows += ["- 实验 " + md(triage.get("experiment_id") or "未标记") +
                         "；模式 " + md(_case_enum_label(triage.get("mode") or "unknown")) +
                         "；人工评价数 " + md(len(triage.get("human_reviews", []))) +
                         "；研判倾向 " + md(_case_enum_label(triage.get("assessment", "unknown"))) +
                         "（不是漏洞真值或准确率）"]
                for review in triage.get("human_reviews", []):
                    rows += ["  - " + md(review.get("reviewer")) + "：有用性 " + md(_case_enum_label(review.get("usefulness")))+
                             "；引文准确性 " + md(_case_enum_label(review.get("citation_accuracy")))+
                             "；复核后的意见 " + md(_case_enum_label(review.get("post_review_disposition") or "unknown"))]
        else:
            rows += ["- 尚无智能调查结果；不能给出模型效能结论。"]

        rows += ["", "## 验证用例 / 受控验证", "",
                 "- 状态：" + md(data["poc_status"]["label"]),
                 "- 说明：" + md(data["poc_status"]["detail"])]
        validation_rows = [item for item in data["operations"] if item.get("kind") == "validation"]
        for operation in validation_rows:
            rows += ["- 验证操作：" + md(operation["id"]) + "；状态 " + md(_case_enum_label(operation.get("status")))
                     + "；门控 " + md(_case_enum_label(operation.get("validation_gate", "unknown")))
                     + "；产品可达性 " + md(_case_enum_label(operation.get("reachability_status", "unknown")))]
        human_assessments = [item for item in data["assessments"] if item.get("reviewer_kind") == "human"]
        if human_assessments:
            rows += ["", "## 人工案例复核"]
            for assessment in human_assessments:
                rows += ["", "- 复核人：" + md(assessment.get("reviewer")) +
                         "；结论：" + md(assessment.get("outcome")) +
                         "；证据 ID：" + md("、".join(assessment.get("evidence_ids", [])))]
                if assessment.get("notes"):
                    rows += ["  - 记录：" + _case_md_narrative(assessment["notes"])]
                if assessment.get("remaining_unknowns"):
                    rows += ["  - 未决项：" + _case_md_narrative("；".join(assessment["remaining_unknowns"]))]
        rows += ["", "## 限制", "", *["- " + _case_md_narrative(x) for x in data["limitations"]],
                 "", "经门控确认的漏洞数：" + md(data["validated_vulnerability"]) +
                 "（候选数不计入；智能调查建议不能单独确认）。"]
        return "\n".join(rows) + "\n"



    def _case_report_exports(case_id):
        data = case_report_json(case_id)
        markdown = _case_report_markdown(data, case_id)
        html_document = _case_markdown_to_html(markdown)
        canonical_json = json.dumps(data, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")
        manifest = {
            "schema_version": 1,
            "case_id": case_id,
            "hash_contract": "SHA-256 over UTF-8 bytes; report.json uses canonical JSON v1 (sorted keys, compact separators, no ASCII escaping).",
            "artifacts": {
                "report.json": {"sha256": hashlib.sha256(canonical_json).hexdigest(),
                                "serialization": "canonical-json-v1"},
                "report.md": {"sha256": hashlib.sha256(markdown.encode("utf-8")).hexdigest()},
                "report.html": {"sha256": hashlib.sha256(html_document.encode("utf-8")).hexdigest()},
            },
            "source_bindings": [{
                "job_id": row["job_id"],
                "report_sha256": row["report_sha256"],
                "repository": row["repository"],
                "commit": row["commit"],
                "candidate_id": row["candidate"]["id"],
                "file": row["candidate"].get("file"),
                "line": row["candidate"].get("line"),
                "source_sha256": row["candidate"].get("source_sha256"),
                "git_blob": (row.get("source_anchor") or {}).get("git_blob"),
                "source_anchor_id": (row.get("source_anchor") or {}).get("anchor_id"),
                "source_anchor_state": (row.get("source_anchor") or {}).get("state", "unknown"),
                "risk_tier": (row.get("risk") or {}).get("risk_tier", "unknown"),
                "vulnerability_state": "candidate",
            } for row in data["candidates"]],
            "operations": [{
                "id": item["id"], "kind": item["kind"], "status": item["status"],
                "result_sha256": item.get("result_sha256"),
                "job_id": item.get("job_id"), "candidate_id": item.get("candidate_id"),
            } for item in data["operations"]],
            "human_assessment_ids": [item.get("id") for item in data["assessments"]
                                     if item.get("reviewer_kind") == "human"],
            "validated_vulnerability": data["validated_vulnerability"],
            "limitations": data["limitations"],
        }
        return {"data": data, "json": canonical_json, "markdown": markdown,
                "html": html_document, "manifest": manifest}



    @router.get("/cases/{case_id}/report.html")
    def case_report_html(case_id: str):
        document = _case_report_exports(case_id)["html"]
        return Response(document, media_type="text/html; charset=utf-8", headers={
            "Content-Disposition": f'inline; filename="ohscanner-case-{case_id}.html"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })



    @router.get("/cases/{case_id}/report.manifest.json")
    def case_report_manifest(case_id: str):
        return _case_report_exports(case_id)["manifest"]



    @router.get("/cases/{case_id}/report.bundle.zip")
    def case_report_bundle(case_id: str):
        exports = _case_report_exports(case_id)
        manifest_json = json.dumps(exports["manifest"], ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")
        bundle = BytesIO()
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.json", exports["json"])
            archive.writestr("report.md", exports["markdown"].encode("utf-8"))
            archive.writestr("report.html", exports["html"].encode("utf-8"))
            archive.writestr("manifest.json", manifest_json)
        return Response(bundle.getvalue(), media_type="application/zip", headers={
            "Content-Disposition": f'attachment; filename="ohscanner-case-{case_id}.zip"',
            "X-Content-Type-Options": "nosniff",
        })





    @router.post("/cases/{case_id}/agent-assessments", status_code=201)
    def agent_assessment(case_id: str, body: AgentProposalRequest):
        links = [link for link in _case_links(store, case_id) if link["candidate_id"] == body.candidate_id]
        if not links:
            raise KeyError("candidate is not linked to this case")
        link = links[0]
        job = store.job(link["job_id"])
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        if report["commit"] != body.source_commit:
            raise ValueError("agent citation commit does not match the candidate's fixed source")
        source = service.source(settings, store, job, candidate["file"])
        if source["blob"] != body.source_blob or source["sha256"] != body.source_sha256:
            raise ValueError("agent citation blob/hash does not match the fixed source")
        lines = source["text"].splitlines()
        if body.line_end < body.line_start or body.line_end > len(lines):
            raise ValueError("agent citation line range is outside the fixed source")
        for citation in (*body.supporting_evidence, *body.refuting_evidence):
            cited_source = service.source(settings, store, job, citation.file)
            cited_lines = cited_source["text"].splitlines()
            if (cited_source["blob"] != citation.blob or cited_source["sha256"] != citation.source_sha256
                    or citation.line_end < citation.line_start or citation.line_end > len(cited_lines)):
                raise ValueError("agent evidence citation does not match the fixed source blob/hash/line range")
        record = {
            "record_kind": "agent_proposal", "reviewer_kind": "agent", "reviewer": body.agent_id,
            "outcome": body.suggestion, "notes": body.summary,
            "source_binding": {"job_id": job["id"], "report_sha256": job["report_sha256"],
                "repository": report["repository"], "commit": report["commit"],
                "candidate_id": candidate["id"], "file": candidate["file"],
                "blob": source["blob"], "source_sha256": source["sha256"],
                "line_start": body.line_start, "line_end": body.line_end},
            "supporting_evidence": [c.model_dump() for c in body.supporting_evidence],
            "refuting_evidence": [c.model_dump() for c in body.refuting_evidence],
            "unresolved_obligations": body.unresolved_obligations,
            "model_runtime": {"provider": body.provider, "model_version": body.model_version,
                "prompt_version": body.prompt_version, "tool_version": body.tool_version,
                "run_id": body.run_id, "input_tokens": body.input_tokens,
                "output_tokens": body.output_tokens, "duration_ms": body.duration_ms,
                "attestation": "provider/runtime metadata is caller-supplied and not authenticated"},
            "confirmation_effect": "none; human approval and existing validation gate remain required",
        }
        return ops.assessment(case_id, record)

    @router.post("/cases/{case_id}/assessments", status_code=201)
    def assessment(case_id: str, body: AssessmentRequest):
        links = _case_links(store, case_id)
        if not links:
            raise KeyError("case not found or empty")
        record = body.model_dump()
        if body.reviewer_kind == "agent":
            raise ValueError("Agent proposals must use the source-bound /agent-assessments endpoint")
        valid_refs = {e["id"] for link in links for e in store.source_evidence(link["job_id"], link["candidate_id"])}
        if not set(body.evidence_ids).issubset(valid_refs):
            raise ValueError("assessment references evidence outside this case")
        if body.outcome in {"confirmed", "reportable"}:
            if len({(item["job_id"], item["candidate_id"]) for item in links}) != 1:
                raise ValueError("confirmed/reportable is disabled for multi-candidate cases; create one case per candidate and review each separately")
            eligible = any(_product_validation_is_bound(settings, store, ops, case_id, oid)
                           for oid in body.validation_operation_ids)
            if not eligible or not body.evidence_ids or not body.remaining_unknowns:
                raise ValueError("只有完成产品本身的验证、且验证记录与当前候选和扫描源码完全匹配，才能标记为已确认或可报告；请补充本案证据和仍需确认的问题。")
        return ops.assessment(case_id, record)


    app.include_router(router)

    @router.get("/cases/{case_id}/manifest.json")
    def legacy_case_report_manifest(case_id: str):
        data = case_report_json(case_id)
        artifacts = {
            "report.json": _case_report_exports(case_id)["json"],
            "report.md": case_report_md(case_id).body,
            "report.html": case_report_html(case_id).body,
        }
        operation_scope = data.get("operation_summaries") or {}
        manifest = {
            "schema_version": 1,
            "case_id": case_id,
            "artifacts": {
                name: {"sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}
                for name, content in artifacts.items()
            },
            "scope": {
                "operations_total": operation_scope.get("total", len(data.get("operations", []))),
                "operations_included": operation_scope.get("included", len(data.get("operations", []))),
                "operations_truncated": bool(operation_scope.get("truncated", False)),
                "validated_vulnerability": data.get("validated_vulnerability", 0),
                "boundary": "AI reports and PoC plans remain candidate/unknown drafts; fixed Harness observations do not alone prove product reachability.",
            },
        }
        body = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        return Response(
            body,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="ohscanner-case-manifest.json"'},
        )

    @router.post("/operations/{key}/retry", status_code=201)
    def retry_operation(key: str):
        item = ops.get(key)
        if item["kind"] == "repository_import_scan":
            try:
                retried = ops.retry_repository_import(key)
            except KeyError:
                raise HTTPException(status_code=404, detail="operation not found") from None
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from None
            reused = retried.pop("retry_reused", False)
            return JSONResponse(status_code=200 if reused else 201, content=retried)
        if not _smart_operation_retry_available(store, ops, item):
            raise HTTPException(status_code=409, detail="此任务当前不可重试；请核对任务状态、授权、固定报告和候选队列")
        from .agent import ProviderConfig
        from .smart_audit import _authorization_is_current
        job = store.job(item["spec"]["job_id"])
        provider = ProviderConfig.from_env(settings.data_dir)
        _authorization, authorization_error = _authorization_is_current(
            settings, store, job, provider)
        if authorization_error:
            raise HTTPException(status_code=409, detail="原源码外发授权已不再匹配当前 Provider 或程序版本，请重新预览并授权")
        try:
            retried = ops.retry_interrupted_smart_operation(key)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        retried["retry_available"] = False
        return retried

    return ops


def _case_markdown_to_html(markdown):
    """Render the small Markdown subset used by case reports without raw HTML."""
    escaped_markdown_chars = re.compile(r"\\([\\`*_{}\[\]()#+\-.!|<>~])")

    def inline(value):
        parts = re.split(r"(\*\*.*?\*\*|`[^`]*`)", value)
        rendered = []
        for part in parts:
            if part.startswith("**") and part.endswith("**") and len(part) >= 4:
                text = escaped_markdown_chars.sub(r"\1", part[2:-2])
                rendered.append("<strong>" + html_escape(text) + "</strong>")
            elif part.startswith("`") and part.endswith("`") and len(part) >= 2:
                text = escaped_markdown_chars.sub(r"\1", part[1:-1])
                rendered.append("<code>" + html_escape(text) + "</code>")
            else:
                text = escaped_markdown_chars.sub(r"\1", part)
                rendered.append(html_escape(text))
        return "".join(rendered)

    body = []
    list_kind = None

    def close_list():
        nonlocal list_kind
        if list_kind:
            body.append("</" + list_kind + ">")
            list_kind = None

    code_fence = None
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if code_fence is not None:
            if re.fullmatch(r"`{" + str(code_fence) + r",}\s*", line):
                body.append("</code></pre>")
                code_fence = None
            else:
                body.append(html_escape(raw_line) + "\n")
            continue
        fence = re.fullmatch(r"(`{3,})([A-Za-z0-9_+-]*)\s*", line)
        if fence:
            close_list()
            code_fence = len(fence.group(1))
            body.append("<pre><code>")
            continue
        if not line:
            close_list()
            continue
        heading = re.match(r"^(#{1,4})\s+(.+)$", line)
        if heading:
            close_list()
            level = len(heading.group(1))
            body.append(f"<h{level}>" + inline(heading.group(2)) + f"</h{level}>")
            continue
        if line.startswith("> "):
            close_list()
            body.append("<blockquote>" + inline(line[2:]) + "</blockquote>")
            continue
        unordered = re.match(r"^-\s+(.+)$", line)
        ordered = re.match(r"^\d+\.\s+(.+)$", line)
        match, kind = (unordered, "ul") if unordered else (ordered, "ol") if ordered else (None, None)
        if match:
            if list_kind != kind:
                close_list()
                list_kind = kind
                body.append("<" + kind + ">")
            body.append("<li>" + inline(match.group(1)) + "</li>")
            continue
        close_list()
        body.append("<p>" + inline(line) + "</p>")
    close_list()
    if code_fence is not None:
        body.append("</code></pre>")
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OHScanner 调查案例报告</title>
<style>
body{margin:0;background:#f4f6fa;color:#243247;font:16px/1.75 system-ui,-apple-system,sans-serif}
main{max-width:1000px;margin:32px auto;padding:36px 44px;background:#fff;border:1px solid #dfe6ef;border-radius:14px;box-shadow:0 8px 30px #20385812}
h1,h2,h3,h4{color:#173b67;line-height:1.35;margin:1.5em 0 .55em}h1{margin-top:0;font-size:2em}
p{margin:.6em 0}li{margin:.35em 0}blockquote{margin:1em 0;padding:.6em 1em;border-left:4px solid #7aa7e8;background:#f3f7ff;color:#526783}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;color:#234d85}
@media(max-width:700px){main{margin:0;padding:22px;border:0;border-radius:0}}
@media print{body{background:#fff}main{max-width:none;margin:0;padding:0;border:0;box-shadow:none}}
</style></head><body><main>""" + "\n".join(body) + "</main></body></html>"



def _fixed_case_source_anchor(settings, store, job, report, candidate,
                              fixed_source=_SOURCE_NOT_SUPPLIED):
    """Resolve a candidate location against the exact saved report and Git source."""
    expected_commit = job.get("spec", {}).get("commit")
    report_sha256 = job.get("report_sha256")
    candidate_sha256 = candidate.get("source_sha256")
    line_number = candidate.get("line")
    if (not expected_commit or report.get("commit") != expected_commit
            or not isinstance(report_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", report_sha256)):
        return {"state": "unknown", "reason": "扫描报告或固定提交绑定缺失。"}
    if not isinstance(candidate_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256):
        return {"state": "unknown", "reason": "候选没有可核验的源码 SHA-256。"}
    if (not isinstance(line_number, int) or isinstance(line_number, bool) or line_number < 1
            or not isinstance(candidate.get("file"), str) or not candidate["file"]):
        return {"state": "unknown", "reason": "候选缺少有效的仓库相对路径或行号。"}
    try:
        source = (service.source(settings, store, job, candidate["file"])
                  if fixed_source is _SOURCE_NOT_SUPPLIED else fixed_source)
        if not isinstance(source, dict):
            raise ValueError("fixed source is unavailable")
        source_text = source.get("text")
        observed_sha256 = (hashlib.sha256(source_text.encode("utf-8")).hexdigest()
                           if isinstance(source_text, str) else None)
        if (source.get("commit") != expected_commit or source.get("sha256") != candidate_sha256
                or observed_sha256 != candidate_sha256):
            return {"state": "unknown", "reason": "候选源码与扫描提交/源码哈希不匹配。"}
        lines = source_text.splitlines()
        if line_number > len(lines):
            return {"state": "unknown", "reason": "候选行号不存在于固定源码中。"}
    except (KeyError, TypeError, ValueError, OSError, UnicodeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # A report remains readable when the Git object is unavailable, but no generated
        # advice may claim a source anchor that could not be independently re-opened.
        return {"state": "unknown", "reason": "固定源码材料暂不可用，未生成引用或建议。"}
    start = max(1, line_number - 2)
    end = min(len(lines), line_number + 2)
    identity = ["case-source-anchor-v1", report.get("repository"), expected_commit,
                report_sha256, candidate["file"], line_number, candidate_sha256]
    return {
        "state": "verified_fixed_source",
        "verified": True,
        "anchor_id": "src-" + hashlib.sha256(json.dumps(identity, ensure_ascii=False,
            separators=(",", ":")).encode()).hexdigest()[:20],
        "repository": report.get("repository"),
        "commit": expected_commit,
        "git_tree": report.get("git_tree"),
        "snapshot_sha256": report.get("snapshot_sha256"),
        "report_sha256": report_sha256,
        "file": candidate["file"],
        "line": line_number,
        "source_sha256": candidate_sha256,
        "git_blob": source.get("blob"),
        "excerpt_start_line": start,
        "excerpt_end_line": end,
        "excerpt": "\n".join(f"{number}: {lines[number - 1]}" for number in range(start, end + 1)),
        "_source_lines": lines,
    }



def _source_anchor_reference(source_anchor):
    if not source_anchor.get("verified"):
        return None
    return {key: source_anchor.get(key) for key in (
        "state", "verified", "anchor_id", "repository", "commit", "git_tree",
        "snapshot_sha256", "report_sha256", "file", "line", "source_sha256", "git_blob")}



def _candidate_remediation_draft(candidate, source_anchor):
    cwe = candidate.get("candidate_cwe")
    draft = _REMEDIATION_DRAFTS.get(cwe) if isinstance(cwe, str) else None
    if not source_anchor.get("verified") or not draft:
        reason = source_anchor.get("reason") or "当前候选 CWE 没有对应的受控修复草案模板。"
        return {"state": "unknown", "label": "修复建议待复核", "draft": None,
                "unverified": True, "reason": reason,
                "source_anchor": _source_anchor_reference(source_anchor)}
    return {
        "state": "draft_unverified",
        "label": "修复建议草案 · 未验证",
        "draft": draft,
        "unverified": True,
        "provenance": "确定性 CWE 草案模板；不是模型结论、已确认根因或补丁",
        "basis": {"candidate_cwe": cwe, "rule_id": candidate.get("rule_id"),
                  "note": "CWE 和规则信息是候选元数据，不单独证明此处存在漏洞。"},
        "review_checks": ["结合固定源码上下文和调用路径核对根因与接口契约。",
                          "修改后补充正例、修复版/安全控制及边界测试，并复核实际补丁。"],
        "ai_basis": {"state": "unknown", "citations": [],
                     "note": "没有引用校验通过且绑定到本候选的 Agent 材料；草案只来自通用 CWE 模板。"},
        "source_anchor": _source_anchor_reference(source_anchor),
    }



def _candidate_poc_plan(candidate, source_anchor):
    if not source_anchor.get("verified"):
        return {"state": "unknown", "label": "验证计划材料不足", "execution": {
                    "requested": False, "queued": False, "executed": False},
                "steps": [], "reason": source_anchor.get("reason"), "source_anchor": None}
    steps = [
        ("review_entry", "从固定源码和调用方核对可达入口、调用身份、前置状态及敏感操作；未由源码证明的条件保持未知。"),
        ("define_oracle", "由人工先写明可观察结果和失败条件；预期值只能来自接口契约、受审查的对照版本或明确的测试规范。"),
        ("prepare_isolated_harness", "如需复现，在临时本地目录构造最小隔离测试环境；禁用网络和生产服务，不执行破坏性操作。"),
        ("compare_controls", "对候选输入与安全/修复控制运行同一测试，保存源码 SHA、命令、日志和结果；组件级隔离测试结果与产品可达性分别记录。"),
        ("human_interpretation", "由复核者解释结果、影响边界和未决项；测试未运行、控制不完整或产品入口未知时保持候选或未知状态。"),
    ]
    return {
        "state": "plan_only",
        "label": "安全验证计划 · 未执行",
        "execution": {"requested": False, "queued": False, "executed": False},
        "authorization": "运行需要用户明确提出执行请求，并通过现有固定版本、隔离环境和验证门控；本报告不会自动创建或启动验证操作。",
        "expected_result": "unknown_until_reviewer_defines_contract_and_oracle",
        "harness_selection": "未选择 Harness；只有与固定仓库、提交、路径和来源哈希完全匹配的已登记适配器才可执行。",
        "steps": [{"id": step_id, "action": action, "status": "not_started",
                   "source_anchor": _source_anchor_reference(source_anchor)}
                  for step_id, action in steps],
        "candidate_cwe": candidate.get("candidate_cwe"),
        "source_anchor": _source_anchor_reference(source_anchor),
    }



def _candidate_reviewer_checklist(source_anchor):
    """Summarize report-material completeness without making a vulnerability verdict."""
    source_verified = isinstance(source_anchor, dict) and source_anchor.get("verified") is True
    items = [
        {"id": "source_binding", "label": "固定源码绑定",
         "state": "verified" if source_verified else "unknown",
         "note": "候选路径、提交和源码摘要已绑定。" if source_verified
                 else "固定源码锚点尚未核验，需恢复来源材料。"},
        {"id": "patch_revalidation", "label": "修复后重验",
         "state": "missing", "note": "尚未提供经过人工审查的补丁和重验结果。"},
        {"id": "affected_versions", "label": "受影响版本",
         "state": "unknown", "note": "尚未核实受影响版本范围。"},
    ]
    return {"status": "incomplete", "review_ready": False, "items": items,
            "purpose": "material_completeness_only_not_vulnerability_verdict"}


def _agent_citation_state(settings, store, result, job, candidate, source_anchor):
    """Recheck persisted Agent citations against evidence payloads bound to the fixed commit."""
    binding = result.get("binding") if isinstance(result, dict) else None
    if not isinstance(binding, dict) or any((
            binding.get("job_id") != job.get("id"),
            binding.get("candidate_id") != candidate.get("id"),
            binding.get("report_sha256") != job.get("report_sha256"),
            binding.get("commit") != (job.get("spec", {}).get("commit") or source_anchor.get("commit")),
            binding.get("source_sha256") != candidate.get("source_sha256"),
    )):
        return {"state": "unknown", "reason": "Agent 结果与本案例的固定候选绑定不匹配。"}
    assessment = result.get("agent_assessment")
    integrity = result.get("citation_integrity")
    if not isinstance(assessment, dict) or not isinstance(integrity, dict):
        return {"state": "unknown", "reason": "智能调查结果缺少可核验的引用材料。"}
    citations = []
    for field in ("supported_claims", "obligation_reviews"):
        rows = assessment.get(field, [])
        if not isinstance(rows, list):
            return {"state": "unknown", "reason": "Agent 引用结构无效。"}
        for row in rows:
            if not isinstance(row, dict):
                return {"state": "unknown", "reason": "Agent 引用结构无效。"}
            refs = row.get("citations", [])
            if not isinstance(refs, list):
                return {"state": "unknown", "reason": "Agent 引用结构无效。"}
            citations.extend(refs)
    if (integrity.get("quote_presence") != "verified_for_all_citations"
            or not citations or integrity.get("citation_count") != len(citations)):
        return {"state": "unknown", "reason": "Agent 引文缺失或未通过完整性校验。"}

    evidence = {}
    initial = result.get("initial_evidence")
    if isinstance(initial, dict):
        context = initial.get("context")
        if (initial.get("evidence_kind") == "source_code"
                and initial.get("file") == candidate.get("file")
                and initial.get("source_sha256") == candidate.get("source_sha256")
                and initial.get("source_commit", binding.get("commit")) == binding.get("commit")
                and isinstance(initial.get("evidence_id"), str)
                and isinstance(context, dict) and isinstance(context.get("source_excerpt"), str)):
            text = context["source_excerpt"]
            start = initial.get("source_excerpt_start_line", context.get("source_excerpt_start_line", 1))
            source_lines = source_anchor.get("_source_lines", [])
            excerpt_lines = text.splitlines()
            excerpt_matches_fixed_source = (
                isinstance(start, int) and not isinstance(start, bool) and start >= 1
                and isinstance(source_lines, list)
                and start + len(excerpt_lines) - 1 <= len(source_lines)
                and excerpt_lines == source_lines[start - 1:start - 1 + len(excerpt_lines)])
            if excerpt_matches_fixed_source:
                evidence[initial["evidence_id"]] = [{"file": initial["file"], "text": text,
                    "lines": {start + index: line for index, line in enumerate(excerpt_lines)},
                    "commit": initial.get("source_commit", binding.get("commit")),
                    "source_sha256": initial.get("source_sha256"),
                    "git_blob": initial.get("git_blob")}]

    for call in result.get("tool_calls", []) if isinstance(result.get("tool_calls"), list) else []:
        if not isinstance(call, dict) or call.get("evidence_kind") != "source_code":
            continue
        evidence_id = call.get("evidence_id")
        payload = call.get("result")
        if not isinstance(evidence_id, str) or not isinstance(payload, dict):
            continue
        entries = payload.get("matches") if isinstance(payload.get("matches"), list) else [payload]
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("commit", payload.get("commit")) != binding.get("commit"):
                continue
            file = entry.get("file") or payload.get("file")
            text = entry.get("text")
            if not isinstance(file, str) or not isinstance(text, str):
                continue
            raw_lines = text.splitlines()
            numbered = [re.match(r"^(\d+): ?(.*)$", line) for line in raw_lines]
            if raw_lines and all(numbered):
                lines = {int(match.group(1)): match.group(2) for match in numbered}
            else:
                start = entry.get("start_line", payload.get("start_line", 1))
                if not isinstance(start, int) or isinstance(start, bool) or start < 1:
                    continue
                lines = {start + index: line for index, line in enumerate(raw_lines)}
            evidence.setdefault(evidence_id, []).append({
                "file": file, "text": text, "lines": lines,
                "commit": entry.get("commit", payload.get("commit")),
                "source_sha256": entry.get("source_sha256", payload.get("source_sha256")),
                "git_blob": entry.get("git_blob", payload.get("git_blob")),
            })

    fixed_sources = {candidate.get("file"): {
        "commit": source_anchor.get("commit"),
        "sha256": source_anchor.get("source_sha256"),
        "blob": source_anchor.get("git_blob"),
        "text": "\n".join(source_anchor.get("_source_lines", [])),
    }}
    for citation in citations:
        if (not isinstance(citation, dict) or not isinstance(citation.get("evidence_id"), str)
                ):
            return {"state": "unknown", "reason": "Agent 引文没有固定源码证据 ID。"}
        entries = evidence.get(citation["evidence_id"], [])
        quote = citation.get("quote")
        cited_file = citation.get("file")
        if not isinstance(cited_file, str):
            bound_files = {entry["file"] for entry in entries if isinstance(entry.get("file"), str)}
            if len(bound_files) != 1:
                return {"state": "unknown", "reason": "Agent 引文来源存在歧义。"}
            cited_file = next(iter(bound_files))
        if (not cited_file or cited_file.startswith("/") or "\\" in cited_file
                or ".." in Path(cited_file).parts):
            return {"state": "unknown", "reason": "Agent 引文路径不是安全的仓库相对路径。"}
        if cited_file not in fixed_sources:
            try:
                fixed = service.source(settings, store, job, cited_file)
            except (KeyError, TypeError, ValueError, OSError, UnicodeError,
                    subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return {"state": "unknown", "reason": "Agent 引文对应的固定提交源码不可用。"}
            if not isinstance(fixed, dict) or fixed.get("commit") != binding.get("commit"):
                return {"state": "unknown", "reason": "Agent 引文源码未绑定到固定提交。"}
            fixed_sources[cited_file] = fixed
        fixed = fixed_sources[cited_file]
        fixed_lines = fixed.get("text", "").splitlines()
        matched = False
        for entry in entries:
            if cited_file != entry["file"]:
                continue
            if (entry.get("commit") is not None
                    and entry["commit"] != binding.get("commit")):
                continue
            if (entry.get("source_sha256") is not None
                    and entry["source_sha256"] != fixed.get("sha256")):
                continue
            if entry.get("git_blob") is not None and entry["git_blob"] != fixed.get("blob"):
                continue
            if (entry.get("commit") is None and entry.get("source_sha256") is None
                    and entry.get("git_blob") is None):
                continue
            if not isinstance(quote, str):
                continue
            start, end = citation.get("line_start"), citation.get("line_end")
            if start is not None or end is not None:
                if (not isinstance(start, int) or isinstance(start, bool)
                        or not isinstance(end, int) or isinstance(end, bool)
                        or start < 1 or end < start
                        or any(line not in entry["lines"] for line in range(start, end + 1))
                        or end > len(fixed_lines)
                        or "\n".join(entry["lines"][line] for line in range(start, end + 1)) != quote
                        or "\n".join(fixed_lines[line - 1] for line in range(start, end + 1)) != quote):
                    continue
            else:
                if quote not in entry["text"] and quote not in "\n".join(entry["lines"].values()):
                    continue
                if quote not in fixed.get("text", ""):
                    continue
            matched = True
            break
        if not matched:
            return {"state": "unknown", "reason": "Agent 引文与其固定提交源码材料不匹配。"}
    cited_sources = [{key: citation.get(key) for key in ("evidence_id", "file", "line_start", "line_end", "quote")
                      if citation.get(key) is not None} for citation in citations]
    return {"state": "unverified_model_advice",
            "reason": "引文逐字匹配固定提交；语义支持和其与修复建议的相关性仍需人工复核。",
            "citations": cited_sources}


def _product_validation_is_bound(settings, store, ops, case_id, operation_id):
    try:
        task = ops.get(operation_id)
        spec = task.get("spec") or {}
        if (task.get("kind") != "validation"
                or task.get("status") not in {"completed", "completed_with_limitations"}
                or spec.get("case_id") != case_id
                or spec.get("validation_scope") != "product_level"
                or spec.get("harness_id") not in PRODUCT_LEVEL_VALIDATOR_IDS):
            return False
        result = ops.result(operation_id)
        if (result.get("validation_gate") != "passed"
                or result.get("case_id") != case_id
                or result.get("validation_scope") != "product_level"
                or result.get("reachability_status") != "verified"
                or result.get("harness_id") != spec.get("harness_id")):
            return False
        binding = _case_product_validation_binding(settings, store, case_id)
        if not binding:
            return False
        manifest_path = ops.directory(operation_id) / "input-manifest.json"
        raw_manifest = manifest_path.read_bytes()
        if len(raw_manifest) > 256 * 1024:
            return False
        if hashlib.sha256(raw_manifest).hexdigest() != result.get("input_manifest_sha256"):
            return False
        manifest = json.loads(raw_manifest)
        if not isinstance(manifest, dict):
            return False
        for record in (spec, result, manifest):
            if (record.get("validation_scope") != "product_level"
                    or record.get("harness_id") != spec.get("harness_id")
                    or record.get("product_validation_binding") != binding):
                return False
            if (record.get("target_repository") != binding["target_repository"]
                    or record.get("target_commit") != binding["target_commit"]):
                return False
        return True
    except (KeyError, TypeError, ValueError, OSError, UnicodeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

def _case_product_validation_binding(settings, store, case_id):
    links = _case_links(store, case_id)
    if len(links) != 1:
        return None
    link = links[0]
    try:
        job = store.job(link["job_id"])
        repository = store.repository(job["repository_id"])
        report = service.read_report(settings, job)
        candidate = service.finding(report, link["candidate_id"])
        source = service.source(settings, store, job, candidate["file"])
    except (KeyError, TypeError, ValueError, OSError, UnicodeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    if candidate.get("source_sha256") and candidate["source_sha256"] != source["sha256"]:
        return None
    binding = {
        "case_id": case_id,
        "job_id": job["id"],
        "candidate_id": link["candidate_id"],
        "repository_id": job["repository_id"],
        "target_repository": repository["name"],
        "target_commit": job["spec"].get("commit"),
        "git_tree": job["spec"].get("git_tree"),
        "report_sha256": job.get("report_sha256"),
        "snapshot_sha256": report.get("snapshot_sha256"),
        "source_file": source["file"],
        "source_sha256": source["sha256"],
        "source_blob": source.get("blob"),
        "archive_binding": source.get("archive_binding"),
        "line": candidate.get("line"),
        "symbol": candidate.get("symbol"),
        "rule_id": candidate.get("rule_id"),
    }
    if not all(binding.get(key) for key in (
        "target_repository", "target_commit", "git_tree", "report_sha256",
        "snapshot_sha256", "source_file", "source_sha256", "rule_id",
    )):
        return None
    return binding

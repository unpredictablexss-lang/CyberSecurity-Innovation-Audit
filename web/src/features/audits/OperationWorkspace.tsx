import { experimentHoldoutPresentation, validationScopePresentation } from "./experimentEvidence.js";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Collapse, Descriptions, Empty, List, Progress, Space, Table, Tabs, Tag, Typography, message } from "antd";
import { api, terminal } from "../../api";
import { go, Hash, Header, State } from "../../components";
import { refreshSelectedOperation } from "../../pages/operationSelection";
import { AgentInvestigationForm, ComparisonForm, InvestigationForm, SyncForm, ValidationForm, SourceContext } from "./OperationForms";
import AgentAssessment from "./AgentAssessment";
import AgentBlindReview from "./AgentBlindReview";
import SourceSyncDetails from "./SourceSyncDetails";
import ProgressiveDeepInvestigationAction from "./ProgressiveDeepInvestigationAction";
import VersionCandidateComparison from "./VersionCandidateComparison";
import { buildIntelligentReviewView } from "./operationProgressModel.js";
const { Text } = Typography;
const importProgressLabels: Record<string,string> = {queued:"等待导入", cloning:"下载源码", fetching:"同步源码", verifying:"核验固定版本", scanning:"静态扫描", completed:"已完成", failed:"失败"};
export function buildRecentWindowSummary(result: any) {
  if (!result || typeof result !== "object") return null;
  const sourceWindows = Array.isArray(result.windows) ? result.windows.slice(0, 2) : [];
  const displayWindows = Array.from({ length: 2 }, (_, index) => sourceWindows[index] || { status: "unknown" });
  const endpointDiff = result.between_window_endpoints || {};
  const rows = endpointDiff.candidate_comparison;
  const comparisonAvailable = Array.isArray(rows);
  const candidates = comparisonAvailable ? rows : [];
  const counts = { new_candidate: 0, disappeared_candidate: 0, persistent_candidate: 0, unknown: 0 };
  for (const row of candidates) {
    if (row?.status === "new_candidate") counts.new_candidate += 1;
    else if (row?.status === "disappeared_candidate") counts.disappeared_candidate += 1;
    else if (row?.status === "persistent_candidate") counts.persistent_candidate += 1;
    else counts.unknown += 1;
  }
  const endpoints = endpointDiff;
  return {
    status: result.status || "unknown",
    lookbackDays: result.lookback_days,
    referenceTime: result.reference_time,
    timezone: result.timezone,
    windows: displayWindows.map((window: any, index: number) => ({
      key: index,
      label: index === 0 ? `${result.lookback_days ?? "N"} 日窗口` : "最近 1 日窗口",
      period: window?.label || "时间范围未知",
      selectedCommitCount: Number.isInteger(window?.selected_commit_count) ? window.selected_commit_count : null,
      baseline: window?.baseline || null,
      endpoint: window?.endpoint || null,
      scanId: Array.isArray(result.scan_ids) ? result.scan_ids[index * 2 + 1] || null : null,
    })),
    betweenEndpoints: {
      from: endpoints.from || null,
      to: endpoints.to || null,
      changedFileCount: Array.isArray(endpoints.changes) ? endpoints.changes.length : null,
      impact: endpoints.impact || result.impact || "unknown",
    },
    comparisonAvailable,
    reason: result.reason || null,
    candidates,
    counts: comparisonAvailable ? counts : { ...counts, unknown: null },
    impact: result.impact || "unknown",
    validatedVulnerability: Number.isInteger(result.validated_vulnerability)
      ? result.validated_vulnerability : 0,
  };
}

function RecentWindowSummary({ result, openScan }: { result: any; openScan: (id: string) => void }) {
  const summary = buildRecentWindowSummary(result);
  if (!summary) return null;
  const labels: Record<string, string> = {
    new_candidate: "新增候选观察", disappeared_candidate: "消失候选观察",
    persistent_candidate: "持续候选", unknown: "未知",
    unknown_detector_version_changed: "检测器版本变化，未知",
  };
  const color: Record<string, string> = { new_candidate: "blue", disappeared_candidate: "orange",
    persistent_candidate: "default", unknown: "default", unknown_detector_version_changed: "default" };
  return <Card className="section-gap" size="small" title="N 日 / 1 日候选观察差异">
    <Alert type={summary.comparisonAvailable ? "info" : "warning"} showIcon
      message={summary.comparisonAvailable ? "显示固定快照间的静态候选变化，不判断漏洞何时引入或修复。" : "比较未完成，候选差异未知。"}
      description={`${summary.reason ? `${summary.reason} ` : ""}影响：${summary.impact}；已确认漏洞：${summary.validatedVulnerability}。候选新增或消失不等于漏洞引入或修复。`} />
    <Descriptions className="section-gap" size="small" column={{ xs: 1, md: 2 }}>
      {summary.windows.map((window: any) => <Descriptions.Item key={window.key} label={window.label}>
        {window.period}<br />提交数：{window.selectedCommitCount ?? "未知"}<br />
        固定端点：{window.baseline ? window.baseline.slice(0, 12) : "未知"} → {window.endpoint ? window.endpoint.slice(0, 12) : "未知"}
        {window.scanId && <div><Button size="small" onClick={() => openScan(window.scanId)}>查看该窗口扫描</Button></div>}
      </Descriptions.Item>)}
      <Descriptions.Item label="两个窗口端点之间">
        {summary.betweenEndpoints.from ? summary.betweenEndpoints.from.slice(0, 12) : "未知"} → {summary.betweenEndpoints.to ? summary.betweenEndpoints.to.slice(0, 12) : "未知"}<br />
        变更文件：{summary.betweenEndpoints.changedFileCount ?? "未知"}；影响：{summary.betweenEndpoints.impact}
      </Descriptions.Item>
      <Descriptions.Item label="候选观察数">
        新增 {summary.counts.new_candidate} · 消失 {summary.counts.disappeared_candidate} · 持续 {summary.counts.persistent_candidate} · 未知 {summary.counts.unknown ?? "未知"}
      </Descriptions.Item>
    </Descriptions>
    <Table<any> size="small" rowKey={(row) => [row.detector_id, row.rule_id, row.file, row.symbol].join("|")}
      dataSource={summary.candidates} pagination={{ pageSize: 5 }} scroll={{ x: 850 }} columns={[
        { title: "观察状态", dataIndex: "status", render: (value) => <Tag color={color[value] || "default"}>{labels[value] || "未知"}</Tag> },
        { title: "检测器 / 规则", render: (_: any, row: any) => <>{row.detector_id || "未知"}<div className="muted">{row.rule_id || "未知"}</div></> },
        { title: "文件 / 符号", render: (_: any, row: any) => <>{row.file || "未知"}<div className="muted">{row.symbol || "未知"}</div></> },
        { title: "前 / 后端候选数", render: (_: any, row: any) => `${Array.isArray(row.before) ? row.before.length : "未知"} / ${Array.isArray(row.after) ? row.after.length : "未知"}` },
        { title: "身份匹配依据", dataIndex: "match_basis", render: (value) => value === "detector_rule_path_symbol" ? "检测器、规则、文件、符号" : "未知" },
      ]} locale={{ emptyText: summary.comparisonAvailable ? "暂无候选观察差异；不表示源码无漏洞。" : "比较未完成；候选差异未知。" }} />
  </Card>;
}
export type OperationView = "all" | "date" | "branches" | "matrix" | "validation" | "investigate" | "agent" | "agent_research" | "sync" | "queue";
const kinds: Record<string, string> = { source_sync: "源码同步 / 自动扫描", source_sync_batch: "多仓库批量同步", revision_range: "固定区间", branch_comparison: "跨版本比较", recent_window_comparison: "N 日 / 1 日对照", version_matrix: "版本矩阵", validation: "隔离验证", investigation: "只读调查", agent_investigation: "模型辅助调查", progressive_quick_screen: "渐进式 L2 快速研判", candidate_review_batch: "历史候选队列（已停用）" };
const headings: Record<OperationView, [string, string]> = {
  all: ["高级源码与验证操作", "保留既有操作入口；任务持久化，候选变化与安全影响分别记录。"],
  date: ["时间增量扫描", "按明确时区固定时间端点；支持单一区间和 N 日 / 1 日双窗口候选对照。"],
  branches: ["跨版本安全分析", "比较同一仓库的分支、Tag 或 Commit；候选变化不等于漏洞引入或修复。"],
  matrix: ["影响与修复", "先核对多个扫描版本的候选观察，再补充影响与修复证据。"],
  validation: ["PoC 验证", "围绕绑定源码和注册 Harness 申请隔离验证，保留失败与未知项。"],
  investigate: ["候选调查", "先用确定性工具整理证据，也可在明确同意后调用受限 Agent。"],
  agent: ["模型辅助调查", "候选源码仅在明确同意后发送；模型提供分诊倾向，漏洞状态不自动升级。"],
  agent_research: ["研究实验记录", "查看执行指标、人工反馈、静态基线与盲审进度；这些数据不代表漏洞真值或检测准确率。"],
  sync: ["源码同步", "显式同步 Git 对象；任务扫描只读扫描版本。"],
  queue: ["持久化操作任务", "查看在线仓库导入、扫描区间、版本比较、同步、调查和验证的真实状态。"],
};
export default function OperationWorkspace({ view = "all", operationId, context = {} }: { view?: OperationView; operationId?: string; context?: SourceContext }) {
  const [repos, setRepos] = useState<any[]>([]), [detectors, setDetectors] = useState<any[]>([]), [cases, setCases] = useState<any[]>([]);
  const [rows, setRows] = useState<any[]>([]), [selected, setSelected] = useState<any>(null);
  const [progressiveStatus, setProgressiveStatus] = useState<any>(null);
  const [reviewQueue, setReviewQueue] = useState<any>({ queued_batches: 0, running_batches: 0, queued_candidates: 0, running_candidates: 0 });
  const [error, setError] = useState(""), [busy, setBusy] = useState(false), [agentStatus, setAgentStatus] = useState<any>(null);
  const [agentEvaluation, setAgentEvaluation] = useState<any>(null);
  const holdoutView = experimentHoldoutPresentation(agentEvaluation?.evidence_evaluation?.holdout);
  const selectedId = useRef<string | null>(operationId || null), live = useRef(true);
  const refresh = useCallback(async () => {
    const [r, d, c, o, a, q] = await Promise.all([api("/repositories/list"), api("/detectors"), api("/cases"), api("/operations"), api("/agent/status"), api("/operations/agent-review-queue/status")]);
    if (!live.current) return;
    setError((current) => current === "TypeError: Failed to fetch" ? "" : current);
    setRepos(r); setDetectors(d); setCases(c); setRows(o); setAgentStatus(a); setReviewQueue(q);
    const id = selectedId.current;
    if (id) {
      const item = await refreshSelectedOperation(id, (key) => api("/operations/" + key), () => live.current ? selectedId.current : null, setSelected);
      if (["revision_range", "recent_window_comparison", "branch_comparison", "version_matrix"].includes(item.kind)) {
        try {
          const [usage, groups] = await Promise.all([
            api("/audits/" + id + "/ai-usage"),
            api("/audits/" + id + "/triage-groups?offset=0&limit=200"),
          ]);
          if (live.current && selectedId.current === id) setProgressiveStatus({ ...usage, groups: groups.groups, group_total: groups.group_total });
        } catch { if (live.current && selectedId.current === id) setProgressiveStatus(null); }
      } else if (live.current && selectedId.current === id) setProgressiveStatus(null);
    }
  }, []);
  useEffect(() => {
    if (view !== "agent_research") { setAgentEvaluation(null); return; }
    let active = true;
    const load = () => void api("/agent/evaluation-summary").then((value) => { if (active) setAgentEvaluation(value); })
      .catch((e) => { if (active) setError(String(e)); });
    load();
    const timer = setInterval(load, 15000);
    return () => { active = false; clearInterval(timer); };
  }, [view]);
  useEffect(() => {
    live.current = true;
    void refresh().catch((e) => { if (live.current) setError(String(e)); });
    const timer = setInterval(() => void refresh().catch((e) => { if (live.current) setError(String(e)); }), 2500);
    return () => { live.current = false; clearInterval(timer); };
  }, [refresh]);
  const show = async (id: string) => {
    selectedId.current = id;
    try {
      const item = await refreshSelectedOperation(id, (key) => api("/operations/" + key), () => live.current ? selectedId.current : null, setSelected);
      if (["revision_range", "recent_window_comparison", "branch_comparison", "version_matrix"].includes(item.kind)) {
        const [usage, groups] = await Promise.all([
          api("/audits/" + id + "/ai-usage"), api("/audits/" + id + "/triage-groups?offset=0&limit=200"),
        ]);
        if (live.current && selectedId.current === id) setProgressiveStatus({ ...usage, groups: groups.groups, group_total: groups.group_total });
      } else setProgressiveStatus(null);
    }
    catch (e) { setError(String(e)); }
  };
  const submit = async (path: string, payload: any) => {
    setBusy(true); setError("");
    try { const item = await api(path, payload); selectedId.current = item.id; setSelected(item); await refresh(); message.success("任务已加入持久化队列"); }
    catch (e) { setError(String(e)); } finally { setBusy(false); }
  };
  const props = { repos, detectors, cases, busy, agentStatus, submit, context };
  const forms = [
    { key: "sync", label: "同步源码", children: <SyncForm {...props} /> },
    { key: "range", label: "两个 SHA 区间", children: <ComparisonForm {...props} kind="range" /> },
    { key: "date", label: "提交者日期区间", children: <ComparisonForm {...props} kind="date" /> },
    { key: "recent", label: "N 日与 1 日对照", children: <ComparisonForm {...props} kind="recent" /> },
    { key: "branches", label: "跨分支比较", children: <ComparisonForm {...props} kind="branches" /> },
    { key: "matrix", label: "版本矩阵", children: <ComparisonForm {...props} kind="matrix" /> },
    { key: "validation", label: "隔离验证", children: <ValidationForm {...props} /> },
    { key: "investigate", label: "只读调查", children: <InvestigationForm {...props} /> },
    { key: "agent", label: "模型辅助调查", children: <AgentInvestigationForm busy={busy} submit={submit} context={context} cases={cases} agentStatus={agentStatus} /> },
  ];
  const filtered = view === "agent_research" ? [] : rows.filter((r) => r.kind !== "candidate_review_batch" && (view === "all" || view === "queue" || (view === "date" ? ["revision_range", "recent_window_comparison"].includes(r.kind) : view === "branches" ? ["branch_comparison", "revision_range"].includes(r.kind) : view === "sync" ? ["source_sync", "source_sync_batch"].includes(r.kind) : r.kind === ({ matrix: "version_matrix", validation: "validation", investigate: "investigation", agent: "agent_investigation" } as Record<string, string>)[view])));
  return <>
    <Header title={headings[view][0]} description={headings[view][1]} />
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {view === "all" ? <Tabs items={forms} /> : view === "date" ? <Tabs items={[forms[2], forms[3]]} /> : view === "branches" ? <Tabs items={[forms[4], forms[5]]} /> : view === "investigate" ? <Tabs items={[forms[7], forms[8]]} /> : view === "agent_research" ? null : forms.find((f) => f.key === view)?.children}
    {view === "agent_research" && agentEvaluation && <Card className="section-gap" size="small" title="模型执行与成本评估（最近 200 个任务）">
      <Alert type="info" showIcon message="Token 为 Provider 完整返回用量的合计；费用仅按已知费率估算，实际账单未核验。耗时来自任务记录和 Agent 子进程；RSS 是子进程高水位，不含 Docker 容器与 Provider 侧资源。以上不构成漏洞准确率或独立真值。" description={agentEvaluation.execution_limitation} />
      <Table<any> className="section-gap" size="small" rowKey={(row) => [row.mode, row.provider, row.endpoint_host, row.model, row.prompt_version, row.tool_policy_version].join("|")}
        dataSource={agentEvaluation.execution_groups || []} pagination={false} scroll={{ x: 1900 }} columns={[
          { title: "模式 / Provider", render: (_, row) => <>{row.mode}<div className="muted">{row.provider}</div><div className="muted">{row.model}</div></> },
          { title: "接口 / 运行条件", render: (_, row) => <><Text>{row.endpoint_host}</Text><div className="muted">接口类型：{row.runtime_conditions?.provider_endpoint || "未知"}</div><div className="muted">进程：{row.runtime_conditions?.application_process || "未知"}</div><div className="muted">Docker RSS：{row.runtime_conditions?.docker_container_metrics || "未知"}</div></> },
          { title: "提示 / 工具版本", render: (_, row) => <>{row.prompt_version}<div className="muted">{row.tool_policy_version}</div></> },
          { title: "任务 / 结果 / 状态", render: (_, row) => <>{row.operation_count} / {row.result_count}<div className="muted">{Object.entries(row.status_counts || {}).map(([name, count]) => String(name) + ": " + String(count)).join("; ")}</div></> },
          { title: "结构校验 通过 / 拒绝 / 未知", render: (_, row) => [row.schema_validation.accepted, row.schema_validation.rejected, row.schema_validation.unknown].join(" / ") },
          { title: "修复任务 / 次数；工具完成 / 拒绝 / 未知", render: (_, row) => <>{row.repair_operation_count} / {row.repair_attempts}<div className="muted">{[row.tool_calls.completed, row.tool_calls.rejected, row.tool_calls.unknown_status].join(" / ")}</div></> },
          { title: "Provider 用量完整 / 不完整 / 未知", render: (_, row) => <>{[row.usage.complete, row.usage.incomplete, row.usage.unknown].join(" / ")}<div className="muted">完整项输入 / 输出合计：{row.token_usage?.input_tokens ?? "未知"} / {row.token_usage?.output_tokens ?? "未知"}</div><div className="muted">完整记录：{row.token_usage?.complete_operation_count ?? 0} 项</div></> },
          { title: "费率估算（非实账）", render: (_, row) => <>{(row.cost_estimate_aggregates || []).map((item: any) => <div key={item.status + item.rate_card_id}>{item.status === "estimated_range" ? `USD ${item.amounts.minimum_usd}–${item.amounts.maximum_usd}` : `USD ${item.amounts.amount_usd}`}{item.amounts.amount_cny ? ` / ${item.alternative_currency || "CNY"} ${item.amounts.amount_cny}（${item.amount_counts.amount_cny || 0} 项）` : ""} · {item.operation_count} 项</div>)}<div className="muted">{Object.entries(row.cost_estimate_status_counts || {}).map(([name, count]) => String(name) + ": " + String(count)).join("; ") || "无费用估算"}</div><div className="muted">实际账单未核验</div></> },
          { title: "任务耗时 median / max（秒）", render: (_, row) => <>{row.wall_time?.median_seconds ?? "未知"} / {row.wall_time?.maximum_seconds ?? "未知"}<div className="muted">已测 {row.wall_time?.measured_operation_count ?? 0} 项</div></> },
          { title: "子进程耗时 median（秒）", render: (_, row) => <>{row.child_execution_time?.median_seconds ?? "未知"}<div className="muted">已测 {row.child_execution_time?.measured_operation_count ?? 0} 项</div></> },
          { title: "子进程峰值 RSS median / max（MiB）", render: (_, row) => { const rss = row.process_peak_rss; const mib = (value: number | null) => value == null ? "未知" : (value / 1048576).toFixed(1); return <>{mib(rss?.median_bytes)} / {mib(rss?.maximum_bytes)}<div className="muted">已测 {rss?.measured_operation_count ?? 0} 项</div></>; } },
        ]} locale={{ emptyText: "暂无 Agent 执行记录" }} />
    </Card>}
    {view === "agent_research" && agentEvaluation && <Card className="section-gap" size="small" title="扫描版本与验证范围">
      <Alert type="info" showIcon
        message={holdoutView.label}
        description={holdoutView.reason + " 不计算模型准确率、Precision 或 Recall。"} />
      <Descriptions className="section-gap" size="small" bordered column={3}>
        <Descriptions.Item label="与本次扫描源码匹配的 Agent 结果">
          {agentEvaluation.evidence_evaluation?.agent?.fixed_source_bound_result_count ?? "unknown"}
        </Descriptions.Item>
        <Descriptions.Item label="源码版本未核对的 Agent 结果">
          {agentEvaluation.evidence_evaluation?.agent?.unknown_binding_count ?? "unknown"}
        </Descriptions.Item>
        <Descriptions.Item label="统计范围">
          {agentEvaluation.evidence_evaluation?.operation_window || "unknown"}
        </Descriptions.Item>
      </Descriptions>
      <Table<any> className="section-gap" size="small" rowKey={(row) => [row.experiment_id || "untagged", row.mode, row.model, row.prompt_version, row.tool_policy_version].join("|")}
        dataSource={agentEvaluation.evidence_evaluation?.agent?.groups || []} pagination={false} scroll={{ x: 950 }}
        columns={[
          { title: "实验批次", dataIndex: "experiment_id", render: (value) => value || "未标记" },
          { title: "模式 / 模型", render: (_, row) => <>{row.mode}<div className="muted">{row.model}</div></> },
          { title: "提示 / 工具策略", render: (_, row) => <>{row.prompt_version}<div className="muted">{row.tool_policy_version}</div></> },
          { title: "运行 / 版本匹配结果 / 未核对", render: (_, row) => `${row.operation_count} / ${row.fixed_source_bound_result_count} / ${row.unknown_binding_count}` },
          { title: "任务状态", render: (_, row) => Object.entries(row.status_counts || {}).map(([name, count]) => `${name}: ${count}`).join("；") || "unknown" },
        ]} locale={{ emptyText: "暂无可汇总的 Agent 运行 · unknown" }} />
      <Alert className="section-gap" type="warning" showIcon
        message="隔离验证按组件 Harness 与产品级验证分开展示"
        description="当前注册的 AUTH-01 是组件 Harness：直接调用组件 stub，不能证明 OpenHarmony 产品入口可达。只有输入清单完整且产品验证明确报告 reachability=verified 才能归为产品级；验证结果不会在此页自动确认为漏洞，也不会自动关联进候选实验。" />
      <Table<any> size="small" rowKey="operation_id" dataSource={agentEvaluation.evidence_evaluation?.validation?.runs || []}
        pagination={{ pageSize: 5 }} scroll={{ x: 900 }} columns={[
          { title: "案例 / 操作", render: (_, row) => <>{row.case_id || "unknown"}<div className="muted">{row.operation_id}</div></> },
          { title: "验证范围", render: (_, row) => validationScopePresentation(row).label },
          { title: "Harness / 仓库", render: (_, row) => <>{row.harness_id || "unknown"}<div className="muted">{row.target_repository}</div></> },
          { title: "扫描代码版本 / 输入清单", render: (_, row) => <><Hash value={row.target_commit} /><div className="muted">{row.input_manifest_state}</div></> },
          { title: "状态 / 验证门 / 可达性", render: (_, row) => <>{row.status}<div className="muted">{row.validation_gate} / {row.reachability_status}</div></> },
        ]} locale={{ emptyText: "没有持久化验证运行 · unknown" }} />
    </Card>}
    {view === "agent_research" && agentEvaluation && <Card className="section-gap" size="small" title="模型人工反馈评测">
      <Alert type="info" showIcon message="仅统计人工对 Agent 分诊的反馈，不代表漏洞准确率、Precision 或 Recall。" description={agentEvaluation.limitation + " 逐条主张支持度是人工语义评价；没有填写的主张显示为未复核。"} />
      <Table<any> className="section-gap" size="small" rowKey={(row) => [row.experiment_id, row.mode, row.model, row.prompt_version, row.tool_policy_version].join("|")}
        dataSource={agentEvaluation.groups} pagination={false} scroll={{ x: 900 }} columns={[
          { title: "模式 / 模型", render: (_, row) => <>{row.mode}<div className="muted">{row.model}</div></> },
          { title: "提示 / 工具版本", render: (_, row) => <>{row.prompt_version}<div className="muted">{row.tool_policy_version}</div></> },
          { title: "操作 / 候选 / 评价", render: (_, row) => `${row.operation_count} / ${row.candidate_count} / ${row.review_count}` },
          { title: "有用 / 部分 / 无用 / 风险", render: (_, row) => [row.usefulness.useful, row.usefulness.partially_useful, row.usefulness.not_useful, row.usefulness.unsafe].join(" / ") },
          { title: "引文准 / 有错 / 多错 / 未核", render: (_, row) => [row.citation_accuracy.all_accurate, row.citation_accuracy.some_incorrect, row.citation_accuracy.mostly_incorrect, row.citation_accuracy.not_checked].join(" / ") },
          { title: "主张支持 / 部分 / 不支持 / 未知 / 未复核", render: (_, row) => [row.claim_support.supported, row.claim_support.partially_supported, row.claim_support.unsupported, row.claim_support.unverifiable, row.claim_support.not_reviewed].join(" / ") },
          { title: "人工复核中位秒数", dataIndex: "median_elapsed_seconds", render: (value) => value ?? "unknown" },
        ]} locale={{ emptyText: "尚无人工反馈；该表不包含漏洞真值标签。" }} />
    </Card>}
    {view === "agent_research" && agentEvaluation?.r0_baseline_reviews?.length > 0 && <Card className="section-gap" size="small" title="R0 静态人工基线记录">
      <Alert type="info" showIcon message="先于模型运行的静态分诊记录；仅为人工意见，不是漏洞真值。" />
      <Table<any> className="section-gap" size="small" rowKey="id" dataSource={agentEvaluation.r0_baseline_reviews}
        pagination={{ pageSize: 5 }} scroll={{ x: 1050 }} columns={[
          { title: "实验批次", dataIndex: "experiment_id" },
          { title: "本次扫描候选", render: (_, row) => <><Text>{row.repository}</Text><div className="muted">{row.commit.slice(0, 12)} · {row.candidate_id.slice(0, 12)}</div></> },
          { title: "静态分诊", dataIndex: "disposition" },
          { title: "逐项基线（支持 / 反向 / 未决）", render: (_, row) => { const counts = { evidence_found: 0, contrary_evidence: 0, unresolved: 0 }; for (const review of row.obligation_reviews || []) { if (review.disposition in counts) counts[review.disposition as keyof typeof counts] += 1; } return String(row.obligations_reviewed ?? 0) + " 项：" + counts.evidence_found + " / " + counts.contrary_evidence + " / " + counts.unresolved + (row.obligations_truncated ? "（仅前 40 项）" : ""); } },
          { title: "复核人 / 秒", render: (_, row) => `${row.reviewer} / ${row.elapsed_seconds ?? "unknown"}` },
          { title: "记录哈希", dataIndex: "record_sha256", render: (value) => <Hash value={value} /> },
        ]} />
    </Card>}    {view === "agent_research" && agentEvaluation?.paired_comparisons?.length > 0 && <Card className="section-gap" size="small" title="同一候选的调查方式对照反馈">
      <Alert type="info" showIcon message="仅按实验批次、固定 repo/commit/candidate、模型和提示/工具版本配对操作者自报评价；不是随机实验、漏洞真值或因果效果。" />
      <Table<any> className="section-gap" size="small"
        rowKey={(row) => [row.experiment_id, row.repository, row.commit, row.candidate_id, row.model].join("|")}
        dataSource={agentEvaluation.paired_comparisons} pagination={false} scroll={{ x: 1000 }} columns={[
          { title: "实验批次", dataIndex: "experiment_id" },
          { title: "固定候选", render: (_, row) => <><Text>{row.repository}</Text><div className="muted">{row.commit.slice(0, 12)} · {row.candidate_id.slice(0, 12)}</div></> },
          { title: "人工静态基线", render: (_, row) => row.r0_static_baseline ? `${row.r0_static_baseline.dispositions.investigate} 调查 / ${row.r0_static_baseline.dispositions.likely_noise} 噪声 / ${row.r0_static_baseline.dispositions.unknown} 未知；${row.r0_static_baseline.median_elapsed_seconds ?? "unknown"} 秒` : "未记录" },
          { title: "模型", dataIndex: "model" },
          { title: "单轮研判评价 / 引文 / 中位秒", render: (_, row) => `${row.single_shot.review_count} / ${row.single_shot.citation_accuracy.all_accurate}·${row.single_shot.citation_accuracy.some_incorrect + row.single_shot.citation_accuracy.mostly_incorrect} / ${row.single_shot.median_elapsed_seconds ?? "unknown"}` },
          { title: "跨文件调查评价 / 引文 / 中位秒", render: (_, row) => `${row.tool_agent.review_count} / ${row.tool_agent.citation_accuracy.all_accurate}·${row.tool_agent.citation_accuracy.some_incorrect + row.tool_agent.citation_accuracy.mostly_incorrect} / ${row.tool_agent.median_elapsed_seconds ?? "unknown"}` },
        ]} />
    </Card>}    {view === "agent_research" && <AgentBlindReview operations={rows} />}
    {view === "matrix" && <Alert className="section-gap" type="info" showIcon message="影响与修复仍需独立证据" description="当前矩阵只记录候选观察。补丁生成、补丁应用和修复后产品验证尚未接入；不会用候选消失自动判定已修复。" />}
    {view !== "agent_research" && <>
    <Card className="section-gap" title="操作任务" extra={<Button onClick={() => void refresh().catch((e) => setError(String(e)))}>刷新列表</Button>}>
      {reviewQueue.queued_batches > 0 && <Alert className="section-gap" type="info" showIcon
        message={`保留了 ${reviewQueue.queued_batches} 条旧版候选队列占位记录`}
        description="这些历史占位记录不会执行模型调用，也不会改变候选或漏洞状态。当前未研判候选请在对应审计任务中查看；历史记录仍保留供追溯。" />}
      <Table<any> rowKey="id" dataSource={filtered} pagination={{ pageSize: 8 }} scroll={{ x: 640 }} columns={[
        { title: "任务", render: (_, row) => <><Text strong>{kinds[row.kind] || row.kind}</Text><div className="muted">{row.id.slice(0, 12)}</div></> },
        { title: "状态", dataIndex: "status", render: (v) => <State value={v} /> },
        { title: "创建时间", dataIndex: "created_at", render: (v) => new Date(v).toLocaleString() },
        { title: "操作", render: (_, row) => <Space><Button onClick={() => void show(row.id)}>查看</Button>{!terminal.has(row.status) && row.kind !== "candidate_review_batch" && <Button danger onClick={async () => {
          try { await api("/operations/" + row.id + "/cancel", {}); await refresh(); } catch (e) { setError(String(e)); }
        }}>取消</Button>}</Space> },
      ]} locale={{ emptyText: <Empty description="尚无此类操作记录" /> }} />
    </Card>
    {selected && <Card className="section-gap" title={<Space>操作详情 <Text copyable>{selected.id}</Text></Space>} extra={<Button onClick={() => { selectedId.current = null; setSelected(null); }}>收起</Button>}>
      <Space wrap><State value={selected.status} /><Text>{kinds[selected.kind] || selected.kind}</Text><Button size="small" onClick={() => go("/tasks/operations/" + selected.id)}>任务中心打开</Button>
        {selected.kind === "repository_import_scan" && selected.result?.scan_job?.id && <Button size="small" type="primary" onClick={() => go("/tasks/" + selected.result.scan_job.id)}>查看自动创建的扫描</Button>}
        {selected.kind === "repository_import_scan" && ["failed", "interrupted", "timed_out"].includes(selected.status) && <Button size="small" type="primary" onClick={async () => {
          try {
            const retried = await api("/operations/" + selected.id + "/retry", {});
            selectedId.current = retried.id;
            await show(retried.id);
            await refresh();
            message.success("已为同一固定 Commit 创建重新排队任务");
          } catch (e) { setError(String(e)); }
        }}>重新排队</Button>}
        {selected.result_sha256 && <><Text>Result SHA-256</Text><Hash value={selected.result_sha256} /></>}</Space>
      {selected.error && <Alert className="section-gap" type="error" message={selected.error} />}
      {selected.kind === "repository_import_scan" && <Card size="small" className="section-gap" title="固定版本下载进度">
        {selected.download_progress ? <>
          <Space wrap><Tag color={selected.download_progress.state === "failed" ? "red" : selected.download_progress.state === "completed" ? "green" : "blue"}>
            {importProgressLabels[selected.download_progress.phase] || selected.download_progress.phase || "处理中"}
          </Tag><Text>{selected.download_progress.message}</Text>
            {selected.download_progress.completed_objects != null && selected.download_progress.total_objects != null &&
              <Text type="secondary">对象 {selected.download_progress.completed_objects.toLocaleString()} / {selected.download_progress.total_objects.toLocaleString()}</Text>}
            {selected.download_progress.received_bytes != null && <Text type="secondary">已接收 {(selected.download_progress.received_bytes / 1048576).toFixed(1)} MiB</Text>}
            {selected.download_progress.bytes_per_second != null && <Text type="secondary">{(selected.download_progress.bytes_per_second / 1048576).toFixed(1)} MiB/s</Text>}
          </Space>
          {selected.download_progress.percent != null && <Progress className="section-gap" percent={selected.download_progress.percent}
            status={selected.download_progress.state === "failed" ? "exception" : selected.download_progress.state === "completed" ? "success" : "active"} />}
        </> : <Text type="secondary">等待 Worker 开始。下载完成后会校验 Commit，再创建静态扫描任务。</Text>}
        {selected.spec?.retry_of && <div><Text type="secondary">此任务是对 {selected.spec.retry_of.slice(0, 12)} 的重新排队。</Text></div>}
      </Card>}
      {selected.kind === "agent_investigation" && !selected.result_sha256 && ["failed", "interrupted", "timed_out", "cancelled"].includes(selected.status) && <Alert className="section-gap" type="warning" showIcon message="本次调查没有可复核结果；候选仍为 unknown" description="任务结束不代表候选是误报或安全。若 Worker 在 Provider 已处理请求后、结果落盘前退出，上游调用和费用仍可能发生。重试前请核对执行事件及 Provider 账单，再重新预览并单独批准新任务。" />}
      {selected.result?.scan_job_id && <Button className="section-gap" onClick={() => go("/tasks/" + selected.result.scan_job_id)}>打开同步后扫描任务 · {String(selected.result.scan_job_id).slice(0, 12)}</Button>}
      {selected.spec?.scan_ids && <Space wrap className="section-gap">端点扫描：{selected.spec.scan_ids.map((id: string) => <Button key={id} size="small" onClick={() => go("/tasks/" + id)}>{id.slice(0, 12)}</Button>)}</Space>}
      {selected.result?.progressive_triage && <Card size="small" className="section-gap" title="渐进式审计 · L0 归并 / L1 排序 / L2-L3 状态">
        {(() => {
          const plan = selected.result.progressive_triage;
          const activeStatus = progressiveStatus?.audit_operation_id === selected.id ? progressiveStatus : null;
          const groups = Array.isArray(activeStatus?.groups) ? activeStatus.groups : Array.isArray(plan.groups) ? plan.groups : [];
          const budget = activeStatus?.budget || {};
          return <>
            <Alert type="info" showIcon
              message={`固定策略 ${plan.policy_profile || "unknown"} · ${plan.grouping?.group_count ?? plan.groups?.length ?? 0} 个候选组 · 阶段：${activeStatus?.phase || "deterministic_ranked"}`}
              description="未选、尚未授权或信息不足的组仍是候选；模型意见不改变漏洞确认状态。仅美元预算为估算，任务调度上限见下方账本。" />
            <Descriptions className="section-gap" size="small" column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="策略修订 / 摘要 SHA-256">{plan.policy_revision ?? "未知"} · <Hash value={plan.policy_sha256} /></Descriptions.Item>
              <Descriptions.Item label="原始候选观察">{plan.original_observation_count ?? "未知"}</Descriptions.Item>
              <Descriptions.Item label="L0 归并组 / L1 选中">{activeStatus ? `${activeStatus.phase_counts.candidate_groups} / ${activeStatus.phase_counts.selected_for_quick_screen}` : `${plan.grouping?.group_count ?? groups.length} / ${plan.ranking?.selected_group_count ?? 0}`}</Descriptions.Item>
              <Descriptions.Item label="L2 完成 / L3 完成">{activeStatus ? `${activeStatus.phase_counts.quick_screen_completed} / ${activeStatus.phase_counts.deep_agent_completed}` : "0 / 0"}</Descriptions.Item>
              <Descriptions.Item label="未完成快筛的组成员">{activeStatus?.phase_counts.unassessed_group_members ?? plan.original_observation_count ?? "未知"}</Descriptions.Item>
              <Descriptions.Item label="模型请求 / 在途">{budget.usage ? `${budget.usage.model_calls_allocated} / ${budget.usage.model_calls_in_flight}` : "尚未开始"}</Descriptions.Item>
              <Descriptions.Item label="输入 / 输出 Token">{budget.usage ? `${budget.usage.input_tokens_allocated} / ${budget.usage.output_tokens_allocated}` : "尚未开始"}</Descriptions.Item>
              <Descriptions.Item label="停止原因">{activeStatus?.stop_reason || budget.stop_reason || "无"}</Descriptions.Item>
              <Descriptions.Item label="确认漏洞数">{plan.validated_vulnerability ?? 0}</Descriptions.Item>
            </Descriptions>
            {activeStatus?.group_total > groups.length && <Text type="secondary">当前展示前 {groups.length} / {activeStatus.group_total} 组；完整列表可通过任务 triage-groups API 分页读取。</Text>}
            <Table<any> size="small" rowKey="group_id" dataSource={groups} pagination={{ pageSize: 5 }} scroll={{ x: 720 }} columns={[
              { title: "排序", dataIndex: ["ranking", "rank"], width: 70 },
              { title: "组 / 家族", render: (_: any, row: any) => <><Text>{row.group_id}</Text><div className="muted">{row.ranking?.family_bucket || "unknown"}</div></> },
              { title: "候选成员", render: (_: any, row: any) => Array.isArray(row.members) ? row.members.length : 0 },
              { title: "L1 决定", render: (_: any, row: any) => row.ranking?.selected
                ? <Tag color="blue">优先复核</Tag> : <Tag>保留候选</Tag> },
              { title: "L2 快筛", render: (_: any, row: any) => {
                const state = row.quick_screen_state || "not_scheduled";
                const labels: Record<string, string> = { not_scheduled: "未授权/未排队", queued: "排队中", running: "执行中", completed: "已完成", partial: "部分/受限", unknown: "结果未知" };
                return <Tag color={state === "completed" ? "green" : state === "running" ? "processing" : state === "unknown" || state === "partial" ? "orange" : undefined}>{labels[state] || state}</Tag>;
              } },
              { title: "L3 深查", render: (_: any, row: any) => {
                const state = row.deep_agent_state || "not_scheduled";
                const labels: Record<string, string> = { not_scheduled: "未授权/未排队", queued: "排队中", running: "执行中", completed: "已完成", partial: "部分/受限", unknown: "结果未知" };
                return <Tag color={state === "completed" ? "green" : state === "running" ? "processing" : state === "unknown" || state === "partial" ? "orange" : undefined}>{labels[state] || state}</Tag>;
              } },
              { title: "选择依据", render: (_: any, row: any) => (row.ranking?.reason_codes || []).join(" · ") || "无" },
            ]} />
          </>;
        })()}
      </Card>}
      {selected.kind === "progressive_quick_screen" && selected.result && <Card size="small" className="section-gap" title="L2 快速研判结果">
        {(() => {
          const result = selected.result.quick_screen || {};
          const state = result.state || selected.result.state || "quick_unknown";
          const assessmentLabels: Record<string, string> = {
            investigate: "建议进入深度调查", defer: "暂缓", possible_refutation: "发现待复核反证线索",
            insufficient_context: "上下文不足", quick_unknown: "研判未知",
          };
          const listText = (value: unknown) => Array.isArray(value) && value.length ? value.join("、") : "无";
          return <>
            <Alert type={state === "completed" ? "info" : "warning"} showIcon
              message={`${assessmentLabels[result.quick_assessment] || assessmentLabels.quick_unknown} · ${result.review_status || "model_unverified"}`}
              description={result.reason_code || result.rationale || "没有可复核的模型研判；候选仍保留为待复核状态。模型意见不确认漏洞或误报。"} />
            <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="候选处置">candidate · validated_vulnerability={selected.result.validated_vulnerability ?? 0}</Descriptions.Item>
              <Descriptions.Item label="请求状态">{state}</Descriptions.Item>
              <Descriptions.Item label="缺失证据">{listText(result.missing_obligations)}</Descriptions.Item>
              <Descriptions.Item label="建议下一步">{listText(result.next_tool_hints)}</Descriptions.Item>
              <Descriptions.Item label="不确定项" span={2}>{listText(result.uncertainties)}</Descriptions.Item>
              <Descriptions.Item label="输入 / 输出 Token">{result.usage?.input_tokens ?? "未知"} / {result.usage?.output_tokens ?? "未知"}</Descriptions.Item>
              <Descriptions.Item label="预算结算">{selected.result.budget?.usage?.state || selected.result.budget?.status || "未知"}</Descriptions.Item>
              <Descriptions.Item label="来源 / consent SHA" span={2}>
                {selected.result.source_binding?.repository || "未知"} @ {String(selected.result.source_binding?.commit || "未知").slice(0, 12)} · {selected.result.source_binding?.consent_sha256 || "未知"}
              </Descriptions.Item>
            </Descriptions>
            <Text type="secondary">引文 ID：{listText(result.evidence_citations)}</Text>
            <Alert className="section-gap" type="info" showIcon message="L3 深度 Agent 需要单独授权" description="只有 L2 完成并建议 investigate 才能继续。提交后复用现有固定版本只读 Agent；它仍是候选调查意见，不会自动确认漏洞或标记误报。" />
            {result.quick_assessment === "investigate" && selected.spec?.job_id && selected.spec?.candidate_id &&
              <ProgressiveDeepInvestigationAction jobId={selected.spec.job_id} candidateId={selected.spec.candidate_id} quickScreenOperationId={selected.id} />}
          </>;
        })()}
      </Card>}
      {selected.kind === "recent_window_comparison" && selected.result && <RecentWindowSummary
        result={selected.result} openScan={(id) => go("/tasks/" + id)} />}
      {Array.isArray(selected.intelligent_review_progress) && <Card size="small" className="section-gap" title="固定版本静态与智能审计进度">
        <Alert type="info" showIcon message="端点静态对比完成不等于智能研判完成"
          description="每个固定版本的 Agent 都独立获得源码外发授权；模型处理失败、候选超出本次授权名额或尚未研判不代表源码安全。" />
        <Table<any> size="small" rowKey="scan_id" pagination={false} dataSource={selected.intelligent_review_progress}
          columns={[
            { title: "版本", render: (_: any, row: any) => <><Hash value={row.commit} /><div><Button size="small" onClick={() => go("/tasks/" + row.scan_id)}>查看扫描任务</Button></div></> },
            { title: "静态扫描", dataIndex: "scan_status", render: (value: string) => <State value={value} /> },
            { title: "智能研判", render: (_: any, row: any) => {
              const progress = buildIntelligentReviewView(row);
              if (!progress) return <Text type="secondary">暂无智能研判摘要</Text>;
              const countLabels: Record<string, string> = {
                queued: "排队", running: "运行", completed: "完成",
                completed_with_limitations: "有限制", failed: "失败",
                cancelled: "取消", timed_out: "超时", interrupted: "中断", blocked: "受阻",
              };
              const renderPhase = (name: string, phase: any) => <div key={name}>
                <Text strong>{name}</Text> <Tag color={phase.state === "completed" ? "green"
                  : phase.state === "completed_with_limitations" || phase.state === "partially_completed" ? "orange"
                    : ["failed", "timed_out", "interrupted", "blocked"].includes(phase.state) ? "red" : undefined}>
                  {phase.stateLabel}
                </Tag>
                <div className="muted">{Object.entries(phase.counts).map(([key, value]) => `${countLabels[key]} ${value}`).join(" · ")}</div>
                {!phase.summariesReturned && <Alert className="section-gap" type="warning" showIcon message={`${name} 子任务摘要未由本次 API 响应提供`}
                  description="缺少 operation ID、状态和结果绑定字段，因此这里不提供 Agent 详情入口；这不表示模型没有运行或没有结果。" />}
                {phase.summariesReturned && phase.operations.length === 0 && <Alert className="section-gap" type="info" showIcon
                  message={`${name} 子任务列表为空`}
                  description={phase.operationCount ? `阶段计数记录 ${phase.operationCount} 项，但没有返回可核对的逐项摘要；不提供详情入口。` : "当前响应明确返回空子任务列表；这只表示没有关联子任务记录，不代表源码安全。"} />}
                {phase.operations.length > 0 && <Space direction="vertical" size={2} className="section-gap">
                  {phase.operations.map((item: any, index: number) => <Space wrap key={`${item.id || "missing"}-${index}`}>
                    <Tag color={item.status === "completed" ? "green" : item.status === "completed_with_limitations" ? "orange" : ["failed", "timed_out", "interrupted", "blocked"].includes(item.status) ? "red" : "default"}>{item.statusLabel}</Tag>
                    <Text>候选 {item.candidateId ? item.candidateId.slice(0, 12) : "未知"}</Text>
                    <Text>Commit {item.commit ? item.commit.slice(0, 12) : "未知"}</Text>
                    <Text type="secondary">Result SHA-256</Text>{item.resultSha256 ? <Hash value={item.resultSha256} /> : <Text type="secondary">{["queued", "running"].includes(item.status) ? "结果尚未生成" : "摘要未提供或无效"}</Text>}
                    {item.reportSha256 && <><Text type="secondary">Report SHA-256</Text><Hash value={item.reportSha256} /></>}
                    {item.bindingValid && item.id
                      ? <Button size="small" onClick={() => void show(item.id)}>查看 {name} 操作详情</Button>
                      : <Text type="danger">{item.bindingIssue || "结果绑定不完整，已隐藏详情入口"}</Text>}
                  </Space>)}
                </Space>}
                {phase.reasons.map((reason: any, index: number) => <Alert key={`${reason.operationId || "reason"}-${index}`} className="section-gap"
                  type="error" showIcon message={`${reason.statusLabel}${reason.operationId ? ` · ${reason.operationId}` : ""}${reason.candidateId ? ` · 候选 ${reason.candidateId.slice(0, 12)}` : ""}`}
                  description={reason.reason} />)}
              </div>;
              return <Space direction="vertical" size={6} style={{ width: "100%" }}>
                <Tag color={progress.stateTone === "success" ? "green" : progress.stateTone === "warning" ? "orange" : progress.stateTone === "error" ? "red" : "default"}>{progress.stateLabel}</Tag>
                {progress.reason && <Text type="secondary">{progress.reason}</Text>}
                <Text type="secondary">候选数：{progress.candidateCount ?? "未知"}；模型结果不等于产品漏洞确认。</Text>
                {renderPhase("初步调查", progress.r1)}
                {renderPhase("深入追查", progress.r2)}
              </Space>;
            } },
          ]} />
      </Card>}
      {(selected.kind === "version_matrix" || selected.kind === "recent_window_comparison") && <VersionCandidateComparison operation={selected}
        onOperationCreated={(item: any) => { if (item?.id) void show(item.id); }} />}
      {["source_sync", "source_sync_batch"].includes(selected.kind) ? <SourceSyncDetails operation={selected} />
        : selected.kind === "agent_investigation" && selected.result ? <AgentAssessment result={selected.result} reviews={selected.agent_reviews || []}
        onSubmit={async (review: any) => { await api("/operations/" + selected.id + "/agent-reviews", review); await show(selected.id); }} /> : <pre className="json-view">{JSON.stringify(selected.result || selected.spec, null, 2)}</pre>}
      {selected.kind === "source_sync_batch"
        ? <Collapse className="section-gap" items={[{ key: "events", label: "同步事件（高级）",
            children: <pre className="raw">{JSON.stringify(selected.events || [], null, 2)}</pre> }]} />
        : <><Text strong>执行事件</Text><pre className="raw">{JSON.stringify(selected.events || [], null, 2)}</pre></>}
      {selected.result_sha256 && <Button href={"/api/v1/operations/" + selected.id + "/result"} target="_blank">查看原始结果 JSON</Button>}
    </Card>}
    </>}
  </>;
}

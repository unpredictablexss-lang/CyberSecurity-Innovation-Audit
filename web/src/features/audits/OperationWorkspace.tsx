import React, { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Collapse, Descriptions, Empty, List, Space, Table, Tabs, Tag, Typography, message } from "antd";
import { api, terminal } from "../../api";
import { go, Hash, Header, State } from "../../components";
import { refreshSelectedOperation } from "../../pages/operationSelection";
import { AgentInvestigationForm, ComparisonForm, InvestigationForm, SyncForm, ValidationForm, SourceContext } from "./OperationForms";
import AgentAssessment from "./AgentAssessment";
import AgentBlindReview from "./AgentBlindReview";
const { Text } = Typography;
export type OperationView = "all" | "date" | "branches" | "matrix" | "validation" | "investigate" | "agent" | "agent_research" | "sync" | "queue";
const kinds: Record<string, string> = { source_sync: "源码同步", repository_import_scan: "在线仓库导入并静态扫描", revision_range: "固定区间", branch_comparison: "跨版本比较", version_matrix: "版本矩阵", validation: "隔离验证", investigation: "只读调查", agent_investigation: "模型辅助调查", candidate_review_batch: "历史候选队列（已停用）" };
const headings: Record<OperationView, [string, string]> = {
  all: ["高级源码与验证操作", "保留既有操作入口；任务持久化，候选变化与安全影响分别记录。"],
  date: ["时间增量扫描", "按明确时区选择提交区间，固定两个端点并比较候选观察。"],
  branches: ["跨版本安全分析", "比较同一仓库的分支、Tag 或 Commit；候选变化不等于漏洞引入或修复。"],
  matrix: ["影响与修复", "先核对多个固定版本的候选观察，再补充影响与修复证据。"],
  validation: ["PoC 验证", "围绕绑定源码和注册 Harness 申请隔离验证，保留失败与未知项。"],
  investigate: ["候选调查", "先用确定性工具整理证据，也可在明确同意后调用受限 Agent。"],
  agent: ["模型辅助调查", "候选源码仅在明确同意后发送；模型提供分诊倾向，漏洞状态不自动升级。"],
  agent_research: ["研究实验记录", "查看执行指标、人工反馈、静态基线与盲审进度；这些数据不代表漏洞真值或检测准确率。"],
  sync: ["源码同步", "显式同步 Git 对象；任务扫描只读固定版本。"],
  queue: ["持久化操作任务", "查看在线仓库导入、固定区间、版本比较、同步、调查和验证的真实状态。"],
};
export default function OperationWorkspace({ view = "all", operationId, context = {} }: { view?: OperationView; operationId?: string; context?: SourceContext }) {
  const [repos, setRepos] = useState<any[]>([]), [detectors, setDetectors] = useState<any[]>([]), [cases, setCases] = useState<any[]>([]);
  const [rows, setRows] = useState<any[]>([]), [selected, setSelected] = useState<any>(null);
  const [reviewQueue, setReviewQueue] = useState<any>({ queued_batches: 0, running_batches: 0, queued_candidates: 0, running_candidates: 0 });
  const [error, setError] = useState(""), [busy, setBusy] = useState(false), [agentStatus, setAgentStatus] = useState<any>(null);
  const [agentEvaluation, setAgentEvaluation] = useState<any>(null);
  const selectedId = useRef<string | null>(operationId || null), live = useRef(true);
  const refresh = useCallback(async () => {
    const [r, d, c, o, a, q] = await Promise.all([api("/repositories/list"), api("/detectors"), api("/cases"), api("/operations"), api("/agent/status"), api("/operations/agent-review-queue/status")]);
    if (!live.current) return;
    setError((current) => current === "TypeError: Failed to fetch" ? "" : current);
    setRepos(r); setDetectors(d); setCases(c); setRows(o); setAgentStatus(a); setReviewQueue(q);
    const id = selectedId.current;
    if (id) await refreshSelectedOperation(id, (key) => api("/operations/" + key), () => live.current ? selectedId.current : null, setSelected);
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
    try { await refreshSelectedOperation(id, (key) => api("/operations/" + key), () => live.current ? selectedId.current : null, setSelected); }
    catch (e) { setError(String(e)); }
  };
  const submit = async (path: string, payload: any) => {
    setBusy(true); setError("");
    try { const item = await api(path, payload); selectedId.current = item.id; setSelected(item); await refresh(); message.success("任务已加入持久化队列"); }
    catch (e) { setError(String(e)); } finally { setBusy(false); }
  };
  const props = { repos, detectors, cases, busy, submit, context };
  const forms = [
    { key: "sync", label: "同步源码", children: <SyncForm {...props} /> },
    { key: "range", label: "两个 SHA 区间", children: <ComparisonForm {...props} kind="range" /> },
    { key: "date", label: "提交者日期区间", children: <ComparisonForm {...props} kind="date" /> },
    { key: "branches", label: "跨分支比较", children: <ComparisonForm {...props} kind="branches" /> },
    { key: "matrix", label: "版本矩阵", children: <ComparisonForm {...props} kind="matrix" /> },
    { key: "validation", label: "隔离验证", children: <ValidationForm {...props} /> },
    { key: "investigate", label: "只读调查", children: <InvestigationForm {...props} /> },
    { key: "agent", label: "模型辅助调查", children: <AgentInvestigationForm busy={busy} submit={submit} context={context} cases={cases} agentStatus={agentStatus} /> },
  ];
  const filtered = view === "agent_research" ? [] : rows.filter((r) => r.kind !== "candidate_review_batch" && (view === "all" || view === "queue" || (view === "date" ? r.kind === "revision_range" : view === "branches" ? ["branch_comparison", "revision_range"].includes(r.kind) : r.kind === ({ matrix: "version_matrix", validation: "validation", investigate: "investigation", agent: "agent_investigation", sync: "source_sync" } as Record<string, string>)[view])));
  return <>
    <Header title={headings[view][0]} description={headings[view][1]} />
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {view === "all" ? <Tabs items={forms} /> : view === "branches" ? <Tabs items={[forms[3], forms[4]]} /> : view === "investigate" ? <Tabs items={[forms[6], forms[7]]} /> : view === "agent_research" ? null : forms.find((f) => f.key === view)?.children}
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
          { title: "固定候选", render: (_, row) => <><Text>{row.repository}</Text><div className="muted">{row.commit.slice(0, 12)} · {row.candidate_id.slice(0, 12)}</div></> },
          { title: "静态分诊", dataIndex: "disposition" },
          { title: "逐项基线（支持 / 反向 / 未决）", render: (_, row) => { const counts = { evidence_found: 0, contrary_evidence: 0, unresolved: 0 }; for (const review of row.obligation_reviews || []) { if (review.disposition in counts) counts[review.disposition as keyof typeof counts] += 1; } return String(row.obligations_reviewed ?? 0) + " 项：" + counts.evidence_found + " / " + counts.contrary_evidence + " / " + counts.unresolved + (row.obligations_truncated ? "（仅前 40 项）" : ""); } },
          { title: "复核人 / 秒", render: (_, row) => `${row.reviewer} / ${row.elapsed_seconds ?? "unknown"}` },
          { title: "记录哈希", dataIndex: "record_sha256", render: (value) => <Hash value={value} /> },
        ]} />
    </Card>}    {view === "agent_research" && agentEvaluation?.paired_comparisons?.length > 0 && <Card className="section-gap" size="small" title="同候选 R1 / R2 配对反馈">
      <Alert type="info" showIcon message="仅按实验批次、固定 repo/commit/candidate、模型和提示/工具版本配对操作者自报评价；不是随机实验、漏洞真值或因果效果。" />
      <Table<any> className="section-gap" size="small"
        rowKey={(row) => [row.experiment_id, row.repository, row.commit, row.candidate_id, row.model].join("|")}
        dataSource={agentEvaluation.paired_comparisons} pagination={false} scroll={{ x: 1000 }} columns={[
          { title: "实验批次", dataIndex: "experiment_id" },
          { title: "固定候选", render: (_, row) => <><Text>{row.repository}</Text><div className="muted">{row.commit.slice(0, 12)} · {row.candidate_id.slice(0, 12)}</div></> },
          { title: "R0 静态基线", render: (_, row) => row.r0_static_baseline ? `${row.r0_static_baseline.dispositions.investigate} 调查 / ${row.r0_static_baseline.dispositions.likely_noise} 噪声 / ${row.r0_static_baseline.dispositions.unknown} 未知；${row.r0_static_baseline.median_elapsed_seconds ?? "unknown"} 秒` : "未记录" },
          { title: "模型", dataIndex: "model" },
          { title: "R1 评价 / 引文 / 中位秒", render: (_, row) => `${row.single_shot.review_count} / ${row.single_shot.citation_accuracy.all_accurate}·${row.single_shot.citation_accuracy.some_incorrect + row.single_shot.citation_accuracy.mostly_incorrect} / ${row.single_shot.median_elapsed_seconds ?? "unknown"}` },
          { title: "R2 评价 / 引文 / 中位秒", render: (_, row) => `${row.tool_agent.review_count} / ${row.tool_agent.citation_accuracy.all_accurate}·${row.tool_agent.citation_accuracy.some_incorrect + row.tool_agent.citation_accuracy.mostly_incorrect} / ${row.tool_agent.median_elapsed_seconds ?? "unknown"}` },
        ]} />
    </Card>}    {view === "agent_research" && <AgentBlindReview operations={rows} />}
    {view === "matrix" && <Alert className="section-gap" type="info" showIcon message="影响与修复仍需独立证据" description="当前矩阵只记录候选观察。补丁生成、补丁应用和修复后产品验证尚未接入；不会用候选消失自动判定已修复。" />}
    {view !== "agent_research" && <>
    <Card className="section-gap" title="操作任务" extra={<Button onClick={() => void refresh().catch((e) => setError(String(e)))}>刷新操作</Button>}>
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
        {selected.kind === "repository_import_scan" && selected.result?.scan_job?.id && <Button size="small" type="primary" onClick={() => go("/tasks/" + selected.result.scan_job.id)}>查看自动排队的静态扫描</Button>}
        {selected.result_sha256 && <><Text>Result SHA-256</Text><Hash value={selected.result_sha256} /></>}</Space>
      {selected.error && <Alert className="section-gap" type="error" message={selected.error} />}
      {selected.kind === "agent_investigation" && !selected.result_sha256 && ["failed", "interrupted", "timed_out", "cancelled"].includes(selected.status) && <Alert className="section-gap" type="warning" showIcon message="本次调查没有可复核结果；候选仍为 unknown" description="任务结束不代表候选是误报或安全。若 Worker 在 Provider 已处理请求后、结果落盘前退出，上游调用和费用仍可能发生。重试前请核对执行事件及 Provider 账单，再重新预览并单独批准新任务。" />}
      {selected.spec?.scan_ids && <Space wrap className="section-gap">端点扫描：{selected.spec.scan_ids.map((id: string) => <Button key={id} size="small" onClick={() => go("/tasks/" + id)}>{id.slice(0, 12)}</Button>)}</Space>}
      {Array.isArray(selected.intelligent_review_progress) && <Card size="small" className="section-gap" title="固定版本静态与智能审计进度">
        <Alert type="info" showIcon message="端点静态对比完成不等于智能研判完成"
          description="每个固定版本的 Agent 都独立获得源码外发授权；模型处理失败、预算不足或尚未研判不代表源码安全。" />
        <Table<any> size="small" rowKey="scan_id" pagination={false} dataSource={selected.intelligent_review_progress}
          columns={[
            { title: "版本", render: (_: any, row: any) => <><Hash value={row.commit} /><div><Button size="small" onClick={() => go("/tasks/" + row.scan_id)}>查看扫描任务</Button></div></> },
            { title: "静态扫描", dataIndex: "scan_status", render: (value: string) => <State value={value} /> },
            { title: "智能研判", render: (_: any, row: any) => {
              const labels: Record<string, string> = {
                static_only: "仅静态（未请求模型）", awaiting_static: "等待静态结果", static_incomplete: "静态结果未完成",
                awaiting_individual_consent: "未授权自动研判", authorization_revoked: "外发授权已撤销",
                awaiting_model_schedule: "等待 Agent 排队", authorization_changed: "授权条件已变更",
                no_eligible_candidates: "无符合条件的研判候选", completed: "已完成研判",
                partially_completed: "部分研判完成", agent_in_progress: "智能研判中",
              };
              return <Tag color={row.agent_status === "completed" ? "green" : row.agent_status === "partially_completed" ? "orange" : "default"}>{labels[row.agent_status] || row.agent_status}</Tag>;
            } },
          ]} />
      </Card>}
      {selected.kind === "agent_investigation" && selected.result ? <AgentAssessment result={selected.result} reviews={selected.agent_reviews || []}
        onSubmit={async (review: any) => { await api("/operations/" + selected.id + "/agent-reviews", review); await show(selected.id); }} /> : <pre className="json-view">{JSON.stringify(selected.result || selected.spec, null, 2)}</pre>}
      <Text strong>执行事件</Text><pre className="raw">{JSON.stringify(selected.events || [], null, 2)}</pre>
      {selected.result_sha256 && <Button href={"/api/v1/operations/" + selected.id + "/result"} target="_blank">查看原始结果 JSON</Button>}
    </Card>}
    </>}
  </>;
}

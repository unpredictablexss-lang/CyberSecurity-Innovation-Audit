import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Col, Descriptions, Empty, Input, Pagination, Row, Select, Space, Statistic, Table, Tabs, Tag, Typography } from "antd";
import { api, artifact, terminal } from "../../api";
import { go, Hash, Header, State } from "../../components";
import Repositories from "../../pages/Repositories";
import Capabilities from "../../pages/Capabilities";
import Cases from "../../pages/Cases";
import JobDetail from "../../pages/JobDetail";
import OperationWorkspace from "../audits/OperationWorkspace";
import AgentProviderSettings from "./AgentProviderSettings";
import { SourceContext } from "../audits/OperationForms";
import { jobDetailPath, retainRiskSource, riskQueuePath } from "./navigation";
import { triageStateLabel } from "./riskLabels.js";
const { Text, Paragraph } = Typography;
export function ScanTable({ jobs, compact = false }: { jobs: any[]; compact?: boolean }) {
  return <Table<any> rowKey="id" size={compact ? "small" : "middle"} dataSource={compact ? jobs.slice(0, 4) : jobs} pagination={compact ? false : { pageSize: 10 }} scroll={{ x: 650 }} columns={[
    { title: "仓库 / 固定版本", render: (_, j) => <><a onClick={() => go("/tasks/" + j.id)}>{j.spec.repository}</a><div className="muted"><Hash value={j.spec.commit} /></div></> },
    { title: "状态", dataIndex: "status", render: (v) => <State value={v} /> },
    { title: "实际耗时", render: (_, j) => j.elapsed_seconds == null ? "尚未结束" : Number(j.elapsed_seconds).toFixed(2) + " s" },
    { title: "创建时间", dataIndex: "created_at", render: (v) => new Date(v).toLocaleString() },
    { title: "操作", render: (_, j) => <Button onClick={() => go("/tasks/" + j.id)}>查看任务</Button> },
  ]} locale={{ emptyText: <Empty description="当前没有扫描任务"><Button onClick={() => go("/audits/repository")}>创建仓库扫描</Button></Empty> }} />;
}
export function TaskCenter({ jobs }: { jobs: any[] }) {
  return <><Header title="任务中心" description="查看扫描与操作的真实阶段、覆盖、失败原因和恢复入口。" />
    <Tabs items={[{ key: "scans", label: "源码扫描", children: <Card><ScanTable jobs={jobs} /></Card> },
      { key: "operations", label: "区间与验证操作", children: <OperationWorkspace view="queue" /> }]} /></>;
}
export function RiskCenter({ jobs, query = new URLSearchParams() }: { jobs: any[]; health?: any; query?: URLSearchParams }) {
  const pageSize = 12;
  const [filters, setFilters] = useState(() => ({
    risk_tier: query.get("risk_tier") || "",
    triage_state: query.get("triage_state") || "",
    repository: query.get("repository") || "",
    detector_id: query.get("detector_id") || "",
    q: query.get("q") || "",
    scan_limit: query.get("scan_limit") || "20",
  }));
  const [draftQuery, setDraftQuery] = useState(filters.q);
  const [page, setPage] = useState(1);
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setLoading(true);
    setSummary(null);
    const params = new URLSearchParams({ scan_limit: filters.scan_limit, offset: String((page - 1) * pageSize), limit: String(pageSize) });
    if (filters.risk_tier) params.set("risk_tier", filters.risk_tier);
    if (filters.triage_state) params.set("triage_state", filters.triage_state);
    if (filters.repository) params.set("repository", filters.repository);
    if (filters.detector_id) params.set("detector_id", filters.detector_id);
    if (filters.q) params.set("q", filters.q);
    api("/overview/risks?" + params.toString())
      .then((value) => { if (live) { setSummary(value); setError(""); } })
      .catch((reason) => { if (live) setError(String(reason)); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [filters, page]);
  const setFilter = (name: string, value: string) => {
    const next = { ...filters, [name]: value };
    setPage(1);
    setFilters(next);
    go(riskQueuePath(next));
  };
  const repositories = Array.from(new Set(jobs.filter((job) => job.report_sha256)
    .map((job) => job.spec?.repository).filter(Boolean))).sort();
  const openCandidate = (row: any) => {
    go(jobDetailPath(row.audit_id, "findings") + "&candidate_id=" + encodeURIComponent(row.candidate_id));
  };
  const items = summary?.items || [];
  return <><Header title="风险中心" description="跨审计查看候选队列；可按风险层级、研判状态、仓库和检测器筛选，并直接打开固定证据。" />
    <Alert className="section-gap" type="info" showIcon
      message="候选观测不等于已确认漏洞"
      description={"队列仅汇总最近 " + filters.scan_limit + " 份可校验报告，最多保留任务中的最近 200 项。高可信项仍是待复核候选；未研判、解析不完整和来源未知均不会被当作安全结论。"} />
    {error && <Alert className="section-gap" type="error" showIcon message="风险队列暂不可用" description={error} />}
    <Card className="section-gap" title="筛选候选">
      <Space wrap>
        <Select aria-label="最近报告范围" style={{ width: 160 }} value={filters.scan_limit}
          onChange={(value) => setFilter("scan_limit", value)}
          options={[{ value: "10", label: "最近 10 份报告" }, { value: "20", label: "最近 20 份报告" }]} />
        <Select aria-label="风险层级筛选" style={{ width: 220 }} value={filters.risk_tier || undefined}
          placeholder="全部风险层级" allowClear onChange={(value) => setFilter("risk_tier", value || "")}
          options={[
            { value: "high_confidence_candidate", label: "高可信候选（仍需确认）" },
            { value: "further_validation", label: "待进一步验证" },
            { value: "unknown_source_binding", label: "来源绑定未知" },
            { value: "low_priority_manual", label: "低优先级人工标记" },
          ]} />
        <Select aria-label="模型研判状态筛选" style={{ width: 220 }} value={filters.triage_state || undefined}
          placeholder="全部研判状态" allowClear onChange={(value) => setFilter("triage_state", value || "")}
          options={[
            { value: "unresolved", label: "未完成模型研判" },
            { value: "not_triaged", label: "尚未开始研判" },
            { value: "not_requested", label: "未请求模型" },
            { value: "waiting_for_authorization", label: "等待授权" },
            { value: "selected", label: "已选入队列" },
            { value: "not_selected", label: "未选入本轮" },
            { value: "queued", label: "排队中" },
            { value: "in_progress", label: "处理中" },
            { value: "completed", label: "已完成" },
            { value: "cancelled", label: "已停止" },
            { value: "blocked", label: "受阻" },
            { value: "partially_completed", label: "部分完成" },
            { value: "failed", label: "失败" },
          ]} />
        <Select aria-label="仓库筛选" style={{ width: 260 }} value={filters.repository || undefined}
          placeholder="全部仓库" allowClear showSearch optionFilterProp="label"
          onChange={(value) => setFilter("repository", value || "")}
          options={repositories.map((name) => ({ value: name, label: name }))} />
        <Select aria-label="检测器筛选" style={{ width: 260 }} value={filters.detector_id || undefined}
          placeholder="全部检测器" allowClear showSearch optionFilterProp="label"
          onChange={(value) => setFilter("detector_id", value || "")}
          options={(summary?.detector_counts || []).map((item: any) => ({
            value: item.detector_id, label: item.detector_id + "（" + item.candidate_count + "）",
          }))} />
        <Input.Search aria-label="候选搜索" allowClear placeholder="搜索仓库、Commit、文件、规则或候选 ID"
          style={{ width: 340 }} value={draftQuery}
          onChange={(event) => setDraftQuery(event.target.value)}
          onSearch={(value) => setFilter("q", value.trim())} />
        <Button onClick={() => {
          const next = { risk_tier: "", triage_state: "", repository: "", detector_id: "", q: "", scan_limit: "20" };
          setDraftQuery("");
          setPage(1);
          setFilters(next);
          go(riskQueuePath(next));
        }}>
          清除筛选
        </Button>
      </Space>
    </Card>
    <Card className="section-gap" title={"候选队列 · " + (loading ? "正在读取" : (summary?.filtered_candidate_count ?? 0) + " 项匹配")}>
      <Table<any> rowKey={(row) => row.audit_id + ":" + row.candidate_id} size="small" dataSource={items}
        pagination={false} loading={loading}
        onRow={(row) => ({ onClick: () => openCandidate(row), style: { cursor: "pointer" } })}
        columns={[
          { title: "风险层级", dataIndex: "risk_tier_label" },
          { title: "仓库 / Commit", render: (_: unknown, row: any) => <><Text>{row.repository}</Text><div className="muted">{String(row.commit || "").slice(0, 12)}</div></> },
          { title: "检测器 / 候选位置", render: (_: unknown, row: any) => <>{row.detector_id || "未知检测器"}<div>{row.file}:{row.line}</div><div className="muted">{row.rule_id}</div></> },
          { title: "研判状态", dataIndex: "triage_state", render: (value: string) => triageStateLabel(value) },
          { title: "查看", render: (_: unknown, row: any) => <Button size="small" onClick={(event) => { event.stopPropagation(); openCandidate(row); }}>证据与下一步</Button> },
        ]}
        locale={{ emptyText: <Empty description={loading ? "正在读取候选队列…" :
          summary?.evaluated_scan_count ? "当前筛选没有候选；这不代表仓库不存在漏洞。" : "暂无可校验的扫描报告。"} /> }} />
      {(summary?.filtered_candidate_count || 0) > pageSize && <Pagination className="section-gap" current={page} pageSize={pageSize}
        total={summary.filtered_candidate_count} showSizeChanger={false} onChange={(value) => setPage(value)} />}
      {loading
        ? <Text type="secondary">正在读取最近报告的候选与研判状态。</Text>
        : <Text type="secondary">当前范围：已检查 {summary?.evaluated_scan_count ?? 0} / 最多 {summary?.scan_limit ?? 20} 份报告；共 {summary?.candidate_observation_count ?? 0} 条候选观测、人工确认漏洞 {summary?.validated_vulnerability ?? 0} 条。点击候选查看固定源码和证据义务。</Text>}
    </Card>
  </>;
}
export function AuditRiskOverview() {
  const [summary, setSummary] = useState<any>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let live = true;
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const value = await api("/overview/risks?scan_limit=10");
        if (live) { setSummary(value); setError(""); }
      } catch (reason) {
        if (live) setError(String(reason));
      } finally {
        busy = false;
        if (live) setLoading(false);
      }
    };
    void load();
    const timer = setInterval(() => void load(), 30000);
    return () => { live = false; clearInterval(timer); };
  }, []);
  const triage = summary?.triage_counts || {};
  const rows = summary?.items || [];

  const openCandidate = (row: any) => {
    go(jobDetailPath(row.audit_id, "findings") + "&candidate_id=" + encodeURIComponent(row.candidate_id));
  };
  return <Card className="section-gap" title="近期风险优先队列"
    extra={<Button type="link" onClick={() => go("/risks?scan_limit=10")}>打开风险中心 →</Button>}>
    <Alert type="info" showIcon
      message="按最近 10 份已保存扫描报告汇总候选观测"
      description="重复观察不会自动归并为根因；候选数不等于漏洞数。高可信项仍是待复核候选，模型未完成或未请求的项目单独保留。" />
    {error && <Alert className="section-gap" type="warning" showIcon message="风险摘要暂不可用" description={error} />}
    <Row gutter={[12, 12]} className="section-gap">{[
      { title: "高可信候选", value: summary?.counts?.high_confidence_candidate ?? "—" },
      { title: "待进一步验证", value: summary?.counts?.further_validation ?? "—" },
      { title: "未完成模型研判", value: summary?.not_triaged_candidate_count ?? "—" },
      { title: "人工确认漏洞", value: summary?.validated_vulnerability ?? "—" },
    ].map((item, index) => {
      const targets = [
        "/risks?scan_limit=10&risk_tier=high_confidence_candidate",
        "/risks?scan_limit=10&risk_tier=further_validation",
        "/risks?scan_limit=10&triage_state=unresolved",
        "/reports",
      ];
      return <Col xs={12} xl={6} key={item.title}>
        <Card size="small" loading={loading} title={item.title} extra={<Button type="link" size="small" onClick={() => go(targets[index])}>查看 →</Button>}>
          <Statistic value={item.value} />
        </Card>
      </Col>;
    })}</Row>
    {summary?.limitations?.length > 0 && <Alert className="section-gap" type="warning" showIcon
      message={summary.unavailable_report_count + " 份报告无法校验，未计入以上统计"}
      description="受影响任务仍可从任务中心检查其原始状态。" />}
    <Table<any> className="section-gap" size="small" rowKey={(row) => row.audit_id + ":" + row.candidate_id}
      dataSource={rows} pagination={false} loading={loading}
      onRow={(row) => ({ onClick: () => openCandidate(row), style: { cursor: "pointer" } })}
      columns={[
        { title: "风险层级", dataIndex: "risk_tier_label" },
        { title: "仓库 / Commit", render: (_: unknown, row: any) => <><Text>{row.repository}</Text><div className="muted">{String(row.commit || "").slice(0, 12)}</div></> },
        { title: "候选位置", render: (_: unknown, row: any) => <>{row.file}:{row.line}<div className="muted">{row.rule_id}</div></> },
        { title: "研判状态", dataIndex: "triage_state", render: (value: string) => triageStateLabel(value) },
        { title: "查看", render: (_: unknown, row: any) => <Button size="small" onClick={(event) => { event.stopPropagation(); openCandidate(row); }}>证据与下一步</Button> },
      ]}
      locale={{ emptyText: <Empty description={summary?.available_report_count ? "最近报告没有候选观测；这不代表仓库不存在漏洞。" : "完成一次扫描后，这里会显示近期风险优先队列。"} /> }} />
    <Text type="secondary">统计范围：已检查 {summary?.evaluated_scan_count ?? 0} / 最多 {summary?.scan_limit ?? 10} 份报告；模型状态 {Object.entries(triage).map(([state, count]) => triageStateLabel(state) + " " + count).join(" · ") || "暂无记录"}。点击候选可打开固定源码和证据义务。</Text>
  </Card>;
}

export function Investigations({ context = {} }: { context?: SourceContext }) {
  const [agentStatus, setAgentStatus] = useState<any>(null);
  useEffect(() => { void api("/agent/status").then(setAgentStatus).catch(() => setAgentStatus(null)); }, []);
  const providerCheck = agentStatus?.last_provider_check;
  const connectionSummary = providerCheck
    ? "最近无源码连接检查通过（" + new Date(providerCheck.checked_at).toLocaleString() + "，" + providerCheck.duration_ms + " ms）；这只证明服务可访问并返回基本结果，不代表模型分析质量。"
    : "模型配置已保存；连通性尚未验证。";
  return <><Header title="智能调查" description="围绕候选组织案例与只读调查，保留反证和仍未知的证据义务。" />
    {agentStatus ? <Alert className="section-gap" type={agentStatus.configured ? "info" : "warning"} showIcon
      message={agentStatus.configured ? (providerCheck ? "模型配置已保存，最近连通性探测通过" : "模型配置已保存，连通性尚未验证") : "真实模型未配置"}
      description={agentStatus.configured ? connectionSummary + " 服务地址：" + agentStatus.endpoint_host + "；模型：" + agentStatus.model + "。每次调查前都会显示外发预览并由你单独授权。" :
        "人工案例与固定只读工具可用。配置模型后才能使用辅助研判；候选源码仅在你检查预览并明确同意后发送，模型不会自动确认漏洞。"} /> :
      <Alert className="section-gap" type="warning" showIcon message="模型配置状态暂不可用" description="可继续使用人工案例和确定性只读工具。" />}
    <Tabs className="section-gap" defaultActiveKey={context.candidate_id ? "tools" : "cases"} items={[
      { key: "cases", label: "调查案例", children: <Cases embedded /> },
      { key: "tools", label: "只读调查步骤", children: <OperationWorkspace view="investigate" context={context} /> },
      { key: "agent", label: "模型辅助调查", children: <OperationWorkspace view="agent" context={context} /> },
      { key: "experiments", label: "研究实验记录", children: <OperationWorkspace view="agent_research" /> },
    ]} /></>;
}
export function ReportCenter({ jobs, cases }: { jobs: any[]; cases: any[] }) {
  const reports = jobs.filter((j) => j.report_sha256);
  const [error, setError] = useState("");
  const downloadCase = async (id: string, kind: "json" | "md") => {
    try {
      const response = await fetch("/api/v1/cases/" + id + "/report." + kind);
      if (!response.ok) throw new Error(await response.text());
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a"); anchor.href = url; anchor.download = "ohscanner-case-" + id + "." + kind;
      document.body.appendChild(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { setError(String(e)); }
  };
  return <><Header title="报告中心" description="导出真实扫描与案例记录；报告与固定源码、规则版本和证据哈希绑定。" />
    {error && <Alert type="error" showIcon message={error} />}
    <Alert type="info" message="当前提供 JSON、Markdown、manifest 与复核包" description="PoC、产品影响、补丁与性能评估需要各自的实测证据；没有把缺失项补成已完成赛题报告。" />
    <Card className="section-gap" title="固定源码扫描报告"><Table<any> rowKey="id" dataSource={reports} scroll={{ x: 850 }} columns={[
      { title: "仓库与版本", render: (_, j) => <><Text strong>{j.spec.repository}</Text><div><Hash value={j.spec.commit} /></div></> },
      { title: "状态", dataIndex: "status", render: (v) => <State value={v} /> },
      { title: "报告 SHA-256", dataIndex: "report_sha256", render: (v) => <Hash value={v} /> },
      { title: "导出", render: (_, j) => <Space wrap>{["report.json", "report.md", "manifest.json", "review.json", "review.md"].map((kind) => <Button key={kind} size="small" href={artifact(j.id, kind)}>{kind}</Button>)}
        <Button size="small" onClick={() => go(jobDetailPath(j.id, "reports"))}>完整证据与局限</Button></Space> },
    ]} locale={{ emptyText: "暂无已发布的扫描报告" }} /></Card>
    <Card className="section-gap" title="调查案例报告"><Table<any> rowKey="id" dataSource={cases} columns={[
      { title: "案例", dataIndex: "title" }, { title: "关联候选", render: (_, c) => c.links.length },
      { title: "导出", render: (_, c) => <Space><Button size="small" onClick={() => void downloadCase(c.id, "json")}>JSON</Button><Button size="small" onClick={() => void downloadCase(c.id, "md")}>Markdown</Button></Space> },
    ]} locale={{ emptyText: "从风险中心的候选建立案例后可导出" }} /></Card>
  </>;
}
export function SettingsView({ repos, detectors, health, refresh, tab }: { repos: any[]; detectors: any[]; health: any; refresh: () => Promise<void>; tab: string }) {
  return <><Header title="系统设置" description="管理当前本地源码、规则能力与运行状态；未接入的配置明确保留限制。" />
    <Tabs activeKey={["sources", "capabilities", "runtime", "agent"].includes(tab) ? tab : "sources"} onChange={(key) => go("/settings/" + key)} items={[
      { key: "sources", label: "仓库与源码管理", children: <><Alert type="info" message="官方清单与镜像身份核验待接入" description="当前登记本地仓库或显式同步 allowlist 源码；不会根据仓库名称冒充官方身份认证。" />
        <Repositories repos={repos} roots={health?.target_roots || []} refresh={refresh} embedded />
        <OperationWorkspace view="sync" /></> },
      { key: "capabilities", label: "语言与规则", children: <Capabilities detectors={detectors} embedded /> },
      { key: "agent", label: "Agent / LLM", children: <AgentProviderSettings /> },
      { key: "runtime", label: "Worker 状态", children: <Card title="当前服务状态">
        <Descriptions column={1} items={[
          { key: "health", label: "API", children: health?.status || "未知" },
          { key: "worker", label: "扫描 Worker", children: health ? health.worker_running ? "运行中" : "未运行" : "未知" },
          { key: "concurrency", label: "扫描并发上限", children: health?.limits?.concurrent_scans ?? "未知" },
          { key: "agent", label: "真实模型", children: health?.capabilities?.agent ? "服务宣告可用，需专项验收" : "未连接；只读调查可单独使用" },
          { key: "validation", label: "产品运行时验证", children: health?.capabilities?.runtime_validation ? "服务宣告可用，需核对证据" : "未验收；组件 Harness 单独记录" },
        ]} /><Paragraph type="secondary">模型服务凭据和连接测试位于“Agent / LLM”设置页；此处仅展示 Worker 运行状态。</Paragraph>
        <Button onClick={() => go("/operations")}>兼容高级操作入口</Button>
      </Card> },
    ]} />
  </>;
}

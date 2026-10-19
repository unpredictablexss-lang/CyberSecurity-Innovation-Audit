import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Col, Descriptions, Empty, Row, Select, Space, Table, Tabs, Tag, Typography } from "antd";
import { api, artifact, terminal } from "../../api";
import { go, Hash, Header, State } from "../../components";
import Repositories from "../../pages/Repositories";
import Capabilities from "../../pages/Capabilities";
import Cases from "../../pages/Cases";
import JobDetail from "../../pages/JobDetail";
import OperationWorkspace from "../audits/OperationWorkspace";
import AgentProviderSettings from "./AgentProviderSettings";
import { SourceContext } from "../audits/OperationForms";
import { jobDetailPath, retainRiskSource } from "./navigation";
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
export function RiskCenter({ jobs }: { jobs: any[] }) {
  const [selected, setSelected] = useState<string | undefined>(() => retainRiskSource(undefined, jobs));
  const completed = jobs.filter((j) => j.report_sha256);
  useEffect(() => { setSelected((current) => retainRiskSource(current, jobs)); }, [jobs]);
  const id = selected;
  return <><Header title="风险中心" description="按固定快照分组浏览候选；保留原始位置、证据义务和人工复核。" />
    <Card className="section-gap"><Space wrap><Text>来源扫描</Text><Select aria-label="风险来源扫描" className="wide-select" value={id} onChange={setSelected}
      options={completed.map((j) => ({ value: j.id, label: j.spec.repository + " · " + j.spec.commit.slice(0, 12) + " · " + j.id.slice(0, 8) }))} /></Space></Card>
    <Alert className="section-gap" type="info" message="分组用于减少重复浏览，不代表已证明共同根因或漏洞。未完成扫描保留 unknown。" />
    {id ? <div className="section-gap"><JobDetail key={id} id={id} initialTab="clusters" /></div> : <Card className="section-gap"><Empty description="暂无可复核的扫描报告"><Button onClick={() => go("/audits/repository")}>开始源码扫描</Button></Empty></Card>}
  </>;
}
export function Investigations({ context = {} }: { context?: SourceContext }) {
  const [agentStatus, setAgentStatus] = useState<any>(null);
  useEffect(() => { void api("/agent/status").then(setAgentStatus).catch(() => setAgentStatus(null)); }, []);
  const providerCheck = agentStatus?.last_provider_check;
  const connectionSummary = providerCheck
    ? "最近通过无源码探测：" + providerCheck.checked_at + " · " + providerCheck.duration_ms + " ms · 输入 " + (providerCheck.input_tokens ?? "unknown") + " / 输出 " + (providerCheck.output_tokens ?? "unknown") + " tokens。该探测只证明 API 连通和最小结构化输出。"
    : "配置完成不代表接口已连通。";
  return <><Header title="智能调查" description="围绕候选组织案例与只读调查，保留反证和仍未知的证据义务。" />
    {agentStatus ? <Alert className="section-gap" type={agentStatus.configured ? "info" : "warning"} showIcon
      message={agentStatus.configured ? (providerCheck ? "模型配置已保存，最近连通性探测通过" : "模型配置已保存，连通性尚未验证") : "真实模型未配置"}
      description={agentStatus.configured ? connectionSummary + " 服务目标 " + agentStatus.endpoint_host + " · 模型 " + agentStatus.model + " · 预览策略 " + (agentStatus.consent_preview_version || "unknown") + " · 脱敏策略 " + (agentStatus.redaction_policy_version || "unknown") + "。调用仍需在候选工具页逐次同意源码外发。" :
        "预览策略 " + (agentStatus.consent_preview_version || "unknown") + " · 脱敏策略 " + (agentStatus.redaction_policy_version || "unknown") + "。人工案例与固定只读工具可用。配置后才可调用真实模型；模型费用/效果尚未实测，且不会自动确认漏洞。"} /> :
      <Alert className="section-gap" type="warning" showIcon message="模型配置状态暂不可用" description="可继续使用人工案例和确定性只读工具。" />}
    <Tabs className="section-gap" defaultActiveKey={context.candidate_id ? "tools" : "cases"} items={[
      { key: "cases", label: "调查案例", children: <Cases embedded /> },
      { key: "tools", label: "只读调查步骤", children: <OperationWorkspace view="investigate" context={context} /> },
      { key: "agent", label: "Agent 调查任务", children: <OperationWorkspace view="agent" context={context} /> },
      { key: "experiments", label: "R0 / R1 / R2 实验记录", children: <AgentExperimentHistory /> },
    ]} /></>;
}
function AgentExperimentHistory() {
  const [summary, setSummary] = useState<any>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    void api("/agent/evaluation-summary")
      .then((value) => { if (live) { setSummary(value); setError(""); } })
      .catch((reason) => { if (live) setError(String(reason)); });
    return () => { live = false; };
  }, []);
  const baselines = summary?.r0_baseline_reviews || [];
  return <Card title="静态人工基线与模型实验">
    <Alert className="section-gap" type="info" showIcon
      message="R0 是人工静态复核记录；记录存在不等于漏洞确认或产品真值。"
      description={summary?.limitation || "R1/R2 的反馈只衡量复核体验与引用质量，不代表漏洞精确率、召回率或独立真值。"} />
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    <Table<any> className="section-gap" rowKey="id" dataSource={baselines}
      columns={[
        { title: "实验", dataIndex: "experiment_id" },
        { title: "仓库 / 固定版本", render: (_, row) => <><Text>{row.repository}</Text><div className="muted"><Hash value={row.commit} /></div></> },
        { title: "候选", render: (_, row) => <><Text>{row.detector_id} · {row.detector_version}</Text><div className="muted"><Hash value={row.candidate_id} /></div></> },
        { title: "复核人 / 范围", render: (_, row) => <>{row.reviewer}<div><Tag>静态人工 R0</Tag></div></> },
        { title: "处置 / 漏洞状态", render: (_, row) => <>{row.disposition}<div><Tag color={row.vulnerability_state === "confirmed" ? "red" : "default"}>{row.vulnerability_state || "unknown"}</Tag></div></> },
        { title: "证据义务", render: (_, row) => (row.obligations_reviewed ?? row.obligation_reviews?.length ?? 0) + " 项" },
        { title: "记录哈希", dataIndex: "record_sha256", render: (value) => <Hash value={value} /> },
        { title: "记录时间", dataIndex: "created_at", render: (value) => value ? new Date(value).toLocaleString() : "未知" },
      ]}
      expandable={{ expandedRowRender: (row) => <><Paragraph>{row.notes || "无复核备注"}</Paragraph><Paragraph type="secondary">validated_vulnerability={row.validated_vulnerability ?? 0} · R0 只表示静态人工研判，不是产品漏洞确认。</Paragraph></> }}
      locale={{ emptyText: <Empty description="尚无 R0 基线记录；完成一次静态人工复核后会显示在这里。" /> }}
    />
  </Card>;
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
      { key: "sources", label: "源码与缓存", children: <><Alert type="info" message="官方清单与镜像身份核验待接入" description="当前登记本地仓库或显式同步 allowlist 源码；不会根据仓库名称冒充官方身份认证。" />
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

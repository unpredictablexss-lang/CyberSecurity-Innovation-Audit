import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Col, Descriptions, Empty, Row, Select, Space, Table, Tabs, Tag, Typography } from "antd";
import { api, artifact, terminal } from "../../api";
import { go, Hash, Header, State } from "../../components";
import Repositories from "../../pages/Repositories";
import Capabilities from "../../pages/Capabilities";
import Cases from "../../pages/Cases";
import JobDetail from "../../pages/JobDetail";
import OperationWorkspace from "../audits/OperationWorkspace";
import { SourceContext } from "../audits/OperationForms";
import { jobDetailPath, retainRiskSource } from "./navigation";
const { Text, Paragraph } = Typography;
export function ScanTable({ jobs, compact = false }: { jobs: any[]; compact?: boolean }) {
  return <Table<any> rowKey="id" dataSource={compact ? jobs.slice(0, 5) : jobs} pagination={compact ? false : { pageSize: 10 }} scroll={{ x: 650 }} columns={[
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
  return <><Header title="智能调查" description="围绕候选组织案例与只读调查，保留反证和仍未知的证据义务。" />
    <Alert className="section-gap" type="info" showIcon message="真实模型未连接" description="人工案例与固定只读工具可以使用；当前没有 LLM 调用、模型费用统计或自动确认漏洞。" />
    <Tabs className="section-gap" defaultActiveKey={context.candidate_id ? "tools" : "cases"} items={[{ key: "cases", label: "调查案例", children: <Cases embedded /> },
      { key: "tools", label: "只读调查步骤", children: <OperationWorkspace view="investigate" context={context} /> }]} /></>;
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
    <Tabs activeKey={["sources", "capabilities", "runtime"].includes(tab) ? tab : "sources"} onChange={(key) => go("/settings/" + key)} items={[
      { key: "sources", label: "源码与缓存", children: <><Alert type="info" message="官方清单与镜像身份核验待接入" description="当前登记本地仓库或显式同步 allowlist 源码；不会根据仓库名称冒充官方身份认证。" />
        <Repositories repos={repos} roots={health?.target_roots || []} refresh={refresh} embedded />
        <OperationWorkspace view="sync" /></> },
      { key: "capabilities", label: "语言与规则", children: <Capabilities detectors={detectors} embedded /> },
      { key: "runtime", label: "Worker 与模型", children: <Card title="当前服务状态">
        <Descriptions column={1} items={[
          { key: "health", label: "API", children: health?.status || "未知" },
          { key: "worker", label: "扫描 Worker", children: health ? health.worker_running ? "运行中" : "未运行" : "未知" },
          { key: "concurrency", label: "扫描并发上限", children: health?.limits?.concurrent_scans ?? "未知" },
          { key: "agent", label: "真实模型", children: health?.capabilities?.agent ? "服务宣告可用，需专项验收" : "未连接；只读调查可单独使用" },
          { key: "validation", label: "产品运行时验证", children: health?.capabilities?.runtime_validation ? "服务宣告可用，需核对证据" : "未验收；组件 Harness 单独记录" },
        ]} /><Paragraph type="secondary">此处为服务只读状态；没有提供虚构的模型连接、Worker 扩容或配置保存按钮。</Paragraph>
        <Button onClick={() => go("/operations")}>兼容高级操作入口</Button>
      </Card> },
    ]} />
  </>;
}

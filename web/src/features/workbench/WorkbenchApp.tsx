import React, { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Col, ConfigProvider, Empty, Layout, Menu, Row, Space, Statistic, Typography } from "antd";
import zhCN from "antd/locale/zh_CN";
import { AppstoreOutlined, BranchesOutlined, BugOutlined, CalendarOutlined, ExperimentOutlined, FileSearchOutlined, FileTextOutlined, FolderOutlined, PlusOutlined, ReloadOutlined, SearchOutlined, SettingOutlined } from "@ant-design/icons";
import "antd/dist/reset.css";
import "../../style.css";
import { api, terminal } from "../../api";
import { go, Header, useRoute } from "../../components";
import RepositoryAudit from "../audits/RepositoryAudit";
import OperationWorkspace from "../audits/OperationWorkspace";
import JobDetail from "../../pages/JobDetail";
import { AuditRiskOverview, Investigations, ReportCenter, RiskCenter, ScanTable, SettingsView, TaskCenter } from "./WorkspaceViews";
import { auditLinks, detailTab, resolveRoute } from "./navigation";
const { Text, Paragraph } = Typography;
function Workspace() {
  const rawRoute = useRoute(); const route = resolveRoute(rawRoute);
  const [repos, setRepos] = useState<any[]>([]), [detectors, setDetectors] = useState<any[]>([]), [jobs, setJobs] = useState<any[]>([]), [cases, setCases] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null), [error, setError] = useState("");
  const sequence = useRef(0), live = useRef(true);
  const refresh = useCallback(async () => {
    const ticket = ++sequence.current;
    try {
      const [r, d, j, h, c] = await Promise.all([api("/repositories/list"), api("/detectors"), api("/scans"), api("/health"), api("/cases")]);
      if (!live.current || ticket !== sequence.current) return;
      setRepos(r); setDetectors(d); setJobs(j); setHealth(h); setCases(c); setError("");
    } catch (e) { if (live.current && ticket === sequence.current) setError(String(e)); }
  }, []);
  useEffect(() => {
    live.current = true; void refresh(); const timer = setInterval(() => void refresh(), 5000);
    return () => { live.current = false; sequence.current++; clearInterval(timer); };
  }, [refresh]);
  useEffect(() => {
    if (rawRoute !== route.canonical) window.history.replaceState(null, "", "#" + route.canonical);
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
  }, [rawRoute, route.canonical]);
  const path = route.path;
  const provider = health?.capabilities?.agent_provider;
  const context = { job_id: route.query.get("job_id") || undefined, candidate_id: route.query.get("candidate_id") || undefined, repository_id: route.query.get("repository_id") || undefined };
  let content: React.ReactNode;
  const operationMatch = path.match(/^\/tasks\/operations\/([A-Za-z0-9_-]+)$/);
  const taskMatch = path.match(/^\/tasks\/([A-Za-z0-9_-]+)$/);
  if (operationMatch) content = <OperationWorkspace key={path} view="queue" operationId={operationMatch[1]} />;
  else if (taskMatch) content = <JobDetail key={path + route.query.get("tab")} id={taskMatch[1]} health={health} initialTab={detailTab(route.query.get("tab"))} candidateId={route.query.get("candidate_id") || undefined} sourceFile={route.query.get("source_file") || undefined} sourceLine={Number(route.query.get("source_line")) || undefined} />;
  else if (path === "/audits/repository") content = <RepositoryAudit repos={repos} detectors={detectors} health={health} refresh={refresh} />;
  else if (path === "/audits/time") content = <OperationWorkspace key={path} view="date" />;
  else if (path === "/audits/versions") content = <OperationWorkspace key={route.canonical} view="branches" context={context} />;
  else if (path === "/tasks") content = <TaskCenter jobs={jobs} />;
  else if (path === "/risks") content = <RiskCenter key={route.canonical} jobs={jobs} query={route.query} />;
  else if (path === "/investigations") content = <Investigations key={route.canonical} context={context} />;
  else if (path === "/poc") content = <OperationWorkspace key={route.canonical} view="validation" context={context} />;
  else if (path === "/impact") content = <OperationWorkspace key={path} view="matrix" />;
  else if (path === "/reports") content = <ReportCenter jobs={jobs} cases={cases} />;
  else if (path === "/settings" || path.startsWith("/settings/")) content = <SettingsView repos={repos} detectors={detectors} health={health} refresh={refresh} tab={path.split("/")[2] || "sources"} />;
  else if (path === "/operations") content = <OperationWorkspace />;
  else if (path === "/overview") content = <>
    <Header title="总览" description="统一管理代码扫描、风险调查与验证工作。" extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => go("/audits/repository")}>新建审计</Button>} />
    <Row gutter={[16, 16]} className="overview-metrics">{[
      { label: "仓库登记记录", value: repos.length, note: "本地登记数；可用状态需核验；官方身份待核验" },
      { label: "执行中 / 排队", value: jobs.filter((j) => !terminal.has(j.status)).length, note: "当前任务列表 · 单扫描 Worker" },
      { label: "已保存扫描", value: jobs.filter((j) => j.report_sha256).length, note: "当前列表 · 关联扫描版本" },
      { label: "调查案例", value: cases.length, note: "人工关联，不代表已确认漏洞" },
    ].map((item) => <Col xs={24} sm={12} lg={6} key={item.label}><Card className="stat-card"><Statistic title={item.label} value={item.value} /><div className="muted">{item.note}</div></Card></Col>)}</Row>
    <Alert className="section-gap" type="info" showIcon
      message={provider?.configured ? "模型服务已配置；每次任务仍须明确授权源码外发" : "模型服务尚未配置"}
      description={(provider?.configured ? provider.provider + " · " + provider.model + " · " + provider.endpoint_host : "静态扫描、人工复核和证据查看仍可使用") + "。配置状态不代表最近连通性探测通过或研判效果已验收；组件 Harness 通过也需要产品入口、权限和 CIA 证据才能支持漏洞确认。"} />
    <AuditRiskOverview />
    <Row gutter={[18, 18]} className="section-gap overview-details"><Col xs={24} xl={16}><Card className="recent-tasks" title="最近审计任务" extra={<Button type="link" onClick={() => go("/tasks")}>查看全部 →</Button>}><ScanTable jobs={jobs} compact /></Card></Col>
      <Col xs={24} xl={8}><Card title="能力与覆盖" extra={<Button type="link" onClick={() => go("/settings/capabilities")}>能力详情</Button>}><div className="capability-summary">
        <div><span>C/C++ 自研检测</span><Text strong>{detectors.filter((d) => d.kind === "research_candidate" && d.supported_languages?.some((l: string) => ["c", "cpp", "c++"].includes(l.toLowerCase()))).length ? "已接入研究规则" : "以规则清单为准"}</Text></div>
        <div><span>IPC / 接口分析</span><Text strong>{detectors.some((d) => d.id === "ohscanner.interface.ipc") ? "有界候选分析" : "以规则清单为准"}</Text></div>
        <div><span>ArkTS / ETS / JS / TS</span><Text type="secondary">有界语法候选；ETS 限制见覆盖</Text></div>
        <div><span>模型辅助调查</span><Text type="secondary">{health?.capabilities?.agent ? (provider?.last_provider_check ? "已配置，连通性探测通过" : "已配置，连通性待验证") : "未配置"}</Text></div>
      </div><div className="coverage-note">实际解析覆盖见各任务报告；未分析、部分解析和证据不足保留 unknown。</div></Card></Col></Row>
    <div className="audit-shortcuts section-gap"><Text type="secondary">新建审计</Text>{auditLinks.map((entry) => <Button key={entry.path} onClick={() => go(entry.path)}>{entry.title} →</Button>)}</div>
    <Row gutter={[18, 18]} className="section-gap"><Col xs={24} xl={14}><Card title="证据工作流"><div className="workflow">{["代码扫描", "静态候选", "补齐证据", "受控验证"].map((s, i) => <div key={s}><span>0{i + 1}</span><strong>{s}</strong></div>)}</div></Card></Col>
      <Col xs={24} xl={10}><Card title="下一步"><Space wrap><Button onClick={() => go("/risks")}>查看候选</Button><Button onClick={() => go("/investigations")}>查看案例</Button><Button onClick={() => go("/reports")}>导出报告</Button></Space><Paragraph className="section-gap" type="secondary">解析失败、未执行和证据不足保留 unknown，不由菜单或模型补成成功。</Paragraph></Card></Col></Row>
  </>;
  else content = <Card><Empty description="页面不存在；旧任务链接仍可直接访问。"><Button onClick={() => go("/overview")}>返回总览</Button></Empty></Card>;
  return <Layout className="app workbench-v41">
    <Layout.Sider width={228} collapsedWidth={64} breakpoint="lg" className="sidebar" theme="light">
      <a className="brand" href="#/overview" aria-label="OHScanner 鸿鉴·智溯 总览">
        <span className="brand-mark" aria-hidden="true"><span>OH</span><i /></span>
        <div className="brand-copy"><strong className="brand-name">OHScanner</strong><b className="brand-cn">鸿鉴·智溯</b><small>OPENHARMONY SECURITY</small></div>
      </a>
      <div className="workspace-card"><span>OH</span><div><strong>源码审计工作区</strong><small>固定源码 · 可追溯证据</small></div></div>
      <div className="sidebar-scroll"><nav aria-label="主导航"><Menu theme="light" mode="inline" selectedKeys={[route.section]} defaultOpenKeys={["new-audit"]} onClick={({ key }) => go(key)} items={[
        { key: "workspace-label", type: "group", label: "工作区", children: [] },
        { key: "/overview", icon: <AppstoreOutlined />, label: "总览" },
        { key: "new-audit", icon: <PlusOutlined />, label: "新建审计", children: [
          { key: "/audits/repository", icon: <FolderOutlined />, label: auditLinks.find((item) => item.path === "/audits/repository")?.title || "仓库审计" },
          { key: "/audits/time", icon: <CalendarOutlined />, label: "时间增量扫描" },
          { key: "/audits/versions", icon: <BranchesOutlined />, label: "跨版本安全分析" },
        ] },
        { type: "divider" },
        { key: "/tasks", icon: <FileSearchOutlined />, label: "任务中心" },
        { key: "/risks", icon: <BugOutlined />, label: "风险中心" },
        { key: "investigation-label", type: "group", label: "漏洞研判", children: [] },
        { key: "/investigations", icon: <SearchOutlined />, label: "智能调查" },
        { key: "/poc", icon: <ExperimentOutlined />, label: "PoC 验证" },
        { key: "/impact", icon: <BranchesOutlined />, label: "影响与修复" },
        { key: "/reports", icon: <FileTextOutlined />, label: "报告中心" },
        { type: "divider" },
        { key: "/settings", icon: <SettingOutlined />, label: "系统设置" },
      ]} /></nav>
      <section className="sidebar-bottom" aria-label="审计能力">
        <div className="capability-heading"><span className="capability-signal" /><span>SECURITY AUDIT</span><span className="capability-version">OH</span></div>
        <div className="capability-row"><span className="capability-icon capability-icon-scan" aria-hidden="true">01</span><div><strong>多引擎静态扫描</strong><small>多路检测 · 交叉分析</small></div></div>
        <div className="capability-divider" />
        <div className="capability-row"><span className="capability-icon capability-icon-ai" aria-hidden="true">AI</span><div><strong>证据驱动智能审计</strong><small>线索关联 · 可追溯研判</small></div></div>
      </section>
      </div>
    </Layout.Sider>
    <Layout><Layout.Header className="topbar"><Space className="workspace-breadcrumb"><Text type="secondary">OHScanner</Text><span>/</span><Text strong>{path === "/overview" ? "总览" : path.startsWith("/audits/") ? "新建审计" : path.startsWith("/tasks") ? "任务中心" : path === "/risks" ? "风险中心" : path === "/investigations" ? "智能调查" : path === "/poc" ? "PoC 验证" : path === "/impact" ? "影响与修复" : path === "/reports" ? "报告中心" : path.startsWith("/settings") ? "系统设置" : "高级操作"}</Text></Space>
      <Space><Text className="worker-status" type="secondary">{health ? health.worker_running ? "Worker 运行中" : "Worker 未运行" : "服务状态未知"}</Text><Button type="text" icon={<ReloadOutlined />} onClick={() => void refresh()}>刷新</Button></Space></Layout.Header>
      <Layout.Content className="main">
        {error && <Alert className="section-gap" type="error" showIcon message={error} description="数据刷新失败，当前视图可能保留上次成功结果。" />}
        {health && !health.worker_running && <Alert className="section-gap" type="warning" message="扫描 Worker 未运行，排队任务将等待启动。" />}
        {content}
      </Layout.Content>
    </Layout>
  </Layout>;
}
export default function WorkbenchApp() {
  return <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: "#315fea", colorBgLayout: "#f4f6fa", colorText: "#243450", colorTextSecondary: "#7889a4", colorBorder: "#e2e8f0", borderRadius: 8, fontSize: 13, controlHeight: 32,
    fontFamily: '"MiSans VF", "MiSans", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif' }, components: { Card: { bodyPadding: 20, headerHeight: 52, headerFontSize: 14 }, Table: { cellPaddingBlock: 11, cellPaddingInline: 14, fontSize: 12 }, Menu: { itemHeight: 38, itemMarginBlock: 2, iconSize: 15 } } }}><Workspace /></ConfigProvider>;
}

import React, { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Col, ConfigProvider, Empty, Layout, Menu, Row, Space, Statistic, Typography } from "antd";
import zhCN from "antd/locale/zh_CN";
import { AppstoreOutlined, BranchesOutlined, BugOutlined, CalendarOutlined, ExperimentOutlined, FileSearchOutlined, FileTextOutlined, FolderOutlined, PlusOutlined, ReloadOutlined, SafetyCertificateOutlined, SearchOutlined, SettingOutlined } from "@ant-design/icons";
import "antd/dist/reset.css";
import "../../style.css";
import { api, terminal } from "../../api";
import { go, Header, useRoute } from "../../components";
import RepositoryAudit from "../audits/RepositoryAudit";
import OperationWorkspace from "../audits/OperationWorkspace";
import JobDetail from "../../pages/JobDetail";
import { Investigations, ReportCenter, RiskCenter, ScanTable, SettingsView, TaskCenter } from "./WorkspaceViews";
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
      const [r, d, j, h, c] = await Promise.all([api("/repositories"), api("/detectors"), api("/scans"), api("/health"), api("/cases")]);
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
  let content: React.ReactNode;
  const operationMatch = path.match(/^\/tasks\/operations\/([A-Za-z0-9_-]+)$/);
  const taskMatch = path.match(/^\/tasks\/([A-Za-z0-9_-]+)$/);
  if (operationMatch) content = <OperationWorkspace key={path} view="queue" operationId={operationMatch[1]} />;
  else if (taskMatch) content = <JobDetail key={path + route.query.get("tab")} id={taskMatch[1]} initialTab={detailTab(route.query.get("tab"))} />;
  else if (path === "/audits/repository") content = <RepositoryAudit repos={repos} detectors={detectors} refresh={refresh} />;
  else if (path === "/audits/time") content = <OperationWorkspace key={path} view="date" />;
  else if (path === "/audits/versions") content = <OperationWorkspace key={path} view="branches" />;
  else if (path === "/tasks") content = <TaskCenter jobs={jobs} />;
  else if (path === "/risks") content = <RiskCenter jobs={jobs} />;
  else if (path === "/investigations") content = <Investigations />;
  else if (path === "/poc") content = <OperationWorkspace key={path} view="validation" />;
  else if (path === "/impact") content = <OperationWorkspace key={path} view="matrix" />;
  else if (path === "/reports") content = <ReportCenter jobs={jobs} cases={cases} />;
  else if (path === "/settings" || path.startsWith("/settings/")) content = <SettingsView repos={repos} detectors={detectors} health={health} refresh={refresh} tab={path.split("/")[2] || "sources"} />;
  else if (path === "/operations") content = <OperationWorkspace />;
  else if (path === "/overview") content = <>
    <Header title="源码安全审计" description="固定源码、记录覆盖、审查证据，让结论可复核。" extra={<Button icon={<ReloadOutlined />} onClick={() => void refresh()}>刷新状态</Button>} />
    <Row gutter={[18, 18]} className="audit-entry-grid">{auditLinks.map((entry, index) => <Col xs={24} xl={8} key={entry.path}><Card className="audit-entry-card">
      <span className="entry-number">0{index + 1}</span><Typography.Title level={4}>{entry.title}</Typography.Title><Paragraph type="secondary">{entry.description}</Paragraph>
      <Button type={index === 0 ? "primary" : "default"} onClick={() => go(entry.path)}>进入{entry.title} →</Button>
    </Card></Col>)}</Row>
    <Row gutter={[18, 18]} className="section-gap">{[
      { label: "已登记仓库", value: repos.length, note: "本地 Git 对象；官方身份待核验" },
      { label: "执行中 / 排队", value: jobs.filter((j) => !terminal.has(j.status)).length, note: "当前任务列表 · 单扫描 Worker" },
      { label: "已保存扫描", value: jobs.filter((j) => j.report_sha256).length, note: "当前列表 · 绑定固定源码" },
      { label: "调查案例", value: cases.length, note: "人工关联，不代表已确认漏洞" },
    ].map((item) => <Col xs={24} sm={12} xl={6} key={item.label}><Card className="stat-card"><Statistic title={item.label} value={item.value} /><div className="muted">{item.note}</div></Card></Col>)}</Row>
    <Alert className="section-gap" type="info" showIcon message="候选、组件复现与产品漏洞分别记录" description="0 条候选不是安全证明。真实模型未连接；组件 Harness 通过也需要产品入口、权限和 CIA 证据才能支持漏洞确认。" />
    <Card className="section-gap" title="最近扫描任务" extra={<Button type="link" onClick={() => go("/tasks")}>任务中心 →</Button>}><ScanTable jobs={jobs} compact /></Card>
    <Row gutter={[18, 18]} className="section-gap"><Col xs={24} xl={14}><Card title="证据工作流"><div className="workflow">{["固定源码", "静态候选", "补齐证据", "受控验证"].map((s, i) => <div key={s}><span>0{i + 1}</span><strong>{s}</strong></div>)}</div></Card></Col>
      <Col xs={24} xl={10}><Card title="下一步"><Space wrap><Button onClick={() => go("/risks")}>审查候选</Button><Button onClick={() => go("/investigations")}>调查案例</Button><Button onClick={() => go("/reports")}>导出报告</Button></Space><Paragraph className="section-gap" type="secondary">解析失败、未执行和证据不足保留 unknown，不由菜单或模型补成成功。</Paragraph></Card></Col></Row>
  </>;
  else content = <Card><Empty description="页面不存在；旧任务链接仍可直接访问。"><Button onClick={() => go("/overview")}>返回总览</Button></Empty></Card>;
  return <Layout className="app workbench-v41">
    <Layout.Sider width={242} collapsedWidth={76} breakpoint="lg" className="sidebar" theme="light">
      <a className="brand" href="#/overview" aria-label="OHScanner 总览"><SafetyCertificateOutlined /><div>OHScanner<small>OPENHARMONY SECURITY</small></div></a>
      <nav aria-label="主导航"><Menu theme="light" mode="inline" selectedKeys={[route.section]} defaultOpenKeys={["new-audit"]} onClick={({ key }) => go(key)} items={[
        { key: "/overview", icon: <AppstoreOutlined />, label: "总览" },
        { key: "new-audit", icon: <PlusOutlined />, label: "新建审计", children: [
          { key: "/audits/repository", icon: <FolderOutlined />, label: "仓库安全扫描" },
          { key: "/audits/time", icon: <CalendarOutlined />, label: "时间增量扫描" },
          { key: "/audits/versions", icon: <BranchesOutlined />, label: "跨版本安全分析" },
        ] },
        { key: "/tasks", icon: <FileSearchOutlined />, label: "任务中心" },
        { key: "/risks", icon: <BugOutlined />, label: "风险中心" },
        { key: "/investigations", icon: <SearchOutlined />, label: "智能调查" },
        { key: "/poc", icon: <ExperimentOutlined />, label: "PoC 验证" },
        { key: "/impact", icon: <BranchesOutlined />, label: "影响与修复" },
        { key: "/reports", icon: <FileTextOutlined />, label: "报告中心" },
        { key: "/settings", icon: <SettingOutlined />, label: "系统设置" },
      ]} /></nav>
      <div className="sidebar-bottom"><span className="local-dot" /> 本地工作区<div>固定版本 · 证据优先</div><small>UI V4.1 · 本机 MiSans 优先</small></div>
    </Layout.Sider>
    <Layout><Layout.Header className="topbar"><Space><span className="workspace-chip">本地审计</span><Text type="secondary">OpenHarmony / 可复核证据</Text></Space>
      <Space><Text className="worker-status" type="secondary">{health ? health.worker_running ? "Worker 运行中" : "Worker 未运行" : "服务状态未知"}</Text><Button type="text" icon={<ReloadOutlined />} onClick={() => void refresh()}>刷新</Button></Space></Layout.Header>
      <Layout.Content className="main">
        {error && <Alert className="section-gap" type="error" showIcon message={error} description="数据刷新失败，当前视图可能保留上次成功结果。" />}
        {health && !health.worker_running && <Alert className="section-gap" type="warning" message="扫描 Worker 未运行，排队任务将等待启动。" />}
        {content}
      </Layout.Content><Layout.Footer className="footer">OHScanner · 候选 / 覆盖 / 证据分别记录 · 采用本机 MiSans 字体与系统回退</Layout.Footer>
    </Layout>
  </Layout>;
}
export default function WorkbenchApp() {
  return <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: "#315f91", colorBgLayout: "#f6f7f9", borderRadius: 9,
    fontFamily: '"MiSans", "MiSans L3", "Microsoft YaHei UI", "Microsoft YaHei", "Noto Sans CJK SC", system-ui, sans-serif' } }}><Workspace /></ConfigProvider>;
}

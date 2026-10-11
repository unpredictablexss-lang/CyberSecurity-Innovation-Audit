import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  ConfigProvider,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Modal,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Table,
  Tabs,
  Tag,
  Timeline,
  Typography,
  message,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  AppstoreOutlined,
  BranchesOutlined,
  CodeOutlined,
  FileSearchOutlined,
  FolderOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ExperimentOutlined,
} from "@ant-design/icons";
import "antd/dist/reset.css";
import "./style.css";
import { api, artifact, terminal } from "./api";
import { State, Hash, go, useRoute, Header } from "./components";
import Repositories from "./pages/Repositories";
import NewScan from "./pages/NewScan";
import JobDetail from "./pages/JobDetail";
import Cases from "./pages/Cases";
import Capabilities from "./pages/Capabilities";
const { Text, Title, Paragraph } = Typography;
function App() {
  const route = useRoute();
  const [repos, setRepos] = useState<any[]>([]);
  const [detectors, setDetectors] = useState<any[]>([]);
  const [jobs, setJobs] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [error, setError] = useState("");
  const refresh = async () => {
    try {
      const [r, d, j, h] = await Promise.all([
        api("/repositories"),
        api("/detectors"),
        api("/scans"),
        api("/health"),
      ]);
      setRepos(r);
      setDetectors(d);
      setJobs(j);
      setHealth(h);
      setError("");
    } catch (e) {
      setError(String(e));
    }
  };
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, []);
  const columns = [
    {
      title: "任务 / 固定版本",
      render: (_: any, j: any) => (
        <>
          <a onClick={() => go("/tasks/" + j.id)}>{j.spec.repository}</a>
          <div className="muted">
            <Hash value={j.spec.commit} />
          </div>
        </>
      ),
    },
    {
      title: "执行状态",
      dataIndex: "status",
      render: (s: string) => <State value={s} />,
    },
    { title: "阶段", dataIndex: "stage" },
    {
      title: "创建时间",
      dataIndex: "created_at",
      render: (s: string) => new Date(s).toLocaleString(),
    },
    {
      title: "",
      render: (_: any, j: any) => (
        <Button onClick={() => go("/tasks/" + j.id)}>查看任务</Button>
      ),
    },
  ];
  let content: React.ReactNode;
  if (route.startsWith("/tasks/"))
    content = <JobDetail key={route} id={route.split("/")[2]} />;
  else if (route === "/repositories")
    content = (
      <Repositories
        repos={repos}
        roots={health?.target_roots || []}
        refresh={refresh}
      />
    );
  else if (route === "/new")
    content = <NewScan repos={repos} detectors={detectors} refresh={refresh} />;
  else if (route === "/cases") content = <Cases />;
  else if (route === "/capabilities")
    content = <Capabilities detectors={detectors} />;
  else if (route === "/tasks")
    content = (
      <>
        <Header
          title="审计任务"
          description="固定输入、真实阶段、持久化结果。执行完成不代表组件安全。"
          extra={
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => go("/new")}
            >
              新建审计
            </Button>
          }
        />
        <Card>
          <Table rowKey="id" columns={columns} dataSource={jobs} />
        </Card>
      </>
    );
  else
    content = (
      <>
        <Header
          title="源码审计工作台"
          description="从固定源码到可复核证据，让每一个结论都有出处。"
          extra={
            <Button
              type="primary"
              size="large"
              icon={<PlusOutlined />}
              onClick={() => go("/new")}
            >
              新建审计
            </Button>
          }
        />
        <Row gutter={18}>
          {[
            {
              title: "已登记仓库",
              value: repos.length,
              note: "本地 Git 对象 · 不自动联网",
            },
            {
              title: "正在执行 / 排队",
              value: jobs.filter((j) => !terminal.has(j.status)).length,
              note: "独立 Worker · 单任务并发",
            },
            {
              title: "已保存扫描",
              value: jobs.filter((j) => j.report_sha256).length,
              note: "固定 Commit · 校验报告完整性",
            },
            {
              title: "已接入检测器",
              value: detectors.length,
              note: "研究候选 · 需要独立复核",
            },
          ].map((x) => (
            <Col span={6} key={x.title}>
              <Card className="stat-card">
                <Statistic title={x.title} value={x.value} />
                <div className="muted">{x.note}</div>
              </Card>
            </Col>
          ))}
        </Row>
        <Alert
          className="section-gap"
          type="info"
          showIcon
          message="候选 ≠ 已确认漏洞"
          description="保留解析、覆盖与证据缺口。0 条候选不是安全证明；当前工作台不执行动态验证或自动升级漏洞结论。"
        />
        <Card
          className="section-gap"
          title="最近审计"
          extra={<a onClick={() => go("/tasks")}>全部任务 →</a>}
        >
          <Table
            rowKey="id"
            dataSource={jobs.slice(0, 5)}
            columns={columns}
            pagination={false}
            locale={{
              emptyText: (
                <Empty description="从登记一个本地仓库开始">
                  <Button onClick={() => go("/repositories")}>登记仓库</Button>
                </Empty>
              ),
            }}
          />
        </Card>
        <Row gutter={18} className="section-gap">
          <Col span={14}>
            <Card title="审计工作流">
              <div className="workflow">
                {["固定源码", "解析与检测", "候选复核", "证据归档"].map(
                  (x, i) => (
                    <div key={x}>
                      <span>0{i + 1}</span>
                      <strong>{x}</strong>
                    </div>
                  ),
                )}
              </div>
            </Card>
          </Col>
          <Col span={10}>
            <Card title="研发能力边界">
              <Paragraph>
                Agent 调查、隔离验证与版本影响将在后续模块接入。
              </Paragraph>
              <Button onClick={() => go("/capabilities")}>
                查看能力与限制
              </Button>
            </Card>
          </Col>
        </Row>
      </>
    );
  return (
    <Layout className="app">
      <Layout.Sider width={228} className="sidebar">
        <div className="brand">
          <SafetyCertificateOutlined />
          <div>
            OHScanner<small>OPENHARMONY AUDIT</small>
          </div>
        </div>
        <div className="nav-caption">审计工作区</div>
        <Menu
          theme="dark"
          selectedKeys={[route.startsWith("/tasks") ? "/tasks" : route]}
          onClick={({ key }) => go(key)}
          items={[
            {
              key: "/overview",
              icon: <AppstoreOutlined />,
              label: "工作台概览",
            },
            {
              key: "/repositories",
              icon: <FolderOutlined />,
              label: "仓库与版本",
            },
            { key: "/new", icon: <PlusOutlined />, label: "新建审计" },
            {
              key: "/tasks",
              icon: <FileSearchOutlined />,
              label: "任务与候选",
            },
            { key: "/cases", icon: <BranchesOutlined />, label: "调查案例" },
            {
              key: "/capabilities",
              icon: <ExperimentOutlined />,
              label: "能力与研发状态",
            },
          ]}
        />
        <div className="sidebar-bottom">
          <span className="local-dot" /> LOCAL WORKSPACE
          <div>Windows 浏览器 · WSL2 执行</div>
          <small>v0.1 · Evidence first</small>
        </div>
      </Layout.Sider>
      <Layout>
        <Layout.Header className="topbar">
          <Space>
            <span className="workspace-chip">本地审计</span>
            <Text type="secondary">固定版本 / 自研检测 / 可复核证据</Text>
          </Space>
          <Button
            type="text"
            icon={<ReloadOutlined />}
            onClick={() => void refresh()}
          >
            刷新
          </Button>
        </Layout.Header>
        <Layout.Content className="main">
          {error && <Alert type="error" message={error} />}{" "}
          {health && !health.worker_running && (
            <Alert
              type="warning"
              message="扫描 Worker 未运行，已排队任务将等待 Worker 启动。"
            />
          )}{" "}
          {content}
        </Layout.Content>
        <Layout.Footer className="footer">
          OHScanner · 候选、覆盖、证据分别记录 · 时间按浏览器本地时区显示
        </Layout.Footer>
      </Layout>
    </Layout>
  );
}
createRoot(document.getElementById("root")!).render(
  <ConfigProvider
    locale={zhCN}
    theme={{
      token: {
        colorPrimary: "#176b63",
        borderRadius: 10,
        fontFamily: "Inter, Segoe UI, Microsoft YaHei, sans-serif",
        colorBgLayout: "#f4f6f9",
      },
    }}
  >
    <App />
  </ConfigProvider>,
);

import React, { useEffect, useRef, useState } from "react";
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
import { api, artifact, terminal } from "../api";
import { State, Hash, go, CodeView, Header, labels } from "../components";
import AuditPlanView from "../features/audits/AuditPlanView";
import SourceEvidence from "../SourceEvidence";
import CandidateActions from "../features/workbench/CandidateActions";
import { requestGate } from "../features/audits/model";
const { Text, Title, Paragraph } = Typography;
export default function JobDetail({ id, initialTab = "findings", candidateId }: { id: string; initialTab?: string; candidateId?: string }) {
  const [job, setJob] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [items, setItems] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [clusters, setClusters] = useState<any[]>([]);
  const [clusterTotal, setClusterTotal] = useState(0);
  const [clusterPage, setClusterPage] = useState(1);
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("");
  const [detail, setDetail] = useState<any>(null);
  const selectedDetailId = useRef<string | null>(null);
  const detailGate = useRef(requestGate());
  const candidateAutoOpened = useRef<string | null>(null);
  const [source, setSource] = useState<any>(null);
  const [selected, setSelected] = useState<React.Key[]>([]);
  const [caseOpen, setCaseOpen] = useState(false);
  const [caseForm] = Form.useForm();
  const [reviewForm] = Form.useForm();
  const [cases, setCases] = useState<any[]>([]);
  const existingCase = Form.useWatch("case_id", caseForm);
  useEffect(() => {
    if (caseOpen)
      api("/cases")
        .then(setCases)
        .catch((e) => setError(String(e)));
  }, [caseOpen]);
  async function loadFindings() {
    try {
      const r = await api(
        "/scans/" +
          id +
          "/findings?offset=" +
          (page - 1) * 20 +
          "&limit=20&q=" +
          encodeURIComponent(query) +
          "&review_status=" +
          filter,
      );
      setItems(r.items);
      setTotal(r.total);
    } catch (e) {
      setError(String(e));
    }
  }
  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setInterval> | undefined;
    async function load() {
      try {
        const [j, e] = await Promise.all([
          api("/scans/" + id),
          api("/scans/" + id + "/events"),
        ]);
        if (!live) return;
        setJob(j);
        setEvents(e);
        if (j.report_sha256) {
          const r = await api("/scans/" + id + "/report");
          if (live) setReport(r);
        }
        if (terminal.has(j.status) && timer) clearInterval(timer);
      } catch (e) {
        if (live) setError(String(e));
      }
    }
    void load();
    timer = setInterval(() => void load(), 2000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [id]);
  async function loadClusters() {
    try {
      const r = await api(
        "/scans/" + id + "/clusters?offset=" + (clusterPage - 1) * 20 + "&limit=20",
      );
      setClusters(r.items);
      setClusterTotal(r.total);
    } catch (e) {
      setError(String(e));
    }
  }
  useEffect(() => {
    if (report) void loadFindings();
  }, [report?.snapshot_sha256, page, query, filter]);
  useEffect(() => {
    if (report) void loadClusters();
  }, [report?.snapshot_sha256, clusterPage]);
  async function open(f: any, options: { select?: boolean; resetReview?: boolean } = {}) {
    if (options.select === false && selectedDetailId.current !== f.id) return;
    if (options.select !== false) selectedDetailId.current = f.id;
    const ticket = detailGate.current.next();
    try {
      const d = await api("/scans/" + id + "/findings/" + f.id);
      if (!detailGate.current.current(ticket) || selectedDetailId.current !== f.id) return;
      setDetail(d);
      const last = d.reviews.at(-1);
      if (options.resetReview !== false) reviewForm.setFieldsValue({
        status: last?.status || "under_review",
        reviewer: last?.reviewer || "",
        notes: "",
      });
    } catch (e) {
      setError(String(e));
    }
  }
  useEffect(() => {
    if (job && candidateId && candidateAutoOpened.current !== candidateId) {
      candidateAutoOpened.current = candidateId;
      void open({ id: candidateId });
    }
  }, [job?.id, candidateId]);
  async function action(name: string) {
    try {
      const j = await api("/scans/" + id + "/" + name, {});
      if (name === "retry") go("/tasks/" + j.id);
      else setJob(j);
    } catch (e) {
      setError(String(e));
    }
  }
  if (!job) return error ? <Alert type="error" showIcon message={error} /> : <Spin />;
  const parse = report?.source_parsing.parsing_status || {};
  const coverage = report
    ? Object.entries(report.detector_coverage.detectors).map(
        ([detector, c]) => ({ detector, ...(c as any) }),
      )
    : [];
  return (
    <>
      <Header
        title={job.spec.repository}
        description={
          "任务 " +
          id.slice(0, 12) +
          " · " +
          new Date(job.created_at).toLocaleString()
        }
        extra={
          <Space>
            <State value={job.status} />
            {!terminal.has(job.status) ? (
              <Button danger onClick={() => void action("cancel")}>
                取消任务
              </Button>
            ) : (
              <Button onClick={() => void action("retry")}>
                按原 Commit 重试
              </Button>
            )}
          </Space>
        }
      />
      {error && <Alert type="error" message={error} />}{" "}
      {job.error && (
        <Alert
          type="warning"
          message={job.error}
          description="未完成分析保留 unknown，不解释为安全。"
        />
      )}
      <Card>
        <Descriptions
          size="small"
          column={3}
          items={[
            {
              key: "commit",
              label: "Commit",
              children: <Hash value={job.spec.commit} />,
            },
            {
              key: "tree",
              label: "Git Tree",
              children: <Hash value={job.spec.git_tree} />,
            },
            {
              key: "ref",
              label: "原始选择",
              children: job.spec.requested_revision,
            },
            {
              key: "scope",
              label: "纳入路径",
              children: job.spec.include_paths.join(", "),
            },
            {
              key: "engine",
              label: "引擎指纹",
              children: <Hash value={job.spec.engine_sha256} />,
            },
            {
              key: "time",
              label: "实际耗时",
              children:
                job.elapsed_seconds === null
                  ? "尚未完成"
                  : job.elapsed_seconds.toFixed(2) + " s",
            },
          ]}
        />
      </Card>
      <AuditPlanView plan={job.spec.audit_plan} />
      {report && (
        <Row gutter={18} className="section-gap">
          {[
            {
              title: "纳入源码文件",
              value: report.scope.selected_source_files,
            },
            { title: "原始候选观测", value: report.diagnostic_count },
            {
              title: "部分 / 失败 / 未解析",
              value:
                (parse.partial || 0) +
                (parse.failed || 0) +
                (parse.not_run || 0),
            },
            { title: "已确认漏洞", value: report.validated_vulnerability ?? "unknown" },
          ].map((x) => (
            <Col span={6} key={x.title}>
              <Card>
                <Statistic {...x} />
              </Card>
            </Col>
          ))}
        </Row>
      )}
      <Card className="section-gap">
        <Tabs
          defaultActiveKey={initialTab}
          items={[
            {
              key: "findings",
              label: "候选与复核",
              children: report ? (
                <>
                  <Space className="toolbar">
                    <Input.Search
                      allowClear
                      placeholder="搜索路径、规则或说明"
                      onSearch={(v) => {
                        setQuery(v);
                        setPage(1);
                      }}
                    />
                    <Select
                      style={{ width: 200 }}
                      value={filter}
                      onChange={(v) => {
                        setFilter(v);
                        setPage(1);
                      }}
                      options={[
                        { value: "", label: "全部复核状态" },
                        ...Object.keys(labels)
                          .filter((x) =>
                            [
                              "unassessed",
                              "under_review",
                              "plausible_unproven",
                              "likely_false_positive",
                              "refuted",
                            ].includes(x),
                          )
                          .map((value) => ({ value, label: labels[value] })),
                      ]}
                    />
                    <Button
                      disabled={!selected.length}
                      onClick={() => setCaseOpen(true)}
                    >
                      关联调查案例（{selected.length}）
                    </Button>
                  </Space>
                  <Table<any>
                    rowKey="id"
                    dataSource={items}
                    rowSelection={{
                      selectedRowKeys: selected,
                      preserveSelectedRowKeys: true,
                      onChange: setSelected,
                    }}
                    pagination={{
                      current: page,
                      pageSize: 20,
                      total,
                      onChange: setPage,
                      showSizeChanger: false,
                    }}
                    columns={[
                      {
                        title: "源码位置",
                        render: (_: any, f: any) => (
                          <a onClick={() => void open(f)}>
                            {f.file}:{f.line}
                          </a>
                        ),
                      },
                      {
                        title: "规则 / CWE 候选",
                        render: (_: any, f: any) => (
                          <>
                            {f.rule_id === "ohcpp-null-dereference-unknown-return-observation-001" &&
                              <Tag color="gold">弱候选 · 待复核</Tag>}
                            <Text code>{f.rule_id}</Text>
                            <div className="muted">{f.candidate_cwe}</div>
                          </>
                        ),
                      },
                      {
                        title: "分析状态",
                        render: (_: any, f: any) => (
                          <State
                            value={f.evidence.analysis_status || "unknown"}
                          />
                        ),
                      },
                      {
                        title: "人工复核",
                        dataIndex: "review_status",
                        render: (s: string) => <State value={s} />,
                      },
                      {
                        title: "",
                        render: (_: any, f: any) => (
                          <Button onClick={() => void open(f)}>查看证据</Button>
                        ),
                      },
                    ]}
                    locale={{
                      emptyText: "0 条候选。请检查覆盖；这不是安全证明。",
                    }}
                  />
                </>
              ) : (
                <Empty description="无已提交结果；不能判断候选或组件安全性" />
              ),
            },
            {
              key: "clusters",
              label: "候选聚类（非根因结论）",
              children: report ? (
                <>
                  <Alert
                    type="info"
                    message="这是减少重复浏览的候选分组，不是根因归并或漏洞结论。"
                    description="仅按同一仓库快照、Detector 版本、规则、文件、符号和源码 SHA 分组；未绑定来源或缺少符号的候选保持独立。组内每条原始候选身份和源码位置都保留。"
                  />
                  <Table<any>
                    className="section-gap"
                    rowKey="cluster_id"
                    dataSource={clusters}
                    pagination={{
                      current: clusterPage,
                      pageSize: 20,
                      total: clusterTotal,
                      onChange: setClusterPage,
                      showSizeChanger: false,
                    }}
                    expandable={{
                      expandIcon: ({ expanded, onExpand, record }) => <Button size="small" type="text" aria-label={expanded ? "收起候选组" : "展开候选组"} onClick={(event) => onExpand(record, event)}>{expanded ? "−" : "+"}</Button>,
                      expandedRowRender: (group: any) => (
                        <Space wrap>
                          {group.candidates.map((candidate: any) => (
                            <Button
                              key={candidate.id}
                              onClick={() => void open({ id: candidate.id })}
                            >
                              {group.file}:{candidate.line} · {candidate.operation || "observation"} · {labels[candidate.review_status] || candidate.review_status}
                            </Button>
                          ))}
                        </Space>
                      ),
                    }}
                    columns={[
                      {
                        title: "文件 / 符号",
                        render: (_: any, group: any) => (
                          <>
                            <Text code>{group.symbol || "(no symbol)"}</Text>
                            <div className="muted">{group.file}</div>
                          </>
                        ),
                      },
                      {
                        title: "规则 / Detector",
                        render: (_: any, group: any) => (
                          <>
                            <Text code>{group.rule_id}</Text>
                            <div className="muted">
                              {group.detector_id} · {group.detector_version}
                            </div>
                          </>
                        ),
                      },
                      { title: "原始候选数", dataIndex: "observation_count" },
                      { title: "分组依据", dataIndex: "grouping_basis" },
                      { title: "根因结论", render: () => "未推断" },
                    ]}
                    locale={{ emptyText: "当前报告没有可分组的候选观测。" }}
                  />
                </>
              ) : (
                <Empty description="无已提交结果" />
              ),
            },
            {
              key: "coverage",
              label: "覆盖与执行",
              children: report ? (
                <>
                  <Alert
                    type="info"
                    message={
                      "解析：" +
                      JSON.stringify(parse) +
                      "；未被检测器认领：" +
                      report.files_in_scope_without_a_claiming_detector.length
                    }
                    description="解析完整、检测执行完成与安全性是不同维度。工作台提供任务级硬超时与进程地址空间限制；下列引擎原始限制不代表已实现检测器逐个隔离。"
                  />
                  <Table
                    rowKey="detector"
                    dataSource={coverage}
                    pagination={false}
                    columns={[
                      { title: "检测器", dataIndex: "detector" },
                      {
                        title: "覆盖",
                        dataIndex: "status",
                        render: (s: string) => <State value={s} />,
                      },
                      { title: "适用", dataIndex: "applicable_files" },
                      {
                        title: "完整",
                        render: (_: any, c: any) => c.analyzed_files.length,
                      },
                      {
                        title: "部分检查",
                        render: (_: any, c: any) =>
                          c.partially_inspected_files.length,
                      },
                      {
                        title: "未分析",
                        render: (_: any, c: any) => c.not_analyzed_files.length,
                      },
                    ]}
                  />
                  {report.detector_runs.map((r: any) => (
                    <Card
                      size="small"
                      className="section-gap"
                      key={r.tool}
                      title={
                        <Space>
                          {r.tool}
                          <State value={r.status} />
                        </Space>
                      }
                    >
                      <Text>
                        候选 {r.diagnostic_count} · 检查 {r.scope_files} 文件 ·{" "}
                        {r.elapsed_seconds.toFixed(3)} s
                      </Text>
                      <details className="section-gap">
                        <summary>
                          查看原始引擎限制（{r.limitations.length}）
                        </summary>
                        <ul>
                          {r.limitations.map((x: string, i: number) => (
                            <li key={i}>{x}</li>
                          ))}
                        </ul>
                      </details>
                    </Card>
                  ))}
                  <Paragraph className="section-gap">未被认领文件：</Paragraph>
                  <pre className="raw">
                    {report.files_in_scope_without_a_claiming_detector.join(
                      "\n",
                    ) || "无"}
                  </pre>
                </>
              ) : (
                <Empty description="无完整结果" />
              ),
            },
            {
              key: "source",
              label: "固定版本源码",
              children: report ? (
                <>
                  <Select
                    showSearch
                    style={{ width: "100%" }}
                    placeholder="选择本次纳入的源码"
                    options={report._workbench.source_inventory.map(
                      (f: any) => ({ value: f.file, label: f.file }),
                    )}
                    onChange={(file) =>
                      api(
                        "/scans/" +
                          id +
                          "/source?file=" +
                          encodeURIComponent(file),
                      )
                        .then(setSource)
                        .catch((e) => setError(String(e)))
                    }
                  />
                  {source && <CodeView source={source} />}
                </>
              ) : (
                <Empty description="无已验证源码清单" />
              ),
            },
            {
              key: "events",
              label: "执行轨迹",
              children: (
                <>
                  <Timeline
                    items={events.map((e) => ({
                      children: (
                        <>
                          <Text strong>{e.stage}</Text>
                          <div>{e.message}</div>
                          <Text type="secondary">
                            {new Date(e.created_at).toLocaleString()}
                          </Text>
                        </>
                      ),
                    }))}
                  />
                  <a href={artifact(id, "worker.log")}>下载最近 256 KiB 日志</a>
                </>
              ),
            },
            {
              key: "reports",
              label: "报告与产物",
              children: report ? (
                <>
                  <Paragraph>
                    原始报告保持不可变；复核包包含追加记录与案例关联。当前没有运行时验证结论。
                  </Paragraph>
                  <Space wrap>
                    {[
                      "manifest.json",
                      "report.json",
                      "report.md",
                      "review.json",
                      "review.md",
                    ].map((k) => (
                      <Button key={k} href={artifact(id, k)}>
                        下载 {k}
                      </Button>
                    ))}
                  </Space>
                  <Descriptions
                    column={1}
                    className="section-gap"
                    items={[
                      {
                        key: "hash",
                        label: "原始报告 SHA-256",
                        children: <Text copyable>{job.report_sha256}</Text>,
                      },
                      {
                        key: "snapshot",
                        label: "源码快照 SHA-256",
                        children: (
                          <Text copyable>{report.snapshot_sha256}</Text>
                        ),
                      },
                    ]}
                  />
                  <ul>
                    {report.limitations.map((x: string, i: number) => (
                      <li key={i}>{x}</li>
                    ))}
                  </ul>
                </>
              ) : (
                <Empty description="无已提交报告" />
              ),
            },
          ]}
        />
      </Card>
      <Drawer
        open={!!detail}
        onClose={() => { selectedDetailId.current = null; detailGate.current.invalidate(); setDetail(null); }}
        width="90vw"
        title={
          <Space>
            <CodeOutlined />
            候选证据与人工复核
          </Space>
        }
      >
        {detail && (
          <>
            <Alert
              type="warning"
              message={(detail.rule_id === "ohcpp-null-dereference-unknown-return-observation-001" ? "弱候选 · 待复核 · " : "") + detail.rule_id + " · " + detail.candidate_cwe}
              description={detail.message}
            />
            <CandidateActions job={job} candidate={detail} />
            <CodeView source={detail.source} line={detail.line} />
            <SourceEvidence
              key={detail.id}
              jobId={id}
              detail={detail}
              reload={() => open(detail, { select: false, resetReview: false })}
            />
            <Row gutter={20} className="section-gap">
              <Col span={12}>
                <Card title="证据义务">
                  {(detail.evidence.obligations || []).map(
                    (o: any, i: number) => (
                      <div className="obligation" key={i}>
                        <Space>
                          <Text strong>{o.kind}</Text>
                          <Tag>{o.status}</Tag>
                        </Space>
                        <div>{o.description || o.detail || ""}</div>
                      </div>
                    ),
                  )}
                  <pre className="raw">
                    {JSON.stringify(detail.evidence, null, 2)}
                  </pre>
                </Card>
              </Col>
              <Col span={12}>
                <Card title="追加人工复核">
                  <Form
                    form={reviewForm}
                    layout="vertical"
                    onFinish={async (values) => {
                      try {
                        await api(
                          "/scans/" +
                            id +
                            "/findings/" +
                            detail.id +
                            "/reviews",
                          {
                            ...values,
                            expected_id: detail.reviews.at(-1)?.id || 0,
                          },
                        );
                        await open(detail, { select: false, resetReview: true });
                        await loadFindings();
                        message.success("复核记录已追加");
                      } catch (e) {
                        message.error(String(e));
                      }
                    }}
                  >
                    <Form.Item
                      name="status"
                      label="复核状态"
                      rules={[{ required: true }]}
                    >
                      <Select
                        options={[
                          "under_review",
                          "plausible_unproven",
                          "likely_false_positive",
                          "refuted",
                          "unassessed",
                        ].map((value) => ({ value, label: labels[value] }))}
                      />
                    </Form.Item>
                    <Form.Item
                      name="reviewer"
                      label="复核人"
                      rules={[{ required: true }]}
                    >
                      <Input maxLength={100} />
                    </Form.Item>
                    <Form.Item
                      name="notes"
                      label="依据、证据位置与下一步"
                      rules={[{ required: true }]}
                    >
                      <Input.TextArea rows={5} maxLength={8000} />
                    </Form.Item>
                    <Button type="primary" htmlType="submit">
                      保存追加记录
                    </Button>
                  </Form>
                  <Timeline
                    className="section-gap"
                    items={detail.reviews.map((r: any) => ({
                      children: (
                        <>
                          <State value={r.status} />
                          <Text strong>{r.reviewer}</Text>
                          <Paragraph style={{ whiteSpace: "pre-wrap" }}>
                            {r.notes}
                          </Paragraph>
                          <Text type="secondary">
                            {new Date(r.created_at).toLocaleString()}
                          </Text>
                        </>
                      ),
                    }))}
                  />
                </Card>
              </Col>
            </Row>
          </>
        )}
      </Drawer>
      <Modal
        open={caseOpen}
        title="建立调查案例"
        onCancel={() => setCaseOpen(false)}
        onOk={() => caseForm.submit()}
      >
        <Paragraph>按人工核对的共同根因关联候选，不会自动确认漏洞。</Paragraph>
        <Form
          form={caseForm}
          layout="vertical"
          onFinish={async (values) => {
            try {
              await api(
                values.case_id
                  ? "/cases/" + values.case_id + "/links"
                  : "/cases",
                {
                  ...(values.case_id ? {} : { title: values.title }),
                  links: selected.map((candidate_id) => ({
                    job_id: id,
                    candidate_id,
                    rationale: values.rationale,
                  })),
                },
              );
              setCaseOpen(false);
              setSelected([]);
              caseForm.resetFields();
              message.success("案例已建立");
            } catch (e) {
              message.error(String(e));
            }
          }}
        >
          <Form.Item name="case_id" label="关联已有案例（不选则创建）">
            <Select
              allowClear
              options={cases.map((c) => ({ value: c.id, label: c.title }))}
            />
          </Form.Item>
          <Form.Item
            name="title"
            label="案例标题"
            hidden={Boolean(existingCase)}
            rules={[{ required: !existingCase }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="rationale"
            label="根因关联依据"
            rules={[{ required: true }]}
          >
            <Input.TextArea rows={4} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

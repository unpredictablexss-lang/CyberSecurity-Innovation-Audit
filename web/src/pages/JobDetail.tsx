import React, { useEffect, useRef, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Collapse,
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
import ProgressiveQuickScreenAction from "../features/audits/ProgressiveQuickScreenAction";
import { requestGate } from "../features/audits/model";
import { disclosureReviewed, disclosureSelectionMatches } from "../features/audits/egressDisclosure.js";
import { candidateConfidenceColor, candidateConfidenceLabel, candidateSeverityColor, candidateSeverityLabel, analysisStatusLabel, coverageSummaryLabel, groupingBasisLabel, groupingSymbolLabel, obligationDescriptionLabel, obligationKindLabel, obligationStatusLabel, reportLimitationLabel, riskReasonsLabel, scanStageLabel, taskReportStatusLabel, taskTriageStatusLabel, triageStateLabel } from "../features/workbench/riskLabels.js";
const { Text, Title, Paragraph } = Typography;
function HighConfidenceCandidateReason({ risk, jobId }: { risk: any; jobId: string }) {
  if (risk?.risk_tier !== "high_confidence_candidate") return null;
  const signal = risk.agent_signal || {};
  const locations = risk.confidence_basis === "ai_source_evidence" ? (risk.ai_evidence || []) : (Array.isArray(signal.evidence_locations) ? signal.evidence_locations : []);
  const explanation = risk.ai_summary || signal.confidence_reason || risk.reason
    || (risk.confidence_basis === "human_r0"
      ? "人工 R0 已对固定源码中的证据义务逐项引用复核。"
      : "固定源码证据门已通过；具体义务与源码仍需人工核对。");
  const openEvidence = (location: any) => {
    const query = new URLSearchParams({
      tab: "source",
      source_file: location.file,
      source_line: String(location.line_start),
    });
    go("/tasks/" + encodeURIComponent(jobId) + "?" + query.toString());
  };
  return <Card className="section-gap" size="small" title="为什么列为高可信">
    <Space wrap><Tag color="gold">高可信候选</Tag><Tag color="orange">待人工复核</Tag></Space>
    <Paragraph className="section-gap">{explanation}</Paragraph>
    {signal.summary && <Alert className="section-gap" type="info" showIcon
      message="智能研判摘要"
      description={<>
        <Paragraph style={{ marginBottom: 4 }}>{signal.summary}</Paragraph>
        <Text type="secondary">摘要由系统根据模型结构化研判生成；引用存在性经过校验，语义是否支持结论仍需人工判断。</Text>
      </>} />}
    {locations.length > 0 ? <div className="section-gap">
      <Text strong>固定源码证据位置</Text>
      <div>{locations.map((location: any, index: number) =>
        <Button key={location.file + ":" + location.line_start + ":" + location.line_end + ":" + index}
          type="link" size="small" onClick={() => openEvidence(location)}>
          {location.file}:{location.line_start}{location.line_end !== location.line_start ? "–" + location.line_end : ""}
        </Button>)}</div>
      {signal.evidence_locations_truncated_count > 0 && <Text type="secondary">
        另有 {signal.evidence_locations_truncated_count} 处位置未展开
      </Text>}
    </div> : <Text type="secondary">该分层来自人工 R0 复核；可在下方逐项检查固定源码和证据义务。</Text>}
    <Text type="secondary">高可信表示证据优先级较高，不代表漏洞已确认。</Text>
  </Card>;
}
export default function JobDetail({ id, initialTab = "findings", candidateId, sourceFile, sourceLine, health }: { id: string; initialTab?: string; candidateId?: string; sourceFile?: string; sourceLine?: number; health?: any }) {
  const [job, setJob] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [triageSummary, setTriageSummary] = useState<any>(null);
  const [riskSummary, setRiskSummary] = useState<any>(null);
  const [selectedRisk, setSelectedRisk] = useState<any>(null);
  const [coverageSummary, setCoverageSummary] = useState<any>(null);
  const [reportSnapshots, setReportSnapshots] = useState<any[]>([]);
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
  const [batchOpen, setBatchOpen] = useState(false);
  const [batchBusy, setBatchBusy] = useState(false);
  const [snapshotBusy, setSnapshotBusy] = useState(false);
  const [retryBusyId, setRetryBusyId] = useState<string | null>(null);
  const [batchPreview, setBatchPreview] = useState<any>(null);
  const [batchDisclosureOpened, setBatchDisclosureOpened] = useState<string[]>([]);
  const [batchSubmissionApproved, setBatchSubmissionApproved] = useState(false);
  const [batchCandidateIds, setBatchCandidateIds] = useState<string[]>([]);
  const [batchMode, setBatchMode] = useState<"single_shot" | "tool_agent">("single_shot");
  const batchPreviewCandidateIds = (batchPreview?.candidates || []).map((item: any) => String(item.candidate_id));
  const batchPreviewMatchesSelection = disclosureSelectionMatches(batchCandidateIds, batchPreviewCandidateIds);
  const batchDisclosureReviewed = batchPreviewMatchesSelection && disclosureReviewed(batchDisclosureOpened, batchCandidateIds);
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
        const triageRequest = api("/scans/" + id + "/triage");
        if (j.report_sha256) {
          const [r, triage, risks, coverage] = await Promise.all([
            api("/scans/" + id + "/report"),
            triageRequest,
            api("/scans/" + id + "/risks?limit=100"),
            api("/scans/" + id + "/coverage"),
          ]);
          if (live) {
            setReport(r); setTriageSummary(triage);
            setRiskSummary(risks); setCoverageSummary(coverage);
          }
        } else {
          const triage = await triageRequest;
          if (live) {
            setReport(null); setTriageSummary(triage);
            setRiskSummary(null); setCoverageSummary(null);
          }
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
  useEffect(() => {
    let live = true;
    if (report?.snapshot_sha256) {
      api("/scans/" + id + "/reports/snapshots")
        .then((result) => { if (live) setReportSnapshots(result.items || []); })
        .catch((e) => { if (live) setError(String(e)); });
    } else {
      setReportSnapshots([]);
    }
    return () => { live = false; };
  }, [id, report?.snapshot_sha256]);
  async function createCombinedReportSnapshot() {
    setSnapshotBusy(true);
    try {
      const saved = await api("/scans/" + id + "/reports/snapshots", {});
      const result = await api("/scans/" + id + "/reports/snapshots");
      setReportSnapshots(result.items || []);
      message.success("不可变审计报告快照已保存：" + String(saved.id).slice(0, 12));
    } catch (e) {
      setError(String(e));
    } finally {
      setSnapshotBusy(false);
    }
  }
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
    if (!report || initialTab !== "source" || !sourceFile) return;
    const allowed = report._workbench?.source_inventory?.some((item: any) => item.file === sourceFile);
    if (!allowed) {
      setError("所引用的文件不属于本次扫描范围");
      return;
    }
    let live = true;
    api("/scans/" + id + "/source?file=" + encodeURIComponent(sourceFile))
      .then((value) => { if (live) setSource(value); })
      .catch((e) => { if (live) setError(String(e)); });
    return () => { live = false; };
  }, [id, report?.snapshot_sha256, initialTab, sourceFile]);
  useEffect(() => {
    if (!detail?.id) {
      setSelectedRisk(null);
      return;
    }
    let live = true;
    setSelectedRisk(null);
    api("/scans/" + encodeURIComponent(id) + "/risks?candidate_id="
      + encodeURIComponent(detail.id) + "&limit=1")
      .then((value) => {
        if (live) setSelectedRisk((value.items || []).find((item: any) => item.candidate_id === detail.id) || null);
      })
      .catch(() => { if (live) setSelectedRisk(null); });
    return () => { live = false; };
  }, [id, detail?.id]);
  useEffect(() => {
    if (job && candidateId && candidateAutoOpened.current !== candidateId) {
      candidateAutoOpened.current = candidateId;
      void open({ id: candidateId });
    }
  }, [job?.id, candidateId]);
  async function previewAgentBatch() {
    const candidateIds = selected.map(String);
    if (!candidateIds.length || candidateIds.length > 5) return;
    setBatchCandidateIds(candidateIds);
    setBatchPreview(null);
    setBatchDisclosureOpened([]);
    setBatchSubmissionApproved(false);
    setBatchOpen(true);
    setBatchBusy(true);
    try {
      const preview = await api("/operations/agent-investigations/batch/preview", {
        job_id: id, candidate_ids: candidateIds, mode: batchMode,
      });
      setBatchPreview(preview);
    } catch (e) {
      message.error(String(e));
      setBatchOpen(false);
    } finally {
      setBatchBusy(false);
    }
  }
  async function enqueueAgentBatch() {
    if (!batchPreview || !batchDisclosureReviewed || !batchSubmissionApproved) return;
    setBatchBusy(true);
    try {
      const result = await api("/operations/agent-investigations/batch", {
        job_id: id, candidate_ids: batchCandidateIds, mode: batchMode,
        source_submission_approved: true, consent_sha256: batchPreview.consent_sha256,
        consent_nonce: batchPreview.consent_nonce,
      });
      setBatchOpen(false); setBatchDisclosureOpened([]); setBatchSubmissionApproved(false);
      setSelected([]);
      message.success("已创建 " + result.created_count + " 个独立模型辅助研判任务");
      if (result.operations?.[0]?.id) go("/tasks/operations/" + result.operations[0].id);
    } catch (e) {
      message.error(String(e));
    } finally {
      setBatchBusy(false);
    }
  }
  async function action(name: string) {
    try {
      const j = await api("/scans/" + id + "/" + name, {});
      if (name === "retry") go("/tasks/" + j.id);
      else setJob(j);
    } catch (e) {
      setError(String(e));
    }
  }
  async function cancelTaskTriage() {
    setBatchBusy(true);
    try {
      const result = await api("/scans/" + id + "/triage/cancel", {});
      setTriageSummary(result);
      message.info("已停止本审计后续模型研判；静态扫描与已有证据仍保留。");
    } catch (e) {
      message.error(String(e));
    } finally {
      setBatchBusy(false);
    }
  }
  async function revokeTaskTriageAuthorization() {
    const consent = triageSummary?.authorization?.consent_sha256;
    if (!consent || triageSummary?.authorization?.revoked) return;
    setBatchBusy(true);
    try {
      const result = await api("/scans/" + id + "/triage/revoke", { consent_sha256: consent });
      setTriageSummary(result);
      message.info("已撤销本次任务级模型外发授权；关联的自动研判任务已取消或正在停止。静态报告仍保留。");
    } catch (e) {
      message.error(String(e));
    } finally {
      setBatchBusy(false);
    }
  }
  async function retryAgentOperation(operationId: string) {
    setRetryBusyId(operationId);
    try {
      const retried = await api("/operations/" + operationId + "/retry", {});
      message.warning("已创建新的调查任务。它会再次调用模型，可能产生新的费用；原任务和审计记录保留。");
      go("/tasks/operations/" + retried.id);
    } catch (e) {
      message.error(String(e));
    } finally {
      setRetryBusyId(null);
    }
  }
  if (!job) return error ? <Alert type="error" showIcon message={error} /> : <Spin />;
  const parse = report?.source_parsing.parsing_status || {};
  const coverage = report
    ? Object.entries(report.detector_coverage.detectors).map(
        ([detector, c]) => ({ detector, ...(c as any) }),
      )
    : [];
  const detailCoverage = detail
    ? coverage.find((row: any) => row.detector === detail.detector_id)
    : null;
  const agentProvider = health?.capabilities?.agent_provider;
  const auditMode = job.spec.audit_mode || "legacy";
  const triageProgress = triageSummary?.triage_progress || {};
  const triageAuthorization = triageSummary?.authorization || {};
  const triageCanCancel = (Number(triageProgress.pending_count || 0) > 0
    || Number(triageProgress.r2_waiting_count || 0) > 0
    || (auditMode === "standard_review" && triageAuthorization.authorized
      && !triageAuthorization.revoked && !terminal.has(job.status)));
  const auditCanCancel = !terminal.has(job.status) || triageCanCancel;
  const triageLabels: Record<string, string> = {
    not_started: "尚未开始", waiting_for_scan: "等待静态扫描报告",
    stopping: "正在停止", cancelled: "已停止",
    waiting_for_authorization: "等待本次任务外发授权",
    in_progress: "处理中", completed: "已完成", partially_completed: "部分完成",
    queued: "排队中", running: "处理中", completed_with_limitations: "完成但有限制",
    blocked: "受阻", blocked_authorization_changed: "授权或计划已变化",
    no_eligible_candidates: "没有适合自动研判的候选",
    stopped: "授权已撤销", failed: "失败", timed_out: "超时", interrupted: "中断",
  };
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
            {auditCanCancel ? (
              <Button danger onClick={() => void action("cancel")}>
                停止扫描和调查
              </Button>
            ) : (
              <Button onClick={() => void action("retry")}>
                重试扫描
              </Button>
            )}
            {triageCanCancel && <Button danger loading={batchBusy}
              onClick={() => void cancelTaskTriage()}>
              停止 AI 调查
            </Button>}
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
      <AuditPlanView plan={job.spec.audit_plan} auditMode={job.spec.audit_mode} />
      {job && <Card className="section-gap" title="审计阶段进度">
        <Row gutter={18}>
          <Col xs={24} md={8}><Descriptions size="small" column={1} title="静态扫描">
            <Descriptions.Item label="状态"><State value={triageSummary?.scan_status || job.status} /></Descriptions.Item>
            <Descriptions.Item label="阶段">{scanStageLabel(triageSummary?.scan_progress?.stage || job.stage)}</Descriptions.Item>
          </Descriptions></Col>
          <Col xs={24} md={8}><Descriptions size="small" column={1} title="报告">
            <Descriptions.Item label="状态">{taskReportStatusLabel(triageSummary, job)}</Descriptions.Item>
            <Descriptions.Item label="报告 SHA-256"><Hash value={job.report_sha256} /></Descriptions.Item>
          </Descriptions></Col>
          <Col xs={24} md={8}><Descriptions size="small" column={1} title="智能研判">
            <Descriptions.Item label="状态">{taskTriageStatusLabel(triageSummary, job)}</Descriptions.Item>
            <Descriptions.Item label="完成 / 有限制 / 失败">{triageSummary?.triage_progress?.completed_count ?? 0} / {triageSummary?.triage_progress?.completed_with_limitations_count ?? 0} / {triageSummary?.triage_progress?.failed_count ?? 0}</Descriptions.Item>
            <Descriptions.Item label="报告候选 / 授权 / 已入队">{triageSummary?.triage_progress?.candidate_count ?? "扫描后统计"} / {triageSummary?.triage_progress?.authorized_candidate_count ?? 0} / {triageSummary?.triage_progress?.queued_count ?? 0}</Descriptions.Item>
            <Descriptions.Item label="处理中 / 未研判">{triageSummary?.triage_progress?.pending_count ?? 0} / {triageSummary?.triage_progress?.not_triaged_count ?? riskSummary?.triage_counts?.not_triaged ?? 0}</Descriptions.Item>
          </Descriptions></Col>
        </Row>
        <Text type="secondary">未授权、超过每端点候选上限、超过受控队列容量或失败的候选仍保持未研判，不会被计为低风险；需缩小范围并重新预览授权。</Text>
      </Card>}
      {report && <>
        <Row gutter={18} className="section-gap">
          {[
            { title: "纳入源码文件", value: report.scope.selected_source_files ?? "未知" },
            { title: "原始候选观测", value: report.diagnostic_count ?? "未知" },
            { title: "候选分组", value: clusterTotal },
            { title: "人工确认漏洞", value: report.validated_vulnerability ?? "unknown" },
          ].map((x) => (
            <Col xs={12} sm={12} xl={6} key={x.title}>
              <Card><Statistic {...x} /></Card>
            </Col>
          ))}
        </Row>
        <Card className="section-gap" title="证据风险分层">
          <Alert type="info" showIcon
            message="风险层级由扫描源码、静态证据和人工逐项复核决定"
            description="模型自报置信度或引文存在性不会提升风险层级。高可信风险仍是待复核候选；未研判和未知不代表安全。" />
          <Row gutter={18} className="section-gap">{[
            { title: "高可信候选", value: riskSummary?.counts?.high_confidence_candidate ?? "未知" },
            { title: "待进一步验证", value: riskSummary?.counts?.further_validation ?? "未知" },
            { title: "低优先级线索", value: riskSummary?.counts?.low_priority_manual ?? "未知" },
            { title: "源码版本未核对", value: riskSummary?.counts?.unknown_source_binding ?? "未知" },
            { title: "未研判候选", value: riskSummary?.triage_counts?.not_triaged ?? "未知" },
            { title: "人工验证漏洞", value: riskSummary?.validated_vulnerability ?? "未知" },
          ].map((x) => <Col xs={12} sm={8} xl={4} key={x.title}><Card size="small"><Statistic {...x} /></Card></Col>)}</Row>
          <Table size="small" rowKey="candidate_id" pagination={false}
            dataSource={(riskSummary?.items || []).slice(0, 20)}
            columns={[
              { title: "可信程度", render: (_: unknown, row: any) =>
                  <Tag color={candidateConfidenceColor(row.risk_tier)}>{candidateConfidenceLabel(row.risk_tier)}</Tag> },
              { title: "危害等级（初判）", render: (_: unknown, row: any) =>
                  <Tag color={candidateSeverityColor(row.severity)}>{candidateSeverityLabel(row.severity)}</Tag> },
              { title: "候选", dataIndex: "candidate_id", render: (value: string) => <Text code>{String(value).slice(0, 12)}</Text> },
              { title: "规则", dataIndex: "rule_id" },
              { title: "位置", render: (_: unknown, row: any) => row.file + ":" + row.line },
              { title: "研判", render: (_: unknown, row: any) => triageStateLabel(row.triage?.state) },
              { title: "下一步", render: (_: unknown, row: any) => riskReasonsLabel(row.reasons) },
            ]} locale={{ emptyText: "当前扫描报告没有原始候选；这不代表仓库不存在漏洞。" }} />
          {(riskSummary?.total || 0) > 20 && <Text type="secondary">按证据优先级显示前 20 项；完整候选可在“候选与复核”中检索。</Text>}
        </Card>
        <Card className="section-gap" title="源码解析覆盖（文件数）">
          <Row gutter={18}>{[
            { title: "完整解析", value: parse.complete ?? "未知" },
            { title: "部分解析", value: parse.partial ?? "未知" },
            { title: "解析失败", value: parse.failed ?? "未知" },
            { title: "未运行解析", value: parse.not_run ?? "未知" },
          ].map((x) => <Col xs={12} sm={6} key={x.title}><Statistic {...x} /></Col>)}</Row>
          <Text type="secondary">覆盖数字与候选数量分开统计；部分、失败和未解析范围都保持未知。</Text>
        </Card>
        <Card className="section-gap" title="模型辅助研判进度">
          {auditMode === "standard_review" ? <>
            <Alert type="info" showIcon
              message={"标准研判 · " + (triageLabels[triageSummary?.state] || "状态未知")}
              description={triageSummary?.limitation || "静态扫描报告与候选已保存。未授权的任务不会发送源码；模型输出不会修改候选或确认状态。"} />
            {triageSummary?.state === "cancelled" && <Alert className="section-gap" type="warning" showIcon
              message="本审计的后续模型研判已停止"
              description="静态扫描和已保存结果保留；其他审计不受影响。若要继续，可从候选详情重新发起 AI 调查，并先检查本次发送内容。" />}
            {triageSummary?.authorization?.authorized && <>
              <Descriptions className="section-gap" size="small" column={1} bordered>
                <Descriptions.Item label="任务级授权">{triageSummary.authorization.revoked ? "已撤销" : "有效"}</Descriptions.Item>
                <Descriptions.Item label="模型目的地">{triageSummary.authorization.provider?.endpoint_host} · {triageSummary.authorization.provider?.model}</Descriptions.Item>
                <Descriptions.Item label="自动研判候选授权">每端点最多 {triageSummary.authorization.candidate_limit} 条（保护上限 10,000）；平台不设累计 Token、费用、调用次数或总时长上限</Descriptions.Item>
                {triageSummary.authorization.conditional_r2_candidate_limit > 0 && <Descriptions.Item label="深入追查候选授权">最多 {triageSummary.authorization.conditional_r2_candidate_limit} 条高/严重候选；只在源码义务仍未解决时追加</Descriptions.Item>}
                <Descriptions.Item label="工作台费用预算">{triageSummary.authorization.platform_cost_budget_enforced
                  ? "USD " + triageSummary.authorization.cost_budget.maximum_usd
                    + "（当前费率卡最坏估算 USD " + triageSummary.authorization.cost_budget.estimated_maximum_usd + "）"
                  : "未设置可执行的费用预算"}</Descriptions.Item>
                <Descriptions.Item label="Provider 账单">实际账单金额无法由本平台硬限制</Descriptions.Item>
              </Descriptions>
              {!triageSummary.authorization.revoked && <Button className="section-gap" danger loading={batchBusy}
                onClick={() => void revokeTaskTriageAuthorization()}>撤销本次任务级模型外发授权</Button>}
            </>}
            {triageSummary?.batches?.length > 0 && <Table className="section-gap" size="small" rowKey="id"
              pagination={false} dataSource={triageSummary.batches}
              columns={[
                { title: "批次", dataIndex: "id", render: (value: string) => <Text code>{String(value).slice(0, 12)}</Text> },
                { title: "状态", dataIndex: "state", render: (value: string) => triageLabels[value] || value },
                { title: "候选 / 授权 / 入队 / 未研判", render: (_: unknown, row: any) => [row.candidate_count, row.authorized_candidate_count, row.queued_count, row.not_triaged_count].join(" / ") },
                { title: "已创建任务", dataIndex: "operation_ids", render: (ids: string[]) => ids?.length || 0 },
                { title: "补充核查", render: (_: unknown, row: any) => {
                  const followup = row.conditional_r2 || {};
                  const labels: Record<string, string> = {
                    not_requested: "未启用", awaiting_r1: "等待条件复核", queued: "已排队",
                    budget_limited: "候选授权数已用尽", not_needed: "当前无需追加",
                    candidate_limit_reached: "超过深入追查授权数", blocked_authorization_changed: "授权变化，未追加",
                  };
                  return (labels[followup.state] || followup.state || "未启用")
                    + (followup.operation_ids?.length ? " · " + followup.operation_ids.length + " 项" : "");
                } },
              ]} />}
            {!agentProvider?.configured && <Alert className="section-gap" type="warning" showIcon
              message="模型服务未配置"
              description={<>静态扫描结果可继续复核。配置服务后才能生成模型外发预览。<Button type="link" onClick={() => go("/settings/agent")}>前往设置</Button></>} />}
            {triageSummary?.items?.some((item: any) => item.retry_available) && <Alert className="section-gap" type="warning" showIcon
              message="部分智能调查在产生结果前中断，可显式重试"
              description="重试会创建新任务，沿用原扫描版本的源码、扫描报告和外发授权；模型请求可能再次计费。旧任务记录不会覆盖。" />}
            {triageSummary?.items?.length > 0 && <Table className="section-gap" size="small" rowKey="id" pagination={false}
              dataSource={triageSummary.items}
              columns={[
                { title: "候选", dataIndex: "candidate_id", render: (value: string) => <Text code>{String(value || "").slice(0, 12)}</Text> },
                { title: "方式", dataIndex: "mode", render: (value: string) => value === "single_shot" ? "AI 分析（单次）" : "AI 追查源码（只读）" },
                { title: "状态", dataIndex: "status", render: (value: string) => <State value={value} /> },
                { title: "模型研判", dataIndex: "assessment", render: (value: string) => value || "尚无结果（未知）" },
                { title: "调查边界", render: (_: unknown, row: any) => row.investigation_limitations?.length ? <Text type="warning">{row.investigation_limitations.join("；")}</Text> : row.result_sha256 ? "未记录额外单次限制" : "尚无结果；候选保持未知" },
                { title: "任务", dataIndex: "id", render: (value: string, row: any) => <Space><Button size="small" onClick={() => go("/tasks/operations/" + value)}>查看</Button>{row.retry_available && <Button size="small" loading={retryBusyId === value} onClick={() => void retryAgentOperation(value)}>重试</Button>}</Space> },
              ]} />}
          </> : auditMode === "static_only" ? <Alert type="info" showIcon
            message="本任务按“仅静态扫描”创建"
            description="静态候选和覆盖报告已保存。若之后决定使用模型，可从候选详情发起 AI 调查，并先检查发送内容。" />
            : <Alert type="info" showIcon message="历史任务未记录研判方式"
              description="此任务按已有静态报告展示；后续模型调用仍需单独预览和授权。" />}
        </Card>
      </>}
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
                    <Select aria-label="模型研判方式" value={batchMode} style={{ minWidth: 220 }}
                      onChange={(value) => setBatchMode(value)}
                      options={[
                        { value: "single_shot", label: "AI 分析（单次）" },
                        { value: "tool_agent", label: "AI 追查源码（只读）" },
                      ]} />
                    <Button
                      type="primary"
                      disabled={!selected.length || selected.length > 5 || !job?.report_sha256 || !agentProvider?.configured}
                      onClick={() => void previewAgentBatch()}
                    >
                      查看发送内容（{selected.length}/5）
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
                        title: "危害等级（初判）",
                        render: (_: any, f: any) => (
                          <Tag color={candidateSeverityColor(f.risk_presentation?.severity)}>
                            {candidateSeverityLabel(f.risk_presentation?.severity)}
                          </Tag>
                        ),
                      },
                      {
                        title: "静态检查状态",
                        render: (_: any, f: any) => (
                          <Tag color={f.evidence.analysis_status === "partial" ? "warning" : f.evidence.analysis_status === "failed" ? "error" : "default"}>
                            {analysisStatusLabel(f.evidence.analysis_status || "unknown")}
                          </Tag>
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
                          <Space wrap>
                            <Button onClick={() => void open(f)}>查看证据</Button>
                            <ProgressiveQuickScreenAction jobId={id} candidateId={f.id}
                              enabled={Boolean(job?.report_sha256 && agentProvider?.configured)} />
                          </Space>
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
                            <Text code>{groupingSymbolLabel(group.symbol)}</Text>
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
                      { title: "分组依据", dataIndex: "grouping_basis", render: groupingBasisLabel },
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
                    message={coverageSummaryLabel(
                      parse,
                      report.files_in_scope_without_a_claiming_detector.length,
                    )}
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
              label: "本次扫描源码",
              children: report ? (
                <>
                  <Select
                    showSearch
                    value={source?.file}
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
                  {source && <CodeView source={source} line={sourceLine || 1} />}
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
                          <Text strong>{scanStageLabel(e.stage)}</Text>
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
                    静态原始报告独立保存；下面的合并报告冻结当时的风险分层、覆盖状态、研判进度和人工验证门结果。后续复核变化会生成新快照，不覆盖旧版本。
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
                    <Button type="primary" loading={snapshotBusy}
                      onClick={() => void createCombinedReportSnapshot()}>
                      生成不可变合并报告快照
                    </Button>
                  </Space>
                  {reportSnapshots.length > 0 && <Table className="section-gap" size="small"
                    rowKey="id" pagination={false} dataSource={reportSnapshots}
                    columns={[
                      { title: "快照", dataIndex: "id", render: (value: string) => <Text code>{String(value).slice(0, 12)}</Text> },
                      { title: "生成时间", dataIndex: "created_at", render: (value: string) => new Date(value).toLocaleString() },
                      { title: "内容 SHA-256", dataIndex: "content_sha256", render: (value: string) => <Hash value={value} /> },
                      { title: "下载", render: (_: unknown, row: any) => <Space>
                        <Button size="small" href={"/api/v1/scans/" + id + "/reports/snapshots/" + row.id + "/json"}>JSON</Button>
                        <Button size="small" href={"/api/v1/scans/" + id + "/reports/snapshots/" + row.id + "/markdown"}>Markdown</Button>
                      </Space> },
                    ]} />}
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
                      <li key={i}>{reportLimitationLabel(x)}</li>
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
              message={<Space wrap>
                <Tag color="gold">规则候选 · 尚未确认</Tag>
                <Text code>{detail.rule_id}</Text>
                {detail.candidate_cwe && <Tag>{detail.candidate_cwe}</Tag>}
                <Tag color={candidateSeverityColor(detail.risk_presentation?.severity)}>
                  {candidateSeverityLabel(detail.risk_presentation?.severity)} · 初判
                </Tag>
              </Space>}
              description={<div>
                <Text type="secondary">检测器原始说明：用于定位候选线索，不代表漏洞已确认。</Text>
                <div style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginTop: 8 }}>
                  {detail.message || "报告未提供规则说明。"}
                </div>
              </div>}
            />
            {detail.risk_assessment && <Card
              className="section-gap"
              title="公开组件风险依据与修复验证"
              extra={<Tag color="orange">组件来源等级：{detail.risk_assessment.severity_label}（{detail.risk_assessment.source_severity}）</Tag>}
            >
              <Descriptions size="small" column={2} bordered>
                <Descriptions.Item label="风险身份">
                  {detail.risk_assessment.identifier} · {(detail.risk_assessment.cwe || []).join(" / ")}
                </Descriptions.Item>
                {detail.risk_assessment.mapping_basis && <Descriptions.Item label="CVE 映射依据" span={2}>
                  {detail.risk_assessment.mapping_basis}
                </Descriptions.Item>}
                <Descriptions.Item label="静态扫描严重度 / 置信度">
                  {detail.severity || "unassessed"} / {detail.confidence || "unassessed"}（候选仍未确认）
                </Descriptions.Item>
                <Descriptions.Item label="CVSS">
                  {detail.risk_assessment.cvss?.version} {detail.risk_assessment.cvss?.score} ({detail.risk_assessment.severity})
                  <div><Text type="secondary">{detail.risk_assessment.cvss?.vector}</Text></div>
                </Descriptions.Item>
                <Descriptions.Item label="等级映射规则" span={2}>
                  {detail.risk_assessment.severity_mapping}
                </Descriptions.Item>
                <Descriptions.Item label="影响版本 / 修复版本" span={2}>
                  {detail.risk_assessment.affected_range} → {(detail.risk_assessment.fixed_versions || []).join(", ")}
                </Descriptions.Item>
                <Descriptions.Item label="固定源码绑定" span={2}>
                  {job.spec?.repository} @ {job.spec?.commit}
                  <div><Text type="secondary">命中文件 SHA-256：{detail.source_sha256 || "unknown"}</Text></div>
                </Descriptions.Item>
                {detail.risk_assessment.source_location && <Descriptions.Item label="上游源码位置" span={2}>
                  {detail.risk_assessment.source_location.file}:{detail.risk_assessment.source_location.lines} · {detail.risk_assessment.source_location.symbol}
                  <div><Text type="secondary">易受影响提交：{detail.risk_assessment.source_location.vulnerable_commit}；修复提交：{detail.risk_assessment.source_location.fixed_commit}</Text></div>
                  <a href={detail.risk_assessment.source_location.url} target="_blank" rel="noreferrer">固定版本源码锚点</a>
                </Descriptions.Item>}
                <Descriptions.Item label="扫描覆盖限制" span={2}>
                  <div>检测器状态：{detailCoverage?.status || "unknown"}；检查文件 {detailCoverage?.applicable_files ?? "unknown"}；完整 {detailCoverage?.analyzed_files?.length ?? "unknown"}；部分 {detailCoverage?.partially_inspected_files?.length ?? "unknown"}；未分析 {detailCoverage?.not_analyzed_files?.length ?? "unknown"}；失败 {detailCoverage?.failed_files?.length ?? "unknown"}。</div>
                  <ul>{(detailCoverage?.limitations || []).map((item: string, index: number) => <li key={index}>{item}</li>)}</ul>
                  <Text type="secondary">partial / blocked 表示未完整覆盖，不代表安全或漏洞确认。</Text>
                </Descriptions.Item>
                <Descriptions.Item label="触发条件" span={2}>
                  {detail.risk_assessment.component_condition}
                </Descriptions.Item>
                <Descriptions.Item label="公开来源" span={2}>
                  <a href={detail.risk_assessment.source} target="_blank" rel="noreferrer">
                    {detail.risk_assessment.source_name}
                  </a>
                </Descriptions.Item>
                <Descriptions.Item label="组件 PoC 入口" span={2}>
                  {detail.risk_assessment.poc?.entrypoint}
                  <div><Text type="secondary">PoC / 修复报告：{detail.risk_assessment.poc?.record}（SHA-256 {detail.risk_assessment.poc?.record_sha256}）</Text></div>
                  <div><Text type="secondary">重放程序：{detail.risk_assessment.poc?.replay}（SHA-256 {detail.risk_assessment.poc?.replay_sha256}）</Text></div>
                  {detail.risk_assessment.poc?.raw_output && <div><Text type="secondary">ASan 原始 stderr：{detail.risk_assessment.poc.raw_output}（SHA-256 {detail.risk_assessment.poc.raw_output_sha256}；{detail.risk_assessment.poc.raw_output_encoding}）</Text></div>}
                </Descriptions.Item>
                <Descriptions.Item label="修复建议 / 上游补丁" span={2}>
                  {detail.risk_assessment.remediation} <a href={detail.risk_assessment.upstream_fix} target="_blank" rel="noreferrer">上游修复提交</a>
                </Descriptions.Item>
                <Descriptions.Item label="修复后组件重验" span={2}>
                  {detail.risk_assessment.component_retest?.fixed_source}；受影响 PoC：{detail.risk_assessment.component_retest?.affected_poc}；修复后：{detail.risk_assessment.component_retest?.fixed_poc}；安全顺序控制：{detail.risk_assessment.component_retest?.safe_order_control}。
                  <div><Text type="secondary">{detail.risk_assessment.component_retest?.scope}</Text></div>
                </Descriptions.Item>
                <Descriptions.Item label="OpenHarmony 产品适用性" span={2}>
                  <Tag>未知</Tag> {detail.risk_assessment.product_evidence}
                </Descriptions.Item>
              </Descriptions>
            </Card>}
            <Descriptions
              className="section-gap"
              size="small"
              bordered
              column={{ xs: 1, sm: 2, lg: 3 }}
              title="扫描来源绑定"
            >
              <Descriptions.Item label="仓库 / 提交">
                <Text code copyable>{job.spec?.repository || report?.repository || "unknown"}</Text>
                <br />
                <Text code copyable>{job.spec?.commit || report?.commit || "unknown"}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="源码 SHA-256">
                <Text code copyable>{detail.source?.sha256 || detail.source_sha256 || "unavailable"}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Git blob">
                <Text code copyable>{detail.source?.blob || detail.source_blob_oid || "unavailable"}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Detector / 版本">
                <Text code>{detail.detector_id || "unknown"}</Text> · {detail.detector_version || "unknown"}
              </Descriptions.Item>
              <Descriptions.Item label="规则版本">
                <Text code>{detail.rule_id || "unknown"}</Text> · {detail.rule_version || "unknown"}
              </Descriptions.Item>
              <Descriptions.Item label="扫描快照 SHA-256">
                <Text code copyable>{report?.snapshot_sha256 || "unavailable"}</Text>
              </Descriptions.Item>
            </Descriptions>

            <HighConfidenceCandidateReason
              jobId={id}
              risk={selectedRisk?.candidate_id === detail.id ? selectedRisk
                : (riskSummary?.items || []).find((item: any) => item.candidate_id === detail.id)}
            />
            {detail.source ? <>
              <CandidateActions job={job} candidate={detail} />
              <CodeView source={detail.source} line={detail.line} />
              <SourceEvidence
                key={detail.id}
                jobId={id}
                detail={detail}
                reload={() => open(detail, { select: false, resetReview: false })}
              />
            </> : <Alert
              className="section-gap"
              type="warning"
              showIcon
              message="本次扫描源码暂不可读"
              description={<>{detail.source_limitation || "候选和报告仍保留；恢复本次扫描源码访问前，复核结论保持未知。"} <Button type="link" onClick={() => go("/settings/sources")}>检查源码目录</Button></>}
            />}
            <Row gutter={20} className="section-gap">
              <Col span={12}>
                <Card title="证据义务">
                  <Text type="secondary">以下是规则生成的核查提示，需结合本次扫描源码逐项验证；当前标签不是漏洞结论。</Text>
                  {(detail.evidence.obligations || []).map(
                    (o: any, i: number) => (
                      <div className="obligation" key={i}>
                        <Space wrap>
                          <Text strong>{obligationKindLabel(o.kind)}</Text>
                          <Tag color={o.status === "unknown" ? "default" : "blue"}>
                            {obligationStatusLabel(o.status)}
                          </Tag>
                        </Space>
                        <div>{obligationDescriptionLabel(o.description || o.detail)}</div>
                      </div>
                    ),
                  )}
                  <Collapse
                    className="section-gap"
                    items={[{
                      key: "raw-evidence",
                      label: "查看原始证据字段（JSON）",
                      children: <pre className="raw">{JSON.stringify(detail.evidence, null, 2)}</pre>,
                    }]}
                  />
                </Card>
              </Col>
              <Col span={12}>
                <Card title="追加人工复核">
                  {detail.source ? <Form
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
                  </Form> : <Alert
                    type="info"
                    showIcon
                    message="暂不能追加源码复核"
                    description="请先恢复此任务本次扫描源码的授权读取，再打开候选证据并记录引用。"
                  />}
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
        title="模型辅助研判外发预览"
        open={batchOpen}
        width={900}
        confirmLoading={batchBusy}
        okText="确认并开始 AI 调查"
        cancelText="取消"
        okButtonProps={{ disabled: !batchPreview || !batchDisclosureReviewed || !batchSubmissionApproved }}
        onOk={() => void enqueueAgentBatch()}
        onCancel={() => { setBatchOpen(false); setBatchDisclosureOpened([]); setBatchSubmissionApproved(false); }}
      >
        {batchBusy && !batchPreview ? <Spin /> : batchPreview ? <>
          <Alert type="warning" showIcon message={"确认后将为每条候选分别创建一个" + (batchMode === "single_shot" ? "单次模型研判" : "连续工具增强调查") + "任务；下列源码上下文会发送给所示模型端点。模型结论仍是候选，需人工审核。"} />
          <Descriptions className="section-gap" bordered size="small" column={2}>
            <Descriptions.Item label="模型端点">{batchPreview.provider?.endpoint_host || "未显示"}</Descriptions.Item>
            <Descriptions.Item label="候选数">{batchPreview.candidate_count}</Descriptions.Item>
            <Descriptions.Item label="请求次数语义">{batchMode === "single_shot" ? "每候选恰好 1 次 Provider 请求" : "无平台累计模型调用上限，直到终止条件"}</Descriptions.Item>
            <Descriptions.Item label="每请求输出上限">{batchPreview.aggregate_budget?.max_output_tokens_per_provider_request ?? "未知"} tokens</Descriptions.Item>
            <Descriptions.Item label="单次 Provider 请求超时">{batchPreview.aggregate_budget?.provider_request_timeout_seconds ?? 45} 秒</Descriptions.Item>
            <Descriptions.Item label="累计 Token / 费用 / 总时长">{batchMode === "single_shot" ? "单次请求；按所选模式限制为一次" : "平台不设累计上限；Provider 账户计费与额度适用"}</Descriptions.Item>
            <Descriptions.Item label="整批预算费用最高估算（非硬上限）">{batchPreview.aggregate_budget_cost_estimate
              ? <Space wrap><Text>≤ USD {batchPreview.aggregate_budget_cost_estimate.maximum_usd}{batchPreview.aggregate_budget_cost_estimate.maximum_cny ? " / CNY " + batchPreview.aggregate_budget_cost_estimate.maximum_cny : ""}；{batchPreview.aggregate_budget_cost_estimate.candidate_or_arm_count} 个任务；{batchPreview.aggregate_budget_cost_estimate.maximum_cny ? "USD/CNY 为独立官方价目参考；" : ""}按{batchPreview.aggregate_budget_cost_estimate.basis === "realtime_payg_all_input_uncached" ? "实时按量费率、输入全部按缓存未命中" : "峰值费率、输入全部按缓存未命中"}</Text><a href={batchPreview.aggregate_budget_cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
              : "费用未知（该 Provider / 模型没有匹配的已知费率）"}</Descriptions.Item>
          </Descriptions>
          <Text type="secondary">预览指纹：{batchPreview.consent_sha256}</Text>
          {batchPreview.candidates?.map((item: any) => <Card key={item.candidate_id} size="small" className="section-gap" title={item.file + ":" + (item.line ?? "?")}>
            <Text code>{item.candidate_id}</Text>
            <Text type="secondary">源码 SHA-256：{item.preview?.binding?.source_sha256}；UTF-8 字节：{item.preview?.initial_context_utf8_bytes}；脱敏类别：{(item.preview?.sensitive_redactions || []).join(", ") || "无"}</Text>
            <Collapse activeKey={batchDisclosureOpened.includes(String(item.candidate_id)) ? [String(item.candidate_id)] : []}
              onChange={(keys) => {
                const opened = Array.isArray(keys) ? keys.map(String) : [String(keys)];
                const next = batchDisclosureOpened.filter((key) => key !== String(item.candidate_id));
                if (opened.includes(String(item.candidate_id))) next.push(String(item.candidate_id));
                setBatchDisclosureOpened(next);
                if (!disclosureReviewed(next, batchCandidateIds)) setBatchSubmissionApproved(false);
              }}
              items={[{ key: String(item.candidate_id), label: "展开该候选实际发送的完整上下文与工具范围", children: <>
                <Text strong>发送给模型的完整初始上下文（JSON）</Text>
                <pre className="raw">{JSON.stringify(item.preview?.initial_context || {}, null, 2)}</pre>
                <Paragraph className="section-gap" type="secondary">可能追加的只读工具数据范围：{(item.preview?.additional_tool_data_scope || []).join(" ") || "无"}</Paragraph>
              </> }]} />
          </Card>)}
          <ul>{batchPreview.disclosure?.map((line: string) => <li key={line}>{line}</li>)}</ul>
          {!batchPreviewMatchesSelection && <Alert className="section-gap" type="error" showIcon message="预览候选与所选候选不一致，不能授权批量发送。请关闭并重新生成预览。" />}
          <Checkbox checked={batchSubmissionApproved}
            disabled={!batchDisclosureReviewed}
            onChange={(event) => setBatchSubmissionApproved(event.target.checked)}>
            我已逐条展开并检查所有候选的完整外发上下文与工具范围，允许按此预览向模型发送
          </Checkbox>
        </> : <Text>正在生成预览…</Text>}
      </Modal>
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

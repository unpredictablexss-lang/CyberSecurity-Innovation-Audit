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
import { caseAgentEvidencePresentation, casePocPlanPresentation, caseRemediationDraftPresentation } from "../features/workbench/caseReport.js";
const { Text, Title, Paragraph } = Typography;
const caseOutcomeLabels: Record<string, string> = {
  candidate: "候选，继续调查",
  dynamic_reproduced_component_issue: "组件级动态复现",
  supports_vulnerability_hypothesis: "支持漏洞假设",
  supports_false_positive_hypothesis: "支持误报假设",
  unknown: "未知",
  proposed_confirmation: "建议进一步确认",
  confirmed: "人工确认",
  reportable: "人工认定可报告",
};
function CaseReportOverview({ report, caseId }: { report: any; caseId: string }) {
  const validationOps = (report?.operations || []).filter((item: any) => item.kind === "validation");
  const poc = report?.poc_status || { state: "not_run", label: "计划未运行", detail: "没有已登记的受控验证操作。" };
  const pocAlert = poc.state === "completed" ? "warning" : poc.state === "running" ? "info" : "info";
  return <Card size="small" className="section-gap" title="综合审计报告">
    <Alert type={report?.validated_vulnerability ? "success" : "warning"} showIcon
      message={report?.validated_vulnerability ? "人工确认 · 验证门控通过" : "候选结果 · 尚未确认为漏洞"}
      description={report?.validated_vulnerability
        ? "该案例有匹配的人工结论及运行时门控记录。"
        : "静态检测和 AI 分析用于定位与整理证据；不会自动升级为已确认漏洞。"} />
    {(report?.candidates || []).map((row: any) => {
      const candidate = row.candidate || {};
      const risk = row.risk || {};
      const triageRows = (report?.operations || []).filter((item: any) =>
        item.kind === "agent_investigation" && item.candidate_id === candidate.id && item.agent_triage);
      const triage = triageRows[0]?.agent_triage;
      const obligations = candidate.evidence?.obligations || [];
      const remediationDraft = row.remediation_draft || {};
      const sourceAnchor = row.source_anchor || {};
      const pocPlan = row.poc_plan || {};
      const triageView = caseAgentEvidencePresentation(triage, sourceAnchor);
      const remediationView = caseRemediationDraftPresentation(remediationDraft, sourceAnchor);
      const pocPlanView = casePocPlanPresentation(pocPlan, sourceAnchor);
      return <Card key={row.job_id + candidate.id} size="small" className="section-gap"
        title={(candidate.detector_id || "静态检测") + " · " + (candidate.rule_id || "候选")}
        extra={<Button type="link" onClick={() => go("/tasks/" + row.job_id)}>查看源码与原始证据</Button>}>
        <Descriptions size="small" bordered column={2}>
          <Descriptions.Item label="风险层级"><Tag color={risk.risk_tier === "high_confidence_candidate" ? "orange" : "blue"}>{risk.risk_tier_label || "源码版本未核对"}</Tag></Descriptions.Item>
          <Descriptions.Item label="观测状态"><Tag>candidate · 单条观测未确认</Tag></Descriptions.Item>
          <Descriptions.Item label="静态严重性 / 置信度">{String(risk.severity ?? "unknown")} / {String(risk.confidence ?? "unknown")}</Descriptions.Item>
          <Descriptions.Item label="代码位置">{candidate.file || "unknown"}:{candidate.line || "?"}</Descriptions.Item>
          <Descriptions.Item label="本次扫描来源">{row.repository || "unknown"} @ <Hash value={row.commit || "unknown"} /></Descriptions.Item>
          <Descriptions.Item label="报告 SHA-256"><Hash value={row.report_sha256 || "unknown"} /></Descriptions.Item>
        </Descriptions>
        <Paragraph className="section-gap"><Text strong>静态规则依据：</Text> {candidate.message || "规则未提供摘要"}</Paragraph>
        <Paragraph><Text type="secondary">风险分层依据：</Text> {(risk.reasons || []).join("；") || "暂无可用依据"}</Paragraph>
        <Paragraph><Text type="secondary">建案理由：</Text> {row.rationale || "未填写"}</Paragraph>
        {!!obligations.length && <div className="obligation">
          <Text strong>待核实的静态证据义务</Text>
          <ul>{obligations.slice(0, 8).map((item: any, index: number) => <li key={index}>
            {item.description || item.kind || String(item)} <Text type="secondary">（{item.status || "unknown"}）</Text>
          </li>)}</ul>
        </div>}
        {sourceAnchor.verified ? <div className="obligation">
          <Text strong>本次扫描源码证据锚点</Text>
          <Paragraph><Text code>{sourceAnchor.file}:{sourceAnchor.line}</Text> · commit <Hash value={sourceAnchor.commit} /> · SHA-256 <Hash value={sourceAnchor.source_sha256} /></Paragraph>
          <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 240, overflow: "auto" }}>
            {sourceAnchor.excerpt}
          </pre>
        </div> : <Alert className="section-gap" type="warning" showIcon
          message="扫描源码材料不可用，相关报告建议保持 unknown" description={sourceAnchor.reason || "没有可核验的来源锚点。"} />}
        {triage ? <div className="obligation">
          <Text strong>AI 调查摘要（{triage.assessment || "unknown"} · 仍为候选）</Text>
          {triageView.available
            ? <Paragraph>{triageView.summary || "模型未提供可读摘要"}</Paragraph>
            : <Alert type="warning" showIcon message="AI 结论与建议保持 unknown"
                description={triage.citation_review?.reason || "本次扫描源码引文材料不足；未展示未经绑定的模型文本。"} />}
          {!!triageView.supportedClaims.length && <>
            <Text strong>引用到的证据</Text>
            <ul>{triageView.supportedClaims.slice(0, 8).map((claim: any, index: number) => <li key={index}>
              {claim.claim || "未命名陈述"}
              {(claim.citations || []).map((citation: any, citationIndex: number) => <div key={citationIndex}>
                <Text type="secondary">{citation.evidence_id || "evidence"}：“{citation.quote || ""}”</Text>
              </div>)}
            </li>)}</ul>
          </>}
          {!!triageView.unknowns.length && <Paragraph><Text strong>仍未知：</Text> {triageView.unknowns.join("；")}</Paragraph>}
          {!!triageView.modelSuggestions.length && <>
            <Text strong>AI 建议的下一步（未验证，不等于修复方案）</Text>
            <ul>{triageView.modelSuggestions.slice(0, 8).map((suggestion: any, index: number) => <li key={index}>
              <Tag color="gold">AI 建议 · 未验证</Tag> {suggestion.text}
              <div><Text type="secondary">本次扫描源码上下文：{suggestion.source_anchor?.file || "unknown"}:{suggestion.source_anchor?.line || "?"} @ {suggestion.source_anchor?.commit || "unknown"}；语义支持仍未验证。</Text></div>
            </li>)}</ul>
          </>}
          <Text type="secondary">引用逐字匹配不证明语义结论；AI 摘要和建议均需人工复核。</Text>
        </div> : <Alert className="section-gap" type="info" showIcon message="暂无绑定到这条候选的 AI 调查结果" />}
        <div className="obligation">
          <Text strong>修复建议草案</Text>
          {remediationView.available
            ? <><Paragraph>{remediationView.draft} <Tag color="gold">未验证 · 非补丁</Tag></Paragraph>
              <Text type="secondary">依据：{remediationView.provenance}；扫描源码锚点 {remediationDraft.source_anchor?.file}:{remediationDraft.source_anchor?.line} @ {remediationDraft.source_anchor?.commit}</Text>
              <Paragraph><Text strong>AI 源码依据：</Text> {remediationView.aiBasis.state} · {remediationView.aiBasis.note}</Paragraph>
              {!!remediationView.aiBasis.citations?.length && <ul>{remediationView.aiBasis.citations.slice(0, 8).map((citation: any, index: number) => <li key={index}>
                {citation.file || "unknown"}:{citation.line_start || "?"}-{citation.line_end || "?"} · {citation.evidence_id || "evidence"}：“{citation.quote || ""}”
                <Text type="secondary">（引文语义及其与修复草案的相关性仍需人工复核）</Text>
              </li>)}</ul>}
              <ul>{remediationView.reviewChecks.map((check: string, index: number) => <li key={index}>{check}</li>)}</ul></>
            : <Paragraph type="secondary">unknown：{remediationView.reason || "没有足够的本次扫描源码或 CWE 材料生成草案。"}</Paragraph>}
        </div>
        <div className="obligation">
          <Text strong>安全验证 / PoC 计划</Text>
          {pocPlanView.available
            ? <><Paragraph><Tag color="blue">只生成计划 · 未执行</Tag> {pocPlanView.authorization}</Paragraph>
              <Text type="secondary">预期结果保持 unknown，直到人工定义接口契约或测试 oracle。计划绑定 {pocPlan.source_anchor?.file}:{pocPlan.source_anchor?.line} @ {pocPlan.source_anchor?.commit}。</Text>
              <ol>{pocPlanView.steps.map((step: any) => <li key={step.id}>
                <Text strong>{step.id}</Text> · {step.action} <Text type="secondary">（{step.status}；锚点 {step.source_anchor?.anchor_id}）</Text>
              </li>)}</ol></>
            : <Paragraph type="secondary">unknown：{pocPlanView.reason || "扫描源码材料不足；未生成伪造证据或可执行步骤。"}</Paragraph>}
        </div>
      </Card>;
    })}
    <Alert className="section-gap" type={pocAlert as any} showIcon message={"PoC / 受控验证：" + (poc.label || "计划未运行")} description={poc.detail || "没有已登记的受控验证操作。"} />
    {!!validationOps.length && <ul>{validationOps.map((item: any) => <li key={item.id}>
      <Text code>{item.id.slice(0, 12)}</Text> · {item.status} · 门控 {item.validation_gate || "unknown"} · 产品可达性 {item.reachability_status || "unknown"}
    </li>)}</ul>}
    <Text type="secondary">报告基于案例关联的扫描报告、已提交的调查结果与人工记录。案例 ID：{caseId}</Text>
  </Card>;
}

function CaseReviewPanel({ caseId, onStatusChange }: { caseId: string; onStatusChange: (value: any) => void }) {
  const [form] = Form.useForm();
  const [report, setReport] = useState<any>(null);
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const outcome = Form.useWatch("outcome", form) || "candidate";
  const requiresGate = outcome === "confirmed" || outcome === "reportable";
  const load = async () => {
    setLoading(true); setError("");
    try {
      const [nextReport, allStatuses] = await Promise.all([
        api("/cases/" + caseId + "/report.json"),
        api("/cases/review-statuses"),
      ]);
      const nextStatus = allStatuses.items?.find((item: any) => item.case_id === caseId) || {
        validated_vulnerability: nextReport.validated_vulnerability || 0,
        latest_human_assessment: nextReport.latest_human_assessment,
      };
      setReport(nextReport); setStatus(nextStatus); onStatusChange(nextStatus);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, [caseId]);
  const evidenceOptions = (report?.candidates || []).flatMap((row: any) =>
    (row.source_evidence || []).map((item: any) => ({
      value: item.id,
      label: row.candidate.file + ":" + item.start_line + "-" + item.end_line + " · " + (item.kind || item.observation || item.note || item.id),
    })));
  const validationOptions = (report?.operations || []).filter((item: any) =>
    item.kind === "validation" && ["completed", "completed_with_limitations"].includes(item.status)
    && item.validation_gate === "passed" && item.reachability_status === "verified");
  const recordAssessment = async (values: any) => {
    const evidenceIds = values.evidence_ids || [];
    const validationIds = values.validation_operation_ids || [];
    const remainingUnknowns = String(values.remaining_unknowns || "").split(String.fromCharCode(10))
      .map((item) => item.replaceAll(String.fromCharCode(13), "").trim()).filter(Boolean);
    if (requiresGate && (!evidenceIds.length || !validationIds.length || !remainingUnknowns.length)) {
      message.error("确认/可报告结论必须同时选择案例证据、通过的运行时验证并填写未决项");
      return;
    }
    setSaving(true); setError("");
    try {
      await api("/cases/" + caseId + "/assessments", {
        outcome: values.outcome, reviewer_kind: "human", reviewer: values.reviewer,
        notes: values.notes, evidence_ids: evidenceIds,
        validation_operation_ids: validationIds, remaining_unknowns: remainingUnknowns,
      });
      message.success("人工案例结论已追加；原始候选与 Agent 结果未被改写");
      form.resetFields(["notes", "remaining_unknowns", "evidence_ids", "validation_operation_ids"]);
      await load();
    } catch (e) { setError(String(e)); }
    finally { setSaving(false); }
  };
  return <>
    {report && <CaseReportOverview report={report} caseId={caseId} />}
    <Card size="small" className="section-gap" title="人工案例审核与结论">
    {error && <Alert type="error" showIcon message={error} />}
    {status?.validated_vulnerability ? <Alert type="success" showIcon message="案例已通过人工确认门控" description={"绑定验证操作：" + (status.validated_by?.validation_operation_id || "记录不可用") + "；该计数来自人工案例结论，不来自 Agent 分诊。"} /> :
      <Alert type="info" showIcon message="Agent 分诊和人工案例结论分开记录" description="可追加人工假设、未知或组件复现结论。只有选择本案例的通过验证、产品可达性已验证的运行操作，并引用案例证据、记录未决项后，API 才接受 confirmed/reportable；模型建议永远不能代替此门控。" />}
    {status?.latest_human_assessment && <Paragraph type="secondary">
      最新人工意见：{caseOutcomeLabels[status.latest_human_assessment.outcome] || status.latest_human_assessment.outcome}
      （{status.latest_human_assessment.reviewer} · {new Date(status.latest_human_assessment.created_at).toLocaleString()}）
    </Paragraph>}
    {loading && !report ? <Spin /> : <>
      <Form form={form} layout="vertical" initialValues={{ outcome: "candidate" }} onFinish={(values) => void recordAssessment(values)}>
        <Space wrap>
          <Form.Item name="reviewer" label="复核人（手工填写）" rules={[{ required: true, max: 100 }]}><Input maxLength={100} /></Form.Item>
          <Form.Item name="outcome" label="人工结论" rules={[{ required: true }]}>
            <Select style={{ width: 260 }} options={Object.entries(caseOutcomeLabels).map(([value, label]) => ({ value, label }))} />
          </Form.Item>
        </Space>
        <Form.Item name="evidence_ids" label="案例来源证据（确认/可报告必填）">
          <Select mode="multiple" allowClear placeholder={evidenceOptions.length ? "选择本次扫描来源证据" : "暂无已登记来源证据；先从候选人工复核处追加证据"} options={evidenceOptions} />
        </Form.Item>
        {requiresGate && <Alert className="section-gap" type="warning" showIcon
          message="确认门控要求运行时验证通过、产品可达性已验证、至少一条案例证据及明确未决项"
          description={validationOptions.length ? "只显示绑定到本案例且已通过验证门的运行操作。" : "当前案例没有合格运行验证；可先保存其他人工意见，不能提交 confirmed/reportable。"} />}
        <Form.Item name="validation_operation_ids" label="通过门控的验证操作（确认/可报告必填）">
          <Select mode="multiple" disabled={!validationOptions.length} options={validationOptions.map((item: any) => ({
            value: item.id, label: item.id.slice(0, 12) + " · " + (item.commit || item.commits?.join(", ") || "扫描代码版本") + " · reachability verified",
          }))} />
        </Form.Item>
        <Form.Item name="remaining_unknowns" label="仍未解决的未知项（每行一项；确认/可报告必填）">
          <Input.TextArea rows={2} maxLength={4000} placeholder="例如：其他调用方可达性、受影响版本范围" />
        </Form.Item>
        <Form.Item name="notes" label="复核依据与说明" rules={[{ required: true, min: 1, max: 8000 }]}>
          <Input.TextArea rows={3} maxLength={8000} />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={saving} disabled={loading}>提交复核意见</Button>
      </Form>
      {(report?.assessments || []).length > 0 && <Card size="small" className="section-gap" title={"追加历史（" + report.assessments.length + "）"}>
        {(report.assessments as any[]).slice().reverse().map((item: any) =>
          <div className="obligation" key={item.id}>
            <Text strong>{item.reviewer_kind === "agent" ? "Agent 建议" : "人工"} · {caseOutcomeLabels[item.outcome] || item.outcome}</Text>
            <div><Text type="secondary">{item.reviewer} · {new Date(item.created_at).toLocaleString()}</Text></div>
            <Paragraph>{item.notes}</Paragraph>
            {!!item.evidence_ids?.length && <Text type="secondary">证据：{item.evidence_ids.join(", ")}</Text>}
            {!!item.remaining_unknowns?.length && <Paragraph type="secondary">未决：{item.remaining_unknowns.join("；")}</Paragraph>}
          </div>)}
      </Card>}
    </>}
    </Card>
  </>;
}
export default function Cases({ embedded = false }: { embedded?: boolean } = {}) {
  const [cases, setCases] = useState<any[]>([]);
  const [reviewStatuses, setReviewStatuses] = useState<Record<string, any>>({});
  const [error, setError] = useState("");
  useEffect(() => {
    Promise.all([api("/cases"), api("/cases/review-statuses")])
      .then(([items, statusResponse]) => {
        setCases(items);
        setReviewStatuses(Object.fromEntries((statusResponse.items || []).map((item: any) => [item.case_id, item])));
      })
      .catch((e) => setError(String(e)));
  }, []);
  const downloadReport = async (caseId: string, kind: "json" | "md" | "html" | "manifest.json" | "bundle.zip") => {
    try {
      const endpoint = kind === "manifest.json" ? "report.manifest.json"
        : kind === "bundle.zip" ? "report.bundle.zip" : "report." + kind;
      const response = await fetch("/api/v1/cases/" + caseId + "/" + endpoint);
      if (!response.ok) throw new Error(await response.text());
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "ohscanner-case-" + caseId + "." + kind;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (e) { message.error(String(e)); }
  };
  return (
    <>
      {!embedded && <Header
        title="调查案例"
        description="人工关联根因，保留逐条依据。案例、候选与确认漏洞分别计数。"
      />}
      {error && <Alert type="error" message={error} />}
      <Card>
        <Table<any>
          rowKey="id"
          dataSource={cases}
          columns={[
            { title: "案例", dataIndex: "title" },
            { title: "状态", render: (_: any, c: any) => {
              const review = reviewStatuses[c.id];
              if (review?.validated_vulnerability) return <Tag color="green">人工确认 · 门控通过</Tag>;
              const latest = review?.latest_human_assessment;
              return latest ? <Tag color="blue">人工意见：{caseOutcomeLabels[latest.outcome] || latest.outcome} · 未确认</Tag> : <Tag>调查中 · 未确认</Tag>;
            } },
            { title: "关联观测", render: (_: any, c: any) => c.links.length },
            { title: "报告", render: (_: any, c: any) => <Space wrap>
              <Button size="small" type="primary" onClick={() => void downloadReport(c.id, "bundle.zip")}>下载完整报告包</Button>
              <Button size="small" onClick={() => void downloadReport(c.id, "html")}>阅读报告</Button>
              <Button size="small" onClick={() => void downloadReport(c.id, "md")}>Markdown</Button>
              <Button size="small" onClick={() => void downloadReport(c.id, "json")}>JSON</Button>
              <Button size="small" onClick={() => void downloadReport(c.id, "manifest.json")}>证据清单</Button>
            </Space> },
            {
              title: "创建时间",
              dataIndex: "created_at",
              render: (x: string) => new Date(x).toLocaleString(),
            },
          ]}
          expandable={{
            expandedRowRender: (c) => (
              <>
                {c.links.map((l: any) => (
                  <div className="obligation" key={l.job_id + l.candidate_id}>
                    <a onClick={() => go("/tasks/" + l.job_id)}>
                      来源任务 {l.job_id.slice(0, 12)}
                    </a>
                    <Paragraph>{l.rationale}</Paragraph>
                    <Text code>{l.candidate_id}</Text>
                    <div><Button type="link" onClick={() => go("/operations")}>打开源码与验证操作</Button></div>
                  </div>
                ))}
                <CaseReviewPanel key={c.id} caseId={c.id}
                  onStatusChange={(value) => setReviewStatuses((current) => ({ ...current, [c.id]: value }))} />
              </>
            ),
          }}
          locale={{ emptyText: "从任务候选列表选择观测并建立案例。" }}
        />
      </Card>
    </>
  );
}

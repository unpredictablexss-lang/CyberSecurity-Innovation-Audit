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
  return <Card size="small" className="section-gap" title="人工案例审核与结论">
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
          <Select mode="multiple" allowClear placeholder={evidenceOptions.length ? "选择固定来源证据" : "暂无已登记来源证据；先从候选人工复核处追加证据"} options={evidenceOptions} />
        </Form.Item>
        {requiresGate && <Alert className="section-gap" type="warning" showIcon
          message="确认门控要求运行时验证通过、产品可达性已验证、至少一条案例证据及明确未决项"
          description={validationOptions.length ? "只显示绑定到本案例且已通过验证门的运行操作。" : "当前案例没有合格运行验证；可先保存其他人工意见，不能提交 confirmed/reportable。"} />}
        <Form.Item name="validation_operation_ids" label="通过门控的验证操作（确认/可报告必填）">
          <Select mode="multiple" disabled={!validationOptions.length} options={validationOptions.map((item: any) => ({
            value: item.id, label: item.id.slice(0, 12) + " · " + (item.commit || item.commits?.join(", ") || "固定提交") + " · reachability verified",
          }))} />
        </Form.Item>
        <Form.Item name="remaining_unknowns" label="仍未解决的未知项（每行一项；确认/可报告必填）">
          <Input.TextArea rows={2} maxLength={4000} placeholder="例如：其他调用方可达性、受影响版本范围" />
        </Form.Item>
        <Form.Item name="notes" label="复核依据与说明" rules={[{ required: true, min: 1, max: 8000 }]}>
          <Input.TextArea rows={3} maxLength={8000} />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={saving} disabled={loading}>追加人工案例审核</Button>
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
  </Card>;
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
  const downloadReport = async (caseId: string, kind: "json" | "md") => {
    try {
      const response = await fetch("/api/v1/cases/" + caseId + "/report." + kind);
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
            { title: "报告", render: (_: any, c: any) => <Space><Button size="small" onClick={() => void downloadReport(c.id, "json")}>JSON</Button><Button size="small" onClick={() => void downloadReport(c.id, "md")}>Markdown</Button></Space> },
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

import React from "react";
import { Alert, Button, Card, Collapse, Descriptions, Form, Input, InputNumber, List, Select, Space, Typography, message } from "antd";
import { useState } from "react";
import { go } from "../../components";
const { Text } = Typography;
const labels: Record<string, string> = { likely_true_positive: "倾向真实候选", likely_false_positive: "倾向误报", needs_more_evidence: "需要更多证据", unknown: "未知" };
export default function AgentAssessment({ result, reviews = [], onSubmit }: { result: any; reviews?: any[]; onSubmit: (review: any) => Promise<void> }) {
  const [form] = Form.useForm();
  const [saving, setSaving] = useState(false);
  const saveReview = async (value: any) => {
    setSaving(true);
    try {
      await onSubmit(value);
      form.resetFields(["claims_to_correct", "missed_evidence", "notes", "elapsed_seconds"]);
      message.success("人工评价已追加到 Agent 操作审计记录");
    } catch (error) {
      message.error(String(error));
    } finally {
      setSaving(false);
    }
  };
  const assessment = result.agent_assessment || {}, binding = result.binding || {};
  const claims = Array.isArray(assessment.supported_claims) ? assessment.supported_claims : [];
  const evidenceLocation = (evidenceId: string) => {
    if (evidenceId === result.initial_evidence?.evidence_id) {
      const start = result.initial_evidence.source_excerpt_start_line;
      const end = result.initial_evidence.source_excerpt_end_line;
      return start && end ? `${binding.file}:${start}-${end}` : binding.file || "初始上下文";
    }
    const tool = (result.tool_calls || []).find((item: any) => item.evidence_id === evidenceId);
    if (!tool) return "证据记录不可用";
    const source = tool.result || {};
    if (source.file && source.start_line && source.end_line) return `${source.file}:${source.start_line}-${source.end_line}`;
    if (source.file) return `${source.file} · 固定提交历史`;
    return tool.tool || "只读工具证据";
  };
  const items = [
    { key: "initial", label: "初始候选上下文", children: <pre className="raw">{JSON.stringify(result.initial_evidence || {}, null, 2)}</pre> },
    { key: "tools", label: `只读工具记录（${(result.tool_calls || []).length}）`, children: <pre className="raw">{JSON.stringify(result.tool_calls || [], null, 2)}</pre> },
    { key: "trace", label: `模型调用记录（${(result.model_calls || []).length}）`, children: <pre className="raw">{JSON.stringify({ model_usage: result.model_usage, model_calls: result.model_calls }, null, 2)}</pre> },
  ];
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Alert type="warning" showIcon message="模型分诊建议，不是漏洞确认" description={`漏洞状态：${result.vulnerability_state || "candidate"}；validated_vulnerability=${result.validated_vulnerability ?? 0}。须由人工结合产品路径与运行证据复核。`} />
    {binding.job_id && binding.candidate_id && <Button type="primary" onClick={() => go(`/tasks/${encodeURIComponent(binding.job_id)}?tab=findings&candidate_id=${encodeURIComponent(binding.candidate_id)}`)}>打开该候选人工复核</Button>}
    <Descriptions bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="分诊倾向">{labels[assessment.assessment] || assessment.assessment || "尚无结果"}</Descriptions.Item>
      <Descriptions.Item label="模式">{result.mode === "single_shot" ? "R1 单轮复核" : "R2 有界工具 Agent"}</Descriptions.Item>
      <Descriptions.Item label="模型">{result.provider?.model || "—"}</Descriptions.Item>
      <Descriptions.Item label="外发目的地">{result.source_submission?.destination_host || "—"}</Descriptions.Item>
      <Descriptions.Item label="候选">{binding.candidate_id || "—"}</Descriptions.Item>
      <Descriptions.Item label="固定提交">{binding.commit || "—"}</Descriptions.Item>
      <Descriptions.Item label="源码位置" span={2}>{binding.file || "—"}</Descriptions.Item>
      <Descriptions.Item label="Token 用量">{result.model_usage ? `${result.model_usage.total_tokens ?? "unknown"} tokens；输入预算 ${result.model_usage.input_budget_tokens ?? "?"}，输出预算 ${result.model_usage.output_budget_tokens ?? "?"}` : "—"}</Descriptions.Item>
      <Descriptions.Item label="费用">{result.model_usage?.cost || "unknown"}</Descriptions.Item>
    </Descriptions>
    {claims.length > 0 && <Card size="small" title="有逐字引句的模型陈述"><List size="small" dataSource={claims} renderItem={(item: any) => <List.Item><Space direction="vertical"><Text>{item.claim}</Text>{(item.citations || []).map((citation: any, index: number) => <Text key={index} type="secondary">{citation.evidence_id} · {evidenceLocation(citation.evidence_id)}：“{citation.quote}”</Text>)}{(item.evidence_ids || []).length > 0 && <Text type="secondary">旧结果引用：{item.evidence_ids.join(", ")}</Text>}</Space></List.Item>} /></Card>}
    <Descriptions bordered size="small" column={1}>
      <Descriptions.Item label="未支持的陈述">{(assessment.unsupported_claims || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="未知项">{(assessment.unknowns || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="建议下一步">{(assessment.next_steps || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="限制">{(result.limitations || []).join("；") || "无"}</Descriptions.Item>
    </Descriptions>
    <Card size="small" title="人工评价 Agent 分诊（不改变候选或漏洞状态）">
      <Alert type="info" showIcon message="此表只记录模型输出的实用性、引文质量和复核成本；不是候选漏洞定性。" />
      {reviews.length > 0 && <List className="section-gap" size="small" header={`追加复核记录（${reviews.length}）`} dataSource={reviews} renderItem={(review: any) =>
        <List.Item><Space direction="vertical"><Text>{review.reviewer} · {review.usefulness} · 引文：{review.citation_accuracy} · {review.elapsed_seconds ?? "unknown"} 秒</Text>
          {!!review.claims_to_correct && <Text type="secondary">需更正：{review.claims_to_correct}</Text>}
          {!!review.missed_evidence && <Text type="secondary">遗漏证据：{review.missed_evidence}</Text>}
          {!!review.notes && <Text type="secondary">{review.notes}</Text>}
        </Space></List.Item>} />}
      <Form className="section-gap" form={form} layout="vertical" onFinish={(value) => void saveReview(value)}
        initialValues={{ usefulness: "partially_useful", citation_accuracy: "not_checked" }}>
        <Form.Item name="reviewer" label="复核人（手工填写）" rules={[{ required: true, max: 100 }]}><Input maxLength={100} /></Form.Item>
        <Space wrap>
          <Form.Item name="usefulness" label="分诊实用性" rules={[{ required: true }]}>
            <Select style={{ width: 220 }} options={[
              { value: "useful", label: "有用" }, { value: "partially_useful", label: "部分有用" },
              { value: "not_useful", label: "无用" }, { value: "unsafe", label: "有误导风险" },
            ]} />
          </Form.Item>
          <Form.Item name="citation_accuracy" label="引文准确性" rules={[{ required: true }]}>
            <Select style={{ width: 220 }} options={[
              { value: "all_accurate", label: "全部准确" }, { value: "some_incorrect", label: "存在错误" },
              { value: "mostly_incorrect", label: "大多错误" }, { value: "not_checked", label: "未核对" },
            ]} />
          </Form.Item>
          <Form.Item name="elapsed_seconds" label="人工复核耗时（秒）"><InputNumber min={0} max={7200} /></Form.Item>
        </Space>
        <Form.Item name="claims_to_correct" label="需更正的模型陈述"><Input.TextArea rows={2} maxLength={1200} /></Form.Item>
        <Form.Item name="missed_evidence" label="遗漏证据或事实"><Input.TextArea rows={2} maxLength={1200} /></Form.Item>
        <Form.Item name="notes" label="备注"><Input.TextArea rows={2} maxLength={1000} /></Form.Item>
        <Button type="primary" htmlType="submit" loading={saving}>追加人工评价</Button>
      </Form>
    </Card>
    <Collapse items={items} />
  </Space>;
}

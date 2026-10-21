import React from "react";
import { Alert, Button, Card, Collapse, Descriptions, Form, Input, InputNumber, List, Select, Space, Tag, Typography, message } from "antd";
import { useState } from "react";
import { go } from "../../components";
import { evidenceLocation, evidenceSourceLocation } from "./agentEvidenceLocation.js";
import { structuredAnswerRejection } from "./agentValidationMessage.js";
import { agentToolIssues } from "./agentToolIssues.js";
import { agentConfidenceLabel, agentScopeLabel, agentVerdictLabel, agentVerdictReasonLabel, productStatusLabel } from "../workbench/riskLabels.js";
const { Text } = Typography;
const labels: Record<string, string> = { likely_true_positive: "倾向真实候选", likely_false_positive: "倾向误报", needs_more_evidence: "需要更多证据", unknown: "未知" };
const obligationLabels: Record<string, string> = {
  evidence_found: "找到相关证据",
  contrary_evidence: "发现相反证据",
  unresolved: "仍未解决",
};
const claimSupportLabels: Record<string, string> = {
  supported: "引文支持主张", partially_supported: "部分支持", unsupported: "不支持", unverifiable: "无法判断",
};
const verdictLabels: Record<string, string> = {
  confirmed: "源码证据门通过（产品状态仍未知）", likely_true_positive: "模型倾向漏洞候选",
  false_positive: "源码证据支持误报解释（仍需人工复核）", likely_false_positive: "模型倾向误报",
  needs_more_evidence: "需要更多证据", unknown: "未知（待核实）", analysis_failed: "分析失败",
};
const dispositionLabels: Record<string, string> = {
  investigate: "继续调查", likely_noise: "人工标记误报/噪声", unknown: "人工判为未知",
};
const evidenceGraphStageLabels: Record<string, string> = {
  candidate_routing: "候选固定与范围",
  root_cause_hypothesis: "根因假设",
  bounded_cross_file_trace: "跨文件源码追查",
  counterevidence_search: "主动反证与未决项",
  official_patch_version_comparison: "官方公告、影响版本与补丁",
  evidence_arbitration: "证据裁决",
};
const evidenceGraphStatusLabels: Record<string, string> = {
  completed: "已绑定",
  recorded: "已记录",
  evidence_collected: "已收集源码",
  not_performed: "未执行",
  search_completed_no_callsite: "已搜索，未找到语法调用点",
  partial_parse: "解析不完整，结果有限",
  review_recorded: "已记录，待人工核对",
  not_available: "本次未收集",
  structure_validated_semantics_unverified: "结构通过，语义未确认",
  incomplete: "未完成",
};
export default function AgentAssessment({ result, reviews = [], onSubmit }: { result: any; reviews?: any[]; onSubmit: (review: any) => Promise<void> }) {
  const [form] = Form.useForm();
  const [saving, setSaving] = useState(false);
  const [claimAdjudications, setClaimAdjudications] = useState<Record<number, string>>({});
  const saveReview = async (value: any) => {
    const missingClaim = claims.findIndex((_: any, index: number) => !claimAdjudications[index]);
    if (missingClaim >= 0) {
      message.warning("请逐条判断模型陈述的引文是否支持该主张；无法确认时选择“无法判断”。");
      return;
    }
    const claim_adjudications = claims.map((_: any, claim_index: number) => ({
      claim_index, disposition: claimAdjudications[claim_index],
    }));
    setSaving(true);
    try {
      await onSubmit({ ...value, claim_adjudications });
      setClaimAdjudications({});
      form.resetFields(["claims_to_correct", "missed_evidence", "notes", "elapsed_seconds"]);
      message.success("人工评价已追加到 Agent 操作审计记录");
    } catch (error) {
      message.error(String(error));
    } finally {
      setSaving(false);
    }
  };
  const assessment = result.agent_assessment || {}, binding = result.binding || {};
  const verdict = result.agent_verdict || {};
  const claims = Array.isArray(assessment.supported_claims) ? assessment.supported_claims : [];
  const obligations = result.initial_evidence?.context?.evidence_obligations || [];
  const sourceCitationPolicy = typeof result.citation_evidence_policy === "string";
  const modelAnswerRetained = result.model_answer_retained !== false;
  const rejectionDescription = structuredAnswerRejection(
    result.structured_answer_validation, result.structured_answer_validation_error_code);
  const obligationReviews = Array.isArray(assessment.obligation_reviews) ? assessment.obligation_reviews : [];
  const toolIssues = agentToolIssues(result.tool_calls);
  const evidenceGraph = result.evidence_graph || {};
  const evidenceGraphStages = Array.isArray(evidenceGraph.nodes)
    ? evidenceGraph.nodes.filter((node: any) => node.kind === "workflow_stage") : [];
  const obligationByIndex = new Map(obligationReviews.map((item: any) => [item.obligation_index, item]));
  const claimObligationLabel = (indices: any) => Array.isArray(indices) && indices.length > 0
    ? indices.map((index: any) => {
      const obligation = Number.isInteger(index) && index >= 0 ? obligations[index] : undefined;
      const description = typeof obligation === "string" ? obligation : obligation?.description || obligation?.kind;
      return "#" + index + (description ? " -> " + description : "");
    }).join("; ") : null;
  const citationLink = (citation: any, index: number) => {
    const location = evidenceSourceLocation(result, citation.evidence_id, citation.quote, citation);
    const label = citation.evidence_id + " · " + evidenceLocation(result, citation.evidence_id, citation.quote, citation) + "：“" + citation.quote + "”";
    return location && binding.job_id
      ? <Button key={index} type="link" size="small" className="source-citation-link"
          onClick={() => go("/tasks/" + encodeURIComponent(binding.job_id) + "?tab=source&source_file=" + encodeURIComponent(location.file) + "&source_line=" + location.line)}>{label}</Button>
      : <Text key={index} type="secondary">{label}</Text>;
  };
  const items = [
    { key: "initial", label: "初始候选上下文", children: <pre className="raw">{JSON.stringify(result.initial_evidence || {}, null, 2)}</pre> },
    { key: "tools", label: `只读工具记录（${(result.tool_calls || []).length}）`, children: <pre className="raw">{JSON.stringify(result.tool_calls || [], null, 2)}</pre> },
    { key: "trace", label: `模型调用记录（${(result.model_calls || []).length}）`, children: <pre className="raw">{JSON.stringify({ model_usage: result.model_usage, model_calls: result.model_calls }, null, 2)}</pre> },
    { key: "model-text", label: "未核验的模型自由文本", children: <Descriptions bordered size="small" column={1}>
      <Descriptions.Item label="模型原始摘要">{modelAnswerRetained ? (assessment.model_summary_unverified || assessment.summary || "旧结果未记录摘要") : "\u672a\u4fdd\u7559\uff1a\u670d\u52a1\u7aef\u6821\u9a8c\u548c\u4e00\u6b21\u53d7\u9650\u4fee\u590d\u5747\u672a\u901a\u8fc7\u3002"}</Descriptions.Item>
      <Descriptions.Item label="模型列出的未支持陈述">{(assessment.unsupported_claims || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="模型列出的未知项">{(assessment.unknowns || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="模型建议的下一步">{(assessment.next_steps || []).join("；") || "无"}</Descriptions.Item>
    </Descriptions> },
  ];
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Alert type={verdict.status === "analysis_failed" ? "error" : ["unknown", "needs_more_evidence"].includes(verdict.status) ? "warning" : "info"} showIcon
      message={agentVerdictLabel(verdict.status) || verdictLabels[verdict.status] || "模型尚未形成有效分诊结果"}
      description={`复核范围：${agentScopeLabel(verdict.scope)}；模型置信度：${agentConfidenceLabel(verdict.confidence)}；产品状态：${productStatusLabel(verdict.product_status)}。${agentVerdictReasonLabel(verdict.reason)} 产品漏洞状态仍为 ${productStatusLabel(result.vulnerability_state || "candidate")}，已验证漏洞数 ${result.validated_vulnerability ?? 0}；产品可达性和影响仍需后续证据。`} />
    {rejectionDescription && <Alert type="error" showIcon message="模型结构化答复未通过服务端校验" description={rejectionDescription} />}
    {(toolIssues.length > 0 || (result.model_tool_calls_skipped || 0) > 0) && <Alert type="warning" showIcon message={`只读工具有 ${toolIssues.length + (result.model_tool_calls_skipped || 0)} 项未完成，相关证据可能不完整`} description={<List size="small" dataSource={toolIssues} renderItem={(item: any) => <List.Item><Text><Text strong>{item.tool}</Text> · {item.status} · {item.errorCode}：{item.message}</Text></List.Item>} footer={(result.model_tool_calls_skipped || 0) > 0 ? `另有 ${result.model_tool_calls_skipped} 个模型请求因工具调用预算耗尽而未执行；对应证据保持未决。` : null} />} />}
    <Alert type="warning" showIcon message="源码引句存在 ≠ 陈述已证实" description={sourceCitationPolicy ? `支持性主张和已判定义务只能引用固定提交中的源码摘录；扫描器义务描述、提交历史只作检索上下文，不能当作源码证明。服务端核对了 ${result.citation_integrity?.citation_count ?? "未知"} 条引句的来源类型和逐字存在性，但仍未验证引句是否在语义上支持模型推理。摘要由服务端从结构化分诊字段生成；模型原始摘要、未支持陈述、未知项和下一步建议仍是未核验文本。` : "这是较早版本的结果，未记录“只能引用源码证据”的策略版本；请人工确认每条引句确实来自固定提交源码，并逐项判断它是否支持模型陈述。摘要和其他模型自由文本均不能当作已验证结论。"} />
    {binding.job_id && binding.candidate_id && <Button type="primary" onClick={() => go(`/tasks/${encodeURIComponent(binding.job_id)}?tab=findings&candidate_id=${encodeURIComponent(binding.candidate_id)}`)}>打开该候选人工复核</Button>}
    {evidenceGraphStages.length > 0 && <Card size="small" title="AI 调查链路"
      extra={<Text type="secondary">证据图 SHA-256：{String(evidenceGraph.graph_sha256 || "").slice(0, 12)}</Text>}>
      <List size="small" dataSource={evidenceGraphStages} renderItem={(stage: any) => <List.Item>
        <Space wrap>
          <Text strong>{evidenceGraphStageLabels[stage.stage] || stage.stage}</Text>
          <Tag color={stage.status === "not_available" || stage.status === "incomplete" || stage.status === "not_performed" ? "default" : "blue"}>
            {evidenceGraphStatusLabels[stage.status] || stage.status}
          </Tag>
          <Text>{stage.summary}</Text>
        </Space>
      </List.Item>} />
      <Text type="secondary">步骤绑定固定提交和源码范围。引文的语义支持、产品可达性仍需人工核对；缺少官方公告/补丁时，N-day/1-day 结论保持未知。</Text>
    </Card>}
    <Descriptions bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="分诊倾向">{labels[assessment.assessment] || assessment.assessment || "尚无结果"}</Descriptions.Item>
      <Descriptions.Item label="模式">{result.mode === "single_shot" ? "单轮模型研判" : "工具增强只读调查"}</Descriptions.Item>
      <Descriptions.Item label="模型">{result.provider?.model || "—"}</Descriptions.Item>
      <Descriptions.Item label="外发目的地">{result.source_submission?.destination_host || "—"}</Descriptions.Item>
      <Descriptions.Item label="候选">{binding.candidate_id || "—"}</Descriptions.Item>
      <Descriptions.Item label="固定提交">{binding.commit || "—"}</Descriptions.Item>
      <Descriptions.Item label="源码位置" span={2}>{binding.file || "—"}</Descriptions.Item>
      <Descriptions.Item label="Token 用量">{result.model_usage ? `${result.model_usage.total_tokens ?? "未知"} tokens；输入预算 ${result.model_usage.input_budget_tokens ?? "未知"}，输出预算 ${result.model_usage.output_budget_tokens ?? "未知"}` : "—"}</Descriptions.Item>
      <Descriptions.Item label="缓存命中输入（输入内）">{result.model_usage?.cached_input_tokens ?? "未知"} tokens</Descriptions.Item>
      <Descriptions.Item label="推理 Token（输出内）">{result.model_usage?.reasoning_tokens ?? "未知"} tokens</Descriptions.Item>
      <Descriptions.Item label="结构化修复次数">{result.validation_repair_attempts ?? "旧结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="Provider 实际费用">{result.model_usage?.cost || "未知"}</Descriptions.Item>
      <Descriptions.Item label="估算费用">{result.model_usage?.cost_estimate?.status === "estimated_range"
        ? <Space wrap><Text>{result.model_usage.cost_estimate.currency} {result.model_usage.cost_estimate.minimum_usd}–{result.model_usage.cost_estimate.maximum_usd}；费率快照 {result.model_usage.cost_estimate.rate_card_id}；非实账</Text><a href={result.model_usage.cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
        : result.model_usage?.cost_estimate?.status === "estimated_amount"
          ? <Space wrap><Text>USD {result.model_usage.cost_estimate.amount_usd}{result.model_usage.cost_estimate.amount_cny ? " / CNY " + result.model_usage.cost_estimate.amount_cny : ""}；USD/CNY 为独立官方价目参考；费率快照 {result.model_usage.cost_estimate.rate_card_id}；非实账</Text><a href={result.model_usage.cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
        : "未知"}</Descriptions.Item>
    </Descriptions>
    {result.summary_provenance === "server_generated_from_structured_triage" && <Card size="small" title="服务端摘要（依据结构化模型标签生成）"><Text>{assessment.summary || "无摘要"}</Text></Card>}
    {claims.length > 0 && <Card size="small" title="有逐字引句的模型陈述"><List size="small" dataSource={claims} renderItem={(item: any, index: number) => <List.Item><Space direction="vertical"><Text>{item.claim}</Text>{claimObligationLabel(item.obligation_indices) ? <Text type="secondary">{String.fromCharCode(0x5173,0x8054,0x6e90,0x7801,0x4e49,0x52a1)}: {claimObligationLabel(item.obligation_indices)}</Text> : <Text type="warning">{String.fromCharCode(0x65e7,0x7ed3,0x679c,0x7f3a,0x5c11,0x7ed3,0x6784,0x5316,0x4e49,0x52a1,0x5173,0x8054,0xff0c,0x9700,0x4eba,0x5de5,0x91cd,0x6838)}.</Text>}{(item.citations || []).map(citationLink)}<Select
              style={{ width: 280 }}
              placeholder="逐条判断引文与主张的关系"
              value={claimAdjudications[index]}
              onChange={(value) => setClaimAdjudications((current) => ({ ...current, [index]: value }))}
              options={[
                { value: "supported", label: "引文支持主张" },
                { value: "partially_supported", label: "部分支持" },
                { value: "unsupported", label: "不支持" },
                { value: "unverifiable", label: "无法判断" },
              ]}
            />{(item.evidence_ids || []).length > 0 && <Text type="secondary">旧结果引用：{item.evidence_ids.join(", ")}</Text>}</Space></List.Item>} /></Card>}
    <Card size="small" title="检测器证据义务逐项分诊">
      <Alert type="info" showIcon message="矩阵覆盖性和引句是否存在已由服务端核验；“找到相关证据”不等于义务已满足或漏洞已证实，语义判断仍需人工复核。" />
      {obligations.length > 0 ? <List className="section-gap" size="small" dataSource={obligations}
        renderItem={(obligation: any, index: number) => {
          const review: any = obligationByIndex.get(index);
          const description = typeof obligation === "string" ? obligation : obligation?.description || obligation?.kind || JSON.stringify(obligation);
          return <List.Item><Space direction="vertical">
            <Text strong>#{index} · {obligation?.kind || "证据义务"} · {obligationLabels[review?.disposition] || "无可用分诊记录"}</Text>
            <Text>{description}</Text>
            {(review?.citations || []).map(citationLink)}
          </Space></List.Item>;
        }} /> : <Text type="secondary">扫描结果未记录证据义务；这不代表安全或义务已满足。</Text>}
      {result.initial_evidence?.context?.evidence_obligations_truncated &&
        <Alert className="section-gap" type="warning" showIcon message="静态证据义务列表已截断；本矩阵只覆盖发送给模型的条目。" />}
    </Card>
    <Descriptions bordered size="small" column={1}>
      <Descriptions.Item label="模型未核验标记的未支持陈述">{(assessment.unsupported_claims || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="模型未核验列出的未知项">{(assessment.unknowns || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="模型未核验的建议下一步">{(assessment.next_steps || []).join("；") || "无"}</Descriptions.Item>
      <Descriptions.Item label="限制">{(result.limitations || []).join("；") || "无"}</Descriptions.Item>
    </Descriptions>
    <Card size="small" title="人工评价 Agent 分诊（不改变候选或漏洞状态）">
      <Alert type="info" showIcon message="逐条判断每组引文能否支持对应模型主张。该语义复核只评价模型证据推理，不代表漏洞定性；有主张时必须逐条选择，不能确认就选“无法判断”。" />
      {reviews.length > 0 && <List className="section-gap" size="small" header={`追加复核记录（${reviews.length}）`} dataSource={reviews} renderItem={(review: any) =>
        <List.Item><Space direction="vertical"><Text>{review.reviewer} · {review.usefulness} · 引文：{review.citation_accuracy} · {review.elapsed_seconds ?? "未知"} 秒</Text>
          {!!review.post_review_disposition && <Text type="secondary">人工处置：{dispositionLabels[review.post_review_disposition] || review.post_review_disposition}</Text>}
          {!!review.claim_adjudications?.length && <Text type="secondary">逐条主张复核：{review.claim_adjudications.map((item: any) => claimSupportLabels[item.disposition] || "未知").join("；")}</Text>}
          {!!review.claims_to_correct && <Text type="secondary">需更正：{review.claims_to_correct}</Text>}
          {!!review.missed_evidence && <Text type="secondary">遗漏证据：{review.missed_evidence}</Text>}
          {!!review.notes && <Text type="secondary">{review.notes}</Text>}
        </Space></List.Item>} />}
      <Form className="section-gap" form={form} layout="vertical" onFinish={(value) => void saveReview(value)}
        initialValues={{ usefulness: "partially_useful", citation_accuracy: "not_checked", post_review_disposition: "investigate" }}>
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
          <Form.Item name="post_review_disposition" label="结果处置（追加审计记录）">
            <Select style={{ width: 220 }} options={[
              { value: "investigate", label: "继续调查" },
              { value: "likely_noise", label: "标记误报/噪声" },
              { value: "unknown", label: "保持未知" },
            ]} />
          </Form.Item>
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

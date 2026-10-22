import React from "react";
import { Alert, Button, Card, Collapse, Descriptions, Form, Input, InputNumber, List, Select, Space, Tag, Typography, message } from "antd";
import { useState } from "react";
import { go } from "../../components";
import { evidenceLocation, evidenceSourceLocation } from "./agentEvidenceLocation.js";
import { buildAgentOperationArtifactView } from "../cases/agentReportViewModel.js";
import { buildEvidenceGraphView } from "../cases/evidenceGraphViewModel.js";
import { artifactFailureMessage, structuredAnswerRejection } from "./agentValidationMessage.js";
import { agentToolIssues } from "./agentToolIssues.js";
import ChineseNarrative from "../cases/ChineseNarrative";
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
const analysisStatusLabels: Record<string, string> = {
  complete: "解析完成", completed: "解析完成", partial: "部分解析", failed: "解析失败",
  unsupported: "暂不支持", skipped: "已跳过", unknown: "未知",
};
const toolErrorLabels: Record<string, string> = { source_read_failed: "源码读取失败", symbol_not_found: "未找到符号", range_rejected: "源码范围不符合读取条件", timeout: "读取超时", unsupported_language: "暂不支持此源码格式" };
const toolStatusLabels: Record<string, string> = {
  completed: "已完成", accepted: "已接受", rejected: "已拒绝", failed: "失败",
  timed_out: "已超时", skipped: "已跳过", unknown: "未知",
};
const toolNameLabels: Record<string, string> = {
  inspect_guard: "检查保护条件", find_callers: "查找调用方", inspect_sink: "检查敏感操作",
  search_source: "搜索源码", read_source: "读取源码", find_symbol: "查找符号",
};
const usefulnessLabels: Record<string, string> = {
  useful: "有用", partially_useful: "部分有用", not_useful: "无用", unsafe: "有误导风险",
};
const obligationKindLabels: Record<string, string> = {
  source_trace_review: "源码依据与相关链追查", reachability: "入口与调用链", impact: "潜在安全影响", authorization: "权限边界",
  trigger: "触发条件", dataflow: "数据流", ownership: "对象归属",
  concurrency: "并发条件", bounds: "长度与边界", "evidence-obligation": "待核实事项",
};
const currencyLabels: Record<string, string> = { USD: "美元", CNY: "人民币" };
function DetailFold({ label, children }: { label: string; children: React.ReactNode }) {
  return <Collapse size="small" defaultActiveKey={[]} items={[{ key: "details", label, children }]} />;
}
function AgentArtifactDetails({ result, onCitation }: {
  result: any;
  onCitation: (citation: any, index: number) => React.ReactNode;
}) {
  const artifacts = buildAgentOperationArtifactView(result);
  if (!artifacts.artifactGeneration && !artifacts.vulnerabilityReport && !artifacts.pocDraft) return null;
  const renderCitations = (citations: any[]) => <List size="small" dataSource={citations}
    renderItem={(item: any, index: number) => <List.Item key={index}>
      {item.raw && typeof item.raw === "object" && !Array.isArray(item.raw) && item.raw.evidence_id
        ? onCitation(item.raw, index)
        : <Text>{item.displayText || [item.evidenceId, item.location, item.quote].filter(Boolean).join(" · ")}</Text>}
    </List.Item>} />;
  return <>
    {artifacts.vulnerabilityReport && <Card className="section-gap" size="small" title="智能调查候选漏洞报告">
      <Text type="secondary">{artifacts.vulnerabilityReport.boundary} · 仅供人工复核</Text>
      {artifacts.vulnerabilityReport.title && <Text strong className="section-gap" style={{ display: "block" }}><ChineseNarrative value={artifacts.vulnerabilityReport.title} /></Text>}
      {(artifacts.vulnerabilityReport.summary || artifacts.vulnerabilityReport.rootCause || artifacts.vulnerabilityReport.impact)
        && <Descriptions className="section-gap" bordered size="small" column={1}>
          {artifacts.vulnerabilityReport.summary && <Descriptions.Item label="摘要"><ChineseNarrative value={artifacts.vulnerabilityReport.summary} /></Descriptions.Item>}
          {artifacts.vulnerabilityReport.rootCause && <Descriptions.Item label="可能原因"><ChineseNarrative value={artifacts.vulnerabilityReport.rootCause} /></Descriptions.Item>}
          {artifacts.vulnerabilityReport.impact && <Descriptions.Item label="潜在影响"><ChineseNarrative value={artifacts.vulnerabilityReport.impact} /></Descriptions.Item>}
        </Descriptions>}
      {artifacts.vulnerabilityReport.preconditions.length > 0 && <div className="section-gap"><Text strong>前置条件</Text>
        <List size="small" dataSource={artifacts.vulnerabilityReport.preconditions} renderItem={(item: string) => <List.Item><ChineseNarrative value={item} /></List.Item>} />
      </div>}
      {artifacts.vulnerabilityReport.attackPath.length > 0 && <div className="section-gap"><Text strong>推测攻击路径</Text>
        <List size="small" dataSource={artifacts.vulnerabilityReport.attackPath} renderItem={(item: string, index: number) => <List.Item>{index + 1}. <ChineseNarrative value={item} /></List.Item>} />
      </div>}
      {artifacts.vulnerabilityReport.remediation && <Alert className="section-gap" type="info" showIcon
        message="修复建议（智能调查草案，待人工复核）" description={<ChineseNarrative value={artifacts.vulnerabilityReport.remediation} />} />}
      {artifacts.vulnerabilityReport.citations.length > 0 && <div className="section-gap"><Text strong>报告引用</Text>{renderCitations(artifacts.vulnerabilityReport.citations)}</div>}
    </Card>}
    {artifacts.pocDraft && <Card className="section-gap" size="small" title="智能调查生成的验证用例草案" extra={<Tag color="orange">{artifacts.pocDraft.statusLabel}</Tag>}>
      <Text type="secondary">{artifacts.pocDraft.boundary} · 草案未执行，需人工验证</Text>
      {artifacts.pocDraft.title && <Text strong className="section-gap" style={{ display: "block" }}><ChineseNarrative value={artifacts.pocDraft.title} /></Text>}
      {artifacts.pocDraft.language && <div className="section-gap">语言：<Text code>{artifacts.pocDraft.language}</Text></div>}
      {artifacts.pocDraft.prerequisites.length > 0 && <div className="section-gap"><Text strong>前置条件</Text>
        <List size="small" dataSource={artifacts.pocDraft.prerequisites} renderItem={(item: string) => <List.Item><ChineseNarrative value={item} /></List.Item>} />
      </div>}
      {artifacts.pocDraft.code.trim() && <Card className="section-gap" size="small" title="草案代码（仅文本展示，不执行）">
        <pre className="raw">{artifacts.pocDraft.code}</pre>
      </Card>}
      {artifacts.pocDraft.runSteps.length > 0 && <div className="section-gap"><Text strong>草案步骤（仅供人工审查）</Text>
        <List size="small" dataSource={artifacts.pocDraft.runSteps} renderItem={(item: string, index: number) => <List.Item>{index + 1}. <ChineseNarrative value={item} /></List.Item>} />
      </div>}
      {artifacts.pocDraft.expectedObservation && <Descriptions className="section-gap" bordered size="small" column={1}>
        <Descriptions.Item label="预期观察（未经验证）"><ChineseNarrative value={artifacts.pocDraft.expectedObservation} /></Descriptions.Item>
      </Descriptions>}
      {artifacts.pocDraft.negativeControl && <Descriptions className="section-gap" bordered size="small" column={1}>
        <Descriptions.Item label="负向对照"><ChineseNarrative value={artifacts.pocDraft.negativeControl} /></Descriptions.Item>
      </Descriptions>}
      {artifacts.pocDraft.citations.length > 0 && <div className="section-gap"><Text strong>验证用例草案引用</Text>{renderCitations(artifacts.pocDraft.citations)}</div>}
    </Card>}
    {artifacts.artifactGeneration && <DetailFold label="报告与验证用例生成记录">
      <Space wrap>
        <Tag color="blue">阶段：{artifacts.artifactGeneration.statusLabel}</Tag>
        <Tag>报告：{artifacts.artifactGeneration.reportStatusLabel}</Tag>
        <Tag>验证用例：{artifacts.artifactGeneration.pocStatusLabel}</Tag>
      </Space>
      <Text className="section-gap" type="secondary" style={{ display: "block" }}>
        本阶段模型调用：{artifacts.artifactGeneration.callsUsed === null
          ? "未记录"
          : artifacts.artifactGeneration.callsUsed + " 次" + (artifacts.artifactGeneration.maximumModelCalls === null
            ? ""
            : " / 最多 " + artifacts.artifactGeneration.maximumModelCalls + " 次")}
      </Text>
      <Alert className="section-gap" type="info" showIcon
        message="生成阶段不代表扫描完成、验证用例已执行或漏洞已确认。" />
    </DetailFold>}
  </>;
}
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
      message.success("人工评价已追加到智能调查操作记录");
    } catch (error) {
      message.error("保存人工评价失败，请稍后重试或检查服务状态。");
    } finally {
      setSaving(false);
    }
  };
  const assessment = result.agent_assessment || {}, binding = result.binding || {};
  const verdict = result.agent_verdict || {};
  const claims = Array.isArray(assessment.supported_claims) ? assessment.supported_claims : [];
  const context = result.initial_evidence?.context || {};
  const knowledgeRetrieval = result.knowledge_retrieval || context.knowledge_retrieval;
  const knowledgeReferences = Array.isArray(result.knowledge_references)
    ? result.knowledge_references
    : (Array.isArray(knowledgeRetrieval?.references) ? knowledgeRetrieval.references : []);
  const obligations = Array.isArray(context.evidence_obligations) ? context.evidence_obligations : [];
  const sourceCitationPolicy = typeof result.citation_evidence_policy === "string";
  const modelAnswerRetained = result.model_answer_retained !== false;
  const rejectionDescription = structuredAnswerRejection(
    result.structured_answer_validation, result.structured_answer_validation_error_code, result.validation_diagnostic || result.skeptic_review?.validation_diagnostic);
  const obligationReviews = Array.isArray(assessment.obligation_reviews) ? assessment.obligation_reviews : [];
  const toolIssues = agentToolIssues(result.tool_calls);
  const rawEvidenceGraph = result.evidence_graph || {};
  const evidenceGraphStages = Array.isArray(rawEvidenceGraph.nodes)
    ? rawEvidenceGraph.nodes.filter((node: any) => node.kind === "workflow_stage") : [];
  const obligationByIndex = new Map(obligationReviews.map((item: any) => [item.obligation_index, item]));
  const renderReportedList = (value: any, emptyLabel: string) => {
    if (!Array.isArray(value)) return <Text type="secondary">结果未记录</Text>;
    if (!value.length) return <Text type="secondary">{emptyLabel}</Text>;
    return <List size="small" dataSource={value} renderItem={(item: any) =>
      <List.Item><Text><ChineseNarrative value={typeof item === "string" ? item : JSON.stringify(item)} /></Text></List.Item>} />;
  };
  const claimObligationLabel = (indices: any) => Array.isArray(indices) && indices.length > 0
    ? <>{indices.map((index: any, position: number) => {
      const obligation = Number.isInteger(index) && index >= 0 ? obligations[index] : undefined;
      const description = typeof obligation === "string" ? obligation : obligation?.description;
      const kind = typeof obligation === "object" ? obligation?.kind : "";
      return <React.Fragment key={String(index)}>{position > 0 ? "；" : ""}#{index}{kind ? " · " + (obligationKindLabels[kind] || "待核实事项") : ""}{description ? <>：<ChineseNarrative value={description} /></> : ""}</React.Fragment>;
    })}</> : null;
  const citationLink = (citation: any, index: number) => {
    const location = evidenceSourceLocation(result, citation.evidence_id, citation.quote, citation);
    const label = citation.evidence_id + " · " + evidenceLocation(result, citation.evidence_id, citation.quote, citation) + "：“" + citation.quote + "”";
    return location && binding.job_id
      ? <Button key={index} type="link" size="small" className="source-citation-link"
          onClick={() => go("/tasks/" + encodeURIComponent(binding.job_id) + "?tab=source&source_file=" + encodeURIComponent(location.file) + "&source_line=" + location.line)}>{label}</Button>
      : <Text key={index} type="secondary">{label}</Text>;
  };
  const evidenceGraph = buildEvidenceGraphView(result.evidence_graph);
  const items = [
    { key: "initial", label: "初始候选上下文（原始记录）", children: <pre className="raw">{JSON.stringify(result.initial_evidence || {}, null, 2)}</pre> },
    { key: "tools", label: `只读工具记录（${(result.tool_calls || []).length}）`, children: <pre className="raw">{JSON.stringify(result.tool_calls || [], null, 2)}</pre> },
    { key: "trace", label: `模型调用记录（${(result.model_calls || []).length}）`, children: <pre className="raw">{JSON.stringify({ model_usage: result.model_usage, model_calls: result.model_calls }, null, 2)}</pre> },
    { key: "model-text", label: "未核验的模型自由文本", children: <Descriptions bordered size="small" column={1}>
      <Descriptions.Item label="模型原始摘要">{result.structured_answer_normalization?.status === "applied"
        ? "未展示：服务端隔离整理了权限等越界结论，原始模型摘要可能含有未核实判断。"
        : modelAnswerRetained ? <ChineseNarrative value={assessment.model_summary_unverified || assessment.summary || "旧结果未记录摘要"} /> : "\u672a\u4fdd\u7559\uff1a\u670d\u52a1\u7aef\u6821\u9a8c\u548c\u4e00\u6b21\u53d7\u9650\u4fee\u590d\u5747\u672a\u901a\u8fc7\u3002"}</Descriptions.Item>
      <Descriptions.Item label="模型列出的未支持陈述">{renderReportedList(assessment.unsupported_claims, "模型未列出未支持陈述。")}</Descriptions.Item>
      <Descriptions.Item label="模型列出的未知项">{renderReportedList(assessment.unknowns, "模型未列出未知项。")}</Descriptions.Item>
      <Descriptions.Item label="模型建议的下一步">{renderReportedList(assessment.next_steps, "模型未列出后续步骤。")}</Descriptions.Item>
    </Descriptions> },
  ];
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Card size="small" title="AI 研判概览" extra={<Tag>候选 · 待人工复核</Tag>}>
      <Space wrap>
        <Tag color={verdict.status === "analysis_failed" ? "error" : "blue"}>{agentVerdictLabel(verdict.status) || verdictLabels[verdict.status] || "尚无有效研判"}</Tag>
        <Text type="secondary">范围：{agentScopeLabel(verdict.scope)} · 置信度：{agentConfidenceLabel(verdict.confidence)}</Text>
      </Space>
      {rejectionDescription && <div style={{ marginTop: 8 }}><Text type="danger">{rejectionDescription}</Text></div>}
      {!rejectionDescription && artifactFailureMessage(result.artifact_generation) && <div style={{ marginTop: 8 }}><Text type="secondary">报告 / PoC 草稿未通过引用或格式校验；下方研判记录仍可查看，详情见“限制与失败详情”。</Text></div>}
      {result.structured_answer_normalization?.status === "applied" && <div style={{ marginTop: 8 }}><Text type="secondary">已保留通过引用校验的源码线索；权限等事项仍待人工核实。</Text></div>}
    </Card>
    <Card size="small" title="智能调查研判报告">
      <Alert type="info" showIcon
        message={result.summary_provenance === "server_generated_from_structured_triage"
          ? "依据结构化分诊字段生成的摘要"
          : "模型摘要（未核验）"}
        description={result.summary_provenance === "server_generated_from_structured_triage"
          ? <ChineseNarrative value={assessment.summary || "结构化结果未提供摘要。"} />
          : modelAnswerRetained
            ? <ChineseNarrative value={assessment.model_summary_unverified || assessment.summary || "结果未记录摘要。"} />
            : "模型原始答复未保留；请以结构化结果和固定源码证据为准。"} />
      <Descriptions bordered size="small" column={{ xs: 1, md: 2 }} className="section-gap">
        <Descriptions.Item label="模型分诊倾向">{labels[assessment.assessment] || (assessment.assessment ? <ChineseNarrative value={assessment.assessment} /> : "结果未记录")}</Descriptions.Item>
        <Descriptions.Item label="复核范围">{agentScopeLabel(verdict.scope)}</Descriptions.Item>
        <Descriptions.Item label="模型置信度">{agentConfidenceLabel(verdict.confidence)}</Descriptions.Item>
        <Descriptions.Item label="产品漏洞状态">{productStatusLabel(result.vulnerability_state || "candidate")}</Descriptions.Item>
        <Descriptions.Item label="固定源码位置">{context.file || binding.file || "结果未记录"}{(context.line || binding.line) ? ":" + (context.line || binding.line) : ""}</Descriptions.Item>
        <Descriptions.Item label="静态解析状态">{analysisStatusLabels[context.analysis_status] || "待核对"}</Descriptions.Item>
        <Descriptions.Item label="检测器 / 规则">{[context.detector_id, context.rule_id].filter(Boolean).join(" / ") || "结果未记录"}</Descriptions.Item>
        <Descriptions.Item label="固定提交 SHA-256">{context.commit || binding.commit || "结果未记录"}</Descriptions.Item>
      </Descriptions>
      {typeof context.source_excerpt === "string" && <DetailFold label={`固定提交源码摘录（${context.source_excerpt_start_line ?? "?"}–${context.source_excerpt_end_line ?? "?"} 行）`}>
        <pre className="raw">{context.source_excerpt || "固定源码摘录为空。"}</pre>
        {context.source_excerpt_truncated && <Text type="secondary">摘录经过长度限制；完整源码仍可在候选详情中查看。</Text>}
      </DetailFold>}
      {knowledgeRetrieval && <Card className="section-gap" size="small" title={`知识库参考资料（${knowledgeReferences.length}）`}>
        <Alert type="info" showIcon message={`本地 BM25 · ${knowledgeRetrieval.status || "未知"} · 索引 ${knowledgeRetrieval.indexed_files ?? 0} 个文件 · 语料 SHA-256 ${knowledgeRetrieval.corpus_sha256 || "不可用"}`}
          description={knowledgeRetrieval.disclaimer || "这些资料只供类比参考，不能证明当前候选、满足源码证据义务或作为当前漏洞结论的引用。"} />
        {knowledgeReferences.length ? <List className="section-gap" size="small" dataSource={knowledgeReferences} renderItem={(item: any) => <List.Item>
          <Space direction="vertical" style={{ width: "100%" }}>
            <Text strong>{item.path}:{item.start_line ?? "?"}–{item.end_line ?? "?"}</Text>
            <Text type="secondary">{item.summary || "参考资料"} · SHA-256 {item.sha256 || "未记录"}</Text>
            <pre className="raw">{item.excerpt || ""}</pre>
          </Space>
        </List.Item>} /> : <Text type="secondary">没有匹配的参考片段（{knowledgeRetrieval.status || "未知"}）。</Text>}
      </Card>}
      {claims.length > 0 && <Card className="section-gap" size="small" title={`模型列出的源码主张（${claims.length}）`}>
        <List size="small" dataSource={claims} renderItem={(item: any) => <List.Item>
          <Space direction="vertical" style={{ width: "100%" }}>
            <Text strong><ChineseNarrative value={item.claim || "主张文本未记录"} /></Text>
            {claimObligationLabel(item.obligation_indices) && <Text type="secondary">关联核查义务：{claimObligationLabel(item.obligation_indices)}</Text>}
            {(item.citations || []).length
              ? item.citations.map(citationLink)
              : <Text type="warning">未提供可展示的固定源码引句。</Text>}
          </Space>
        </List.Item>} />
      </Card>}
      <DetailFold label={`逐项证据核查与模型分诊（${obligations.length}）`}>
        <Alert type="info" showIcon message="模型标签仅表示本次研判记录，不代表义务已满足或漏洞已确认。" />
        {obligations.length > 0 ? <List className="section-gap" size="small" dataSource={obligations}
          renderItem={(obligation: any, index: number) => {
            const review: any = obligationByIndex.get(index);
            const description = typeof obligation === "string" ? obligation : obligation?.description || obligation?.kind || "义务描述未记录";
            const label = obligationLabels[review?.disposition] || (review ? "未知分诊标签" : "模型未提供逐项结果");
            return <List.Item><Space direction="vertical">
              <Text strong>#{index} · {obligationKindLabels[obligation?.kind] || "待核实事项"} · {label}</Text>
              <Text><ChineseNarrative value={description} /></Text>
              {(review?.citations || []).map(citationLink)}
            </Space></List.Item>;
          }} /> : <Text type="secondary">静态结果未记录证据义务；这不代表安全或义务已满足。</Text>}
        {context.evidence_obligations_truncated && <Alert className="section-gap" type="warning" showIcon message="静态证据义务列表已截断；报告只覆盖已保存并发送研判的条目。" />}
      </DetailFold>
      <div className="section-gap"><Text strong>模型列出的未知项</Text>{renderReportedList(assessment.unknowns, "模型未列出未知项。")}</div>
      <div className="section-gap"><Text strong>模型建议的后续步骤</Text>{renderReportedList(assessment.next_steps, "模型未列出后续步骤。")}</div>
      <div className="section-gap"><Text strong>未支持的模型陈述</Text>{renderReportedList(assessment.unsupported_claims, "模型未列出未支持陈述。")}</div>

    </Card>
    <AgentArtifactDetails result={result} onCitation={citationLink} />
    <DetailFold label="限制与失败详情（点击展开）">
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Alert type={verdict.status === "analysis_failed" ? "error" : ["unknown", "needs_more_evidence"].includes(verdict.status) ? "warning" : "info"} showIcon
      message={agentVerdictLabel(verdict.status) || verdictLabels[verdict.status] || "模型尚未形成有效分诊结果"}
      description={`复核范围：${agentScopeLabel(verdict.scope)}；模型置信度：${agentConfidenceLabel(verdict.confidence)}；产品状态：${productStatusLabel(verdict.product_status)}。${agentVerdictReasonLabel(verdict.reason)} 产品漏洞状态仍为 ${productStatusLabel(result.vulnerability_state || "candidate")}，已验证漏洞数 ${result.validated_vulnerability ?? 0}；产品可达性和影响仍需后续证据。`} />
    {artifactFailureMessage(result.artifact_generation) && <Alert type="warning" showIcon message="报告 / PoC 草稿未通过校验" description={artifactFailureMessage(result.artifact_generation)} />}
    {rejectionDescription && <Alert type="error" showIcon message="模型结构化答复未通过服务端校验" description={rejectionDescription} />}
    {(toolIssues.length > 0 || (result.model_tool_calls_skipped || 0) > 0) && <Alert type="warning" showIcon message={`只读工具有 ${toolIssues.length + (result.model_tool_calls_skipped || 0)} 项未完成，相关证据可能不完整`} description={<List size="small" dataSource={toolIssues} renderItem={(item: any) => <List.Item><Text><Text strong>{toolNameLabels[item.tool] || "其他只读工具"}</Text> · {toolStatusLabels[item.status] || "待核对"} · 错误类型：{toolErrorLabels[item.errorCode] || "其他错误"}：<ChineseNarrative value={item.message} /></Text></List.Item>} footer={(result.model_tool_calls_skipped || 0) > 0 ? `另有 ${result.model_tool_calls_skipped} 个模型请求因工具调用预算耗尽而未执行；对应证据保持未决。` : null} />} />}
    <Alert type="warning" showIcon message="源码引句存在 ≠ 陈述已证实" description={sourceCitationPolicy ? `支持性主张和已判定义务只能引用固定提交中的源码摘录；扫描器义务描述、提交历史只作检索上下文，不能当作源码证明。服务端核对了 ${result.citation_integrity?.citation_count ?? "未知"} 条引句的来源类型和逐字存在性，但仍未验证引句是否在语义上支持模型推理。摘要由服务端从结构化分诊字段生成；模型原始摘要、未支持陈述、未知项和下一步建议仍是未核验文本。` : "这是较早版本的结果，未记录“只能引用源码证据”的策略版本；请人工确认每条引句确实来自固定提交源码，并逐项判断它是否支持模型陈述。摘要和其他模型自由文本均不能当作已验证结论。"} />
        <div><Text strong>完整结果限制</Text>{renderReportedList(result.limitations, "结果未记录额外限制。")}</div>
      </Space>
    </DetailFold>
    {evidenceGraph && <DetailFold label={`跨文件证据链 · ${evidenceGraph.statusLabel}`}>
      <Alert type="info" showIcon message="固定版本追踪结果"
        description={<>{evidenceGraph.binding.repository || "仓库未记录"} · 提交 <Text code>{evidenceGraph.binding.commit || "未知"}</Text> · {evidenceGraph.evidence.length} 份来源记录、{evidenceGraph.citations.length} 条引用关系。该图用于核对智能调查从候选到其他源码位置的调查路径；引用位置已绑定固定源码，但系统没有自动判断引句是否在语义上证明主张。</>} />
      {evidenceGraph.stages.length > 0 && <List className="section-gap" size="small" header={<Text strong>调查阶段</Text>}
        dataSource={evidenceGraph.stages} renderItem={(stage: any) => <List.Item>
          <Space wrap><Text>{stage.label}</Text><Tag color={["completed", "accepted"].includes(stage.status) ? "green" : stage.status === "running" ? "blue" : "orange"}>{stage.statusLabel}</Tag></Space>
        </List.Item>} />}
      {evidenceGraph.citations.length > 0 && <List className="section-gap" size="small" header={<Text strong>源码引用关系</Text>}
        dataSource={evidenceGraph.citations} renderItem={(edge: any) => <List.Item>
          <Space direction="vertical" size={2} style={{ width: "100%" }}>
            <Space wrap><Tag>{edge.stageLabel}</Tag><Text strong>{edge.label}</Text>
              {binding.job_id && edge.file && edge.line
                ? <Button type="link" size="small" onClick={() => go("/tasks/" + encodeURIComponent(binding.job_id) + "?tab=source&source_file=" + encodeURIComponent(edge.file) + "&source_line=" + edge.line)}>{edge.location}</Button>
                : <Text code>{edge.location}</Text>}
            </Space>
            <Text type="secondary">来源 {edge.evidenceId || "未记录"}；引用语义由人工复核，不能直接作为漏洞确认依据。</Text>
          </Space>
        </List.Item>} />}
      {evidenceGraph.unresolved.length > 0 && <Alert className="section-gap" type="warning" showIcon message={"有 " + evidenceGraph.unresolved.length + " 条引用未绑定到固定源码"}
        description={<List size="small" dataSource={evidenceGraph.unresolved} renderItem={(item: any) => <List.Item>{item.stageLabel} · {item.file || "文件未记录"} · <ChineseNarrative value={item.reason} /></List.Item>} />} />}
      <Text type="secondary">漏洞状态：{productStatusLabel(evidenceGraph.productState)}；已确认漏洞：{evidenceGraph.validatedVulnerability}。{evidenceGraph.boundary}</Text>
    </DetailFold>}
    {binding.job_id && binding.candidate_id && <Button type="primary" onClick={() => go(`/tasks/${encodeURIComponent(binding.job_id)}?tab=findings&candidate_id=${encodeURIComponent(binding.candidate_id)}`)}>打开该候选人工复核</Button>}
    <DetailFold label="模型调用、用量与来源信息">
    <Descriptions bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="分诊倾向">{labels[assessment.assessment] || (assessment.assessment ? <ChineseNarrative value={assessment.assessment} /> : "尚无结果")}</Descriptions.Item>
      <Descriptions.Item label="模式">{result.mode === "single_shot" ? "AI 初步分析" : "AI 深入追查"}</Descriptions.Item>
      <Descriptions.Item label="模型">{result.provider?.model || "—"}</Descriptions.Item>
      <Descriptions.Item label="外发目的地">{result.source_submission?.destination_host || "—"}</Descriptions.Item>
      <Descriptions.Item label="候选">{binding.candidate_id || "—"}</Descriptions.Item>
      <Descriptions.Item label="扫描代码版本">{binding.commit || "—"}</Descriptions.Item>
      <Descriptions.Item label="源码位置" span={2}>{binding.file || "—"}</Descriptions.Item>
      <Descriptions.Item label="模型用量（令牌）">{result.model_usage ? (result.model_usage.total_tokens ?? "未知") + " 个令牌；" + (result.model_usage.local_cumulative_token_budget === "none" ? "平台累计上限：无" : "历史任务输入/输出预算 " + (result.model_usage.input_budget_tokens ?? "未知") + "/" + (result.model_usage.output_budget_tokens ?? "未知")) + "；" + (result.model_usage.per_request_output_limit_policy === "none_locally_provider_model_default_applies" ? "平台单次输出上限：无（模型或服务商限制仍适用）" : result.model_usage.per_request_output_limit_tokens == null ? "单次输出上限：未知" : "单次输出上限 " + result.model_usage.per_request_output_limit_tokens + " 个令牌") : "—"}</Descriptions.Item>
      <Descriptions.Item label="缓存命中输入（输入内）">{result.model_usage?.cached_input_tokens ?? "未知"} 个令牌</Descriptions.Item>
      <Descriptions.Item label="推理令牌（输出内）">{result.model_usage?.reasoning_tokens ?? "未知"} 个令牌</Descriptions.Item>
      <Descriptions.Item label="结构化修复次数">{result.validation_repair_attempts ?? "旧结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="模型服务商实际费用">{result.model_usage?.cost === "unknown" ? "未知" : result.model_usage?.cost || "未知"}</Descriptions.Item>
      <Descriptions.Item label="估算费用">{result.model_usage?.cost_estimate?.status === "estimated_range"
        ? <Space wrap><Text>{currencyLabels[result.model_usage.cost_estimate.currency] || result.model_usage.cost_estimate.currency} {result.model_usage.cost_estimate.minimum_usd}–{result.model_usage.cost_estimate.maximum_usd}；费率快照 {result.model_usage.cost_estimate.rate_card_id}；非实账</Text><a href={result.model_usage.cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
        : result.model_usage?.cost_estimate?.status === "estimated_amount"
          ? <Space wrap><Text>美元 {result.model_usage.cost_estimate.amount_usd}{result.model_usage.cost_estimate.amount_cny ? " / 人民币 " + result.model_usage.cost_estimate.amount_cny : ""}；美元与人民币为独立官方价目参考；费率快照 {result.model_usage.cost_estimate.rate_card_id}；非实账</Text><a href={result.model_usage.cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
        : "未知"}</Descriptions.Item>
    </Descriptions>
    </DetailFold>
    {claims.length > 0 && <Card size="small" title="人工逐条复核模型主张">{claims.map((item: any, index: number) => <div className="obligation" key={index}>
      <Text strong><ChineseNarrative value={item.claim || "主张文本未记录"} /></Text>
      {claimObligationLabel(item.obligation_indices) ? <div><Text type="secondary">关联核查义务：{claimObligationLabel(item.obligation_indices)}</Text></div>
        : <div><Text type="warning">结果未记录结构化义务关联；需人工核对。</Text></div>}
      {(item.citations || []).map(citationLink)}
      <Select className="section-gap" style={{ width: 280 }} placeholder="逐条判断引文与主张的关系"
        value={claimAdjudications[index]}
        onChange={(value) => setClaimAdjudications((current) => ({ ...current, [index]: value }))}
        options={[
          { value: "supported", label: "引文支持主张" },
          { value: "partially_supported", label: "部分支持" },
          { value: "unsupported", label: "不支持" },
          { value: "unverifiable", label: "无法判断" },
        ]} />
      {(item.evidence_ids || []).length > 0 && <div><Text type="secondary">旧结果引用：{item.evidence_ids.join(", ")}</Text></div>}
    </div>)}</Card>}
    <Card size="small" title="人工评价智能调查意见（不改变候选或漏洞状态）">
      <Alert type="info" showIcon message="逐条判断每组引文能否支持对应模型主张。该语义复核只评价模型证据推理，不代表漏洞定性；有主张时必须逐条选择，不能确认就选“无法判断”。" />
      {reviews.length > 0 && <List className="section-gap" size="small" header={`追加复核记录（${reviews.length}）`} dataSource={reviews} renderItem={(review: any) =>
        <List.Item><Space direction="vertical"><Text>{review.reviewer} · {usefulnessLabels[review.usefulness] || "未记录"} · 引文准确性：{({ all_accurate: "全部准确", some_incorrect: "存在错误", mostly_incorrect: "大多错误", not_checked: "未核对" } as Record<string, string>)[review.citation_accuracy] || "未记录"} · {review.elapsed_seconds ?? "未知"} 秒</Text>
          {!!review.post_review_disposition && <Text type="secondary">人工处置：{dispositionLabels[review.post_review_disposition] || review.post_review_disposition}</Text>}
          {!!review.claim_adjudications?.length && <Text type="secondary">逐条主张复核：{review.claim_adjudications.map((item: any) => claimSupportLabels[item.disposition] || "未知").join("；")}</Text>}
          {!!review.claims_to_correct && <Text type="secondary">需更正：<ChineseNarrative value={review.claims_to_correct} /></Text>}
          {!!review.missed_evidence && <Text type="secondary">遗漏证据：<ChineseNarrative value={review.missed_evidence} /></Text>}
          {!!review.notes && <Text type="secondary"><ChineseNarrative value={review.notes} /></Text>}
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
        <Button type="primary" htmlType="submit" loading={saving}>提交复核结果</Button>
      </Form>
    </Card>
    <Collapse items={items} />
  </Space>;
}

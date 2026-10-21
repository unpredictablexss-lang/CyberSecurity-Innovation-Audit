import React from "react";
import { Alert, Card, Collapse, Descriptions, Empty, List, Space, Tag, Typography } from "antd";
import { caseReportAgentFeedbackBoundary, caseReportOperationScopeLabel, caseReportView } from "./reportModel.js";
import { buildAgentReportView } from "./agentReportViewModel.js";
import PocValidationPlan from "./PocValidationPlan";

const { Paragraph, Text } = Typography;
const stateLabels: Record<string, string> = {
  candidate: "候选", completed: "已完成", completed_with_limitations: "已完成（有限制）",
  blocked: "受阻", failed: "失败", interrupted: "中断", cancelled: "已取消",
};
const triageLabels: Record<string, string> = {
  likely_true_positive: "倾向真实候选", likely_false_positive: "倾向误报",
  needs_more_evidence: "需要更多证据", unknown: "未知",
};
const jsonText = (value: any) => JSON.stringify(value ?? {}, null, 2);
const listValue = (value: any) => Array.isArray(value) ? value : [];
function ReadOnlyList({ items, empty }: { items: any[]; empty: string }) {
  if (!items.length) return <Text type="secondary">{empty}</Text>;
  return <List size="small" dataSource={items} renderItem={(item: any) =>
    <List.Item>{typeof item === "string" ? item : jsonText(item)}</List.Item>} />;
}
function CitationList({ items }: { items: any[] }) {
  if (!items.length) return <Text type="secondary">结果未提供引用。</Text>;
  return <List size="small" dataSource={items} renderItem={(item: any) =>
    <List.Item><Space direction="vertical" style={{ width: "100%" }}>
      {item.displayText
        ? <Text>{item.displayText}</Text>
        : <>
          <Space wrap>
            {item.evidenceId && <Text code>{item.evidenceId}</Text>}
            {item.location && <Text type="secondary">{item.location}</Text>}
          </Space>
          {item.quote && <Paragraph style={{ marginBottom: 0 }}>{item.quote}</Paragraph>}
          <details><summary>查看原始引用记录</summary><pre className="raw">{jsonText(item.raw)}</pre></details>
        </>}
    </Space></List.Item>} />;
}
function AgentGeneratedReports({ triage }: { triage: any }) {
  const { vulnerabilityReport, pocDraft, artifactGeneration } = buildAgentReportView(triage);
  return <>
    {artifactGeneration && <Card className="section-gap" size="small" title="报告 / PoC 生成阶段">
      <Space wrap>
        <Tag color="blue">阶段：{artifactGeneration.statusLabel}</Tag>
        <Tag>报告：{artifactGeneration.reportStatusLabel}</Tag>
        <Tag>PoC：{artifactGeneration.pocStatusLabel}</Tag>
      </Space>
      <Paragraph className="section-gap" type="secondary">
        报告 / PoC 阶段模型调用：{artifactGeneration.callsUsed === null
          ? "未记录"
          : artifactGeneration.callsUsed + " 次" + (artifactGeneration.maximumModelCalls === null
            ? ""
            : " / 最多 " + artifactGeneration.maximumModelCalls + " 次")}
      </Paragraph>
      <Alert type="info" showIcon
        message="这里只显示报告与 PoC 草案生成阶段状态"
        description="阶段状态和调用数不代表扫描任务完成、PoC 已执行或漏洞已确认。" />
    </Card>}
    {vulnerabilityReport && <Card className="section-gap" size="small" title="AI 候选漏洞报告">
      <Alert type="warning" showIcon message={vulnerabilityReport.boundary}
        description="报告内容来自绑定到本次 Agent 操作的结构化结果，仅供人工复核，不是 confirmed 漏洞结论。" />
      {vulnerabilityReport.title && <Paragraph><Text strong>{vulnerabilityReport.title}</Text></Paragraph>}
      {vulnerabilityReport.summary && <Card className="section-gap" size="small" title="摘要"><Paragraph>{vulnerabilityReport.summary}</Paragraph></Card>}
      {vulnerabilityReport.rootCause && <Card className="section-gap" size="small" title="可能原因"><Paragraph>{vulnerabilityReport.rootCause}</Paragraph></Card>}
      {vulnerabilityReport.impact && <Card className="section-gap" size="small" title="潜在影响"><Paragraph>{vulnerabilityReport.impact}</Paragraph></Card>}
      {vulnerabilityReport.preconditions.length > 0 && <Card className="section-gap" size="small" title="前置条件">
        <List size="small" dataSource={vulnerabilityReport.preconditions} renderItem={(item: string) => <List.Item>{item}</List.Item>} />
      </Card>}
      {vulnerabilityReport.attackPath.length > 0 && <Card className="section-gap" size="small" title="推测攻击路径">
        <List size="small" dataSource={vulnerabilityReport.attackPath} renderItem={(item: string, index: number) =>
          <List.Item><Text>{index + 1}. {item}</Text></List.Item>} />
      </Card>}
      {vulnerabilityReport.remediation && <Card className="section-gap" size="small" title="修复方向"><Paragraph>{vulnerabilityReport.remediation}</Paragraph></Card>}
      {vulnerabilityReport.citations.length > 0 && <Card className="section-gap" size="small" title={"报告引用（" + vulnerabilityReport.citations.length + "）"}>
        <CitationList items={vulnerabilityReport.citations} />
      </Card>}
    </Card>}
    {pocDraft && <Card className="section-gap" size="small" title="AI PoC 草案" extra={<Tag color="orange">{pocDraft.statusLabel}</Tag>}>
      <Alert type="warning" showIcon message={pocDraft.boundary}
        description={pocDraft.status === "insufficient_evidence"
          ? "该 Agent 结果标记证据不足。以下仅展示已绑定结果中的草案字段，不会执行，也不能证明漏洞成立。"
          : "以下仅展示已绑定 Agent 结果中的 PoC 草案，不会执行或验证，也不能证明漏洞成立。"} />
      {pocDraft.title && <Paragraph className="section-gap"><Text strong>{pocDraft.title}</Text></Paragraph>}
      {pocDraft.language && <Paragraph>语言：<Text code>{pocDraft.language}</Text></Paragraph>}
      {pocDraft.prerequisites.length > 0 && <Card className="section-gap" size="small" title="前置条件">
        <List size="small" dataSource={pocDraft.prerequisites} renderItem={(item: string) => <List.Item>{item}</List.Item>} />
      </Card>}
      {pocDraft.code.trim() && <Card className="section-gap" size="small" title="草案代码（仅文本展示，不执行）">
        <pre className="raw">{pocDraft.code}</pre>
      </Card>}
      {pocDraft.runSteps.length > 0 && <Card className="section-gap" size="small" title="草案步骤（仅供人工审查）">
        <List size="small" dataSource={pocDraft.runSteps} renderItem={(item: string, index: number) =>
          <List.Item><Text>{index + 1}. {item}</Text></List.Item>} />
      </Card>}
      {pocDraft.expectedObservation && <Card className="section-gap" size="small" title="预期观察（未经验证）"><Paragraph>{pocDraft.expectedObservation}</Paragraph></Card>}
      {pocDraft.negativeControl && <Card className="section-gap" size="small" title="负向对照"><Paragraph>{pocDraft.negativeControl}</Paragraph></Card>}
      {pocDraft.citations.length > 0 && <Card className="section-gap" size="small" title={"草案引用（" + pocDraft.citations.length + "）"}>
        <CitationList items={pocDraft.citations} />
      </Card>}
    </Card>}
  </>;
}
function CandidateEvidence({ row, operations }: { row: any; operations: any[] }) {
  const candidate = row.candidate || {};
  const sourceEvidence = listValue(row.source_evidence);
  const reviews = listValue(row.reviews);
  return <Card size="small" title={(candidate.file || "未知文件") + ":" + (candidate.line ?? "?") + " · " + (candidate.detector_id || "未知检测器") + " / " + (candidate.rule_id || "未知规则")}>
    <Space wrap>
      <Tag color="orange">candidate</Tag><Tag>影响范围 unknown</Tag><Tag>{candidate.severity || "未分级"}</Tag>
      {candidate.confidence && <Tag>{candidate.confidence}</Tag>}
    </Space>
    <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="固定来源">{row.repository || "unknown"} @ {row.commit || "unknown"}</Descriptions.Item>
      <Descriptions.Item label="扫描报告 SHA-256">{row.report_sha256 || "未记录"}</Descriptions.Item>
      <Descriptions.Item label="候选 ID">{candidate.id || "未记录"}</Descriptions.Item>
      <Descriptions.Item label="扫描器描述">{candidate.message || "未记录"}</Descriptions.Item>
    </Descriptions>
    {row.rationale && <Paragraph>关联理由：{row.rationale}</Paragraph>}
    <Card size="small" title={"人工登记源码证据（" + sourceEvidence.length + "）"}>
      {sourceEvidence.length
        ? <List size="small" dataSource={sourceEvidence} renderItem={(item: any) =>
          <List.Item><Space direction="vertical">
            <Text strong>{item.file || candidate.file || "未知文件"}:{item.start_line ?? "?"}{item.end_line ? "–" + item.end_line : ""} · {item.kind || "人工证据"}</Text>
            <Text>{item.note || item.observation || "未记录说明"}</Text>
            <Text type="secondary">证据 ID：{item.id || "未记录"}</Text>
          </Space></List.Item>} />
        : <Text type="secondary">尚未登记人工源码证据。</Text>}
    </Card>
    <Card className="section-gap" size="small" title={"候选复核记录（" + reviews.length + "）"}>
      {reviews.length
        ? <List size="small" dataSource={reviews} renderItem={(item: any) =>
          <List.Item><Space direction="vertical">
            <Text strong>{item.status || "未记录"} · {item.reviewer || "未知复核人"}</Text>
            <Text>{item.notes || "未记录说明"}</Text><Text type="secondary">{item.created_at || ""}</Text>
          </Space></List.Item>} />
        : <Text type="secondary">尚无候选级人工复核记录。</Text>}
    </Card>
    <PocValidationPlan candidateRow={row} operations={operations} />
  </Card>;
}
function AgentOperation({ operation }: { operation: any }) {
  const triage = operation.agent_triage || {};
  const binding = triage.binding || {};
  const initial = triage.initial_evidence || {};
  const context = initial.context || {};
  const claims = listValue(triage.supported_claims);
  const obligations = listValue(context.evidence_obligations);
  const obligationReviews = listValue(triage.obligation_reviews);
  const reviews = listValue(triage.human_reviews);
  const suggestions = listValue(triage.repair_guidance?.items);
  const rawItems = [
    { key: "initial", label: "初始候选上下文（原始记录）", children: <pre className="raw">{jsonText(initial)}</pre> },
    { key: "tools", label: "只读工具轨迹（" + listValue(triage.tool_calls).length + "）", children: <pre className="raw">{jsonText(triage.tool_calls)}</pre> },
    { key: "model", label: "模型调用与用量（" + listValue(triage.model_calls).length + "）", children: <pre className="raw">{jsonText({ model_usage: triage.model_usage, model_calls: triage.model_calls })}</pre> },
    { key: "consent", label: "源码外发授权绑定", children: <pre className="raw">{jsonText({ source_submission: triage.source_submission, binding, prompt_version: triage.prompt_version, tool_policy_version: triage.tool_policy_version })}</pre> },
  ];
  return <Card size="small" title={"Agent 分诊 · " + operation.id}>
    <Alert type="warning" showIcon message={"仅是模型辅助分诊：" + (triageLabels[triage.assessment] || triage.assessment || "未知") + "；漏洞状态 " + (triage.vulnerability_state || "candidate")}
      description="源码引句逐字存在不代表语义主张成立。Agent 结果、人工对 Agent 的有用性评价，都不替代产品验证或人工漏洞结论。" />
    <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="结果 SHA-256">{operation.result_sha256 || "未记录"}</Descriptions.Item>
      <Descriptions.Item label="实验 ID">{triage.experiment_id || "未关联实验"}</Descriptions.Item>
      <Descriptions.Item label="固定来源">{binding.repository || "unknown"} @ {binding.commit || "unknown"}</Descriptions.Item>
      <Descriptions.Item label="固定位置">{binding.file || context.file || "unknown"}{binding.line || context.line ? ":" + (binding.line || context.line) : ""}</Descriptions.Item>
      <Descriptions.Item label="候选 ID">{binding.candidate_id || "未记录"}</Descriptions.Item>
      <Descriptions.Item label="摘要来源">{triage.summary_provenance || "未记录"}</Descriptions.Item>
    </Descriptions>
    <Card className="section-gap" size="small" title="研判摘要">
      <Paragraph>{triage.summary || "结果未记录摘要。"}</Paragraph>
      {triage.model_summary_unverified && <details><summary>查看未经核验的模型原始摘要</summary><Paragraph>{triage.model_summary_unverified}</Paragraph></details>}
    </Card>
    <Card className="section-gap" size="small" title={"模型列出的源码主张（" + claims.length + "）"}>
      {claims.length
        ? <List size="small" dataSource={claims} renderItem={(claim: any) =>
          <List.Item><Space direction="vertical" style={{ width: "100%" }}>
            <Text strong>{claim.claim || "主张未记录"}</Text>
            {(claim.citations || []).length
              ? claim.citations.map((citation: any, index: number) =>
                <Text key={index} type="secondary">{citation.evidence_id || "证据"}{citation.file ? " · " + citation.file + ":" + (citation.line_start ?? "?") + "–" + (citation.line_end ?? "?") : ""}：“{citation.quote || "未记录引句"}”</Text>)
              : <Text type="warning">没有可展示的源码引句。</Text>}
            {Array.isArray(claim.obligation_indices) && <Text type="secondary">关联证据义务：{claim.obligation_indices.map((i: any) => "#" + i).join("、") || "未关联"}</Text>}
          </Space></List.Item>} />
        : <Text type="secondary">结果未记录结构化主张。</Text>}
    </Card>
    <Card className="section-gap" size="small" title={"证据义务分诊（" + obligations.length + "）"}>
      {obligations.length ? <List size="small" dataSource={obligations} renderItem={(item: any, index: number) => {
        const review = obligationReviews.find((row: any) => row.obligation_index === index);
        return <List.Item><Space direction="vertical">
          <Text strong>#{index} · {item?.kind || "证据义务"} · {review?.disposition || "未逐项复核"}</Text>
          <Text>{typeof item === "string" ? item : item?.description || "义务描述未记录"}</Text>
          {(review?.citations || []).map((citation: any, citationIndex: number) =>
            <Text key={citationIndex} type="secondary">{citation.evidence_id || "证据"}：“{citation.quote || "无引句"}”</Text>)}
        </Space></List.Item>;
      }} /> : <Text type="secondary">初始上下文未记录证据义务；不代表义务已满足。</Text>}
      {context.evidence_obligations_truncated && <Alert className="section-gap" type="warning" showIcon message="初始上下文中的证据义务已截断。" />}
    </Card>
    <Descriptions className="section-gap" bordered size="small" column={1}>
      <Descriptions.Item label="模型列出的未知项"><ReadOnlyList items={listValue(triage.unknowns)} empty="未记录未知项。" /></Descriptions.Item>
      <Descriptions.Item label="未支持陈述"><ReadOnlyList items={listValue(triage.unsupported_claims)} empty="未记录未支持陈述。" /></Descriptions.Item>
      <Descriptions.Item label="建议后续调查"><ReadOnlyList items={listValue(triage.next_steps)} empty="未记录后续步骤。" /></Descriptions.Item>
      <Descriptions.Item label="调查限制"><ReadOnlyList items={listValue(triage.limitations)} empty="未记录额外限制。" /></Descriptions.Item>
    </Descriptions>
    <Card className="section-gap" size="small" title={"修复 / 验证方向（" + suggestions.length + "）"}>
      <Alert type="info" showIcon message="未经验证的模型建议" description="当前没有生成或应用补丁；每条建议需由人工审查，并在固定版本上单独验证。" />
      <ReadOnlyList items={suggestions} empty="该 Agent 结果没有列出修复或验证方向。" />
    </Card>
    <AgentGeneratedReports triage={triage} />
    <Card className="section-gap" size="small" title={"人工 Agent 反馈（" + reviews.length + "）"}>
      <Paragraph type="secondary">{caseReportAgentFeedbackBoundary(reviews)}</Paragraph>
      {reviews.length ? <List size="small" dataSource={reviews} renderItem={(review: any) =>
        <List.Item><Space direction="vertical">
          <Text strong>{review.reviewer || "未知复核人"} · 有用性 {review.usefulness || "未记录"} · 引文准确性 {review.citation_accuracy || "未记录"}</Text>
          <Text>复核耗时：{review.elapsed_seconds ?? "未记录"} 秒；处理后意见：{review.post_review_disposition || "未记录"}</Text>
          {review.claims_to_correct && <Text>需更正：{review.claims_to_correct}</Text>}
          {review.missed_evidence && <Text>遗漏证据：{review.missed_evidence}</Text>}
          {review.notes && <Text>备注：{review.notes}</Text>}
        </Space></List.Item>} /> : <Text type="secondary">无绑定到该操作的人工反馈记录。</Text>}
      <Alert className="section-gap" type="warning" showIcon message="本案例报告没有独立盲评或模型准确率结论。" description="如需比较实验效果，应查看绑定同一 experiment_id 的配对/盲评记录；本页的人工反馈只评价单次 Agent 分诊。" />
    </Card>
    <Collapse className="section-gap" items={rawItems} />
  </Card>;
}
function ValidationOperation({ operation }: { operation: any }) {
  const evidence = operation.validation_evidence || {};
  const revisions = Object.entries(evidence.revisions || {}) as [string, any][];
  return <Card size="small" title={"固定验证 Harness · " + operation.id}>
    <Alert type={operation.validation_gate === "passed" ? "warning" : "info"} showIcon
      message={"组件验证门：" + (operation.validation_gate || "未知") + "；产品可达性：" + (operation.reachability_status || "unknown") + "；计入确认数：" + (operation.validated_vulnerability ?? 0)}
      description="组件 Harness 的固定输入与重复运行结果只能支持组件级观察；不能据此推断生产产品入口可达或漏洞已确认。" />
    <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="Harness">{evidence.harness_id || "旧结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="操作状态">{stateLabels[operation.status] || operation.status || "未知"}</Descriptions.Item>
      <Descriptions.Item label="目标仓库">{evidence.target_repository || "结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="目标固定提交">{evidence.target_commit || operation.commit || "结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="支持库固定提交">{evidence.cutils_commit || "结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="容器退出码">{evidence.docker_exit_code ?? "结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="输入清单 SHA-256">{evidence.input_manifest_sha256 || "结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="执行命令 SHA-256">{evidence.validation_command_sha256 || "结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="容器日志 SHA-256">{evidence.docker_log_sha256 || "结果未记录"}</Descriptions.Item>
      <Descriptions.Item label="门控说明">{operation.gate_reason || "未记录"}</Descriptions.Item>
    </Descriptions>
    {revisions.length ? <Card className="section-gap" size="small" title={"固定版本结果（" + revisions.length + "）"}>
      <List size="small" dataSource={revisions} renderItem={([name, revision]) => {
        const build = revision.build || {}, replay = revision.replay || {};
        const cases = Array.isArray(revision.replay_cases) ? revision.replay_cases : [];
        return <List.Item><Space direction="vertical" style={{ width: "100%" }}>
          <Text strong>{name} · {revision.commit || "提交未记录"}</Text>
          <Text>构建退出码：{build.returncode ?? "未知"}；重放：{replay.label || "未知"}；全部案例匹配：{String(replay.all_cases_match ?? "未知")}；触发次数：{replay.triggered ?? "未知"} / {replay.attempts ?? "未知"}</Text>
          {Object.keys(build).length > 0 && <Text type="secondary">编译器：{build.compiler || "未记录"} {build.compiler_version || ""}；sanitizer：{(build.sanitizers || []).join(", ") || "未记录"}</Text>}
          {cases.length > 0 && <List size="small" dataSource={cases} renderItem={(item: any) =>
            <List.Item><Text>{item.case_id || "案例"} · {item.role || "角色未记录"}：预期 {jsonText(item.expected)}；观察 {jsonText(item.observed)}；匹配 {jsonText(item.matches_expectation)}</Text></List.Item>} />}
          {revision.expectations_met && <Text type="secondary">预期检查：{jsonText(revision.expectations_met)}</Text>}
        </Space></List.Item>;
      }} />
    </Card> : <Empty description="此操作没有包含可读的逐版本 Harness 结果；请查看操作状态与结果摘要。" />}
    {evidence.patched_revision && <Card className="section-gap" size="small" title="补丁重放绑定">
      <Descriptions size="small" column={1}>
        <Descriptions.Item label="合成提交">{evidence.patched_revision.synthetic_commit || "未记录"}</Descriptions.Item>
        <Descriptions.Item label="基线提交">{evidence.patched_revision.base_commit || "未记录"}</Descriptions.Item>
        <Descriptions.Item label="上游修复提交">{evidence.patched_revision.fixed_commit || "未记录"}</Descriptions.Item>
        <Descriptions.Item label="补丁 SHA-256">{evidence.patched_revision.patch_sha256 || "未记录"}</Descriptions.Item>
      </Descriptions>
    </Card>}
    <ReadOnlyList items={listValue(evidence.limitations)} empty="验证结果未记录限制。" />
  </Card>;
}
export default function CaseEvidenceReport({ report }: { report: any }) {
  const view = caseReportView(report);
  return <Card size="small" className="section-gap" title="案例证据与调查报告">
    <Alert type="info" showIcon message={caseReportOperationScopeLabel(view.operationScope)}
      description={"报告保留 " + view.candidates.length + " 条关联候选；操作结果展开 " + view.operationScope.included + " 条。经人工门控确认数：" + view.validatedVulnerability + "。候选数、Agent 分诊和组件 Harness 观察均不自动成为产品漏洞确认。"} />
    {view.operationScope.truncated && <Alert className="section-gap" type="warning" showIcon
      message={"还有 " + view.operationScope.omitted + " 条本案例操作结果未在此页展开"}
      description={"接口最多展开最近 " + view.operationScope.limit + " 条；本页和本次下载报告都只覆盖 " + view.operationScope.included + " / " + view.operationScope.total + " 条。未展开的记录仍存在，不能据此认为它们没有结果。"} />}
    <Card className="section-gap" size="small" title={"关联候选与固定证据（" + view.candidates.length + "）"}>
      {view.candidates.length
        ? <Space direction="vertical" style={{ width: "100%" }}>
          {view.candidates.map((row: any, index: number) => <CandidateEvidence key={row.candidate?.id || index} row={row} operations={view.operations} />)}
        </Space>
        : <Empty description="没有关联候选记录。" />}
    </Card>
    <Card className="section-gap" size="small" title={"Agent 调查（" + view.agentOperations.length + "）"}>
      {view.agentOperations.length
        ? <Space direction="vertical" style={{ width: "100%" }}>
          {view.agentOperations.map((operation: any) => <AgentOperation key={operation.id} operation={operation} />)}
        </Space>
        : <Text type="secondary">此案例没有包含 Agent 调查结果。</Text>}
    </Card>
    <Card className="section-gap" size="small" title={"PoC / 固定 Harness 验证（" + view.validationOperations.length + "）"}>
      {view.validationOperations.length
        ? <Space direction="vertical" style={{ width: "100%" }}>
          {view.validationOperations.map((operation: any) => <ValidationOperation key={operation.id} operation={operation} />)}
        </Space>
        : <Text type="secondary">此案例没有包含隔离验证结果；当前 PoC / 产品影响保持 unknown。</Text>}
    </Card>
    {view.otherOperations.length > 0 && <Card className="section-gap" size="small" title={"其他操作（" + view.otherOperations.length + "）"}>
      <List size="small" dataSource={view.otherOperations} renderItem={(operation: any) =>
        <List.Item><Space direction="vertical">
          <Text strong>{operation.kind || "操作"} · {stateLabels[operation.status] || operation.status || "未知"}</Text>
          <Text>操作 ID：{operation.id} · 结果 SHA-256：{operation.result_sha256 || "未记录"}</Text>
          <Text type="secondary">固定提交：{(operation.commits || []).join(", ") || operation.commit || "未记录"}</Text>
        </Space></List.Item>} />
    </Card>}
  </Card>;
}

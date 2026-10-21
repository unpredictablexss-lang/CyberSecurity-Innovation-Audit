import React, { useMemo, useRef, useState } from "react";
import { Alert, Button, Card, Collapse, Descriptions, Space, Table, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { go } from "../../components";
import { buildMatrixCandidatePairs, JOINT_CANDIDATE_CREATE_PATH, JOINT_CANDIDATE_PREVIEW_PATH,
  buildJointLinkedAgentChildrenView, buildJointEgressSummary, jointCandidateCreatePayload, jointCandidatePreviewPayload } from "./operationProgressModel.js";

const { Text } = Typography;
const SHA256 = /^[a-f0-9]{64}$/i;

function short(value: any) { return typeof value === "string" ? value.slice(0, 12) : "未知"; }
function previewFresh(preview: any) {
  const expiry = Date.parse(preview?.consent?.expires_at || "");
  return Number.isFinite(expiry) && expiry > Date.now();
}
function statusLabel(status: any) {
  const labels: Record<string, string> = {
    completed: "已完成", queued: "排队中", running: "运行中", failed: "失败",
    blocked: "受阻", cancelled: "已取消", interrupted: "已中断", timed_out: "超时",
  };
  return labels[String(status)] || "状态未知";
}
function stageLabel(stage: any) {
  if (stage === "initial_review") return "初步调查";
  if (stage === "source_tracing") return "深入追查";
  return "调查阶段未知";
}
function countRows(value: any) {
  return Array.isArray(value) ? value.length : 0;
}
function SideSource({ label, side }: { label: string; side: any }) {
  return <Descriptions.Item label={label}>
    <div>固定版本：{short(side?.commit)}</div>
    <div>候选位置：{side?.candidate_file || "未知文件"}:{side?.candidate_line ?? "未知行"}</div>
  </Descriptions.Item>;
}
function EvidencePreview({ context }: { context: any }) {
  const evidence = Array.isArray(context?.evidence_preview) ? context.evidence_preview : [];
  const manifests = context?.linked_review_manifest || {};
  const rows = [...(Array.isArray(manifests.from) ? manifests.from : []),
    ...(Array.isArray(manifests.to) ? manifests.to : [])];
  return <Space direction="vertical" style={{ width: "100%" }} size="middle">
    <Alert type="info" showIcon message="以下内容就是本次将发送给模型的固定证据"
      description="历史智能调查摘要会标成导航参考，不作为本次可引用证据；本次结论仍为 candidate/unknown。" />
    {evidence.map((item: any, index: number) => {
      const side = item.side === "from" ? "来源版本" : item.side === "to" ? "目标版本" : "版本未知";
      const origin = item.origin === "smart_investigation_tool" ? "深入追查中的只读源码" : "静态候选源码";
      const lines = Array.isArray(item.lines) ? item.lines.join("") : String(item.lines || "");
      return <Card size="small" key={item.evidence_id || index} title={side + " · " + item.file + ":" + item.line_start + (item.line_end !== item.line_start ? "-" + item.line_end : "")}>
        <Text type="secondary">{origin}</Text>
        <pre className="raw">{lines}</pre>
        <Collapse items={[{ key: "binding", label: "技术绑定详情", children: <Descriptions size="small" column={1}>
          <Descriptions.Item label="证据 ID">{item.evidence_id || "未提供"}</Descriptions.Item>
          <Descriptions.Item label="源码 SHA-256">{item.source_sha256 || "未提供"}</Descriptions.Item>
          {item.operation_id && <Descriptions.Item label="关联调查 ID">{item.operation_id}</Descriptions.Item>}
          {item.tool_result_sha256 && <Descriptions.Item label="调查结果 SHA-256">{item.tool_result_sha256}</Descriptions.Item>}
        </Descriptions> }]} />
      </Card>;
    })}
    {rows.length > 0 && <Card size="small" title="已有智能调查摘要（仅导航参考，不作为证据）">
      {rows.map((item: any, index: number) => <div className="section-gap" key={item.operation_id || index}>
        <Space wrap><Tag>{stageLabel(item.review_stage)}</Tag><Tag>{statusLabel(item.status)}</Tag>
          <Tag>{item.assessment || "判断未知"}</Tag></Space>
        {item.summary_transmitted && <Typography.Paragraph>{item.summary_transmitted}</Typography.Paragraph>}
        {countRows(item.claims_transmitted) > 0 && <><Text strong>已有支持观点</Text><ul>{item.claims_transmitted.map((claim: any, i: number) => <li key={i}>{typeof claim === "string" ? claim : JSON.stringify(claim)}</li>)}</ul></>}
        {countRows(item.unknowns_transmitted) > 0 && <><Text strong>已记录的未知项</Text><ul>{item.unknowns_transmitted.map((claim: any, i: number) => <li key={i}>{typeof claim === "string" ? claim : JSON.stringify(claim)}</li>)}</ul></>}
        {countRows(item.next_steps_transmitted) > 0 && <><Text strong>建议后续核查</Text><ul>{item.next_steps_transmitted.map((claim: any, i: number) => <li key={i}>{typeof claim === "string" ? claim : JSON.stringify(claim)}</li>)}</ul></>}
        <Collapse items={[{ key: "review-bindings", label: "摘要来源与绑定详情", children: <Descriptions size="small" column={1}>
          <Descriptions.Item label="调查操作 ID">{item.operation_id || "未提供"}</Descriptions.Item>
          <Descriptions.Item label="调查结果 SHA-256">{item.result_sha256 || "未提供"}</Descriptions.Item>
          <Descriptions.Item label="引用数量">{item.prior_citations_transmitted ?? 0}</Descriptions.Item>
          <Descriptions.Item label="固定源码证据 ID">{(item.fixed_source_evidence_ids || []).join("、") || "无"}</Descriptions.Item>
        </Descriptions> }]} />
      </div>)}
    </Card>}
    {evidence.length === 0 && rows.length === 0 && <Text type="secondary">服务端没有返回可展示的源码摘录或关联调查摘要；请勿据此认为模型会收到空证据。</Text>}
  </Space>;
}

export default function VersionCandidateComparison({ operation, onOperationCreated }: {
  operation: any; onOperationCreated?: (operation: any) => void;
}) {
  const pairs = useMemo(() => buildMatrixCandidatePairs(operation), [operation]);
  const [activePairKey, setActivePairKey] = useState<string | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<any>(null);
  const requestTicket = useRef(0);
  if (!operation || operation.kind !== "version_matrix" || !Array.isArray(operation.result?.comparisons)) return null;

  const pair = pairs.find((item) => item.key === activePairKey) || null;
  const previewConsent = preview?.consent;
  const binding = previewConsent?.binding;
  const context = preview?.context_summary;
  const linkedAgentChildren = buildJointLinkedAgentChildrenView(context);
  const egressSummary = buildJointEgressSummary(context);
  const consentValid = preview?.eligible === true && previewFresh(preview)
    && typeof previewConsent?.consent_nonce === "string" && Boolean(previewConsent.consent_nonce)
    && typeof previewConsent?.consent_sha256 === "string" && SHA256.test(previewConsent.consent_sha256);
  const evidence = Array.isArray(context?.evidence_preview) ? context.evidence_preview : [];

  const loadPreview = async (selected: any) => {
    const ticket = ++requestTicket.current;
    setActivePairKey(selected.key); setPreview(null); setCreated(null); setError(""); setPreviewBusy(true);
    try {
      const payload = jointCandidatePreviewPayload(operation.id, selected);
      const result = await api(JOINT_CANDIDATE_PREVIEW_PATH, payload);
      if (ticket === requestTicket.current) setPreview(result);
    } catch (e) {
      if (ticket === requestTicket.current) setError(String(e));
    } finally {
      if (ticket === requestTicket.current) setPreviewBusy(false);
    }
  };

  const createComparison = async () => {
    if (!pair || !consentValid || createBusy) return;
    setCreateBusy(true); setError("");
    try {
      const payload = jointCandidateCreatePayload(operation.id, pair, previewConsent);
      const item = await api(JOINT_CANDIDATE_CREATE_PATH, payload);
      setCreated(item); onOperationCreated?.(item);
      message.success("联合比较任务已加入队列；模型结果仍需人工复核");
    } catch (e) {
      setError(String(e)); setPreview(null);
    } finally { setCreateBusy(false); }
  };

  const columns: any[] = [
    { title: "固定版本对", render: (_: any, row: any) => <>{short(row.fromCommit)} → {short(row.toCommit)}<div className="muted">静态观察：{row.status}</div></> },
    { title: "匹配候选", render: (_: any, row: any) => <><Text>{row.file}</Text><div className="muted">{row.detectorId} · {row.ruleId}</div>
      {row.eligibleForPreview ? <div className="muted">{short(row.fromCandidate.id)} → {short(row.toCandidate.id)}</div>
        : <div className="muted">两侧候选身份不是唯一的一对一匹配</div>}</> },
    { title: "联合研判", render: (_: any, row: any) => <Button size="small" disabled={!row.eligibleForPreview || !SHA256.test(operation.result_sha256 || "")}
      loading={previewBusy && activePairKey === row.key} onClick={() => void loadPreview(row)}>
      {activePairKey === row.key && preview ? "重新预览授权" : "预览联合研判"}</Button> },
  ];

  return <Card className="section-gap" size="small" title="跨版本候选联合研判">
    <Alert type="info" showIcon message="只对两个固定版本中唯一配对的候选进行联合调查" description="预览只读取已保存报告和固定源码，不调用模型、不外发源码、不创建任务。确认后才会向模型发送下方展示的内容。结果仍是 candidate/unknown，不能确认漏洞或证明漏洞由哪个版本引入/修复。" />
    {!SHA256.test(operation.result_sha256 || "") && <Alert className="section-gap" type="warning" showIcon message="版本矩阵结果缺少有效摘要，不能安全绑定联合调查。" />}
    <Table<any> className="section-gap" size="small" rowKey="key" dataSource={pairs} pagination={{ pageSize: 5 }} scroll={{ x: 760 }} columns={columns}
      expandable={{ expandedRowKeys: activePairKey ? [activePairKey] : [],
        onExpand: (expanded: boolean, row: any) => { if (!expanded && row.key === activePairKey) { requestTicket.current += 1; setActivePairKey(null); setPreview(null); } },
        expandedRowRender: (row: any) => row.key !== activePairKey ? null : <Space direction="vertical" style={{ width: "100%" }}>
          {error && <Alert type="error" showIcon message="联合调查未完成" description={error} />}
          {previewBusy && <Alert type="info" showIcon message="正在读取固定报告并生成授权预览" />}
          {preview && <>
            <Alert type={preview.eligible ? "warning" : "error"} showIcon
              message={preview.eligible ? "请核对将发送给模型的源码和调查摘要" : "当前候选对不满足联合调查条件"}
              description={preview.reason || (preview.eligible ? "预览没有调用模型或创建任务；只有明确同意后才会创建一次联合调查。" : "服务端拒绝了该候选对的预览。此时不会创建任务。")} />
            {binding && <Descriptions size="small" bordered column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="模型服务">{previewConsent.provider?.destination || "目的地未知"} · {previewConsent.provider?.model || "模型未知"}</Descriptions.Item>
              <SideSource label="来源版本" side={binding.from} />
              <SideSource label="目标版本" side={binding.to} />
              <Descriptions.Item label="本次将发送的内容" span={2}>
                固定源码片段 {egressSummary.evidenceCount ?? context?.source_evidence_count ?? "未知"} 项，涉及 {egressSummary.fileCount ?? "未知"} 个文件、两个固定版本；关联调查摘要 {egressSummary.linkedReviewCount ?? "未知"} 项（仅导航参考）。
              </Descriptions.Item>
              <Descriptions.Item label="授权有效期" span={2}>{previewConsent.expires_at || "未知"}</Descriptions.Item>
              {Array.isArray(context?.limitations) && context.limitations.length > 0 && <Descriptions.Item label="调查边界" span={2}>
                <ul>{context.limitations.map((item: any, index: number) => <li key={index}>{String(item)}</li>)}</ul>
              </Descriptions.Item>}
            </Descriptions>}
            <Collapse items={[{ key: "egress", label: "查看将发送给模型的内容", children: <EvidencePreview context={context} /> }]} />
            <Text type="secondary">这是一项仅适用于本次候选对及上述预览内容的一次性授权；创建时服务端会复核授权随机值、有效期和摘要。内容变化或授权过期时需要重新预览和授权，不会自动用于其他任务。</Text>
            {binding && <Collapse items={[{ key: "technical", label: "技术详情", children: <Descriptions size="small" bordered column={1}>
              <Descriptions.Item label="固定仓库">{binding.repository_id || "未提供"}</Descriptions.Item>
              <Descriptions.Item label="来源版本完整 Commit">{binding.from?.commit || "未提供"}</Descriptions.Item>
              <Descriptions.Item label="目标版本完整 Commit">{binding.to?.commit || "未提供"}</Descriptions.Item>
              <Descriptions.Item label="矩阵操作 ID">{binding.matrix_operation_id || "未提供"}</Descriptions.Item>
              <Descriptions.Item label="矩阵结果 SHA-256">{binding.matrix_result_sha256 || "未提供"}</Descriptions.Item>
              <Descriptions.Item label="授权 SHA-256">{previewConsent.consent_sha256 || "未提供"}</Descriptions.Item>
              <Descriptions.Item label="脱敏策略">{context?.redaction_policy_version || "未提供"} · 分类 {(context?.redaction_categories || []).join("、") || "无"}</Descriptions.Item>
              <Descriptions.Item label="两侧 Agent 操作摘要">
                {egressSummary.linkedReviewProvided ? egressSummary.linkedReviewCount : "未提供"} 项；操作 ID、状态与结果摘要见“将发送内容”中的导航摘要绑定详情。
              </Descriptions.Item>
            </Descriptions> }]} />}
            {preview.eligible && <>
              {!consentValid && <Alert type="error" showIcon message="授权预览缺少有效摘要或已过期，请重新预览。" />}
              <Button type="primary" disabled={!consentValid} loading={createBusy} onClick={() => void createComparison()}>
                明确同意外发范围并创建联合调查
              </Button>
            </>}
          </>}
          {created?.id && <Alert type="success" showIcon message={"联合调查已创建：" + (created.status || "queued")}
            description={<Space wrap><Button size="small" onClick={() => onOperationCreated?.(created)}>查看任务结果</Button>
              <Button size="small" onClick={() => go("/tasks/operations/" + created.id)}>在任务中心打开</Button></Space>} />}
        </Space> }}
      locale={{ emptyText: "没有可供配对的固定版本候选观察" }} />
    <Text type="secondary">平台没有调查累计 Token 或费用上限；模型服务按账户费率和额度计费，任务可取消。联合结果不构成漏洞确认；此处不会生成或执行 PoC。</Text>
  </Card>;
}

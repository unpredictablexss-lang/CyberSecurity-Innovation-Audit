import React from "react";
import { Alert, Collapse, Descriptions, Modal, Space, Typography } from "antd";

const { Text } = Typography;

function short(value: unknown): string {
  if (typeof value !== "string" || !value) return "未知";
  return value.length > 12 ? value.slice(0, 12) + "…" : value;
}

function endpointsFor(preview: any) {
  if (Array.isArray(preview?.scans)) return preview.scans;
  return preview?.manifest ? [preview] : [];
}

function sourceLines(preview: any) {
  const direct = preview?.context_summary?.evidence_preview ?? preview?.evidence_preview;
  if (Array.isArray(direct)) return direct;
  if (Array.isArray(direct?.items)) return direct.items;
  return [];
}

function knowledgePreviews(preview: any) {
  if (Array.isArray(preview?.arms)) {
    return preview.arms.map((arm: any) => ({ mode: arm.mode, retrieval: arm.preview?.knowledge_retrieval }))
      .filter((item: any) => item.retrieval);
  }
  const direct = preview?.knowledge_retrieval;
  return direct ? [{ mode: null, retrieval: direct }] : [];
}

const PROFILE_LABELS: Record<string, string> = {
  economical: "经济", standard: "标准", deep: "深度", custom: "自定义",
};

export default function TaskTriageConsentModal({ open, preview, loading = false, onCancel, onConfirm }: {
  open: boolean; preview: any; loading?: boolean; onCancel: () => void; onConfirm: () => void;
}) {
  const endpoints = endpointsFor(preview);
  const evidence = sourceLines(preview);
  const knowledge = knowledgePreviews(preview);
  const consentExpiry = preview?.expires_at || preview?.consent?.expires_at;
  const provider = preview?.provider || endpoints[0]?.provider || {};
  const progressive = preview?.progressive_policy || null;
  const eligible = preview?.eligible === true && endpoints.length > 0;
  return <Modal
    title="智能审计：确认模型外发范围"
    open={open}
    width={760}
    confirmLoading={loading}
    okText="同意范围并开始智能审计"
    cancelText="返回修改"
    okButtonProps={{ disabled: !eligible }}
    onCancel={onCancel}
    onOk={onConfirm}
    destroyOnClose
  >
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Alert type="warning" showIcon
        message="预览不会调用模型、发送源码或创建任务"
        description="确认后，系统先运行静态扫描，再按下列固定来源和候选上限，把扫描产生的有限候选信息与源码证据发送到模型进行调查。扫描完成后才知道确切候选和源码片段；超出上限或未入选的候选仍待人工研判，不代表安全。" />
      <Text type="secondary">这是一项仅适用于本次固定仓库、版本、模型和源码范围的一次性授权，不会自动用于其他任务。创建时服务端会复核预览摘要；绑定内容变化时需要重新预览和授权。扫描后才确定的具体片段仍受本次来源范围和候选上限约束。</Text>
      {provider && <Descriptions size="small" bordered column={{ xs: 1, sm: 2 }}>
        <Descriptions.Item label="模型服务">{provider.endpoint_host || provider.destination_host || provider.destination || "目的地未知"}</Descriptions.Item>
        <Descriptions.Item label="模型">{provider.model || "未知"}</Descriptions.Item>
        {progressive && <>
          <Descriptions.Item label="渐进策略">{PROFILE_LABELS[progressive.policy?.profile] || "未知"} · 修订 {progressive.revision ?? "未知"}</Descriptions.Item>
          <Descriptions.Item label="策略摘要 SHA-256">{short(progressive.policy_sha256)}</Descriptions.Item>
          <Descriptions.Item label="本次本地排序名额" span={2}>
            {progressive.policy?.limits?.quick_screen_groups_per_audit ?? "未知"} 个候选组；后续 L2/L3 会继承这里的冻结策略和共享模型预算。
          </Descriptions.Item>
        </>}
        {endpoints.map((item: any, index: number) => {
          const manifest = item.manifest || {};
          const binding = manifest.binding || {};
          const cap = manifest.candidate_limit ?? manifest.r1_candidate_limit;
          const r2Cap = manifest.r2_candidate_limit;
          const repo = binding.repository || item.repository || preview.repository || "已登记仓库";
          const commit = item.commit || binding.commit;
          const paths = Array.isArray(binding.include_paths) ? binding.include_paths : [];
          return <React.Fragment key={String(commit || index) + "-" + index}>
            <Descriptions.Item label={endpoints.length > 1 ? "固定来源 " + (index + 1) : "固定来源"}>
              {repo}{commit ? <> @ <Text code>{short(commit)}</Text></> : ""}
            </Descriptions.Item>
            <Descriptions.Item label="候选上限">
              {Number.isInteger(cap) ? "最多 " + cap + " 条自动初步调查" : "上限见技术详情"}
              {Number.isInteger(r2Cap) && r2Cap > 0 ? "；符合条件时最多 " + r2Cap + " 条深入追查" : ""}
              <div><Text type="secondary">精确候选总数在扫描后统计；未入选项保留待复核。</Text></div>
            </Descriptions.Item>
          <Descriptions.Item label="系统额度策略">
            {PROFILE_LABELS[manifest.system_policy?.profile] || "系统设置"} · 修订 {manifest.system_policy?.revision ?? "未知"} · 单轮输出最多 {manifest.system_policy?.max_output_tokens_per_request ?? manifest.budgets?.r1_max_output_tokens_per_request ?? "未知"} tokens
          </Descriptions.Item>
            <Descriptions.Item label="源码范围" span={2}>
              {paths.length ? paths.join("、") : "当前审计纳入范围"}
            </Descriptions.Item>
          </React.Fragment>;
        })}
        <Descriptions.Item label="授权有效期" span={2}>
          {consentExpiry || "服务端未提供固定到期时间；任务创建时会重验来源、模型和范围摘要，绑定项变化会拒绝创建。"}
        </Descriptions.Item>
      </Descriptions>}
      <Alert type="info" showIcon message="额度继承、调查费用与取消" description="单轮输出上限从系统设置中冻结的策略继承，不需要为本任务重复填写。此旧自动分诊流程尚未接入累计 Token、请求次数和调查时长账本；费用按服务商实际计费与账户额度执行。任务运行期间可随时取消。" />
      {!eligible && <Alert type="error" showIcon message={preview?.reason || "当前无法生成可用的授权预览；没有任务会被创建。"} />}
      <Collapse items={[{ key: "details", label: "查看将发送给模型的内容与技术详情", children: <>
        <Typography.Paragraph type="secondary">
          当前预览先展示发送类别和固定范围。静态扫描尚未运行，因此精确候选、代码摘录及扫描后关联的证据清单还未生成；若服务端提供了有界证据预览，会在这里逐项列出。
        </Typography.Paragraph>
        {evidence.length > 0 ? <Space direction="vertical" style={{ width: "100%" }}>
          {evidence.map((item: any, index: number) => <div key={item.evidence_id || index}>
            <Text strong>{(item.side === "from" ? "来源版本 · " : item.side === "to" ? "目标版本 · " : "") + (item.file || item.path || "源码片段")}{item.line_start ? ":" + item.line_start + (item.line_end && item.line_end !== item.line_start ? "-" + item.line_end : "") : ""}</Text>
            {item.origin && <div><Text type="secondary">{item.origin === "smart_investigation_tool" ? "智能调查中的固定源码证据" : "静态扫描候选源码"}</Text></div>}
            {item.summary && <div>{item.summary}</div>}
            {item.lines && <pre className="raw">{Array.isArray(item.lines) ? item.lines.join("") : String(item.lines)}</pre>}
            {item.finding_summary && <Typography.Paragraph>{item.finding_summary}</Typography.Paragraph>}
            {Array.isArray(item.citations) && item.citations.map((citation: any, citationIndex: number) =>
              <Typography.Paragraph key={citation.id || citationIndex} type="secondary">{citation.label || citation.title || citation.path || String(citation)}</Typography.Paragraph>)}
          </div>)}
        </Space> : <Text type="secondary">本接口没有返回扫描后的精确源码摘录。</Text>}
        {knowledge.length > 0 && <div className="section-gap">
          <Text strong>将发送的 CVE / PoC / Harness 参考资料</Text>
          <Typography.Paragraph type="secondary">
            每个 R1/R2 使用同一候选的本地 BM25 检索结果。资料是结项包中的不可信类比信息，不证明当前候选、不满足当前源码证据义务，也不能作为当前漏洞结论的引用。授权摘要绑定语料 SHA-256 和实际片段；语料变化后需重新预览。
          </Typography.Paragraph>
          {knowledge.map(({ mode, retrieval }: any, groupIndex: number) => <div key={mode || groupIndex} className="section-gap">
            {mode && <Text strong>{mode === "single_shot" ? "R1 单轮研判" : "R2 工具调查"}</Text>}
            <Descriptions size="small" column={1}>
              <Descriptions.Item label="检索状态">{retrieval.status} · 索引文件 {retrieval.indexed_files ?? 0}</Descriptions.Item>
              <Descriptions.Item label="语料 SHA-256">{retrieval.corpus_sha256 || "不可用"}</Descriptions.Item>
            </Descriptions>
            {Array.isArray(retrieval.references) && retrieval.references.length
              ? <Space direction="vertical" style={{ width: "100%" }}>{retrieval.references.map((item: any, index: number) => <div key={item.path + ":" + item.start_line + ":" + index}>
                <Text strong>{item.path}:{item.start_line}{item.end_line !== item.start_line ? "-" + item.end_line : ""}</Text>
                <div><Text type="secondary">{item.summary}</Text></div>
                <div><Text type="secondary">文件 SHA-256：{item.sha256}</Text></div>
                <pre className="raw">{item.excerpt}</pre>
              </div>)}</Space>
              : <Text type="secondary">{retrieval.status === "no_match" ? "没有匹配片段；按现有流程继续。" : "语料为空或不可用；按现有流程继续。"}</Text>}
          </div>)}
        </div>}
        {endpoints.map((item: any, index: number) => {
          const manifest = item.manifest || {};
          return <div key={"manifest-" + index} className="section-gap">
            <Text strong>{endpoints.length > 1 ? "固定来源 " + (index + 1) + " 的披露范围" : "外发范围"}</Text>
            <ul>{(manifest.source_disclosure || []).map((line: string, lineIndex: number) =>
              <li key={lineIndex}>{line.replace(/\bR1\b/g, "初步调查").replace(/\bR2\b/g, "深入追查")}</li>)}</ul>
            <Descriptions size="small" column={1}>
              <Descriptions.Item label="候选超限处理">超过每个版本的授权上限时，未入选候选保持待研判，不会视为安全。</Descriptions.Item>
              <Descriptions.Item label="单次输出长度">{manifest.per_candidate_budgets?.r1?.max_output_tokens_per_request == null ? "由模型服务商和模型决定" : String(manifest.per_candidate_budgets.r1.max_output_tokens_per_request) + " tokens"}；单次超时 {manifest.per_candidate_budgets?.r1?.provider_request_timeout_seconds || "未知"} 秒</Descriptions.Item>
              {manifest.per_candidate_budgets?.r2 && <Descriptions.Item label="深入追查单次输出长度">{manifest.per_candidate_budgets.r2.max_output_tokens_per_request == null ? "由模型服务商和模型决定" : String(manifest.per_candidate_budgets.r2.max_output_tokens_per_request) + " tokens"}；单次超时 {manifest.per_candidate_budgets.r2.provider_request_timeout_seconds} 秒</Descriptions.Item>}
              <Descriptions.Item label="扫描计划 SHA-256">{item.plan_sha256 || manifest.binding?.plan_sha256 || "未返回"}</Descriptions.Item>
              <Descriptions.Item label="工作流 SHA-256">{item.workflow_sha256 || manifest.binding?.workflow_sha256 || "未返回"}</Descriptions.Item>
              <Descriptions.Item label="授权摘要 SHA-256">{item.consent_sha256 || "未返回"}</Descriptions.Item>
              <Descriptions.Item label="授权随机值">{item.consent_nonce || "未返回"}</Descriptions.Item>
            </Descriptions>
          </div>;
        })}
      </> }]} />
      <Text type="secondary">模型输出只作为候选线索，漏洞仍需人工复核；该授权不会把静态命中自动标记为已确认漏洞。</Text>
    </Space>
  </Modal>;
}

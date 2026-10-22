import { useState } from "react";
import { Alert, Button, Checkbox, Descriptions, Modal, Space, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { go } from "../../components";

const { Paragraph, Text } = Typography;

export default function ProgressiveQuickScreenBatchAction({ auditOperationId, enabled }: {
  auditOperationId: string;
  enabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [approved, setApproved] = useState(false);
  const [preview, setPreview] = useState<any>(null);

  async function showPreview() {
    setOpen(true); setLoading(true); setApproved(false); setPreview(null);
    try {
      const value = await api("/operations/progressive-quick-screen-batches/preview", {
        audit_operation_id: auditOperationId,
      });
      setPreview(value);
    } catch (error) {
      setOpen(false);
      message.error("批量 AI 初步分析操作未能完成，请检查服务状态或任务详情后重试。");
    } finally { setLoading(false); }
  }

  async function start() {
    if (!preview || !approved) return;
    setLoading(true);
    try {
      const operation = await api("/operations/progressive-quick-screen-batches", {
        audit_operation_id: auditOperationId,
        source_submission_approved: true,
        consent_sha256: preview.consent_sha256,
        consent_nonce: preview.consent_nonce,
        consent_expires_at: preview.consent_expires_at,
      });
      setOpen(false);
      message.success(`已创建任务级AI 初步分析：${preview.scheduled_group_count} 组；均保留为候选`);
      if (operation?.id) go("/tasks/operations/" + operation.id);
    } catch (error) { message.error("批量 AI 初步分析操作未能完成，请检查服务状态或任务详情后重试。"); }
    finally { setLoading(false); }
  }

  return <>
      <Button size="small" type="primary" disabled={!enabled} onClick={() => void showPreview()}>
      预览并批量进行AI 初步分析
    </Button>
    <Modal title="批量研判的源码发送预览" open={open} width={960} confirmLoading={loading}
      okText="确认授权并开始" cancelText="取消" okButtonProps={{ disabled: !preview || !approved }}
      onOk={() => void start()} onCancel={() => { setOpen(false); setApproved(false); }} destroyOnClose>
      {loading && !preview ? <Paragraph>正在为已选组读取并校验固定源码片段…</Paragraph> : preview ? <>
        <Alert type="warning" showIcon message="本次授权会按下列清单逐组发送短源码片段；每组发起一次模型请求，不开放工具，并按既定策略顺序执行。"
          description="未列入清单、跳过、未开始、失败或结果未知的候选仍保留，任何AI 初步分析意见都不会确认漏洞或误报。" />
        <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
          <Descriptions.Item label="父审计任务">{preview.audit_operation_id}</Descriptions.Item>
          <Descriptions.Item label="模型服务商 / 模型">{preview.provider?.provider || preview.provider?.endpoint_host} · {preview.provider?.model}</Descriptions.Item>
          <Descriptions.Item label="冻结策略版本">{preview.progressive_policy?.revision} · {preview.progressive_policy?.policy_sha256}</Descriptions.Item>
          <Descriptions.Item label="本地筛选 选中 / 本次执行">{preview.selected_group_count} / {preview.scheduled_group_count} 组</Descriptions.Item>
          <Descriptions.Item label="单轮输出上限">最多 {Math.min(512, preview.budget_limits?.max_output_tokens_per_request ?? 512)} tokens / 候选</Descriptions.Item>
          <Descriptions.Item label="冻结累计上限">输入 {preview.budget_limits?.max_input_tokens_per_audit ?? "未知"} / 输出 {preview.budget_limits?.max_output_tokens_per_audit ?? "未知"} tokens；最多 {preview.budget_limits?.max_model_calls_per_audit ?? "未知"} 次请求</Descriptions.Item>
          <Descriptions.Item label="AI 时长 / 费用">最多 {preview.budget_limits?.max_ai_wall_seconds ?? "未知"} 秒；美元估算不构成服务商账单上限</Descriptions.Item>
          <Descriptions.Item label="授权摘要 SHA-256" span={2}>{preview.consent_sha256}</Descriptions.Item>
        </Descriptions>
        {preview.skipped?.length > 0 && <Alert className="section-gap" type="info" showIcon
          message={`有 ${preview.skipped.length} 组未纳入本次外发`} description={preview.skipped.map((row: any) => `${row.group_id}: ${row.reason}`).join("；")} />}
        <Text strong>本次将发送的源码片段（共 {preview.disclosures?.length || 0} 组）</Text>
        <div className="section-gap" style={{ maxHeight: "42vh", overflow: "auto", paddingRight: 8 }}>
          {(preview.disclosures || []).map((item: any) => <section key={item.group_id} className="section-gap" style={{ border: "1px solid #d9d9d9", borderRadius: 8, padding: 12 }}>
            <Space wrap><Tag color="blue">{item.group_id}</Tag><Text code>{item.candidate_id}</Text><Text>{item.repository}@{item.commit}</Text></Space>
            <Paragraph className="section-gap" style={{ marginBottom: 4 }}>{item.file}:{item.line_start}–{item.line_end}</Paragraph>
            <Text type="secondary">报告 SHA-256：{item.report_sha256} · 源码 SHA-256：{item.source_sha256}</Text>
            <div className="muted">脱敏：{item.redactions?.length ? item.redactions.join("、") : "未发现需替换的敏感值"}</div>
            <pre className="raw section-gap" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 260, overflow: "auto" }}>{item.excerpt}</pre>
          </section>)}
        </div>
        <Paragraph type="secondary">AI 深入追查 仍需逐项新的源码范围预览和授权。冻结 Token、请求数或时长预算耗尽后，后续请求停止，剩余候选继续待复核；Provider 账户额度与 API 错误仍可能提前阻止请求。</Paragraph>
        <Checkbox checked={approved} onChange={(event) => setApproved(event.target.checked)}>
          我已逐项检查上面列出的固定版本源码片段、模型和用量说明，并明确允许本任务发送这些内容。
        </Checkbox>
        <div className="section-gap"><Space wrap><Tag color="blue">保留为候选</Tag><Text type="secondary">本次只授权清单内的AI 初步分析，不包含AI 深入追查；结果不会自动确认为漏洞、误报或安全。</Text></Space></div>
      </> : null}
    </Modal>
  </>;
}

import { useState } from "react";
import { Alert, Button, Checkbox, Descriptions, Modal, Space, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { go } from "../../components";

const { Paragraph, Text } = Typography;

export default function ProgressiveQuickScreenAction({ jobId, candidateId, enabled }: {
  jobId: string;
  candidateId: string;
  enabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [approved, setApproved] = useState(false);
  const [preview, setPreview] = useState<any>(null);

  async function showPreview() {
    setOpen(true);
    setLoading(true);
    setApproved(false);
    setPreview(null);
    try {
      const value = await api("/operations/progressive-quick-screens/preview", {
        job_id: jobId, candidate_id: candidateId,
      });
      setPreview(value);
    } catch (error) {
      setOpen(false);
      message.error(String(error));
    } finally {
      setLoading(false);
    }
  }

  async function start() {
    if (!preview || !approved) return;
    setLoading(true);
    try {
      const operation = await api("/operations/progressive-quick-screens", {
        job_id: jobId,
        candidate_id: candidateId,
        source_submission_approved: true,
        consent_sha256: preview.consent_sha256,
        consent_nonce: preview.consent_nonce,
        consent_expires_at: preview.consent_expires_at,
      });
      setOpen(false);
      message.success("L2 快速研判任务已创建；候选仍保持待复核状态");
      if (operation?.id) go("/tasks/operations/" + operation.id);
    } catch (error) {
      message.error(String(error));
    } finally {
      setLoading(false);
    }
  }

  return <>
    <Button size="small" disabled={!enabled} onClick={() => void showPreview()}>L2 快速研判</Button>
    <Modal
      title="L2 快速研判外发预览"
      open={open}
      width={760}
      confirmLoading={loading}
      okText="确认并创建任务"
      cancelText="取消"
      okButtonProps={{ disabled: !preview || !approved }}
      onOk={() => void start()}
      onCancel={() => { setOpen(false); setApproved(false); }}
      destroyOnClose
    >
      {loading && !preview ? <Paragraph>正在从固定扫描版本读取并校验源码…</Paragraph> : preview ? <>
        <Alert type="warning" showIcon message="仅发送一个脱敏后的固定源码片段，一次模型请求，不启用工具。AI 结果仅作待复核研判，不确认漏洞或误报。" />
        <Descriptions className="section-gap" bordered size="small" column={2}>
          <Descriptions.Item label="模型端点">{preview.provider?.endpoint_host || preview.provider?.model || "未知"}</Descriptions.Item>
          <Descriptions.Item label="调用与工具">1 次；工具关闭</Descriptions.Item>
          <Descriptions.Item label="单次输出额度">{preview.disclosure?.max_output_tokens == null ? "无本地上限，由服务商决定" : String(preview.disclosure.max_output_tokens) + " tokens"}</Descriptions.Item>
          <Descriptions.Item label="原始候选">{candidateId}</Descriptions.Item>
          <Descriptions.Item label="来源报告 SHA-256">{preview.evidence?.[0]?.report_sha256 || "未知"}</Descriptions.Item>
          <Descriptions.Item label="策略版本 / SHA">{preview.progressive_policy?.revision} / {preview.progressive_policy?.policy_sha256}</Descriptions.Item>
          <Descriptions.Item label="本地选择">{preview.ranking?.decisions?.[0]?.selected ? "已入选" : "未入选"}</Descriptions.Item>
          <Descriptions.Item label="源码文件与行号" span={2}>{preview.evidence?.[0]?.file}:{preview.evidence?.[0]?.line_start}–{preview.evidence?.[0]?.line_end}</Descriptions.Item>
          <Descriptions.Item label="源码 SHA-256" span={2}>{preview.evidence?.[0]?.source_sha256}</Descriptions.Item>
          <Descriptions.Item label="脱敏项" span={2}>{preview.disclosure?.sensitive_redactions?.join("、") || "未发现需替换的敏感值"}</Descriptions.Item>
        </Descriptions>
        <Text strong>实际发送的源码片段</Text>
        <pre className="raw section-gap">{preview.disclosure?.source_excerpt || "无可发送源码"}</pre>
        <Paragraph type="secondary">额度由本地账本按扫描任务统计。费用目前是估算信息，不能限制 Provider 实际账单。过期或源码、策略、模型变化时必须重新预览。</Paragraph>
        <Checkbox checked={approved} onChange={(event) => setApproved(event.target.checked)}>
          我已检查上述来源、源码片段和 Provider，并明确允许发送本次内容。
        </Checkbox>
        <div className="section-gap"><Space wrap><Tag color="blue">保留 candidate</Tag><Text type="secondary">结果不会自动设为 confirmed、误报或安全。</Text></Space></div>
      </> : null}
    </Modal>
  </>;
}

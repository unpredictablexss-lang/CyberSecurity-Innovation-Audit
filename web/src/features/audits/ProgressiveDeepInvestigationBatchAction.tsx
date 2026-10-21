import { useState } from "react";
import { Alert, Button, Checkbox, Descriptions, Modal, Space, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { go } from "../../components";

const { Paragraph, Text } = Typography;

export default function ProgressiveDeepInvestigationBatchAction({ quickScreenBatchId, enabled }: {
  quickScreenBatchId: string;
  enabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [approved, setApproved] = useState(false);
  const [preview, setPreview] = useState<any>(null);

  async function showPreview() {
    setOpen(true); setLoading(true); setApproved(false); setPreview(null);
    try {
      setPreview(await api("/operations/progressive-deep-investigation-batches/preview", {
        progressive_quick_screen_batch_id: quickScreenBatchId,
      }));
    } catch (error) {
      setOpen(false); message.error(String(error));
    } finally { setLoading(false); }
  }

  async function start() {
    if (!preview || !approved) return;
    setLoading(true);
    try {
      const operation = await api("/operations/progressive-deep-investigation-batches", {
        progressive_quick_screen_batch_id: quickScreenBatchId,
        source_submission_approved: true,
        consent_sha256: preview.consent_sha256,
        consent_nonce: preview.consent_nonce,
        consent_expires_at: preview.consent_expires_at,
      });
      setOpen(false);
      message.success(`已创建 L3 深度调查批次：${preview.selected_group_count} 组；逐组受任务账本限制`);
      if (operation?.id) go("/tasks/operations/" + operation.id);
    } catch (error) { message.error(String(error)); }
    finally { setLoading(false); }
  }

  return <>
    <Button size="small" type="primary" disabled={!enabled} onClick={() => void showPreview()}>
      预览并批量授权 L3 深查
    </Button>
    <Modal title="任务级 L3 深度调查范围与预算预览" open={open} width={1020}
      confirmLoading={loading} okText="确认清单并排队" cancelText="取消"
      okButtonProps={{ disabled: !preview || !approved }}
      onOk={() => void start()} onCancel={() => { setOpen(false); setApproved(false); }} destroyOnClose>
      {loading && !preview ? <Paragraph>正在逐组构造固定来源 Agent、只读工具和 Skeptic 范围…</Paragraph> : preview ? <>
        <Alert type="warning" showIcon message="仅对 L2 已完成且建议 investigate 的组继续；本次授权覆盖下面展示的全部 Agent/Skeptic 调查范围，不运行 PoC。"
          description="Worker 按组顺序执行，沿用现有固定 Commit 只读 Agent 与任务级 Token、调用、并发、时间账本。未开始、失败和未知项继续保留为候选；美元额度仍是估算提示。" />
        <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
          <Descriptions.Item label="审计任务">{preview.audit_operation_id}</Descriptions.Item>
          <Descriptions.Item label="L2 批次 / 结果 SHA">{preview.l2_batch_operation_id} · {preview.l2_batch_result_sha256}</Descriptions.Item>
          <Descriptions.Item label="Provider / 模型">{preview.provider?.provider || preview.provider?.endpoint_host} · {preview.provider?.model}</Descriptions.Item>
          <Descriptions.Item label="已选 L3 组">{preview.selected_group_count}</Descriptions.Item>
          <Descriptions.Item label="深度组 / 模型调用上限">{preview.budget_limits?.deep_groups_per_audit} / {preview.budget_limits?.max_model_calls_per_audit}</Descriptions.Item>
          <Descriptions.Item label="输入 / 输出 Token 任务上限">{preview.budget_limits?.max_input_tokens_per_audit} / {preview.budget_limits?.max_output_tokens_per_audit}</Descriptions.Item>
          <Descriptions.Item label="时间上限 / USD 提示">{preview.budget_limits?.max_ai_wall_seconds} 秒 / ${preview.budget_limits?.max_cost_usd}（非账单硬封顶）</Descriptions.Item>
          <Descriptions.Item label="授权摘要 SHA-256" span={2}>{preview.consent_sha256}</Descriptions.Item>
        </Descriptions>
        {preview.skipped?.length > 0 && <Alert className="section-gap" type="info" showIcon
          message={`${preview.skipped.length} 组未纳入本次 L3 批次`}
          description={preview.skipped.map((row: any) => `${row.group_id}: ${row.reason}`).join("；")} />}
        <Text strong>逐组固定来源与 Agent 可访问范围</Text>
        <div className="section-gap" style={{ maxHeight: "50vh", overflow: "auto", paddingRight: 8 }}>
          {(preview.disclosures || []).map((item: any) => <section key={item.group_id} className="section-gap"
            style={{ border: "1px solid #d9d9d9", borderRadius: 8, padding: 12 }}>
            <Space wrap><Tag color="blue">{item.group_id}</Tag><Text code>{item.candidate_id}</Text><Text>{item.repository}@{item.commit}</Text></Space>
            <Paragraph className="section-gap" style={{ marginBottom: 4 }}>{item.file || "固定来源上下文"} · 报告 {item.report_sha256}</Paragraph>
            <Text strong>初始上下文</Text><pre className="raw section-gap">{JSON.stringify(item.initial_context, null, 2)}</pre>
            <Text strong>允许的工具与附加源码范围</Text>
            <div>{(item.allowed_tools || []).join("、") || "无"}</div>
            <pre className="raw section-gap">{(item.additional_tool_data_scope || []).join("\n") || "无额外源码范围"}</pre>
            <Text type="secondary">输入/输出 Token：{item.budgets?.max_total_input_tokens} / {item.budgets?.max_total_output_tokens}；步骤：{item.budgets?.max_steps}；最长：{item.budgets?.timeout_seconds} 秒</Text>
            <Paragraph className="section-gap">授权说明：{Array.isArray(item.disclosure) ? item.disclosure.join(" ") : "固定来源只读调查"}</Paragraph>
          </section>)}
        </div>
        <Checkbox checked={approved} onChange={(event) => setApproved(event.target.checked)}>
          我已逐组检查上面列出的候选、固定源码范围、工具、Provider 和预算，并明确授权此 L3 批次。
        </Checkbox>
        <div className="section-gap"><Space wrap><Tag color="blue">保留 candidate</Tag><Text type="secondary">L3 与 Skeptic 结果是调查证据，不会自动确认漏洞或标记误报。</Text></Space></div>
      </> : null}
    </Modal>
  </>;
}

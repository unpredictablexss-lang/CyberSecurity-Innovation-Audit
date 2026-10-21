import { useState } from "react";
import { Alert, Button, Checkbox, Descriptions, Modal, Space, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { go } from "../../components";

const { Paragraph, Text } = Typography;

export default function ProgressiveDeepInvestigationAction({ jobId, candidateId, quickScreenOperationId, progressiveGroupId }: {
  jobId: string;
  candidateId: string;
  quickScreenOperationId: string;
  progressiveGroupId?: string;
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
      const value = await api("/operations/progressive-deep-investigations/preview", {
        job_id: jobId, candidate_id: candidateId,
        progressive_quick_screen_operation_id: quickScreenOperationId,
        progressive_group_id: progressiveGroupId,
        mode: "tool_agent",
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
      const operation = await api("/operations/progressive-deep-investigations", {
        job_id: jobId, candidate_id: candidateId,
        progressive_quick_screen_operation_id: quickScreenOperationId,
        progressive_group_id: progressiveGroupId,
        mode: "tool_agent",
        max_steps: preview.budgets?.max_steps,
        max_output_tokens: preview.budgets?.max_output_tokens,
        max_total_input_tokens: preview.budgets?.max_total_input_tokens,
        max_total_output_tokens: preview.budgets?.max_total_output_tokens,
        timeout_seconds: preview.budgets?.timeout_seconds,
        source_submission_approved: true,
        consent_sha256: preview.consent_sha256,
        consent_nonce: preview.consent_nonce,
      });
      setOpen(false);
      message.success("L3 深度 Agent 已排队；它会沿用固定版本只读工具并受父任务预算门约束");
      if (operation?.id) go("/tasks/operations/" + operation.id);
    } catch (error) {
      message.error(String(error));
    } finally {
      setLoading(false);
    }
  }

  return <>
    <Button className="section-gap" type="primary" onClick={() => void showPreview()}>
      继续深度 Agent · 重新预览授权
    </Button>
    <Modal title="L3 深度 Agent 外发与预算预览" open={open} width={820}
      confirmLoading={loading} okText="确认授权并排队" cancelText="取消"
      okButtonProps={{ disabled: !preview || !approved }}
      onOk={() => void start()} onCancel={() => { setOpen(false); setApproved(false); }} destroyOnClose>
      {loading && !preview ? <Paragraph>正在校验 L2 结果并读取固定版本的只读调查上下文…</Paragraph> : preview ? <>
        <Alert type="warning" showIcon message="L2 的 investigate 建议只作为调度条件，不是漏洞确认。L3 会访问预览列出的固定 Commit 范围并执行 Skeptic 反证。" />
        <Descriptions className="section-gap" bordered size="small" column={2}>
          <Descriptions.Item label="Provider / 模型">{preview.provider?.endpoint_host || "未知"} · {preview.provider?.model || "未知"}</Descriptions.Item>
          <Descriptions.Item label="固定仓库 / Commit">{preview.binding?.repository} · {preview.binding?.commit}</Descriptions.Item>
          <Descriptions.Item label="候选 / 文件">{candidateId} · {preview.binding?.file}</Descriptions.Item>
          <Descriptions.Item label="已选只读工具">{preview.allowed_tools?.join("、") || "无"}</Descriptions.Item>
          <Descriptions.Item label="最大模型调用">任务共享上限 {preview.budgets?.progressive_task_shared_model_calls ?? "未知"}</Descriptions.Item>
          <Descriptions.Item label="最大工具步骤 / 深度组">{preview.budgets?.max_steps ?? "未知"}</Descriptions.Item>
          <Descriptions.Item label="本候选输入 / 输出 Token 上限">{preview.budgets?.max_total_input_tokens ?? "未知"} / {preview.budgets?.max_total_output_tokens ?? "未知"}</Descriptions.Item>
          <Descriptions.Item label="最长本操作时间">{preview.budgets?.timeout_seconds ?? "未知"} 秒</Descriptions.Item>
          <Descriptions.Item label="父审计 USD 策略">{preview.budgets?.progressive_task_shared_wall_seconds ?? "未知"} 秒；美元额度不是 Provider 账单硬上限</Descriptions.Item>
        </Descriptions>
        <Text strong>实际发送的初始上下文</Text>
        <pre className="raw section-gap">{JSON.stringify(preview.initial_context, null, 2)}</pre>
        <Text strong>只读工具可访问范围</Text>
        <pre className="raw section-gap">{(preview.additional_tool_data_scope || []).join("\n") || "没有额外工具范围"}</pre>
        <CollapseDisclosure items={preview.disclosure} />
        <Alert className="section-gap" type="info" message="L3 使用现有跨文件 Agent、Skeptic 与报告流程；模型结果仍待人工复核，候选状态不会自动改变。" />
        <Checkbox checked={approved} onChange={(event) => setApproved(event.target.checked)}>
          我已检查初始上下文、只读工具范围、Provider 和预算，并明确授权这次 L3 调查。
        </Checkbox>
        <div className="section-gap"><Space wrap><Tag color="blue">继续 candidate</Tag><Text type="secondary">可能反证仍需核实，不能自动记为误报。</Text></Space></div>
      </> : null}
    </Modal>
  </>;
}

function CollapseDisclosure({ items }: { items: unknown }) {
  return <Paragraph className="section-gap" type="secondary">{Array.isArray(items) ? items.join(" ") : "本次授权仅适用于上方固定来源、工具范围和预算。"}</Paragraph>;
}

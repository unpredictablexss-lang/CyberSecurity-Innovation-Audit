import React, { useState } from "react";
import { Alert, Button, Checkbox, Descriptions, Modal, Space, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { go } from "../../components";
import ChineseNarrative from "../cases/ChineseNarrative";

const { Paragraph, Text } = Typography;
const toolLabels: Record<string, string> = {
  inspect_guard: "检查保护条件", find_callers: "查找调用方", inspect_sink: "检查敏感操作",
  search_source: "搜索源码", read_source: "读取源码", find_symbol: "查找符号",
};

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
      message.error("深度调查操作未能完成，请检查服务状态或任务详情后重试。");
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
      message.success("深度智能调查已排队；将使用固定版本源码和只读工具继续追查");
      if (operation?.id) go("/tasks/operations/" + operation.id);
    } catch (error) {
      message.error("深度调查操作未能完成，请检查服务状态或任务详情后重试。");
    } finally {
      setLoading(false);
    }
  }

  return <>
    <Button className="section-gap" type="primary" onClick={() => void showPreview()}>
      继续深度调查 · 重新预览授权
    </Button>
    <Modal title="深度调查的源码发送与访问范围预览" open={open} width={820}
      confirmLoading={loading} okText="确认授权并排队" cancelText="取消"
      okButtonProps={{ disabled: !preview || !approved }}
      onOk={() => void start()} onCancel={() => { setOpen(false); setApproved(false); }} destroyOnClose>
      {loading && !preview ? <Paragraph>正在校验快速研判结果并读取固定版本的只读调查上下文…</Paragraph> : preview ? <>
        <Alert type="warning" showIcon message="快速研判的“建议继续调查”只用于决定后续流程，不代表漏洞已确认。深度调查将访问预览列出的固定提交源码，并进行反方核查。" />
        <Descriptions className="section-gap" bordered size="small" column={2}>
          <Descriptions.Item label="模型服务商 / 模型">{preview.provider?.endpoint_host || "未知"} · {preview.provider?.model || "未知"}</Descriptions.Item>
          <Descriptions.Item label="固定仓库 / Commit">{preview.binding?.repository} · {preview.binding?.commit}</Descriptions.Item>
          <Descriptions.Item label="候选 / 文件">{candidateId} · {preview.binding?.file}</Descriptions.Item>
          <Descriptions.Item label="已选只读工具">{preview.allowed_tools?.map((tool: string) => toolLabels[tool] || "只读源码工具").join("、") || "无"}</Descriptions.Item>
          <Descriptions.Item label="累计调查限制">平台不设累计令牌用量、调用次数、步骤、时长或费用上限</Descriptions.Item>
          <Descriptions.Item label="单次模型请求">单次输出上限 {preview.budgets?.max_output_tokens_per_request ?? "由模型服务商决定"} 个令牌；网络超时后保留未决证据</Descriptions.Item>
        </Descriptions>
        <Text strong>本次发送的初始上下文</Text>
        <pre className="raw section-gap">{JSON.stringify(preview.initial_context, null, 2)}</pre>
        <Text strong>只读工具可查看的范围</Text>
        <pre className="raw section-gap">{(preview.additional_tool_data_scope || []).join("\n") || "没有额外工具范围"}</pre>
        <CollapseDisclosure items={preview.disclosure} />
        <Alert className="section-gap" type="info" message="深度调查会跨文件追查、寻找反证并整理报告；结果仍需人工复核，候选状态不会自动改变。" />
        <Checkbox checked={approved} onChange={(event) => setApproved(event.target.checked)}>
          我已检查初始上下文、只读工具范围和模型服务商，并明确授权这次深度调查。
        </Checkbox>
        <div className="section-gap"><Space wrap><Tag color="blue">继续调查候选</Tag><Text type="secondary">反证线索仍需核实，系统不会自动标记为误报。</Text></Space></div>
      </> : null}
    </Modal>
  </>;
}

function CollapseDisclosure({ items }: { items: unknown }) {
  return <Paragraph className="section-gap" type="secondary">{Array.isArray(items) ? items.map((item: any, index: number) => <React.Fragment key={index}><ChineseNarrative value={item} /> </React.Fragment>) : "本次授权仅适用于上方固定来源和工具范围。"}</Paragraph>;
}

import React from "react";
import { Alert, Collapse, Table, Typography } from "antd";
export default function AuditPlanView({ plan }: { plan: any }) {
  if (!plan) return null;
  const decisions: Record<string, string> = { planned: "计划尝试", skipped: "跳过", blocked: "条件不足" };
  const reasons: Record<string, string> = {
    language_match_attempt: "语言匹配，计划尝试", no_matching_language: "当前范围无适用语言",
    explicit_selection_required: "仅显式选择：先复核适用范围", not_selected: "未选择",
    required_facts_unavailable: "所需程序事实不足",
  };
  return <div className="section-gap">
    <Alert showIcon type={plan.suggested_detector_ids.length ? "info" : "warning"}
      message={`规则计划：${plan.suggested_detector_ids.length} 项适用，${plan.parse_limitations.length} 个文件解析不完整`}
      description={`固定版本 ${plan.source.commit.slice(0, 12)}；仅计划尝试，实际执行和覆盖以扫描报告为准。`} />
    <Collapse items={[{ key: "plan", label: "查看规则版本与跳过原因", children: <>
      <Table size="small" pagination={false} rowKey="id" dataSource={plan.detectors} columns={[
        { title: "检测器", dataIndex: "id", render: (v) => <Typography.Text code>{v}</Typography.Text> },
        { title: "版本", dataIndex: "version" },
        { title: "计划", dataIndex: "decision", render: (v) => decisions[v] || v },
        { title: "原因", dataIndex: "reason_codes", render: (v: string[]) => v.map((code) => reasons[code] || code).join("；") },
      ]} />
      <Typography.Paragraph type="secondary">计划 SHA-256：{plan.plan_sha256}。未匹配文件 {plan.files_without_planned_detector.length} 个，安全状态 unknown。</Typography.Paragraph>
    </> }]} />
  </div>;
}

import React from "react";
import { auditWorkflowLabel } from "./model";
import { Alert, Collapse, Descriptions, Table, Typography } from "antd";
export default function AuditPlanView({ plan, auditMode }: { plan: any; auditMode?: string }) {
  if (!plan) return null;
  const decisions: Record<string, string> = { planned: "计划尝试", skipped: "跳过", blocked: "条件不足" };
  const reasons: Record<string, string> = {
    language_match_attempt: "语言匹配，计划尝试", no_matching_language: "当前范围无适用语言",
    explicit_selection_required: "仅显式选择：先复核适用范围", not_selected: "未选择",
    admission_not_approved: "尚未准入：真实证据或执行条件不足",
    required_facts_unavailable: "所需程序事实不足",
  };
  const source = plan.source || {};
  const budget = plan.execution_budget || {};
  const languageSummary = Object.entries(plan.languages || {}).map(([language, count]) => language + ": " + count).join("；") || "未识别到受支持源码";
  return <div className="section-gap">
    <Descriptions size="small" bordered column={1} items={[
      { key: "repository", label: "登记仓库名称", children: <>{source.repository || "未知"} <Typography.Text type="secondary">（本机登记标签，不代表官方身份核验）</Typography.Text></> },
      { key: "commit", label: "扫描代码版本", children: <Typography.Text code copyable>{source.commit || "unknown"}</Typography.Text> },
      { key: "tree", label: "Git Tree", children: <Typography.Text code copyable>{source.git_tree || "unknown"}</Typography.Text> },
      { key: "scope", label: "纳入路径", children: (source.include_paths || []).join("、") || "未知" },
      { key: "workflow", label: "审计流程", children: auditWorkflowLabel(plan, auditMode) },
      { key: "files", label: "已识别源码", children: (source.files || []).length + " 个文件；语言：" + languageSummary + "；解析不完整：" + (plan.parse_limitations || []).length + " 个文件" },
      { key: "budget", label: "执行预算", children: (budget.timeout_seconds ?? "未知") + " 秒超时 · " + (budget.memory_mb ?? "未知") + " MiB 内存上限" },
    ]} />
    <Alert className="section-gap" showIcon type={plan.suggested_detector_ids.length ? "info" : "warning"}
      message={`规则计划：${plan.suggested_detector_ids.length} 项计划尝试，${plan.detectors.filter((d: any) => d.admission).length} 项尚未准入，${plan.parse_limitations.length} 个文件解析不完整`}
      description={`扫描版本 ${plan.source.commit.slice(0, 12)}；仅计划尝试，实际执行和覆盖以扫描报告为准。工作流 SHA-256 会绑定单轮与补充核查预算。`} />
    <Collapse items={[{ key: "plan", label: "查看规则版本与跳过原因", children: <>
      <Table size="small" pagination={false}
        expandable={{
          rowExpandable: (row: any) => !!row.admission,
          expandedRowRender: (row: any) => <div>
            <Typography.Paragraph>{row.admission.summary}。执行已禁用；安全结论 unknown。</Typography.Paragraph>
            <Typography.Text strong>扫描准入还缺：</Typography.Text>
            <ul>{row.admission.missing_evidence.map((item: string) => <li key={item}>{item}</li>)}</ul>
            <Typography.Text strong>漏洞确认另需：</Typography.Text>
            <ul>{row.admission.confirmation_evidence.map((item: string) => <li key={item}>{item}</li>)}</ul>
          </div>,
        }} rowKey="id" dataSource={plan.detectors} columns={[
        { title: "检测器", dataIndex: "id", render: (v) => <Typography.Text code>{v}</Typography.Text> },
        { title: "版本", dataIndex: "version" },
        { title: "计划", dataIndex: "decision", render: (v) => decisions[v] || v },
        { title: "原因", dataIndex: "reason_codes", render: (v: string[]) => v.map((code) => reasons[code] || code).join("；") },
      ]} />
      <Typography.Paragraph type="secondary">扫描计划 SHA-256：{plan.plan_sha256}。流程预览 SHA-256：{plan.workflow_sha256 || "unknown"}。未匹配文件 {plan.files_without_planned_detector.length} 个，安全状态 unknown。</Typography.Paragraph>
    </> }]} />
  </div>;
}

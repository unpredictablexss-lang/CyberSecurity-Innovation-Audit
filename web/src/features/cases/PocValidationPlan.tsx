import React from "react";
import { Alert, Card, Collapse, Descriptions, Empty, List, Space, Tag, Typography } from "antd";
import { buildPocValidationPlan } from "./pocPlanModel.js";

const { Paragraph, Text } = Typography;

export default function PocValidationPlan({ candidateRow, operations = [] }: { candidateRow: any; operations?: any[] }) {
  const plan = buildPocValidationPlan(candidateRow, operations);
  const binding = plan.sourceBinding;
  const advancedDetails = <>
    <Alert type="info" showIcon
      message={plan.sourceBindingComplete ? "来源字段齐全，但未重新核验 Git 对象" : "来源记录不完整"}
      description={plan.sourceBindingComplete
        ? "以下身份值来自扫描报告；本页面没有重新从目标 Git 仓库校验 tree、blob 或内容哈希。"
        : "缺项：" + (plan.bindingMissingLabels.join("、") || "来源记录不完整") + "。计划仍保持 candidate / unknown。"} />
    <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="候选 ID"><Text code>{binding.candidateId || "unknown"}</Text></Descriptions.Item>
      <Descriptions.Item label="完整固定提交"><Text code>{binding.commit || "unknown"}</Text></Descriptions.Item>
      <Descriptions.Item label="报告 SHA-256"><Text style={{ wordBreak: "break-all" }}>{binding.reportSha256 || "unknown"}</Text></Descriptions.Item>
      <Descriptions.Item label="源码 SHA-256"><Text style={{ wordBreak: "break-all" }}>{binding.sourceSha256 || "unknown"}</Text></Descriptions.Item>
      <Descriptions.Item label="源码快照 SHA-256"><Text style={{ wordBreak: "break-all" }}>{binding.snapshotSha256 || "unknown"}</Text></Descriptions.Item>
      <Descriptions.Item label="Git tree OID"><Text code>{binding.treeOid || "unknown"}</Text></Descriptions.Item>
      <Descriptions.Item label="Git blob OID"><Text code>{binding.sourceBlobOid || "unknown"}</Text></Descriptions.Item>
      <Descriptions.Item label="扫描配置">{binding.profileId || "unknown"}</Descriptions.Item>
      <Descriptions.Item label="检测器 / 版本">{binding.detectorId || "unknown"} / {binding.detectorVersion || "unknown"}</Descriptions.Item>
      <Descriptions.Item label="规则 / 版本">{binding.ruleId || "unknown"} / {binding.ruleVersion || "unknown"}</Descriptions.Item>
      <Descriptions.Item label="来源状态">{binding.identityStatusLabel}</Descriptions.Item>
      <Descriptions.Item label="原始校验说明">{binding.verification}</Descriptions.Item>
      <Descriptions.Item label="源码字节范围">{binding.byteStart ?? "unknown"}–{binding.byteEnd ?? "unknown"}</Descriptions.Item>
    </Descriptions>
    <Card className="section-gap" size="small" title="人工登记的源码位置">
      {plan.sourceEvidence.length
        ? <List size="small" dataSource={plan.sourceEvidence} renderItem={(item: any) =>
          <List.Item><Space direction="vertical">
            <Text strong>{item.file}:{item.startLine ?? "?"}{item.endLine ? "–" + item.endLine : ""} · {item.kind}</Text>
            <Text>{item.note}</Text><Text type="secondary">证据 ID：{item.id}</Text>
          </Space></List.Item>} />
        : <Text type="secondary">暂无与候选文件匹配的人工位置记录。</Text>}
    </Card>
    <Card className="section-gap" size="small" title="与本候选绑定的 Agent 调查">
      {plan.matchingAgentOperationIds.length
        ? <List size="small" dataSource={plan.matchingAgentOperationIds} renderItem={(id: string) =>
          <List.Item><Space><Text>匹配的 Agent 调查记录</Text><Text code>{id}</Text></Space></List.Item>} />
        : <Text type="secondary">没有找到来源绑定与本候选一致的 Agent 调查记录。</Text>}
    </Card>
    <Card className="section-gap" size="small" title="同仓库、同提交的其他验证记录">
      {plan.validationContext.length
        ? <>
          <Paragraph>这些操作仅与候选仓库和提交一致，没有候选标识绑定，因此只作背景，不代表本候选已触发、已修复或已确认。</Paragraph>
          <List size="small" dataSource={plan.validationContext} renderItem={(item: any) =>
            <List.Item><Space wrap>
              <Text>固定测试组件</Text><Text code>{item.harnessId}</Text>
              <Tag>{item.statusLabel}</Tag><Text>{item.targetRepository} @ {String(item.targetCommit || "").slice(0, 12)}</Text>
              <Text type="secondary">操作记录 <Text code>{item.id}</Text></Text>
              <Tag color="orange">未绑定到本候选</Tag>
            </Space></List.Item>} />
        </>
        : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有同仓库、同固定提交的既有验证记录。" />}
    </Card>
  </>;

  return <Card className="section-gap" size="small" title="PoC 计划草案（未执行）">
    <Alert type="warning" showIcon
      message="当前结论：候选（candidate）/ 待确认（unknown）"
      description="这是待人工审查的验证计划，不是执行结果；没有生成可执行 PoC，也不表示漏洞已经确认。" />
    <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 3 }}>
      <Descriptions.Item label="仓库">{binding.repository || "待确认"}</Descriptions.Item>
      <Descriptions.Item label="固定版本">{binding.commit ? String(binding.commit || "").slice(0, 12) : "待确认"}</Descriptions.Item>
      <Descriptions.Item label="候选位置">{binding.file || "待确认"}{binding.line ? ":" + binding.line : ""}</Descriptions.Item>
    </Descriptions>
    <Card className="section-gap" size="small" title={"待核对事项（" + plan.obligations.length + " 项有记录）"}>
      {plan.obligations.length > 0 && <List size="small" dataSource={plan.obligations} renderItem={(item: any) =>
        <List.Item><Space direction="vertical" style={{ width: "100%" }}>
          <Space wrap>
            <Text strong>{item.kindLabel}</Text>
            <Tag color={item.status === "satisfied" ? "blue" : "orange"}>{item.statusLabel}</Tag>
            <Text type="secondary">来源：{item.sourceLabel}</Text>
          </Space>
          <Text>{item.description}</Text>
        </Space></List.Item>} />}
      <List size="small" dataSource={plan.unknowns} renderItem={(item: string) =>
        <List.Item><Space><Tag color="orange">待确认</Tag><Text>{item}</Text></Space></List.Item>} />
    </Card>
    <Card className="section-gap" size="small" title="验证步骤">
      <List size="small" dataSource={plan.sections} renderItem={(item: any, index: number) =>
        <List.Item><Space direction="vertical" style={{ width: "100%" }}>
          <Text strong>{index + 1}. {item.title}</Text>
          <Paragraph style={{ marginBottom: 0 }}>{item.detail}</Paragraph>
        </Space></List.Item>} />
    </Card>
    <Collapse className="section-gap" items={[{
      key: "advanced-source-details",
      label: "高级来源详情（候选 ID、哈希、检测器与原始记录）",
      children: advancedDetails,
    }]} />
  </Card>;
}

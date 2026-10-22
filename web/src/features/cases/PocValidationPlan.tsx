import React from "react";
import { Alert, Card, Collapse, Descriptions, Empty, List, Space, Tag, Typography } from "antd";
import { buildPocValidationPlan } from "./pocPlanModel.js";
import ChineseNarrative from "./ChineseNarrative";

const { Paragraph, Text } = Typography;

export default function PocValidationPlan({ candidateRow, operations = [] }: { candidateRow: any; operations?: any[] }) {
  const plan = buildPocValidationPlan(candidateRow, operations);
  const binding = plan.sourceBinding;
  const advancedDetails = <>
    <Alert type="info" showIcon
      message={plan.sourceBindingComplete ? "来源字段齐全，但未重新核验 Git 对象" : "来源记录不完整"}
      description={plan.sourceBindingComplete
        ? "以下身份值来自扫描报告；本页面没有重新从目标 Git 仓库校验 tree、blob 或内容哈希。"
        : "缺项：" + (plan.bindingMissingLabels.join("、") || "来源记录不完整") + "。计划仍保持候选 / 未知状态。"} />
    <Descriptions className="section-gap" bordered size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="候选 ID"><Text code>{binding.candidateId || "未知"}</Text></Descriptions.Item>
      <Descriptions.Item label="完整固定提交"><Text code>{binding.commit || "未知"}</Text></Descriptions.Item>
      <Descriptions.Item label="报告 SHA-256"><Text style={{ wordBreak: "break-all" }}>{binding.reportSha256 || "未知"}</Text></Descriptions.Item>
      <Descriptions.Item label="源码 SHA-256"><Text style={{ wordBreak: "break-all" }}>{binding.sourceSha256 || "未知"}</Text></Descriptions.Item>
      <Descriptions.Item label="源码快照 SHA-256"><Text style={{ wordBreak: "break-all" }}>{binding.snapshotSha256 || "未知"}</Text></Descriptions.Item>
      <Descriptions.Item label="Git tree OID"><Text code>{binding.treeOid || "未知"}</Text></Descriptions.Item>
      <Descriptions.Item label="Git blob OID"><Text code>{binding.sourceBlobOid || "未知"}</Text></Descriptions.Item>
      <Descriptions.Item label="扫描配置">{binding.profileId || "未知"}</Descriptions.Item>
      <Descriptions.Item label="检测器 / 版本">{binding.detectorId || "未知"} / {binding.detectorVersion || "未知"}</Descriptions.Item>
      <Descriptions.Item label="规则 / 版本">{binding.ruleId || "未知"} / {binding.ruleVersion || "未知"}</Descriptions.Item>
      <Descriptions.Item label="来源状态">{binding.identityStatusLabel}</Descriptions.Item>
      <Descriptions.Item label="原始校验说明"><ChineseNarrative value={binding.verification} /></Descriptions.Item>
      <Descriptions.Item label="源码字节范围">{binding.byteStart ?? "未知"}–{binding.byteEnd ?? "未知"}</Descriptions.Item>
    </Descriptions>
    <Card className="section-gap" size="small" title="人工登记的源码位置">
      {plan.sourceEvidence.length
        ? <List size="small" dataSource={plan.sourceEvidence} renderItem={(item: any) =>
          <List.Item><Space direction="vertical">
            <Text strong>{item.file}:{item.startLine ?? "?"}{item.endLine ? "–" + item.endLine : ""} · <ChineseNarrative value={item.kind || "人工证据"} /></Text>
            <ChineseNarrative value={item.note} /><Text type="secondary">证据 ID：{item.id}</Text>
          </Space></List.Item>} />
        : <Text type="secondary">暂无与候选文件匹配的人工位置记录。</Text>}
    </Card>
    <Card className="section-gap" size="small" title="与本候选绑定的智能调查">
      {plan.matchingAgentOperationIds.length
        ? <List size="small" dataSource={plan.matchingAgentOperationIds} renderItem={(id: string) =>
          <List.Item><Space><Text>匹配的智能调查记录</Text><Text code>{id}</Text></Space></List.Item>} />
        : <Text type="secondary">没有找到来源绑定与本候选一致的智能调查记录。</Text>}
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

  return <Card className="section-gap" size="small" title="验证计划草案（未执行）">
    <Alert type="warning" showIcon
      message="当前结论：候选 / 待确认"
      description="这是待人工审查的验证计划，不是执行结果；没有生成可执行验证用例，也不表示漏洞已经确认。" />
    <Alert className="section-gap" type="info" showIcon
      message="获得授权的智能调查可生成 PoC 草案"
      description="对候选创建并授权智能调查后，模型会根据本次读取的固定源码与研判证据提出本地测试草案；证据不足时保留空白。草案只展示、不自动执行，需人工审查并通过受控验证。结果见智能调查与报告草案。" />
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
          <ChineseNarrative value={item.description} />
        </Space></List.Item>} />}
      <List size="small" dataSource={plan.unknowns} renderItem={(item: string) =>
        <List.Item><Space><Tag color="orange">待确认</Tag><ChineseNarrative value={item} /></Space></List.Item>} />
    </Card>
    <Card className="section-gap" size="small" title="验证步骤">
      <List size="small" dataSource={plan.sections} renderItem={(item: any, index: number) =>
        <List.Item><Space direction="vertical" style={{ width: "100%" }}>
          <Text strong>{index + 1}. <ChineseNarrative value={item.title} /></Text>
          <Paragraph style={{ marginBottom: 0 }}><ChineseNarrative value={item.detail} /></Paragraph>
        </Space></List.Item>} />
    </Card>
    <Collapse className="section-gap" items={[{
      key: "advanced-source-details",
      label: "高级来源详情（候选 ID、哈希、检测器与原始记录）",
      children: advancedDetails,
    }]} />
  </Card>;
}

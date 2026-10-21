import React, { useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Col, Divider, Input, InputNumber, Radio, Row, Space, Spin, Switch, Tag, Typography, message } from "antd";

const { Paragraph, Text } = Typography;
const API_PATH = "/api/v1/agent/triage-policy";
const LIMIT_FIELDS: Array<{ key: string; label: string; min: number; max: number; unit?: string }> = [
  { key: "quick_screen_groups_per_audit", label: "自动快筛候选组数", min: 1, max: 10_000, unit: "组" },
  { key: "deep_groups_per_audit", label: "可进入深度调查的候选组数", min: 0, max: 1_000, unit: "组" },
  { key: "max_tool_steps_per_group", label: "每组只读工具步骤上限", min: 1, max: 12, unit: "步" },
  { key: "max_model_concurrency", label: "模型请求并发", min: 1, max: 8, unit: "路" },
  { key: "max_model_calls_per_audit", label: "单次审计模型请求总数", min: 1, max: 10_000, unit: "次" },
];
const TOKEN_LIMIT_FIELDS: Array<{ key: string; label: string; min: number; max: number; unit?: string }> = [
  { key: "max_input_tokens_per_audit", label: "单次审计输入 Token 上限", min: 1_024, max: 2_000_000, unit: "tokens" },
  { key: "max_output_tokens_per_audit", label: "单次审计累计输出 Token 上限", min: 256, max: 500_000, unit: "tokens" },
  { key: "max_output_tokens_per_request", label: "单轮模型输出上限", min: 128, max: 3_000, unit: "tokens" },
  { key: "max_ai_wall_seconds", label: "单次审计 AI 总时长", min: 60, max: 14_400, unit: "秒" },
];
const INTEGRATION_LABELS: Record<string, string> = {
  connected_to_multi_endpoint_operation_results: "已接入多端审计结果",
  l2_l3_fixed_source_consent_and_parent_budget_gate: "已接入固定源码授权与共享预算门禁",
  task_level_explicit_consent_batch_and_individual_explicit_consent: "L2 单项与批量授权已接入",
  task_level_explicit_scope_consent_sequential_existing_agent_with_shared_budget: "L3 固定范围授权与共享预算已接入",
  unknown: "状态未知",
};

type Limits = Record<string, number | string>;
type Profile = "economical" | "standard" | "deep" | "custom";

function normalizeLimits(value: Limits): Limits {
  return {
    ...value,
    max_tool_steps_per_group: Math.min(12, Number(value.max_tool_steps_per_group) || 8),
    // v1 tasks did not expose an L3 per-request cap; its former default was 1200.
    max_output_tokens_per_request: value.max_output_tokens_per_request
      ?? Math.min(1200, Number(value.max_output_tokens_per_audit) || 1200),
  };
}

export default function IntelligentAuditPolicySettings() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [profile, setProfile] = useState<Profile>("standard");
  const [limits, setLimits] = useState<Limits>({});
  const [familyQuotas, setFamilyQuotas] = useState(true);
  const [presets, setPresets] = useState<Record<string, { limits: Limits; family_quotas: boolean }>>({});
  const [integration, setIntegration] = useState<Record<string, unknown>>({});
  const [savedConfiguration, setSavedConfiguration] = useState("");

  const configurationSignature = (nextProfile: Profile, nextLimits: Limits, nextFamilyQuotas: boolean) =>
    JSON.stringify({ profile: nextProfile, limits: nextLimits, family_quotas: nextFamilyQuotas });

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(API_PATH);
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || response.statusText);
      setRevision(body.revision);
      setUpdatedAt(body.updated_at);
      setProfile(body.policy.profile);
      setLimits(normalizeLimits(body.policy.limits));
      setFamilyQuotas(body.policy.family_quotas);
      setPresets(body.presets || {});
      setIntegration(body.integration || {});
      setSavedConfiguration(configurationSignature(body.policy.profile, normalizeLimits(body.policy.limits), body.policy.family_quotas));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const isCustom = profile === "custom";
  const hasUnsavedChanges = Boolean(savedConfiguration)
    && savedConfiguration !== configurationSignature(profile, limits, familyQuotas);
  const changedLimitsValid = useMemo(() => LIMIT_FIELDS.every(({ key, min, max }) => {
    const value = limits[key];
    return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
  }) && typeof limits.max_cost_usd === "string"
    && /^(?:0|[1-9]\d{0,5})(?:\.\d{1,8})?$/.test(limits.max_cost_usd)
    && Number(limits.max_cost_usd) > 0 && Number(limits.max_cost_usd) <= 1000
    && Number(limits.max_output_tokens_per_request) <= Number(limits.max_output_tokens_per_audit)
    && Number(limits.deep_groups_per_audit) <= Number(limits.quick_screen_groups_per_audit), [limits]);

  const selectProfile = (next: Profile) => {
    setProfile(next);
    if (next !== "custom" && presets[next]) {
      setLimits(presets[next].limits);
      setFamilyQuotas(presets[next].family_quotas);
    }
    if (next === "custom" && !Object.keys(limits).length && presets.standard) {
      setLimits({ ...presets.standard.limits });
      setFamilyQuotas(presets.standard.family_quotas);
    }
  };

  const editLimit = (key: string, value: number | string | null) => {
    setProfile("custom");
    if (key === "max_cost_usd") {
      setLimits((current) => ({ ...current, [key]: String(value ?? "") }));
      return;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      setLimits((current) => ({ ...current, [key]: Math.trunc(value) }));
    }
  };

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      const response = await fetch(API_PATH, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-OHScanner-Client": "workbench-v1" },
        body: JSON.stringify({
          expected_revision: revision,
          profile,
          ...(isCustom ? { limits, family_quotas: familyQuotas } : {}),
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || response.statusText);
      setRevision(body.revision);
      setUpdatedAt(body.updated_at);
      setProfile(body.policy.profile);
      setLimits(normalizeLimits(body.policy.limits));
      setFamilyQuotas(body.policy.family_quotas);
      setSavedConfiguration(configurationSignature(body.policy.profile, normalizeLimits(body.policy.limits), body.policy.family_quotas));
      message.success("智能审计策略已保存到本机设置");
    } catch (reason) {
      setError(String(reason));
      if (String(reason).includes("policy changed")) void load();
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <Card><Spin /></Card>;
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Alert type="info" showIcon message="智能审计策略说明"
      description={<Space direction="vertical" size={4}>
        <Text>静态审计在本地运行。渐进 L2/L3 和普通 Agent 调查发送源码前会展示固定范围并要求本次授权；任务创建后冻结当前策略，后续修改只影响新任务。</Text>
        <Text type="secondary">L0/L1：{INTEGRATION_LABELS[String(integration.grouping_and_ranking)] || "状态未知"}；L2：{INTEGRATION_LABELS[String(integration.quick_screen_executor)] || "状态未知"}；L3：{INTEGRATION_LABELS[String(integration.deep_agent_executor)] || "状态未知"}。</Text>
      </Space>} />
    {error && <Alert type="error" showIcon message="策略读取或保存失败" description={error} />}
    <Card title="选择策略" extra={<Tag color={hasUnsavedChanges ? "orange" : updatedAt ? "green" : "blue"}>
      {hasUnsavedChanges ? "有未保存更改" : updatedAt ? `已保存 · 修订 ${revision}` : "使用默认标准策略"}
    </Tag>}>
      <Radio.Group value={profile} onChange={(event) => selectProfile(event.target.value)}>
        <Space wrap>
          <Radio.Button value="economical">经济</Radio.Button>
          <Radio.Button value="standard">标准（推荐）</Radio.Button>
          <Radio.Button value="deep">深度</Radio.Button>
          <Radio.Button value="custom">自定义</Radio.Button>
        </Space>
      </Radio.Group>
      <Paragraph type="secondary" style={{ marginTop: 14, marginBottom: 0 }}>
        选择经济、标准或深度后，保存即可一次应用整套候选范围、单轮输出、累计 Token、请求次数、工具步数、并发与 AI 时长；要改单项时先切换到“自定义”。普通 Agent 单候选、批量、配对任务以及渐进 L2/L3 都从这里继承额度；L2 单轮最多 512 tokens，L3 与普通调查使用所选策略的单轮上限。费用金额仅用于账本参考，不能作为服务商账单硬限额。
      </Paragraph>
    </Card>
    <Card title="审计范围与资源预算" extra={isCustom ? <Tag color="blue">自定义</Tag> : <Tag color="blue">{profile === "standard" ? "标准策略" : profile === "economical" ? "经济策略" : "深度策略"}</Tag>}>
      <Typography.Title level={5} style={{ marginTop: 0 }}>候选与执行范围</Typography.Title>
      <Row gutter={[16, 8]}>
        {LIMIT_FIELDS.map(({ key, label, min, max, unit }) => (
          <Col xs={24} md={12} key={key}>
            <Text>{label}</Text>
            <InputNumber style={{ width: "100%", marginTop: 6 }} min={min} max={max}
              precision={0} step={1} disabled={!isCustom || saving}
              value={typeof limits[key] === "number" ? limits[key] as number : undefined}
              addonAfter={unit} onChange={(value) => editLimit(key, value)} />
          </Col>
        ))}
      </Row>
      <Divider />
      <Typography.Title level={5} style={{ marginTop: 0 }}>Token 与调查时长</Typography.Title>
      <Row gutter={[16, 8]}>
        {TOKEN_LIMIT_FIELDS.map(({ key, label, min, max, unit }) => (
          <Col xs={24} md={12} key={key}>
            <Text>{label}</Text>
            <InputNumber style={{ width: "100%", marginTop: 6 }} min={min} max={max}
              precision={0} step={1} disabled={!isCustom || saving}
              value={typeof limits[key] === "number" ? limits[key] as number : undefined}
              addonAfter={unit} onChange={(value) => editLimit(key, value)} />
          </Col>
        ))}
        <Col xs={24} md={12}>
          <Text>费用参考金额（不作为硬停止线）</Text>
          <Input style={{ marginTop: 6 }} disabled={!isCustom || saving} value={String(limits.max_cost_usd || "")}
            addonAfter="USD" onChange={(event) => editLimit("max_cost_usd", event.target.value)} />
        </Col>
      </Row>
      <Space style={{ marginTop: 18 }}>
        <Switch checked={familyQuotas} disabled={!isCustom || saving} onChange={(checked) => setFamilyQuotas(checked)} />
        <Text>启用漏洞家族覆盖配额</Text>
      </Space>
      <Paragraph type="secondary" style={{ marginTop: 12 }}>
        保存后新建的渐进式智能审计和普通 Agent 调查会自动继承这些额度，任务表单不再重复配置；创建任务时会冻结本策略，已有任务不受后续设置修改影响。渐进审计使用任务共享账本；普通 Agent 调查按单任务限制累计用量、请求、工具步骤和时长。标准审计的旧自动分诊 R1/R2 已继承单轮输出上限，但还没有累计 Token、请求次数和总时长账本。美元金额只作估算参考，真正账单和账户额度由服务商决定；未进入自动调查范围的候选继续保留人工复核。
      </Paragraph>
      <Space>
        <Button type="primary" onClick={() => void save()} loading={saving} disabled={saving || (isCustom && !changedLimitsValid)}>保存并应用到之后的新任务</Button>
        <Button onClick={() => void load()} disabled={saving}>重新读取</Button>
        {updatedAt && <Text type="secondary">最近保存：{new Date(updatedAt).toLocaleString()}</Text>}
      </Space>
    </Card>
  </Space>;
}

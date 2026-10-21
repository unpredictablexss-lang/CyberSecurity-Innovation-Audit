import React, { useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Col, Input, InputNumber, Radio, Row, Space, Spin, Switch, Tag, Typography, message } from "antd";

const { Paragraph, Text } = Typography;
const API_PATH = "/api/v1/agent/triage-policy";
const LIMIT_FIELDS: Array<{ key: string; label: string; min: number; max: number; unit?: string }> = [
  { key: "quick_screen_groups_per_audit", label: "快速研判组数（整个任务）", min: 1, max: 10_000, unit: "组" },
  { key: "deep_groups_per_audit", label: "深度 Agent 组数（整个任务）", min: 0, max: 1_000, unit: "组" },
  { key: "max_tool_steps_per_group", label: "跨文件工具步骤（每个深度组）", min: 1, max: 32, unit: "步" },
  { key: "max_model_concurrency", label: "模型请求并发", min: 1, max: 8, unit: "路" },
  { key: "max_ai_wall_seconds", label: "AI 调查时间预算", min: 60, max: 14_400, unit: "秒" },
  { key: "max_model_calls_per_audit", label: "模型调用参考上限（整个任务）", min: 1, max: 10_000, unit: "次" },
  { key: "max_input_tokens_per_audit", label: "输入 Token 参考上限（整个任务）", min: 1_024, max: 2_000_000, unit: "tokens" },
  { key: "max_output_tokens_per_audit", label: "输出 Token 参考上限（整个任务）", min: 256, max: 500_000, unit: "tokens" },
];

type Limits = Record<string, number | string>;
type Profile = "economical" | "standard" | "deep" | "custom";

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
      setLimits(body.policy.limits);
      setFamilyQuotas(body.policy.family_quotas);
      setPresets(body.presets || {});
      setIntegration(body.integration || {});
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const isCustom = profile === "custom";
  const changedLimitsValid = useMemo(() => LIMIT_FIELDS.every(({ key, min, max }) => {
    const value = limits[key];
    return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
  }) && typeof limits.max_cost_usd === "string"
    && /^(?:0|[1-9]\d{0,5})(?:\.\d{1,8})?$/.test(limits.max_cost_usd)
    && Number(limits.max_cost_usd) > 0 && Number(limits.max_cost_usd) <= 1000, [limits]);

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
      setLimits(body.policy.limits);
      setFamilyQuotas(body.policy.family_quotas);
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
    <Alert type="info" showIcon message="L0–L3 渐进式审计策略已接入"
      description={`运行状态：L0/L1 ${String(integration.grouping_and_ranking || "unknown")}；Worker 门禁 ${String(integration.worker_enforcement || "unknown")}；L2 ${String(integration.quick_screen_executor || "unknown")}；L3 ${String(integration.deep_agent_executor || "unknown")}；任务账本 ${String(integration.task_budget_ledger || "unknown")}。静态审计仍只做本地分析；L2/L3 必须先预览固定源码范围并取得任务级授权。美元预算用于调度参考，Provider 账单没有硬封顶。`} />
    {error && <Alert type="error" showIcon message="策略读取或保存失败" description={error} />}
    <Card title="选择策略" extra={<Tag color={updatedAt ? "green" : "blue"}>{updatedAt ? `已保存 · 修订 ${revision}` : "使用默认标准策略"}</Tag>}>
      <Radio.Group value={profile} onChange={(event) => selectProfile(event.target.value)}>
        <Space wrap>
          <Radio.Button value="economical">经济</Radio.Button>
          <Radio.Button value="standard">标准（推荐）</Radio.Button>
          <Radio.Button value="deep">深度</Radio.Button>
          <Radio.Button value="custom">自定义</Radio.Button>
        </Space>
      </Radio.Group>
      <Paragraph type="secondary" style={{ marginTop: 14, marginBottom: 0 }}>
        配额针对一次完整审计任务；时间范围、分支对比和版本矩阵不得按端点重复发放。
        初始预设来自产品建议，尚未通过真实 Provider 费用和召回实验验证。
      </Paragraph>
    </Card>
    <Card title="资源预算" extra={isCustom ? <Tag>自定义</Tag> : <Tag>{profile}</Tag>}>
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
        <Col xs={24} md={12}>
          <Text>美元预算建议值（软预算）</Text>
          <Input style={{ marginTop: 6 }} disabled={!isCustom || saving} value={String(limits.max_cost_usd || "")}
            addonAfter="USD" onChange={(event) => editLimit("max_cost_usd", event.target.value)} />
        </Col>
      </Row>
      <Space style={{ marginTop: 18 }}>
        <Switch checked={familyQuotas} disabled={!isCustom || saving} onChange={(checked) => setFamilyQuotas(checked)} />
        <Text>启用漏洞家族覆盖配额</Text>
      </Space>
      <Paragraph type="secondary" style={{ marginTop: 12 }}>
        日期、区间、分支和矩阵操作结果会按任务冻结的策略分组和排序；L2 快筛与 L3 深度调查使用任务共享账本限制模型调用和 Token 额度。未进入模型预算的静态候选仍保留供人工查看，不会变成误报或安全结论。
      </Paragraph>
      <Space>
        <Button type="primary" onClick={() => void save()} loading={saving} disabled={saving || (isCustom && !changedLimitsValid)}>保存策略</Button>
        <Button onClick={() => void load()} disabled={saving}>重新读取</Button>
        {updatedAt && <Text type="secondary">最近保存：{new Date(updatedAt).toLocaleString()}</Text>}
      </Space>
    </Card>
  </Space>;
}

import React, { useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Col, Input, InputNumber, Radio, Row, Space, Spin, Switch, Tag, Typography, message } from "antd";

const { Paragraph, Text } = Typography;
const API_PATH = "/api/v1/agent/triage-policy";
const LIMIT_FIELDS: Array<{ key: string; label: string; min: number; max: number; unit?: string }> = [
  { key: "quick_screen_groups_per_audit", label: "自动快筛候选组数", min: 1, max: 10_000, unit: "组" },
  { key: "deep_groups_per_audit", label: "可进入深度调查的候选组数 / 手动批量条数", min: 0, max: 1_000, unit: "组" },
  { key: "max_model_concurrency", label: "模型请求并发", min: 1, max: 8, unit: "路" },
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
  const [requestOutput, setRequestOutput] = useState<number | null>(5000);
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
      setRequestOutput(body.policy.request_output_tokens === null ? null : (body.policy.request_output_tokens ?? 5000));
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
          request_output_tokens: requestOutput,
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
      setRequestOutput(body.policy.request_output_tokens === null ? null : (body.policy.request_output_tokens ?? 5000));
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
    <Alert type="info" showIcon message="智能审计使用范围"
      description={`运行状态：L0/L1 ${String(integration.grouping_and_ranking || "unknown")}；Worker 门禁 ${String(integration.worker_enforcement || "unknown")}；L2 ${String(integration.quick_screen_executor || "unknown")}；L3 ${String(integration.deep_agent_executor || "unknown")}。静态审计只做本地分析；L2/L3 会先展示固定源码范围并要求授权。平台不设累计 Token、模型调用或调查时长上限；真实额度和费用由模型服务商账户决定，调查可随时取消。`} />
    {error && <Alert type="error" showIcon message="策略读取或保存失败" description={error} />}
    <Card title="单次模型输出额度（统一配置）">
      <Space wrap>
        <Switch checked={requestOutput === null} disabled={saving} onChange={(checked) => setRequestOutput(checked ? null : 5000)} />
        <Text>不设本地 Token 上限（实验）</Text>
        {requestOutput !== null && <InputNumber aria-label="单次模型输出额度" min={128} max={65536} precision={0}
          value={requestOutput} disabled={saving} addonAfter="Token" onChange={(value) => { if (value != null) setRequestOutput(Number(value)); }} />}
      </Space>
      <Paragraph type="secondary" style={{ marginTop: 12 }}>默认 5000，包含模型思考与回答。AI 初步分析、深入追查、反证复核和报告草案统一读取这里；实验模式不向模型服务商传输出 Token 上限，服务商自身限制仍可能生效。保存后新建任务使用新值，旧任务保留原额度；修改后须重新预览授权。</Paragraph>
      <Button type="primary" loading={saving} onClick={() => void save()}>保存单次输出设置</Button>
    </Card>
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
        预设只调整自动进入 L2/L3 的候选范围与请求并发，不限制单次调查累计 Token、模型调用或总时长。
      </Paragraph>
    </Card>
    <Card title="候选范围与并发" extra={isCustom ? <Tag>自定义</Tag> : <Tag>{profile}</Tag>}>
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
          <Text>费用估算参考（不触发停止）</Text>
          <Input style={{ marginTop: 6 }} disabled={!isCustom || saving} value={String(limits.max_cost_usd || "")}
            addonAfter="USD" onChange={(event) => editLimit("max_cost_usd", event.target.value)} />
        </Col>
      </Row>
      <Space style={{ marginTop: 18 }}>
        <Switch checked={familyQuotas} disabled={!isCustom || saving} onChange={(checked) => setFamilyQuotas(checked)} />
        <Text>启用漏洞家族覆盖配额</Text>
      </Space>
      <Paragraph type="secondary" style={{ marginTop: 12 }}>
        任务会冻结候选分组、自动快筛范围和并发策略。账本记录模型用量供查看，不会因累计 Token、调用次数、时长或费用停止调查；未进入自动调查范围的静态候选仍保留供人工查看，不会因此变成误报或安全结论。
      </Paragraph>
      <Space>
        <Button type="primary" onClick={() => void save()} loading={saving} disabled={saving || (isCustom && !changedLimitsValid)}>保存策略</Button>
        <Button onClick={() => void load()} disabled={saving}>重新读取</Button>
        {updatedAt && <Text type="secondary">最近保存：{new Date(updatedAt).toLocaleString()}</Text>}
      </Space>
    </Card>
  </Space>;
}

import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Form, Input, Modal, Space, Tag, message } from "antd";
import { api } from "../../api";

export default function AgentProviderSettings() {
  const [form] = Form.useForm();
  const [modal, contextHolder] = Modal.useModal();
  const [settings, setSettings] = useState<any>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [probe, setProbe] = useState<any>(null);
  const refresh = async () => {
    setError(""); setProbe(null);
    try {
      const current = await api("/agent/provider-settings");
      setSettings(current);
      form.setFieldsValue({ base_url: current.base_url, model: current.model, proxy_url: current.proxy_url, api_key: "" });
    } catch (e) { setError(String(e)); }
  };
  useEffect(() => { void refresh(); }, []);
  const save = async (values: any) => {
    setBusy(true); setError(""); setProbe(null);
    try {
      const result = await api("/agent/provider-settings", values);
      setSettings(result); form.setFieldValue("api_key", "");
      message.success("模型配置已保存到本机服务");
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };
  const test = () => modal.confirm({
    title: "测试模型 API 连通性？",
    content: "将向已配置端点发送一条预设的无源码请求，验证 API 连通性和调查所用的 JSON Schema 结构化输出（最多输出 32 tokens），可能产生少量 API 费用；不会创建调查任务或发送候选源码。该检查不验证工具调用、代码分析、引用正确性或模型质量。",
    okText: "发送无源码测试", cancelText: "取消",
    onOk: async () => {
      setBusy(true); setError(""); setProbe(null);
      try { const result = await api("/agent/provider-check", { confirm_no_source_request: true }); setProbe(result); message.success("连通性检查通过"); }
      catch (e) { setError(String(e)); }
      finally { setBusy(false); }
    },
  });
  const clear = () => modal.confirm({
    title: "移除已保存的 API Key？",
    content: "移除后真实模型调查将不可用，已有人工静态复核记录和扫描数据不会受影响。",
    okText: "移除 Key", cancelText: "保留",
    onOk: async () => {
      setBusy(true); setError(""); setProbe(null);
      try { const result = await api("/agent/provider-settings/clear", {}); setSettings(result); message.success("已移除本机保存的 API Key"); }
      catch (e) { setError(String(e)); }
      finally { setBusy(false); }
    },
  });
  return <Card title="Agent / LLM 模型服务" extra={<Button onClick={() => void refresh()} disabled={busy}>刷新状态</Button>}>
    {contextHolder}
    <Alert className="section-gap" type="info" showIcon message="凭据由本地服务保存；面板不会回显 API Key，保存也不会发送源码。"
      description="单机模式将 Key 存在 OHSCANNER_DATA 下独立且仅当前系统用户可读写的文件，不写入 Git、SQLite 或任务记录。共享/托管部署应接入系统密钥库或外部 Secret Manager。候选源码外发仍需逐次预览并批准。" />
    {settings && !settings.editable && <Alert className="section-gap" type="warning" showIcon message="配置由服务环境变量管理，面板只读。" />}
    <Alert className="section-gap" type="info" showIcon message="小米 MiMo 后端接入方式"
      description="本地 Agent 后端仅支持 MiMo 按量 API（https://api.xiaomimimo.com/v1，普通 API Key）。Token Plan 专用端点和 tp-/ttp- 密钥的条款只允许受支持的编程工具，不允许接入自建应用后端；服务端会拒绝 token-plan-*.xiaomimimo.com 地址。" />
    {settings?.base_url && (() => {
      try {
        const endpoint = new URL(settings.base_url);
        if (endpoint.hostname === "api.deepseek.com" && endpoint.pathname.replace(/\/$/, "") === "/anthropic") {
          return <Alert className="section-gap" type="warning" showIcon message="当前地址与 Agent 请求协议不匹配。"
            description="本版本 Agent 使用 OpenAI Responses API，DeepSeek 地址应填写 https://api.deepseek.com。/anthropic 是 Anthropic Messages API 地址；用它测试会请求 /anthropic/responses 并失败。请改为 Responses 地址后保存，再运行无源码连通性检查。" />;
        }
      } catch { /* Backend validation will report malformed endpoints. */ }
      return null;
    })()}
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {settings && <Form form={form} layout="vertical" onFinish={save} disabled={!settings.editable || busy}>
      <Form.Item name="base_url" label="兼容 Responses API 的 HTTPS 地址" rules={[{ required: true }, { type: "url" }]}><Input placeholder="https://api.openai.com/v1" autoComplete="url" /></Form.Item>
      <Form.Item name="model" label="模型名称" rules={[{ required: true, max: 200 }]}><Input placeholder="填写服务商提供的模型 ID" autoComplete="off" /></Form.Item>
      <Form.Item name="api_key" label="API Key" extra={settings.api_key_configured ? "已保存。留空保留当前 Key；输入新值会轮换。" : "只在此表单输入；服务端不提供读取接口。"}><Input.Password autoComplete="new-password" placeholder={settings.api_key_configured ? "已配置（留空保留）" : "粘贴 API Key"} /></Form.Item>
      <Form.Item name="proxy_url" label="可选代理地址" extra="仅支持不含用户名、密码、路径和查询参数的 HTTP(S) 代理 URL。"><Input placeholder="留空使用系统直连" autoComplete="off" /></Form.Item>
      <Space wrap>
        <Button type="primary" htmlType="submit" loading={busy} disabled={!settings.editable}>保存模型配置</Button>
        <Button onClick={test} loading={busy} disabled={!settings.configured}>测试 API 与结构化输出</Button>
        {settings.api_key_configured && <Button danger onClick={clear} loading={busy} disabled={!settings.editable}>移除 API Key</Button>}
        <Tag color={settings.configured ? "green" : "default"}>{settings.configured ? "模型已配置" : "尚未配置"}</Tag>
        <Tag>{settings.configuration_source === "environment" ? "服务环境变量" : "本机私有配置"}</Tag>
      </Space>
      {(probe || settings.last_provider_check) && (() => {
        const checked = probe || settings.last_provider_check;
        const inputTokens = probe ? probe.usage?.input_tokens : checked.input_tokens;
        const outputTokens = probe ? probe.usage?.output_tokens : checked.output_tokens;
        return <Alert className="section-gap" type="success" showIcon message={`最近通过：${checked.checked_at || "本次页面会话"}`}
          description={`端点 ${checked.endpoint_host} · 模型 ${checked.model} · ${checked.duration_ms} ms · 输入 ${inputTokens ?? "未知"} / 输出 ${outputTokens ?? "未知"} tokens。探测只验证 API 连通性与最小结构化响应，不验证工具调用、代码分析、引用正确性或模型效果。保存新配置后需要重新测试。`} />;
      })()}
    </Form>}
  </Card>;
}

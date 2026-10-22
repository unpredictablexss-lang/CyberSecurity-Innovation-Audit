import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Form, Input, Modal, Select, Space, Tag, message } from "antd";
import { api } from "../../api";

export default function AgentProviderSettings() {
  const [form] = Form.useForm();
  const [modal, contextHolder] = Modal.useModal();
  const [settings, setSettings] = useState<any>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [probe, setProbe] = useState<any>(null);
  const apiProtocol = Form.useWatch("api_protocol", form) || settings?.api_protocol || "openai-responses";
  const refresh = async () => {
    setError(""); setProbe(null);
    try {
      const current = await api("/agent/provider-settings");
      setSettings(current);
      form.setFieldsValue({ api_protocol: current.api_protocol || "openai-responses", base_url: current.base_url,
        model: current.model, proxy_url: current.proxy_url, api_key: "" });
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
    content: "将按所选接口协议向服务发送一条预设的无源码请求，验证 API 连通性和 JSON 结构化输出（最多输出 256 tokens），可能产生少量 API 费用；不会创建调查任务或发送候选源码。该检查不验证函数工具调用、代码分析、引用正确性或模型质量。",
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
    <Alert className="section-gap" type="info" showIcon message="支持两类常见模型接口协议"
      description="Responses API 可用于 OpenAI、MiMo 等兼容端点；Chat Completions 兼容接口可用于 DeepSeek、阿里云百炼、火山方舟及兼容网关。具体模型还需支持 JSON 输出；AI 深入追查需要额外支持函数调用。Anthropic Messages 与 Gemini 原生接口暂未适配；若服务商提供 OpenAI 兼容端点，可选择 Chat Completions。" />
    {settings?.base_url && (() => {
      try {
        const endpoint = new URL(settings.base_url);
        if (endpoint.pathname.replace(/\/$/, "").endsWith("/anthropic")) {
          return <Alert className="section-gap" type="warning" showIcon message="当前地址与 Agent 请求协议不匹配。"
            description="该地址属于 Anthropic Messages API 路径，本地当前适配 Responses API 和 OpenAI 兼容 Chat Completions。请填写服务商文档中的兼容接口基础地址，再按对应协议测试。" />;
        }
      } catch { /* Backend validation will report malformed endpoints. */ }
      return null;
    })()}
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {settings && <Form form={form} layout="vertical" onFinish={save} disabled={!settings.editable || busy}>
      <Form.Item name="api_protocol" label="模型接口协议" rules={[{ required: true }]} extra="按服务商文档选择协议；服务端会自动追加对应 API 路径。">
        <Select options={[
          { value: "openai-responses", label: "OpenAI Responses API" },
          { value: "openai-chat-completions", label: "OpenAI 兼容 Chat Completions" },
        ]} />
      </Form.Item>
      <Alert className="section-gap" type="info" showIcon message={apiProtocol === "openai-responses" ? "Responses API 地址" : "Chat Completions 兼容地址"}
        description={apiProtocol === "openai-responses"
          ? "例如 https://api.openai.com/v1、https://api.xiaomimimo.com/v1。请填服务商提供的基础地址，不要重复填写 /responses。"
          : "例如 https://api.deepseek.com、https://dashscope.aliyuncs.com/compatible-mode/v1 或 https://ark.cn-beijing.volces.com/api/v3。请填基础地址，不要重复填写 /chat/completions。"} />
      <Form.Item name="base_url" label="HTTPS 接口基础地址" rules={[{ required: true }, { type: "url" }]}
        extra={`服务端将请求 ${apiProtocol === "openai-responses" ? "/responses" : "/chat/completions"}；基础地址须来自所选服务商的 API 文档。`}>
        <Input placeholder={apiProtocol === "openai-responses" ? "https://api.openai.com/v1" : "https://api.deepseek.com"} autoComplete="url" />
      </Form.Item>
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
          description={`协议 ${checked.api_protocol || settings.api_protocol} · 端点 ${checked.endpoint_host} · 模型 ${checked.model} · ${checked.duration_ms} ms · 输入 ${inputTokens ?? "未知"} / 输出 ${outputTokens ?? "未知"} tokens。探测只验证 API 连通性与最小 JSON 响应，不验证工具调用、代码分析、引用正确性或模型效果。保存新配置后需要重新测试。`} />;
      })()}
    </Form>}
  </Card>;
}

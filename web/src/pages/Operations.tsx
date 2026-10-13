import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Form, Input, InputNumber, Select, Space, Table, Tabs, Tag, Typography, message } from "antd";
import { api, terminal } from "../api";
import { Header, Hash } from "../components";

const { Text } = Typography;
const commaList = (value: string) => value.split(",").map((x) => x.trim()).filter(Boolean);

export default function OperationsPage() {
  const [repos, setRepos] = useState<any[]>([]);
  const [detectors, setDetectors] = useState<any[]>([]);
  const [cases, setCases] = useState<any[]>([]);
  const [rows, setRows] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const refresh = async () => {
    const [r, d, c, o] = await Promise.all([api("/repositories"), api("/detectors"), api("/cases"), api("/operations")]);
    setRepos(r); setDetectors(d); setCases(c); setRows(o);
    if (selected) setSelected(await api("/operations/" + selected.id));
  };
  useEffect(() => { void refresh().catch((e) => message.error(String(e))); const t = setInterval(() => void refresh().catch(() => {}), 2500); return () => clearInterval(t); }, [selected?.id]);
  const submit = async (path: string, values: any, transform: (v: any) => any = (v) => v) => {
    setBusy(true);
    try { const item = await api(path, transform(values)); setSelected(item); await refresh(); message.success("任务已加入队列"); }
    catch (e) { message.error(String(e)); }
    finally { setBusy(false); }
  };
  const common = <>
    <Form.Item name="repository_id" label="已登记仓库" rules={[{ required: true }]}><Select options={repos.map((r) => ({ value: r.id, label: r.name + " · " + r.path }))} /></Form.Item>
    <Form.Item name="detector_ids" label="检测器" rules={[{ required: true }]}><Select mode="multiple" options={detectors.map((d) => ({ value: d.id, label: d.id }))} /></Form.Item>
    <Form.Item name="include_paths_text" label="纳入路径（逗号分隔）" initialValue="."><Input /></Form.Item>
    <Form.Item name="timeout_seconds" label="单端点超时（秒）" initialValue={600}><InputNumber min={30} max={3600} /></Form.Item>
    <Form.Item name="memory_mb" label="内存上限（MiB）" initialValue={2048}><InputNumber min={256} max={8192} /></Form.Item>
  </>;
  const rangeForm = (date: boolean) => <Form layout="vertical" onFinish={(v) => submit(date ? "/operations/date-ranges" : "/operations/revision-ranges", v, (x) => ({
    ...x, include_paths: commaList(x.include_paths_text || "."), include_paths_text: undefined,
  }))}>
    {common}
    {date ? <>
      <Form.Item name="branch" label="固定分支或标签" rules={[{ required: true }]}><Input placeholder="refs/remotes/origin/master" /></Form.Item>
      <Form.Item name="start" label="起始时间（半开区间含起点）" rules={[{ required: true }]}><Input placeholder="2025-01-01T00:00:00" /></Form.Item>
      <Form.Item name="end" label="结束时间（不含终点）" rules={[{ required: true }]}><Input placeholder="2025-02-01T00:00:00" /></Form.Item>
      <Form.Item name="timezone" label="时区" initialValue="Asia/Shanghai"><Input /></Form.Item>
    </> : <>
      <Form.Item name="baseline" label="Baseline 完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="endpoint" label="Endpoint 完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
    </>}
    <Button type="primary" htmlType="submit" loading={busy}>创建固定源码任务</Button>
  </Form>;
  const items = [
    { key: "sync", label: "同步源码", children: <Form layout="vertical" onFinish={(v) => submit("/operations/source-sync", v)}>
      <Form.Item name="repository" label="OpenHarmony 仓库名" rules={[{ required: true }]}><Input placeholder="openharmony/commonlibrary_c_utils" /></Form.Item>
      <Form.Item name="url" label="HTTPS 地址（仅 GitHub / Gitee / GitCode 的 OpenHarmony 仓库）" rules={[{ required: true }]}><Input placeholder="https://gitee.com/openharmony/commonlibrary_c_utils.git" /></Form.Item>
      <Form.Item name="timeout_seconds" label="超时（秒）" initialValue={900}><InputNumber min={10} max={3600} /></Form.Item>
      <Alert type="info" showIcon message="同步只抓取 Git 对象，不构建代码；扫描任务仍必须选择固定 Commit。" />
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>排队同步</Button>
    </Form> },
    { key: "range", label: "两个 SHA 区间", children: rangeForm(false) },
    { key: "date", label: "提交者日期区间", children: rangeForm(true) },
    { key: "matrix", label: "版本矩阵", children: <Form layout="vertical" onFinish={(v) => submit("/operations/version-matrices", { ...v, commits: commaList(v.commits_text), include_paths: commaList(v.include_paths_text || "."), include_paths_text: undefined })}>
      <Form.Item name="case_id" label="调查案例" rules={[{ required: true }]}><Select options={cases.map((c) => ({ value: c.id, label: c.title }))} /></Form.Item>
      {common}
      <Form.Item name="commits_text" label="2–8 个完整 SHA（逗号分隔）" rules={[{ required: true }]}><Input.TextArea rows={3} /></Form.Item>
      <Button type="primary" htmlType="submit" loading={busy}>创建版本矩阵</Button>
    </Form> },
    { key: "validation", label: "隔离验证", children: <Form layout="vertical" onFinish={(v) => submit("/operations/validations", v)}>
      <Form.Item name="case_id" label="调查案例" rules={[{ required: true }]}><Select options={cases.map((c) => ({ value: c.id, label: c.title }))} /></Form.Item>
      <Form.Item name="harness_id" label="审查过的 Harness"><Select options={[{ value: "auth01_descriptor_bypass", label: "AUTH-01 描述符边界" }]} /></Form.Item>
      <Form.Item name="target_repository_id" label="inputmethod_imf 仓库" rules={[{ required: true }]}><Select options={repos.filter((r) => r.name === "openharmony/inputmethod_imf").map((r) => ({ value: r.id, label: r.path }))} /></Form.Item>
      <Form.Item name="target_commit" label="Harness 固定版本 SHA" rules={[{ required: true }]}><Input placeholder="vulnerable 或 fixed 的完整 SHA" /></Form.Item>
      <Form.Item name="cutils_repository_id" label="commonlibrary_c_utils 仓库" rules={[{ required: true }]}><Select options={repos.filter((r) => r.name === "openharmony/commonlibrary_c_utils").map((r) => ({ value: r.id, label: r.path }))} /></Form.Item>
      <Form.Item name="cutils_commit" label="支持源码完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="repeats" label="每个攻击/控制用例重复次数" initialValue={3}><InputNumber min={3} max={3} /></Form.Item>
      <Alert type="warning" showIcon message="只在 Docker 中执行；WSL 未配置固定镜像或 daemon 时会标记 blocked，不会在宿主机回退运行。" />
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>排队验证</Button>
    </Form> },
    { key: "investigate", label: "只读调查", children: <Form layout="vertical" onFinish={(v) => submit("/operations/investigations", v)}>
      <Form.Item name="job_id" label="已完成扫描任务 ID" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="candidate_id" label="候选 ID" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="max_output_bytes" label="最大输出字节数" initialValue={65536}><InputNumber min={1024} max={262144} /></Form.Item>
      <Alert type="info" showIcon message="仅调用固定源码摘录、证据义务、Git 历史和符号事实；不调用模型、不执行任意命令、不升级结论。" />
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>创建只读调查</Button>
    </Form> },
  ];
  const columns = [
    { title: "种类", dataIndex: "kind" },
    { title: "状态", dataIndex: "status", render: (s: string) => <Tag color={s === "blocked" ? "orange" : s === "failed" ? "red" : s === "completed" ? "green" : "blue"}>{s}</Tag> },
    { title: "创建时间", dataIndex: "created_at", render: (s: string) => new Date(s).toLocaleString() },
    { title: "操作", render: (_: any, row: any) => <Space><Button onClick={async () => setSelected(await api("/operations/" + row.id))}>查看</Button>{!terminal.has(row.status) && !["blocked", "completed_with_limitations"].includes(row.status) && <Button danger onClick={() => api("/operations/" + row.id + "/cancel").then(refresh)}>取消</Button>}</Space> },
  ];
  return <>
    <Header title="源码运营与证据闭环" description="同步与扫描分开；区间按两个固定 SHA；验证只运行注册的 Docker Harness；调查工具只读。" />
    <Alert className="section-gap" type="info" showIcon message="结果边界" description="版本差异是候选变化，不自动说明漏洞引入/修复。动态组件复现也不等于产品可达或可报告漏洞。" />
    <Card className="section-gap"><Tabs items={items} /></Card>
    <Card className="section-gap" title="持久化操作队列"><Table rowKey="id" columns={columns} dataSource={rows} pagination={{ pageSize: 8 }} /></Card>
    {selected && <Card className="section-gap" title={<Space>操作详情 <Text type="secondary">{selected.id}</Text></Space>} extra={<Button onClick={() => setSelected(null)}>收起</Button>}>
      <Space className="section-gap"><Tag>{selected.kind}</Tag><Tag>{selected.status}</Tag>{selected.result_sha256 && <><Text>Result SHA-256</Text><Hash value={selected.result_sha256} /></>}</Space>
      {selected.error && <Alert type="error" message={selected.error} />}
      <pre className="json-view">{JSON.stringify(selected.result || selected.spec, null, 2)}</pre>
      <Typography.Title level={5}>事件</Typography.Title>
      <pre className="json-view">{JSON.stringify(selected.events || [], null, 2)}</pre>
    </Card>}
  </>;
}
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Form, Input, InputNumber, Select, Space, Table, Tabs, Tag, Typography, message } from "antd";
import { api, terminal } from "../api";
import { Header, Hash } from "../components";
import { refreshSelectedOperation } from "./operationSelection";

const { Text } = Typography;
const commaList = (value: string) => value.split(",").map((x) => x.trim()).filter(Boolean);

export default function OperationsPage() {
  const [repos, setRepos] = useState<any[]>([]);
  const [detectors, setDetectors] = useState<any[]>([]);
  const [cases, setCases] = useState<any[]>([]);
  const [refsByRepository, setRefsByRepository] = useState<Record<string, any[]>>({});
  const [rows, setRows] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [datePreview, setDatePreview] = useState<any>(null);
  const [revisionForm] = Form.useForm();
  const [dateForm] = Form.useForm();
  const [branchForm] = Form.useForm();
  const [matrixForm] = Form.useForm();
  const selectedOperationId = useRef<string | null>(null);
  const refresh = useCallback(async (operationId: string | null = selectedOperationId.current) => {
    const [r, d, c, o] = await Promise.all([api("/repositories"), api("/detectors"), api("/cases"), api("/operations")]);
    setRepos(r); setDetectors(d); setCases(c); setRows(o);
    if (operationId) await refreshSelectedOperation(operationId, (id) => api("/operations/" + id), () => selectedOperationId.current, setSelected);
  }, []);
  const showOperation = async (id: string) => {
    selectedOperationId.current = id;
    try { await refreshSelectedOperation(id, (key) => api("/operations/" + key), () => selectedOperationId.current, setSelected); }
    catch (e) { message.error(String(e)); }
  };
  useEffect(() => { void refresh().catch((e) => message.error(String(e))); const t = setInterval(() => void refresh().catch(() => {}), 2500); return () => clearInterval(t); }, [refresh]);
  const submit = async (path: string, values: any, transform: (v: any) => any = (v) => v) => {
    setBusy(true);
    try { const item = await api(path, transform(values)); selectedOperationId.current = item.id; setSelected(item); await refresh(item.id); message.success("任务已加入队列"); }
    catch (e) { message.error(String(e)); }
    finally { setBusy(false); }
  };
  const loadRefs = async (repositoryId: string) => {
    if (refsByRepository[repositoryId]) return;
    const refs = await api("/repositories/" + repositoryId + "/revisions");
    setRefsByRepository((previous) => ({ ...previous, [repositoryId]: refs }));
  };
  const common = (form: any, clearFields: string[], onRepositoryChange?: () => void) => <>
    <Form.Item name="repository_id" label="已登记仓库" rules={[{ required: true }]}><Select
      showSearch
      optionFilterProp="label"
      options={repos.map((r) => ({ value: r.id, label: r.name + " · " + r.path }))}
      onOpenChange={(open) => { if (open) void refresh().catch((e) => message.error(String(e))); }}
      onChange={(id) => {
        form.setFieldsValue(Object.fromEntries(clearFields.map((field) => [field, undefined])));
        onRepositoryChange?.();
        void loadRefs(id).catch((e) => message.error(String(e)));
      }}
    /></Form.Item>
    <Form.Item name="detector_ids" label="检测器" rules={[{ required: true }]}><Select mode="multiple" options={detectors.map((d) => ({ value: d.id, label: d.id }))} /></Form.Item>
    <Form.Item name="include_paths_text" label="纳入路径（逗号分隔）" initialValue="."><Input /></Form.Item>
    <Form.Item name="timeout_seconds" label="单端点超时（秒）" initialValue={600}><InputNumber min={30} max={3600} /></Form.Item>
    <Form.Item name="memory_mb" label="内存上限（MiB）" initialValue={2048}><InputNumber min={256} max={8192} /></Form.Item>
  </>;
  const refSelect = (form: any, name: string, label: string) => <Form.Item noStyle shouldUpdate={(previous, current) => previous.repository_id !== current.repository_id}>
    {() => <Form.Item name={name} label={label} rules={[{ required: true }]}>
      <Select showSearch optionFilterProp="label" placeholder="选择当前仓库的 branch 或 tag"
        options={(refsByRepository[form.getFieldValue("repository_id")] || []).map((item) => ({ value: item.ref, label: item.ref }))} />
    </Form.Item>}
  </Form.Item>;
  const rangeForm = (date: boolean) => {
    const form = date ? dateForm : revisionForm;
    return <Form form={form} layout="vertical" onValuesChange={() => date && setDatePreview(null)} onFinish={(v) => submit(date ? "/operations/date-ranges" : "/operations/revision-ranges", v, (x) => ({
    ...x, include_paths: commaList(x.include_paths_text || "."), include_paths_text: undefined,
  }))}>
    {common(form, date ? ["branch"] : [])}
    {date ? <>
      {refSelect(dateForm, "branch", "分支或标签")}
      <Form.Item name="start" label="起始日期时间（包含）" rules={[{ required: true }]}><Input type="datetime-local" step={1} /></Form.Item>
      <Form.Item name="end" label="结束日期时间（不包含）" rules={[{ required: true }]}><Input type="datetime-local" step={1} /></Form.Item>
      <Form.Item name="timezone" label="所选时间的时区" initialValue="Asia/Shanghai" rules={[{ required: true }]}>
        <Select options={["Asia/Shanghai", "UTC", "America/Los_Angeles", "Europe/London"].map((zone) => ({ value: zone, label: zone }))} />
      </Form.Item>
      <Alert type="info" showIcon message="提交者时间 · first-parent · 半开区间 [start,end)；时间区间跨度内可能包含区间外提交，预览会列出。" />
      <Button className="section-gap" onClick={async () => {
        try {
          const values = await dateForm.validateFields(["repository_id", "branch", "start", "end", "timezone"]);
          const preview = await api("/operations/date-ranges/preview", values);
          setDatePreview(preview);
        } catch (e) { message.error(String(e)); }
      }}>预览时间区间</Button>
      {datePreview && <Alert className="section-gap" type="success" showIcon message={`${datePreview.branch} · 命中 ${datePreview.selected_commits.length} 个提交 · 拓扑跨度外提交 ${datePreview.intervening_outside_date.length} 个`}
        description={<Space direction="vertical"><div>时间区间：[{datePreview.start}, {datePreview.end}) · {datePreview.timezone} · committer time</div><Space wrap>Tip <Hash value={datePreview.tip} /> 基线 <Hash value={datePreview.baseline} /> 终点 <Hash value={datePreview.endpoint} /></Space><Space wrap>所选提交：{datePreview.selected_commits.map((sha: string) => <Hash key={sha} value={sha} />)}</Space></Space>} />}
    </> : <>
      <Form.Item name="baseline" label="Baseline 完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="endpoint" label="Endpoint 完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
    </>}
    <Button type="primary" htmlType="submit" loading={busy}>创建固定源码任务</Button>
  </Form>;
  };
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
    { key: "branches", label: "跨分支比较", children: <Form form={branchForm} layout="vertical" onFinish={(v) => submit("/operations/branch-comparisons", {
      ...v, include_paths: commaList(v.include_paths_text || "."), include_paths_text: undefined,
    })}>
      {common(branchForm, ["baseline_ref", "endpoint_ref"])}
      {refSelect(branchForm, "baseline_ref", "基准分支或标签")}
      {refSelect(branchForm, "endpoint_ref", "对比分支或标签")}
      <Alert type="info" showIcon message="提交时服务端固定两个 ref 对应的 Commit / Tree；支持无祖先关系的分支端点比较，不扫描整段历史。" />
      <Button type="primary" htmlType="submit" loading={busy}>扫描并比较两个端点</Button>
    </Form> },
    { key: "matrix", label: "版本矩阵", children: <Form form={matrixForm} layout="vertical" onFinish={(v) => {
      const { commits_text, include_paths_text, ...payload } = v;
      return submit("/operations/version-matrices", {
        ...payload,
        commits: commaList(commits_text),
        include_paths: commaList(include_paths_text || "."),
      });
    }}>
      <Form.Item name="case_id" label="调查案例" rules={[{ required: true }]}><Select options={cases.map((c) => ({ value: c.id, label: c.title }))} /></Form.Item>
      {common(matrixForm, ["commits_text"])}
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
    { title: "操作", render: (_: any, row: any) => <Space><Button onClick={() => void showOperation(row.id)}>查看</Button>{!terminal.has(row.status) && !["blocked", "completed_with_limitations"].includes(row.status) && <Button danger onClick={() => api("/operations/" + row.id + "/cancel", {}).then(() => refresh())}>取消</Button>}</Space> },
  ];
  return <>
    <Header title="源码运营与证据闭环" description="同步与扫描分开；区间按两个固定 SHA；验证只运行注册的 Docker Harness；调查工具只读。" />
    <Alert className="section-gap" type="info" showIcon message="结果边界" description="版本差异是候选变化，不自动说明漏洞引入/修复。动态组件复现也不等于产品可达或可报告漏洞。" />
    <Card className="section-gap"><Tabs items={items} /></Card>
    <Card className="section-gap" title="持久化操作队列"><Table rowKey="id" columns={columns} dataSource={rows} pagination={{ pageSize: 8 }} /></Card>
    {selected && <Card className="section-gap" title={<Space>操作详情 <Text type="secondary">{selected.id}</Text></Space>} extra={<Button onClick={() => { selectedOperationId.current = null; setSelected(null); }}>收起</Button>}>
      <Space className="section-gap"><Tag>{selected.kind}</Tag><Tag>{selected.status}</Tag>{selected.result_sha256 && <><Text>Result SHA-256</Text><Hash value={selected.result_sha256} /></>}</Space>
      {selected.error && <Alert type="error" message={selected.error} />}
      <pre className="json-view">{JSON.stringify(selected.result || selected.spec, null, 2)}</pre>
      <Typography.Title level={5}>事件</Typography.Title>
      <pre className="json-view">{JSON.stringify(selected.events || [], null, 2)}</pre>
    </Card>}
  </>;
}

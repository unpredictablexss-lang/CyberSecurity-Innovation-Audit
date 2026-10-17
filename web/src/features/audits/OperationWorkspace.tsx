import React, { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Descriptions, Empty, Space, Table, Tabs, Typography, message } from "antd";
import { api, terminal } from "../../api";
import { go, Hash, Header, State } from "../../components";
import { refreshSelectedOperation } from "../../pages/operationSelection";
import { ComparisonForm, InvestigationForm, SyncForm, ValidationForm } from "./OperationForms";
const { Text } = Typography;
export type OperationView = "all" | "date" | "branches" | "matrix" | "validation" | "investigate" | "sync" | "queue";
const kinds: Record<string, string> = { source_sync: "源码同步", revision_range: "固定区间", branch_comparison: "跨版本比较", version_matrix: "版本矩阵", validation: "隔离验证", investigation: "只读调查" };
const headings: Record<OperationView, [string, string]> = {
  all: ["高级源码与验证操作", "保留既有操作入口；任务持久化，候选变化与安全影响分别记录。"],
  date: ["时间增量扫描", "按明确时区选择提交区间，固定两个端点并比较候选观察。"],
  branches: ["跨版本安全分析", "比较同一仓库的分支、Tag 或 Commit；候选变化不等于漏洞引入或修复。"],
  matrix: ["影响与修复", "先核对多个固定版本的候选观察，再补充影响与修复证据。"],
  validation: ["PoC 验证", "围绕绑定源码和注册 Harness 申请隔离验证，保留失败与未知项。"],
  investigate: ["只读调查步骤", "从固定候选出发收集证据；当前尚未接入真实模型。"],
  sync: ["源码同步", "显式同步 Git 对象；任务扫描只读固定版本。"],
  queue: ["持久化操作任务", "查看固定区间、版本比较、同步、调查和验证的真实状态。"],
};
export default function OperationWorkspace({ view = "all", operationId }: { view?: OperationView; operationId?: string }) {
  const [repos, setRepos] = useState<any[]>([]), [detectors, setDetectors] = useState<any[]>([]), [cases, setCases] = useState<any[]>([]);
  const [rows, setRows] = useState<any[]>([]), [selected, setSelected] = useState<any>(null);
  const [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const selectedId = useRef<string | null>(operationId || null), live = useRef(true);
  const refresh = useCallback(async () => {
    const [r, d, c, o] = await Promise.all([api("/repositories"), api("/detectors"), api("/cases"), api("/operations")]);
    if (!live.current) return;
    setRepos(r); setDetectors(d); setCases(c); setRows(o);
    const id = selectedId.current;
    if (id) await refreshSelectedOperation(id, (key) => api("/operations/" + key), () => live.current ? selectedId.current : null, setSelected);
  }, []);
  useEffect(() => {
    live.current = true;
    void refresh().catch((e) => { if (live.current) setError(String(e)); });
    const timer = setInterval(() => void refresh().catch((e) => { if (live.current) setError(String(e)); }), 2500);
    return () => { live.current = false; clearInterval(timer); };
  }, [refresh]);
  const show = async (id: string) => {
    selectedId.current = id;
    try { await refreshSelectedOperation(id, (key) => api("/operations/" + key), () => live.current ? selectedId.current : null, setSelected); }
    catch (e) { setError(String(e)); }
  };
  const submit = async (path: string, payload: any) => {
    setBusy(true); setError("");
    try { const item = await api(path, payload); selectedId.current = item.id; setSelected(item); await refresh(); message.success("任务已加入持久化队列"); }
    catch (e) { setError(String(e)); } finally { setBusy(false); }
  };
  const props = { repos, detectors, cases, busy, submit };
  const forms = [
    { key: "sync", label: "同步源码", children: <SyncForm {...props} /> },
    { key: "range", label: "两个 SHA 区间", children: <ComparisonForm {...props} kind="range" /> },
    { key: "date", label: "提交者日期区间", children: <ComparisonForm {...props} kind="date" /> },
    { key: "branches", label: "跨分支比较", children: <ComparisonForm {...props} kind="branches" /> },
    { key: "matrix", label: "版本矩阵", children: <ComparisonForm {...props} kind="matrix" /> },
    { key: "validation", label: "隔离验证", children: <ValidationForm {...props} /> },
    { key: "investigate", label: "只读调查", children: <InvestigationForm {...props} /> },
  ];
  const filtered = rows.filter((r) => view === "all" || view === "queue" || (view === "date" ? r.kind === "revision_range" : view === "branches" ? ["branch_comparison", "revision_range"].includes(r.kind) : r.kind === ({ matrix: "version_matrix", validation: "validation", investigate: "investigation", sync: "source_sync" } as Record<string, string>)[view]));
  return <>
    <Header title={headings[view][0]} description={headings[view][1]} />
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {view === "all" ? <Tabs items={forms} /> : view === "branches" ? <Tabs items={[forms[3], forms[4]]} /> : forms.find((f) => f.key === view)?.children}
    {view === "matrix" && <Alert className="section-gap" type="info" showIcon message="影响与修复仍需独立证据" description="当前矩阵只记录候选观察。补丁生成、补丁应用和修复后产品验证尚未接入；不会用候选消失自动判定已修复。" />}
    <Card className="section-gap" title="操作任务" extra={<Button onClick={() => void refresh().catch((e) => setError(String(e)))}>刷新操作</Button>}>
      <Table<any> rowKey="id" dataSource={filtered} pagination={{ pageSize: 8 }} scroll={{ x: 640 }} columns={[
        { title: "任务", render: (_, row) => <><Text strong>{kinds[row.kind] || row.kind}</Text><div className="muted">{row.id.slice(0, 12)}</div></> },
        { title: "状态", dataIndex: "status", render: (v) => <State value={v} /> },
        { title: "创建时间", dataIndex: "created_at", render: (v) => new Date(v).toLocaleString() },
        { title: "操作", render: (_, row) => <Space><Button onClick={() => void show(row.id)}>查看</Button>{!terminal.has(row.status) && <Button danger onClick={async () => {
          try { await api("/operations/" + row.id + "/cancel", {}); await refresh(); } catch (e) { setError(String(e)); }
        }}>取消</Button>}</Space> },
      ]} locale={{ emptyText: <Empty description="尚无此类操作记录" /> }} />
    </Card>
    {selected && <Card className="section-gap" title={<Space>操作详情 <Text copyable>{selected.id}</Text></Space>} extra={<Button onClick={() => { selectedId.current = null; setSelected(null); }}>收起</Button>}>
      <Space wrap><State value={selected.status} /><Text>{kinds[selected.kind] || selected.kind}</Text><Button size="small" onClick={() => go("/tasks/operations/" + selected.id)}>任务中心打开</Button>
        {selected.result_sha256 && <><Text>Result SHA-256</Text><Hash value={selected.result_sha256} /></>}</Space>
      {selected.error && <Alert className="section-gap" type="error" message={selected.error} />}
      {selected.spec?.scan_ids && <Space wrap className="section-gap">端点扫描：{selected.spec.scan_ids.map((id: string) => <Button key={id} size="small" onClick={() => go("/tasks/" + id)}>{id.slice(0, 12)}</Button>)}</Space>}
      <pre className="json-view">{JSON.stringify(selected.result || selected.spec, null, 2)}</pre>
      <Text strong>执行事件</Text><pre className="raw">{JSON.stringify(selected.events || [], null, 2)}</pre>
      {selected.result_sha256 && <Button href={"/api/v1/operations/" + selected.id + "/result"} target="_blank">查看原始结果 JSON</Button>}
    </Card>}
  </>;
}

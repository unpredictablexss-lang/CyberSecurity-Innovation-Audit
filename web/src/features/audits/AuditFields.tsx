import React, { useEffect, useRef, useState } from "react";
import { Alert, AutoComplete, Button, Checkbox, Col, Collapse, Form, Input, InputNumber, Row, Select, Space, Typography } from "antd";
import { api } from "../../api";
import { go } from "../../components";
import { approvedDetectorIds, requestGate } from "./model";
const { Text } = Typography;
export type AuditProps = { repos: any[]; detectors: any[]; refresh: () => Promise<void> };
export function useRepositoryRefs(repositoryId?: string) {
  const [refs, setRefs] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const gate = useRef(requestGate());
  useEffect(() => {
    const ticket = gate.current.next(); setRefs([]); setError(""); setLoading(Boolean(repositoryId));
    if (repositoryId) void api("/repositories/" + repositoryId + "/revisions")
      .then((items) => { if (gate.current.current(ticket)) setRefs(items); })
      .catch((e) => { if (gate.current.current(ticket)) setError(String(e)); })
      .finally(() => { if (gate.current.current(ticket)) setLoading(false); });
    return () => gate.current.invalidate();
  }, [repositoryId]);
  return { refs, error, loading };
}
export function RepositoryField({ repos, onChange, refresh }: { repos: any[]; onChange: () => void; refresh?: () => Promise<void> }) {
  return <Form.Item name="repository_id" label="审计仓库" rules={[{ required: true, message: "请选择仓库" }]}>
    <Select showSearch optionFilterProp="label" placeholder="搜索已登记仓库" options={repos.map((r) => ({ value: r.id, label: r.name + " · " + r.path }))}
      onChange={onChange} onOpenChange={(open) => { if (open && refresh) void refresh().catch(() => {}); }} />
  </Form.Item>;
}
export function RefField({ name, label, refs, required = true }: { name: string; label: string; refs: any[]; required?: boolean }) {
  return <Form.Item name={name} label={label} rules={[{ required, message: "请选择或填写版本" }]}>
    <AutoComplete allowClear options={refs.map((r) => ({ value: r.ref }))} placeholder="分支、Tag 或完整 Commit SHA"
      filterOption={(input, option) => String(option?.value).toLowerCase().includes(input.toLowerCase())} />
  </Form.Item>;
}
export function ScopeBudget() {
  return <Collapse className="audit-options" items={[{ key: "scope", label: "范围与执行预算", children: <>
    <Form.Item name="include_text" label="纳入路径（每行一个，. 表示当前仓库源码）"><Input.TextArea rows={3} /></Form.Item>
    <Row gutter={18}><Col span={12}><Form.Item name="timeout_seconds" label="单端点超时（秒）"><InputNumber min={30} max={3600} /></Form.Item></Col>
      <Col span={12}><Form.Item name="memory_mb" label="地址空间上限（MiB）"><InputNumber min={256} max={8192} /></Form.Item></Col></Row>
    <Text type="secondary">单仓最多 2,000 个源码文件、总源码 32 MiB；超限会明确失败。</Text>
  </> }]} />;
}
export function RuleNotice({ detectors }: { detectors: any[] }) {
  let count = 0; try { count = approvedDetectorIds(detectors).length; } catch { /* visible blocking state below */ }
  const fullRulesResearch = Form.useWatch("full_rules_research");
  const researchOnly = detectors.filter((d) => d.kind === "research_candidate" && d.default_enabled === false);
  const nullRule = researchOnly.find((d) => d.id === "ohscanner.cpp.null_dereference");
  const reason = nullRule?.admission_reason || "该规则仅在明确选择研究模式时启用。";
  return <div className="section-gap">
    <Form.Item name="full_rules_research" valuePropName="checked" initialValue={false}>
      <Checkbox>显式启用全规则研究模式（包含默认关闭的弱候选规则）</Checkbox>
    </Form.Item>
    {fullRulesResearch ? <Alert showIcon type="warning"
      message="全规则研究模式：输出为弱候选/待复核"
      description={`本次启用原因：你已显式选择研究模式。${reason} 当前范围的候选量无法在扫描前精确估算；历史全规则试运行约有 546,559 条候选，实际数量会随源码范围和规则版本变化。`}
    /> : <Alert showIcon type={count ? "info" : "warning"}
      message={count ? "使用平台当前已批准的普通扫描规则" : "没有可用的已批准规则"}
      description={count ? "实际规则版本、解析覆盖和未分析范围会保存在任务与报告中。输出仍是待复核候选。全规则研究可在上方显式开启。" : "请刷新系统能力配置后再创建审计。"} />}
  </div>;
}
export function ScopeAvailability() {
  return <div className="scope-note"><Space wrap><Text strong>审计范围</Text><Text>单个已登记仓库</Text>
    <Button size="small" disabled>多仓</Button><Button size="small" disabled>全部官方活跃仓库</Button></Space>
    <p>官方仓库目录、归档选择与多仓编排尚未接入；当前只读已登记的本地 Git 对象。</p>
    <Button type="link" onClick={() => go("/settings/sources")}>登记仓库或显式同步源码 →</Button></div>;
}
export const auditDefaults = { include_text: ".", timeout_seconds: 600, memory_mb: 2048, full_rules_research: false };

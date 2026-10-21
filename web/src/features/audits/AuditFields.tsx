import React, { useEffect, useRef, useState } from "react";
import { Alert, AutoComplete, Button, Checkbox, Col, Collapse, Form, Input, InputNumber, Row, Select, Space, Typography } from "antd";
import { api } from "../../api";
import { go } from "../../components";
import { approvedDetectorIds, requestGate } from "./model";
const { Text } = Typography;
export type AuditProps = { repos: any[]; detectors: any[]; refresh: () => Promise<void> };
export function useRepositoryRefs(repositoryId?: string) {
  const [refs, setRefs] = useState<any[]>([]);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const gate = useRef(requestGate());
  useEffect(() => {
    const ticket = gate.current.next(); setRefs([]); setLoadedFor(null); setError(""); setLoading(Boolean(repositoryId));
    if (repositoryId) void api("/repositories/" + repositoryId + "/revisions")
      .then((items) => { if (gate.current.current(ticket)) { setRefs(items); setLoadedFor(repositoryId); } })
      .catch((e) => { if (gate.current.current(ticket)) setError(String(e)); })
      .finally(() => { if (gate.current.current(ticket)) setLoading(false); });
    return () => gate.current.invalidate();
  }, [repositoryId]);
  return { refs: loadedFor === (repositoryId || null) ? refs : [], error, loading, loadedFor };
}
export function RepositoryField({ repos, onChange, refresh }: { repos: any[]; onChange: () => void; refresh?: () => Promise<void> }) {
  const [catalog, setCatalog] = useState<any[] | null>(null);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState("");
  const checkedAt = useRef(0);
  const loadCatalog = async (force = false) => {
    if (catalogLoading || (!force && catalog && Date.now() - checkedAt.current < 30000)) return;
    setCatalogLoading(true);
    setCatalogError("");
    try {
      const result = await api("/repositories/catalog");
      setCatalog(Array.isArray(result) ? result : []);
      checkedAt.current = Date.now();
    } catch (error) {
      setCatalogError(String(error));
    } finally {
      setCatalogLoading(false);
    }
  };
  useEffect(() => { void loadCatalog(); }, []);
  const available = (catalog || []).filter((item) => item.status === "available");
  const unavailable = (catalog || []).filter((item) => item.status !== "available");
  const options = available.map((item) => ({ value: item.id, label: item.display_name || item.name }));
  return <>
    <Form.Item name="repository_id" label="审计仓库" rules={[{ required: true, message: "请选择通过目录和 Git 校验的仓库" }]}>
      <Select
        showSearch
        optionFilterProp="label"
        placeholder={catalogLoading ? "正在核验已登记仓库…" : "搜索可用仓库名称"}
        options={options}
        loading={catalogLoading}
        disabled={catalogLoading || catalog === null}
        notFoundContent={catalogLoading ? "正在核验…" : catalogError ? "仓库目录核验失败" : "没有通过校验的仓库"}
        onChange={onChange}
        onOpenChange={(open) => {
          if (open) {
            void loadCatalog();
            if (refresh) void refresh().catch(() => {});
          }
        }}
      />
    </Form.Item>
    {catalogError && <Alert className="section-gap" type="error" showIcon message="仓库目录暂时无法核验" description={catalogError}
      action={<Button size="small" onClick={() => void loadCatalog(true)}>重试</Button>} />}
    {!catalogLoading && catalog !== null && !catalogError && available.length === 0 && <Alert className="section-gap" type="warning" showIcon
      message="尚无通过安全校验的可审计仓库" description="请前往“系统设置 → 仓库与源码管理”，在服务端已批准的源码根目录中发现并登记 Git 仓库。"
      action={<Button size="small" type="link" onClick={() => go("/settings/sources")}>前往设置</Button>} />}
    {!catalogLoading && catalog !== null && !catalogError && available.length > 0 && <Space className="section-gap" direction="vertical" align="start">
      <Text type="secondary">
        已核验 {available.length} 个可用仓库；选择器仅显示名称，不显示服务器物理路径。当前登记总数 {catalog.length}。
      </Text>
      {unavailable.length > 0 && <Alert showIcon type="warning"
        message={`另有 ${unavailable.length} 个已登记仓库当前无法用于审计`}
        description="仓库路径、Git 对象或源码根目录授权可能已变化。前往仓库与源码管理查看具体原因；本次只能选择通过校验的仓库。"
        action={<Button size="small" type="link" onClick={() => go("/settings/sources")}>检查设置</Button>} />}
    </Space>}
  </>;
}
export function RefField({ name, label, refs, required = true }: { name: string; label: string; refs: any[]; required?: boolean }) {
  return <Form.Item name={name} label={label} rules={[{ required, message: "请选择或填写版本" }]}>
    <AutoComplete allowClear options={refs.map((r) => ({ value: r.ref, label: r.is_default ? r.ref + "（默认分支）" : r.ref }))} placeholder="分支、Tag 或完整 Commit SHA"
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
      description={`本次启用原因：你已显式选择研究模式。${reason} 当前范围的候选量无法在扫描前精确估算。量级参考：一轮历史全规则试运行报告 546,559 条候选，但原始 run 身份未绑定；本地可核验的另一轮 final run 有 403,360 条 NULL 原始观察（403,359 个唯一 diagnostic ID，run 1696df82…）。两者不是同一轮结果，该数字只作预警，不是本次预测。实际数量会随源码范围和规则版本变化。`}
    /> : <Alert showIcon type={count ? "info" : "warning"}
      message={count ? "使用平台当前已批准的普通扫描规则" : "没有可用的已批准规则"}
      description={count ? "实际规则版本、解析覆盖和未分析范围会保存在任务与报告中。输出仍是待复核候选。全规则研究可在上方显式开启。" : "请刷新系统能力配置后再创建审计。"} />}
  </div>;
}
export function ScopeAvailability() {
  return <div className="scope-note"><Space wrap><Text strong>审计范围</Text><Text>单仓库 · 扫描版本快照</Text></Space>
    <p>每个任务会记录所选仓库和提交版本，确保候选与证据对应同一版本。官方仓库目录与多仓批量审计尚未开放；请先在设置中登记本地仓库，再按仓库分别创建任务。</p>
    <Button type="link" onClick={() => go("/settings/sources")}>登记仓库或显式同步源码 →</Button></div>;
}
export const auditDefaults = { include_text: ".", timeout_seconds: 600, memory_mb: 2048, full_rules_research: false, audit_mode: "standard_review" };

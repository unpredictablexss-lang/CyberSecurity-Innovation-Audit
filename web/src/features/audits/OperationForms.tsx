import CandidateScope from "./CandidateScope";
import React, { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Collapse, Descriptions, Form, Input, InputNumber, Modal, Radio, Select, Space, Tabs, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { Hash, go } from "../../components";
import { analysisStatusLabel, coverageStatusLabel, triageStateLabel } from "../workbench/riskLabels.js";
import { auditDefaults, AuditModeSelector, RepositoryField, RefField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import { approvedDetectorIds, datePreviewPayload, operationPayload, recentRange, requestGate, selectedAuditModeValues } from "./model";
import TaskTriageConsentModal from "./TaskTriageConsentModal";
import { canApproveSourceSubmission, canCreateAgentInvestigation, disclosureReviewed, disclosureSelectionMatches, redactionNotice } from "./egressDisclosure.js";
const { Text } = Typography;
export type SourceContext = { job_id?: string; candidate_id?: string; repository_id?: string; case_id?: string };
export type OperationFormProps = { context?: SourceContext; repos: any[]; detectors: any[]; cases: any[]; busy: boolean; agentStatus?: any; submit: (path: string, payload: any) => Promise<void> };
export function ComparisonForm({ kind, repos, detectors, cases, busy, agentStatus, submit, context = {} }: OperationFormProps & { kind: "date" | "recent" | "branches" | "range" | "matrix" }) {
  const [form] = Form.useForm();
  const repository = Form.useWatch("repository_id", form);
  const auditMode = Form.useWatch("audit_mode", form) || "static_only";
  const { refs, error: refError } = useRepositoryRefs(repository);
  const [preview, setPreview] = useState<any>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [triagePreview, setTriagePreview] = useState<any>(null);
  const [consentOpen, setConsentOpen] = useState(false);
  const [consentBusy, setConsentBusy] = useState(false);
  const [error, setError] = useState("");
  const gate = useRef(requestGate());
  const pendingPayload = useRef<any>(null);
  const smartMode = auditMode === "standard_review";
  let ready = false;
  try { ready = approvedDetectorIds(detectors).length > 0; } catch { /* blocked */ }
  const submitLabel = kind === "date" ? "固定区间并创建任务" : kind === "recent" ? "创建 N 日与 1 日对照" : kind === "matrix" ? "创建版本矩阵" : "扫描并比较两个端点";
  const submitPath = kind === "date" ? "/operations/date-ranges" : kind === "recent" ? "/operations/recent-comparisons" : kind === "matrix" ? "/operations/version-matrices" : kind === "range" ? "/operations/revision-ranges" : "/operations/branch-comparisons";
  const invalidate = () => {
    gate.current.invalidate();
    setPreview(null);
    setTriagePreview(null);
    setConsentOpen(false);
    setPreviewBusy(false);
    pendingPayload.current = null;
    setError("");
  };
  async function finish(values: any) {
    const ticket = gate.current.next();
    setError("");
    const selected = selectedAuditModeValues(values);
    try {
      const payload = operationPayload(kind, selected, detectors);
      if (!payload.auto_triage) {
        await submit(submitPath, payload);
        return;
      }
      if (agentStatus?.configured === false) throw new Error("模型服务尚未配置。请先配置模型，或切换到静态审计。");
      setPreviewBusy(true);
      setTriagePreview(null);
      const result = await api("/operations/scan-previews", { kind, payload });
      if (!gate.current.current(ticket)) return;
      const consent = result?.triage_authorization_preview;
      if (consent?.eligible !== true || !Array.isArray(consent.scans) || !consent.scans.length) {
        throw new Error(consent?.reason || "无法生成完整的模型外发预览，没有创建任务。");
      }
      pendingPayload.current = payload;
      setTriagePreview(consent);
      setConsentOpen(true);
    } catch (e) {
      if (gate.current.current(ticket)) setError(String(e));
    } finally {
      if (gate.current.current(ticket)) setPreviewBusy(false);
    }
  }
  async function authorizeAndCreate() {
    const payload = pendingPayload.current;
    const scans = triagePreview?.scans;
    if (!payload?.auto_triage || triagePreview?.eligible !== true || !Array.isArray(scans) || !scans.length) return;
    if (scans.some((item: any) => !item.plan_sha256 || !item.workflow_sha256 || !item.consent_sha256 || !item.consent_nonce)) {
      setError("授权预览缺少固定计划或授权摘要，请重新预览。");
      setConsentOpen(false);
      setTriagePreview(null);
      return;
    }
    setConsentBusy(true);
    setError("");
    try {
      await submit(submitPath, {
        ...payload,
        triage_authorizations: scans.map((item: any) => ({
          plan_sha256: item.plan_sha256,
          workflow_sha256: item.workflow_sha256,
          consent_sha256: item.consent_sha256,
          consent_nonce: item.consent_nonce,
        })),
      });
      setConsentOpen(false);
      pendingPayload.current = null;
    } catch (e) {
      setError(String(e));
      setConsentOpen(false);
      setTriagePreview(null);
      pendingPayload.current = null;
    } finally {
      setConsentBusy(false);
    }
  }
  return <Card title={kind === "date" ? "时间范围与固定端点" : kind === "recent" ? "近 N 日与近 1 日提交对照" : kind === "matrix" ? "关联案例的版本矩阵" : "选择两个版本"}>
    {kind !== "matrix" && <ScopeAvailability />}
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {refError && <Alert type="warning" message={refError} />}
    <Form name={"audit-" + kind} form={form} layout="vertical"
      initialValues={{ ...auditDefaults, audit_mode: "static_only", timezone: "Asia/Shanghai", lookback_days: 7,
        reference_time: new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16),
        repository_id: context.repository_id, auto_r2: true }}
      onValuesChange={invalidate}
      onFinish={finish}>
      <AuditModeSelector />
      <Alert className="section-gap" type="info" showIcon
        message={smartMode ? "智能审计：先静态扫描，再调查候选证据" : "静态审计：只运行本地检测器"}
        description={smartMode
          ? "点击后先读取固定版本并展示模型目的地、源码范围和候选上限；只有你在授权弹窗中同意，任务才会创建。静态扫描完成后才会把限定证据发送给模型。模型意见仍需人工复核。"
          : "点击后直接创建静态扫描任务，不调用模型、不发送源码；扫描结果和覆盖情况供人工复核。"} />
      {smartMode && agentStatus?.configured === false && <Alert className="section-gap" type="warning" showIcon message="模型服务尚未配置，智能审计暂不可用；静态审计仍可使用。" />}
      <RepositoryField repos={repos} onChange={() => {
        form.setFieldsValue({ branch: undefined, baseline_ref: undefined, endpoint_ref: undefined, baseline: undefined, endpoint: undefined, commits_text: undefined });
        invalidate();
      }} />
      {kind === "date" ? <>
        <RefField name="branch" label="分支或标签" refs={refs} />
        <div className="form-shortcuts"><Text type="secondary">快捷时间范围</Text><Space wrap>{[7, 15, 30].map((days) => <Button key={days} onClick={() => { invalidate(); form.setFieldsValue(recentRange(days, form.getFieldValue("timezone") || "Asia/Shanghai")); }}>近 {days} 天</Button>)}</Space></div>
        <Form.Item name="start" label="开始时间（包含）" rules={[{ required: true }]}><Input type="datetime-local" step={1} onInput={(event) => { form.setFieldValue("start", event.currentTarget.value); invalidate(); }} /></Form.Item>
        <Form.Item name="end" label="结束时间（不包含）" rules={[{ required: true }]}><Input type="datetime-local" step={1} onInput={(event) => { form.setFieldValue("end", event.currentTarget.value); invalidate(); }} /></Form.Item>
        <Form.Item name="timezone" label="所选时间的时区" rules={[{ required: true }]}><Select options={["Asia/Shanghai", "UTC", "America/Los_Angeles", "Europe/London"].map((value) => ({ value, label: value }))} /></Form.Item>
        <Alert type="info" message="按提交者时间与 first-parent 选择时间窗口，扫描固定两个端点。" description="这不是逐提交扫描；预览区间只用于核对选出的固定提交，不创建任务。" />
        <Button aria-label="预览时间区间" className="section-gap" loading={previewBusy} onClick={async () => {
          const ticket = gate.current.next(); setPreviewBusy(true); setPreview(null); setError("");
          try {
            const values = await form.validateFields(["repository_id", "branch", "start", "end", "timezone"]);
            const result = await api("/operations/date-ranges/preview", datePreviewPayload(values));
            if (gate.current.current(ticket)) setPreview(result);
          } catch (e) { if (gate.current.current(ticket)) setError(String(e)); }
          finally { if (gate.current.current(ticket)) setPreviewBusy(false); }
        }}>预览时间范围（可选）</Button>
        {preview && <Alert className="section-gap" type="success" showIcon message={"已选中 " + preview.selected_commits.length + " 个提交；拓扑跨度外 " + preview.intervening_outside_date.length + " 个"}
          description={<Space direction="vertical"><Text>{preview.branch} · {preview.timezone} · [{preview.start}, {preview.end})</Text><Text type="secondary">预览不创建任务；提交时会重新解析并固定版本。</Text>
            <Collapse items={[{ key: "fixed-commits", label: "技术详情：固定提交", children: <Space wrap>基线 <Hash value={preview.baseline} /> 终点 <Hash value={preview.endpoint} /></Space> }]} /></Space>} />}
      </> : kind === "recent" ? <>
        <RefField name="branch" label="分支或标签" refs={refs} />
        <Form.Item name="lookback_days" label="N 日窗口长度" rules={[{ required: true }]}><InputNumber min={2} max={90} precision={0} /></Form.Item>
        <Form.Item name="reference_time" label="对照时点（本地时间）" rules={[{ required: true }]}><Input type="datetime-local" step={1} /></Form.Item>
        <Form.Item name="timezone" label="所选时间的时区" rules={[{ required: true }]}><Select options={["Asia/Shanghai", "UTC", "America/Los_Angeles", "Europe/London"].map((value) => ({ value, label: value }))} /></Form.Item>
        <Alert type="info" message="系统会对比两个不重叠时间窗口的固定端点。" description="例如 N=7 时，对比时点前第 7 天至前 1 天，以及最近 1 天；这不是逐提交扫描或漏洞引入证明。两段都没有提交时，系统会拒绝创建任务。" />
        <Button aria-label="预览近N日和近1日区间" className="section-gap" loading={previewBusy} onClick={async () => {
          const ticket = gate.current.next(); setPreviewBusy(true); setPreview(null); setError("");
          try {
            const values = await form.validateFields(["repository_id", "branch", "lookback_days", "reference_time", "timezone"]);
            const payload = operationPayload("recent", selectedAuditModeValues(values), detectors);
            const result = await api("/operations/recent-comparisons/preview", payload);
            if (gate.current.current(ticket)) setPreview(result);
          } catch (e) { if (gate.current.current(ticket)) setError(String(e)); }
          finally { if (gate.current.current(ticket)) setPreviewBusy(false); }
        }}>预览时间窗口（可选）</Button>
        {preview?.long_window && <Alert className="section-gap" type="success" showIcon message={"已预览 " + preview.long_window.selected_commits.length + " 个较早提交、" + preview.one_day_window.selected_commits.length + " 个最近 1 日提交"}
          description={<Space direction="vertical"><Text>{preview.branch} · {preview.timezone} · 对照时点 {preview.reference_time}</Text><Text type="secondary">预览不创建任务；提交时会重新解析并固定版本。</Text>
            <Collapse items={[{ key: "fixed-commits", label: "技术详情：固定提交", children: <Space wrap>较早窗口：<Hash value={preview.long_window.baseline} /> → <Hash value={preview.long_window.endpoint} /><br />最近 1 日：<Hash value={preview.one_day_window.baseline} /> → <Hash value={preview.one_day_window.endpoint} /></Space> }]} /></Space>} />}
      </> : kind === "branches" ? <>
        <RefField name="baseline_ref" label="基准版本" refs={refs} />
        <RefField name="endpoint_ref" label="目标版本" refs={refs} />
        <Alert type="info" message="支持分支、Tag 或完整 Commit；创建时会固定两个版本。" />
      </> : kind === "range" ? <>
        <Form.Item name="baseline" label="基准版本完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="endpoint" label="目标版本完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
      </> : <>
        <Form.Item name="case_id" label="调查案例" rules={[{ required: true }]}><Select placeholder="案例必须已关联所选仓库的候选" options={cases.map((c) => ({ value: c.id, label: c.title }))} /></Form.Item>
        <Form.Item name="commits_text" label="2–8 个完整 Commit（每行一个或逗号分隔）" rules={[{ required: true }]}><Input.TextArea rows={3} /></Form.Item>
        {!cases.length && <Alert type="info" message="请先从风险候选建立调查案例，再创建版本矩阵。" action={<Button size="small" onClick={() => go("/risks")}>查看风险</Button>} />}
      </>}
      <Collapse className="audit-options" items={[{ key: "advanced", label: "高级范围与调查设置", children: <>
        <ScopeBudget />
        <RuleNotice detectors={detectors} />
        {smartMode && agentStatus?.configured !== false && <>
          <CandidateScope />
          <Form.Item name="auto_r2" valuePropName="checked" extra="符合证据条件时，在固定源码范围内继续只读跨文件调查。">
            <Checkbox>允许深入追查</Checkbox>
          </Form.Item>
        </>}
      </> }]} />
      <Button aria-label={submitLabel} className="section-gap" type="primary" htmlType="submit" size="large"
        loading={busy || previewBusy}
        disabled={!ready || !repos.length || (kind === "matrix" && !cases.length) || (smartMode && agentStatus?.configured === false)}>
        {smartMode ? "预览授权并开始智能审计" : submitLabel}
      </Button>
    </Form>
    <TaskTriageConsentModal open={consentOpen} preview={triagePreview} loading={consentBusy}
      onCancel={() => { setConsentOpen(false); setTriagePreview(null); pendingPayload.current = null; }}
      onConfirm={() => void authorizeAndCreate()} />
  </Card>;
}export function SyncForm({ busy, submit, detectors }: Pick<OperationFormProps, "busy" | "submit" | "detectors">) {
  const [form] = Form.useForm();
  const scanAfterSync = Form.useWatch("scan_after_sync", form) === true;
  const selectedNames: string[] = Form.useWatch("catalog_selection", form) || [];
  const [catalog, setCatalog] = useState<any>(null), [catalogPage, setCatalogPage] = useState(1);
  const [selectedCatalog, setSelectedCatalog] = useState<Record<string, any>>({});
  const [catalogBusy, setCatalogBusy] = useState(false), [catalogError, setCatalogError] = useState("");
  const [preflightBusy, setPreflightBusy] = useState(false), [preflightError, setPreflightError] = useState("");
  const [preflight, setPreflight] = useState<any>(null), [preparedSubmission, setPreparedSubmission] = useState<any>(null);
  const loadCatalog = async (page = catalogPage) => {
    setCatalogBusy(true); setCatalogError("");
    try { const result = await api("/repositories/online-catalog?page=" + page); setCatalog(result); setCatalogPage(result.page); }
    catch (error) { setCatalogError(String(error)); }
    finally { setCatalogBusy(false); }
  };
  const selectCatalogRows = (names: string[]) => {
    const bounded = names.slice(0, 8);
    if (names.length > 8) message.warning("每批最多选择 8 个仓库，请分批同步。");
    const available = { ...selectedCatalog };
    for (const item of catalog?.repositories || []) available[item.name] = item;
    const next: Record<string, any> = {};
    for (const name of bounded) if (available[name]) next[name] = available[name];
    setSelectedCatalog(next);
    form.setFieldValue("catalog_selection", bounded);
    if (bounded.length === 1 && next[bounded[0]]) {
      const item = next[bounded[0]];
      form.setFieldsValue({ repository: item.name, url: item.url,
        revision: item.default_branch ? "refs/remotes/origin/" + item.default_branch : "HEAD" });
    }
    if (bounded.length) form.setFieldValue("audit_mode", "static_only");
  };
  const finish = async ({ catalog_selection, ...values }: any) => {
    try {
      const names: string[] = Array.isArray(catalog_selection) ? catalog_selection : [];
      let path: string;
      let payload: any;
      let repositories: any[];
      if (names.length) {
        if (names.length > 8) throw new Error("每批最多同步 8 个仓库。");
        const items = names.map((name) => selectedCatalog[name]).filter(Boolean);
        if (items.length !== names.length) throw new Error("部分仓库信息已失效，请重新加载目录并选择。");
        repositories = items.map((item: any) => ({
          repository: item.name, url: item.url, timeout_seconds: values.timeout_seconds,
          scan_after_sync: values.scan_after_sync === true,
          revision: item.default_branch ? "refs/remotes/origin/" + item.default_branch : "HEAD",
          include_paths: values.include_paths?.length ? values.include_paths : ["."],
          detector_ids: values.detector_ids?.length ? values.detector_ids : null,
          destination_dir: values.destination_dir?.trim() || null,
          audit_mode: "static_only",
          scan_timeout_seconds: values.scan_timeout_seconds, memory_mb: values.memory_mb,
        }));
        path = "/operations/source-sync/batch";
        payload = { repositories };
      } else {
        path = "/operations/source-sync";
        payload = values;
        repositories = [values];
      }
      setPreflightBusy(true);
      setPreflightError("");
      setPreflight(null);
      const plan = await api("/operations/source-sync/preview", { repositories });
      setPreparedSubmission({ path, payload });
      setPreflight(plan);
    } catch (error) { setCatalogError(String(error)); }
    finally { setPreflightBusy(false); }
  };
  const confirmPreparedSync = async () => {
    if (!preflight?.eligible || !preparedSubmission) return;
    setPreflightError("");
    try {
      await submit(preparedSubmission.path, preparedSubmission.payload);
      setPreflight(null);
      setPreparedSubmission(null);
    } catch (error) { setPreflightError(String(error)); }
  };
  const dismissPreflight = () => {
    setPreflight(null);
    setPreparedSubmission(null);
    setPreflightError("");
  };
  const formatBytes = (value: number) => {
    if (!Number.isFinite(value) || value < 0) return "未知";
    const gb = value / (1024 ** 3);
    return gb >= 1 ? `${gb.toFixed(1)} GiB` : `${(value / (1024 ** 2)).toFixed(0)} MiB`;
  };
  return <Card title="下载源码到本地（可选扫描）"><Form name="source-sync" form={form} layout="vertical" initialValues={{ timeout_seconds: 900, scan_after_sync: false, revision: "HEAD", include_paths: ["."], audit_mode: "static_only", scan_timeout_seconds: 600, memory_mb: 2048 }} onFinish={finish}>
    <Alert className="section-gap" type="info" showIcon message="选择服务端保存位置；默认只下载，不会自动扫描"
      description="路径属于运行 OHScanner 的服务器。Windows 系统示例：D:\OpenHarmony；Ubuntu 示例：/home/audit/OpenHarmony；WSL 示例：/mnt/d/OpenHarmony。当前 WSL 服务会自动转换 Windows 盘符路径。留空使用默认源码缓存。" />
    <Form.Item name="destination_dir" label="源码保存位置（可选）" extra="每个仓库会放在此目录下的独立子目录；批量下载会复用同一个保存位置。">
      <Input placeholder="例如 /mnt/d/OpenHarmony 或 D:\OpenHarmony" />
    </Form.Item>
    <Space wrap className="section-gap">
      <Button loading={catalogBusy} onClick={() => void loadCatalog(1)}>加载 OpenHarmony 仓库目录</Button>
      {catalog && <><Button disabled={catalogBusy || catalog.page <= 1} onClick={() => void loadCatalog(catalog.page - 1)}>上一页</Button><Text type="secondary">第 {catalog.page} 页，每页最多 {catalog.per_page} 项</Text><Button disabled={catalogBusy || !catalog.next_page} onClick={() => void loadCatalog(catalog.next_page)}>下一页</Button></>}
    </Space>
    {catalogError && <Alert className="section-gap" type="warning" showIcon message="仓库操作未完成" description={catalogError} />}
    {catalog && <>
      <Alert className="section-gap" type="info" showIcon message={`当前页 ${catalog.repositories.length} 个 OpenHarmony 仓库 · 已选 ${selectedNames.length}/8`}
        description="可跨页选择仓库，提交后按顺序逐个同步。每批最多 8 个，不会批量下载整个组织。" />
      <Form.Item name="catalog_selection" label="选择一个或多个在线仓库">
        <Select mode="multiple" maxCount={8} showSearch optionFilterProp="label" maxTagCount="responsive"
          placeholder="搜索当前页仓库名或描述"
          options={(catalog.repositories || []).map((item: any) => ({ value: item.name,
            label: item.name + (item.archived ? " · 已归档" : "") + (item.fork ? " · fork" : "") +
              (item.description ? " · " + item.description : "") }))}
          onChange={selectCatalogRows} />
      </Form.Item>
    </>}
    {!selectedNames.length && <>
      <Form.Item name="repository" label="OpenHarmony 仓库名" rules={[{ required: true }]}><Input placeholder="openharmony/commonlibrary_c_utils" /></Form.Item>
      <Form.Item name="url" label="HTTPS 地址（GitHub / Gitee / GitCode 的 OpenHarmony 仓库）" rules={[{ required: true }]}><Input placeholder="https://gitee.com/openharmony/commonlibrary_c_utils.git" /></Form.Item>
    </>}
    <Form.Item name="timeout_seconds" label="每仓同步超时（秒）"><InputNumber min={10} max={3600} /></Form.Item>
    <Form.Item name="scan_after_sync" valuePropName="checked"><Checkbox>同步成功后固定版本并排队静态扫描</Checkbox></Form.Item>
    {scanAfterSync && <>
      {!selectedNames.length
        ? <Form.Item name="revision" label="同步后扫描版本" rules={[{ required: true }]}><Input placeholder="HEAD 或 refs/remotes/origin/master" /></Form.Item>
        : <Alert className="section-gap" type="info" showIcon message="批量扫描使用各仓库目录中的默认分支" description="每个扫描任务固定自己的提交和文件树；批量扫描只运行静态检测，不会自动调用模型。" />}
      <Form.Item name="include_paths" label="纳入路径"><Select mode="tags" tokenSeparators={[",", "\n"]} /></Form.Item>
      {!selectedNames.length && <Form.Item name="audit_mode" label="扫描后的审计方式"><Radio.Group><Space direction="vertical"><Radio value="static_only">仅静态扫描</Radio><Radio value="standard_review">标准研判（结果中提供 Agent 入口）</Radio></Space></Radio.Group></Form.Item>}
      <Form.Item name="scan_timeout_seconds" label="单次扫描超时（秒）"><InputNumber min={30} max={3600} /></Form.Item>
      <Form.Item name="memory_mb" label="扫描内存预算（MB）"><InputNumber min={256} max={8192} /></Form.Item>
    </>}
    <Alert type="info" message={scanAfterSync ? "下载成功后创建固定版本静态扫描任务" : "下载源码，不创建扫描任务"} description="下载不会运行仓库构建脚本。需要扫描时再勾选上方选项；静态扫描不会自动发送源码给模型。" />
    <Button className="section-gap" type="primary" htmlType="submit" loading={busy || preflightBusy}>
      预览同步计划
    </Button>
    <Modal open={Boolean(preflight)} title="确认源码同步计划" okText="确认并排队" cancelText="返回修改"
      confirmLoading={busy} okButtonProps={{ disabled: !preflight?.eligible }}
      onCancel={dismissPreflight} onOk={() => void confirmPreparedSync()}>
      {preflight && <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Alert type={preflight.eligible ? "info" : "error"} showIcon
          message={`计划处理 ${preflight.repository_count} 个仓库 · 可用空间 ${formatBytes(preflight.available_disk_bytes)}`}
          description="预览不会下载源码。仓库大小需下载时确定，系统下载期间会保留至少 512 MiB 可用空间；自动排队的扫描只运行静态检测，不会发送源码给模型。" />
        {(preflight.repositories || []).map((item: any) => <Card size="small" key={item.repository}
          title={<Space wrap><Text strong>{item.repository}</Text>
            <Tag color={item.eligible ? "blue" : "red"}>{item.action === "clone" ? "首次下载" : item.action === "fetch" ? "更新本地副本" : "无法同步"}</Tag>
          </Space>}>
          <Space direction="vertical" size={2}>
            <Text type="secondary">保存到：{item.destination_dir}</Text>
            <Text type="secondary">来源：{item.source_id}</Text>
            {item.current_head && <Text type="secondary">当前本地提交：{item.current_head.slice(0, 12)}</Text>}
            {item.scan_after_sync && <Text type="secondary">同步后扫描版本：{item.requested_revision}</Text>}
            {item.reason && <Text type="danger">{item.reason}</Text>}
          </Space>
        </Card>)}
        {preflightError && <Alert type="error" showIcon message="同步任务未创建" description={preflightError} />}
        {(preflight.limitations || []).map((item: string) => <Text type="secondary" key={item}>{item}</Text>)}
      </Space>}
    </Modal>
  </Form></Card>;
}
export function InvestigationForm({ busy, submit, context = {} }: Pick<OperationFormProps, "busy" | "submit" | "context">) {
  return <Card title="启动只读候选调查"><Form name="candidate-investigation" layout="vertical" initialValues={{ max_output_bytes: 65536, job_id: context.job_id, candidate_id: context.candidate_id }} onFinish={(v) => void submit("/operations/investigations", v)}>
    <Form.Item name="job_id" label="已完成扫描任务 ID" rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item name="candidate_id" label="候选 ID" rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item name="max_output_bytes" label="最大输出字节数"><InputNumber min={1024} max={262144} /></Form.Item>
    <Alert type="info" message="只读调查不调用模型" description="当前只读取扫描时使用的源码片段、证据义务、Git 历史和符号；如需真实模型辅助，请切换到 LLM Agent 并逐次预览、授权源码外发。该只读步骤不执行任意命令，也不自动确认漏洞。" />
    <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>开始源码调查</Button>
  </Form></Card>;
}
export function ValidationForm({ repos, cases, busy, submit, context = {} }: Omit<OperationFormProps, "detectors">) {
  const [form] = Form.useForm();
  const selectedHarness = Form.useWatch("harness_id", form) || "auth01_descriptor_bypass";
  const [tests, setTests] = useState<any[]>([]);
  const [catalogError, setCatalogError] = useState("");
  useEffect(() => {
    let active = true;
    void api("/validation-tests").then((result) => {
      if (active) { setTests(Array.isArray(result?.tests) ? result.tests : []); setCatalogError(""); }
    }).catch((error) => { if (active) setCatalogError("读取已接入复现测试失败：" + String(error)); });
    return () => { active = false; };
  }, []);
  const selectedTest = tests.find((item) => item.id === selectedHarness);
  const needsTarget = selectedTest?.requires_target_support !== false;
  const selectedBlocked = selectedTest?.source_status === "blocked";
  const target = repos.filter((r) => r.name === "openharmony/inputmethod_imf");
  const support = repos.filter((r) => r.name === "openharmony/commonlibrary_c_utils");
  return <Card title="受控组件复现计划">{context.candidate_id && <Alert className="section-gap" type="info" message={"来源候选 " + context.candidate_id} description="先关联案例以便归档。不同测试绑定各自固定源码或样例；组件复现结果不代表该候选已复现。" action={<Button onClick={() => go("/tasks/" + context.job_id)}>返回来源任务</Button>} />}<Alert type="warning" showIcon message="复现只运行已接入的固定测试，并在隔离 Docker 容器内执行。" description="缺少 Docker daemon 或固定镜像时任务会显示受阻。组件结果不证明产品入口可达或漏洞已确认。" />
    <Form form={form} name="validation-plan" className="section-gap" layout="vertical" initialValues={{ harness_id: "auth01_descriptor_bypass", repeats: 3 }} onFinish={({ approval, ...values }) => {
      const payload = { ...values };
      if (!needsTarget) for (const key of ["target_repository_id", "target_commit", "cutils_repository_id", "cutils_commit"]) delete payload[key];
      void submit("/operations/validations", payload);
    }}>
      <Form.Item name="case_id" label="调查案例" rules={[{ required: true }]}><Select options={cases.map((c) => ({ value: c.id, label: c.title }))} /></Form.Item>
      <Form.Item name="harness_id" label="已接入的复现测试" rules={[{ required: true }]}><Select loading={!tests.length && !catalogError} options={tests.map((item) => ({ value: item.id, label: item.source_status === "blocked" ? item.label + "（当前受阻）" : item.label }))} /></Form.Item>
      {catalogError && <Alert type="error" message={catalogError} />}
      {selectedTest && <Alert className="section-gap" type={selectedBlocked ? "warning" : "info"} showIcon message={selectedBlocked ? "固定测试源码不可用" : selectedTest.label} description={selectedBlocked ? selectedTest.source_reason : selectedTest.description} />}
      {needsTarget && <>
        <Form.Item name="target_repository_id" label="inputmethod_imf 仓库" rules={[{ required: true }]}><Select options={target.map((r) => ({ value: r.id, label: r.path }))} /></Form.Item>
        <Form.Item name="target_commit" label="AUTH-01 目标版本 SHA" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="cutils_repository_id" label="commonlibrary_c_utils 仓库" rules={[{ required: true }]}><Select options={support.map((r) => ({ value: r.id, label: r.path }))} /></Form.Item>
        <Form.Item name="cutils_commit" label="支持源码完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
      </>}
      <Form.Item name="repeats" label="每个攻击/控制用例重复次数"><InputNumber min={3} max={3} /></Form.Item>
      <Form.Item name="approval" valuePropName="checked" rules={[{ validator: (_, v) => v ? Promise.resolve() : Promise.reject(new Error("请确认审阅验证对象和环境限制")) }]}>
        <Radio>已查看所选复现测试范围，仅申请受控执行</Radio>
      </Form.Item>
      {(!cases.length || (needsTarget && (!target.length || !support.length))) && <Alert type="info" message={needsTarget ? "需先登记 AUTH-01 目标和支持源码仓库，并关联案例。" : "需先关联一个案例用于归档。"} />}
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy} disabled={!selectedTest || selectedBlocked || !cases.length || (needsTarget && (!target.length || !support.length))}>提交复现任务</Button>
    </Form>
  </Card>;
}


export function AgentInvestigationForm({ busy, submit, context = {}, cases = [], agentStatus }: Pick<OperationFormProps, "busy" | "submit" | "context" | "cases"> & { agentStatus: any }) {
  const [form] = Form.useForm();
  const [modal, contextHolder] = Modal.useModal();
  const mode = Form.useWatch("mode", form) || "tool_agent";
  const experimentId = Form.useWatch("experiment_id", form);
  const sourceSubmissionApproved = Form.useWatch("source_submission_approved", form) === true;
  const [preview, setPreview] = useState<any>(null);
  const [previewDisclosureOpened, setPreviewDisclosureOpened] = useState(false);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [previewError, setPreviewError] = useState("");
  const [baselineBusy, setBaselineBusy] = useState(false);
  const [baselineStatus, setBaselineStatus] = useState<any>(null);
  const [baselineError, setBaselineError] = useState("");
  const [pairPreview, setPairPreview] = useState<any>(null);
  const [pairDisclosureOpened, setPairDisclosureOpened] = useState<string[]>([]);
  const [pairSubmissionApproved, setPairSubmissionApproved] = useState(false);
  const [pairBusy, setPairBusy] = useState(false);
  const [pairError, setPairError] = useState("");
  const pairRequiredDisclosureKeys = (pairPreview?.arms || []).map((arm: any) => String(arm.mode));
  const pairDisclosureReviewed = disclosureSelectionMatches(["single_shot", "tool_agent"], pairRequiredDisclosureKeys)
    && disclosureReviewed(pairDisclosureOpened, pairRequiredDisclosureKeys);
  const previewGate = useRef(requestGate());
  const [providerCheckBusy, setProviderCheckBusy] = useState(false);
  const [providerCheckResult, setProviderCheckResult] = useState<any>(null);
  const [providerCheckError, setProviderCheckError] = useState("");
  const [staticCandidate, setStaticCandidate] = useState<any>(null);
  const [staticPreviewBusy, setStaticPreviewBusy] = useState(false);
  const [staticPreviewError, setStaticPreviewError] = useState("");
  const [r0SourceStart, setR0SourceStart] = useState<number | null>(null);
  const [r0SourceCount, setR0SourceCount] = useState(20);
  const [r0SourceBusy, setR0SourceBusy] = useState(false);
  const [r0SourceError, setR0SourceError] = useState("");
  const [r0SourceRanges, setR0SourceRanges] = useState<any[]>([]);
  const ready = Boolean(agentStatus?.configured);
  const linkedCases = cases.filter((item: any) =>
    item.links?.some((link: any) => link.job_id === context.job_id && link.candidate_id === context.candidate_id));
  const staticReviewReady = Boolean(staticCandidate?.source?.sha256
    && staticCandidate.source.sha256 === staticCandidate.source_sha256);
  const statusIsComplete = (value: string) => ["completed", "complete", "analyzed"].includes(value);
  const staticAnalysisIncomplete = Boolean(staticCandidate && (
    !statusIsComplete(staticCandidate.scan_status || "unknown")
    || !statusIsComplete(staticCandidate.detector_coverage?.status || "unknown")
    || !statusIsComplete(staticCandidate.analysis_status || "unknown")
  ));
  const staticExcerpt = String(staticCandidate?.source?.text || "");
  const evidenceRouting = staticCandidate?.evidence_routing;
  const agentSourceActionable = Array.isArray(evidenceRouting?.agent_source_review_indices)
    && evidenceRouting.agent_source_review_indices.length > 0;
  const routingLabels: Record<string, string> = {
    agent_source_review_with_human_followup: "Agent 可协助本次扫描源码调查，但仍需人工或动态验证",
    agent_source_review: "可用只读 Agent 收集本次扫描源码线索；仍需人工复核",
    human_or_runtime_validation: "当前未决项应交人工或动态验证",
    human_review: "没有待 Agent 补充的已分类源码义务；交人工复核",
  };
  const formatObligationDetails = (items: any[]) => {
    const obligations = staticCandidate?.evidence?.obligations || [];
    if (!items?.length) return ["无"];
    return items.map((rawIndex) => {
      const index = Number(rawIndex);
      const item = Number.isInteger(index) && index >= 0 ? obligations[index] : null;
      if (!item || typeof item !== "object") return "#" + (index + 1) + "（原始义务不可用，保持人工复核）";
      const kind = typeof item.kind === "string" ? item.kind : "未知类型";
      const status = typeof item.status === "string" ? item.status : "unknown";
      const description = typeof item.description === "string" ? item.description : "未提供说明";
      return "#" + (index + 1) + " " + kind + "（" + status + "）：" + description;
    });
  };
  useEffect(() => {
    let active = true;
    setStaticCandidate(null); setStaticPreviewError("");
    if (!context.job_id || !context.candidate_id) {
      setStaticPreviewBusy(false);
      return () => { active = false; };
    }
    setStaticPreviewBusy(true);
    api("/agent/static-review-preview?job_id=" + encodeURIComponent(context.job_id) + "&candidate_id=" + encodeURIComponent(context.candidate_id))
      .then((value) => {
        if (!active) return;
        setStaticCandidate(value);
        const obligations = Array.isArray(value.evidence?.obligations) ? value.evidence.obligations.slice(0, 40) : [];
        form.setFieldValue("r0_obligation_reviews", obligations.map((_: unknown, index: number) => ({
          obligation_index: index, disposition: "unresolved",
        })));
      })
      .catch((error) => { if (active) setStaticPreviewError(String(error)); })
      .finally(() => { if (active) setStaticPreviewBusy(false); });
    return () => { active = false; };
  }, [context.job_id, context.candidate_id]);
  const checkProvider = () => modal.confirm({
    title: "发送无源码连通性请求？",
    content: "将向已配置的模型服务发送一条预设测试文本；请求正文不含仓库、候选或源码，但认证头会携带该服务的 API key。服务商仍可能按其规则计费。",
    okText: "发送测试请求", cancelText: "取消",
    onOk: async () => {
      setProviderCheckBusy(true); setProviderCheckError(""); setProviderCheckResult(null);
      try {
        const result = await api("/agent/provider-check", { confirm_no_source_request: true });
        setProviderCheckResult(result);
        message.success("Provider 连通性检查通过；这不代表模型分析质量已验证");
      } catch (e) { setProviderCheckError(String(e)); }
      finally { setProviderCheckBusy(false); }
    },
  });
  const invalidatePreview = () => {
    previewGate.current.invalidate(); setPreview(null); setPreviewBusy(false); setPreviewError("");
    setPreviewDisclosureOpened(false);
    form.setFieldValue("source_submission_approved", false);
  };
  useEffect(() => {
    form.setFieldsValue({ job_id: context.job_id, candidate_id: context.candidate_id,
      case_id: context.case_id, source_submission_approved: false,
      experiment_id: undefined, r0_reviewer: undefined, r0_disposition: undefined,
      r0_elapsed_seconds: undefined, r0_notes: undefined,
      r0_obligation_reviews: [], r0_obligations_acknowledged: false });
    setR0SourceStart(null); setR0SourceCount(20); setR0SourceRanges([]); setR0SourceError("");
    invalidatePreview(); setBaselineStatus(null); setBaselineError("");
  }, [context.job_id, context.candidate_id]);

  useEffect(() => {
    form.setFieldValue("case_id", context.case_id);
    invalidatePreview();
  }, [context.case_id, agentStatus?.configured, agentStatus?.model, agentStatus?.endpoint_host,
      agentStatus?.consent_preview_version, agentStatus?.redaction_policy_version]);

  const loadR0SourceRange = async () => {
    if (!Number.isInteger(r0SourceStart) || !r0SourceStart || !staticCandidate || r0SourceCount < 1 || r0SourceCount > 40) {
      setR0SourceError("请输入有效起始行，并将读取行数设为 1–40。");
      return;
    }
    setR0SourceBusy(true); setR0SourceError("");
    try {
      const result = await api("/agent/static-review-source", {
        job_id: context.job_id, candidate_id: context.candidate_id,
        start_line: r0SourceStart, line_count: r0SourceCount,
      });
      if (result.source_sha256 !== staticCandidate.source_sha256
          || result.report_sha256 !== staticCandidate.binding?.report_sha256
          || result.file !== staticCandidate.file) {
        throw new Error("补读源码与当前候选的扫描报告/源码身份不匹配");
      }
      setR0SourceRanges((current) => [...current.filter((item) =>
        item.start_line !== result.start_line || item.end_line !== result.end_line), result]);
    } catch (e) { setR0SourceError(String(e)); }
    finally { setR0SourceBusy(false); }
  };

  const recordBaseline = async () => {
    setBaselineBusy(true); setBaselineError("");
    try {
      const values = await form.validateFields(["job_id", "candidate_id", "experiment_id",
        "r0_reviewer", "r0_disposition", "r0_elapsed_seconds", "r0_notes",
        "r0_obligations_acknowledged", "r0_obligation_reviews"]);
      const result = await api("/agent/baseline-reviews", {
        job_id: values.job_id, candidate_id: values.candidate_id,
        experiment_id: values.experiment_id?.trim(), reviewer: values.r0_reviewer,
        disposition: values.r0_disposition, elapsed_seconds: values.r0_elapsed_seconds,
        notes: values.r0_notes || "",
        reviewer_acknowledged: Boolean(values.r0_obligations_acknowledged),
        obligation_reviews: (values.r0_obligation_reviews || []).map((item: any) => ({
          ...item, quote: item.quote?.trim() || undefined, notes: item.notes || "",
        })),
        source_ranges: r0SourceRanges.map((item) => ({
          start_line: item.start_line, end_line: item.end_line,
        })),
      });
      setBaselineStatus(result);
    } catch (e) { setBaselineError(String(e)); }
    finally { setBaselineBusy(false); }
  };

  const requestPairPreview = async () => {
    setPairBusy(true); setPairError(""); setPairPreview(null); setPairDisclosureOpened([]); setPairSubmissionApproved(false);
    try {
      const values = await form.validateFields(["job_id", "candidate_id", "experiment_id",
        "case_id", "max_output_tokens", "max_steps", "max_total_input_tokens", "max_total_output_tokens", "timeout_seconds"]);
      if (!values.experiment_id?.trim()) throw new Error("请先填写实验批次 ID");
      const result = await api("/operations/agent-investigations/paired/preview", {
        job_id: values.job_id, candidate_id: values.candidate_id,
        experiment_id: values.experiment_id?.trim(), case_id: values.case_id || undefined,
        max_output_tokens: values.max_output_tokens,
          max_steps: values.max_steps, max_total_input_tokens: values.max_total_input_tokens,
          max_total_output_tokens: values.max_total_output_tokens, timeout_seconds: values.timeout_seconds,
      });
      setPairPreview(result); setPairDisclosureOpened([]); setPairSubmissionApproved(false);
    } catch (e) { setPairError(String(e)); }
    finally { setPairBusy(false); }
  };
  const enqueuePair = async () => {
    if (!pairPreview || !pairDisclosureReviewed || !pairSubmissionApproved) return;
    setPairBusy(true); setPairError("");
    try {
      const result = await api("/operations/agent-investigations/paired", {
        job_id: form.getFieldValue("job_id"), candidate_id: form.getFieldValue("candidate_id"),
        experiment_id: form.getFieldValue("experiment_id")?.trim(),
        case_id: form.getFieldValue("case_id") || undefined,
        max_output_tokens: form.getFieldValue("max_output_tokens"),
        max_steps: form.getFieldValue("max_steps"), max_total_input_tokens: form.getFieldValue("max_total_input_tokens"),
        max_total_output_tokens: form.getFieldValue("max_total_output_tokens"), timeout_seconds: form.getFieldValue("timeout_seconds"),
        source_submission_approved: true, consent_sha256: pairPreview.consent_sha256,
        consent_nonce: pairPreview.consent_nonce,
      });
      setPairPreview(null); setPairDisclosureOpened([]); setPairSubmissionApproved(false);
      message.success("模型对照任务已成对创建；这只是运行配对，不代表效果结论");
      if (result.operations?.[0]?.id) go("/tasks/operations/" + result.operations[0].id);
    } catch (e) { setPairError(String(e)); }
    finally { setPairBusy(false); }
  };
  const requestPreview = async () => {
    const ticket = previewGate.current.next(); setPreviewBusy(true); setPreview(null); setPreviewError(""); setPreviewDisclosureOpened(false);
    try {
      const values = await form.validateFields(["job_id", "candidate_id", "experiment_id", "case_id", "mode",
        "max_output_tokens", "max_steps", "max_total_input_tokens", "max_total_output_tokens", "timeout_seconds"]);
      const result = await api("/operations/agent-investigations/preview",
        { job_id: values.job_id, candidate_id: values.candidate_id,
          experiment_id: values.experiment_id, case_id: values.case_id,
          mode: values.mode,
          max_output_tokens: values.max_output_tokens,
          max_steps: values.max_steps, max_total_input_tokens: values.max_total_input_tokens,
          max_total_output_tokens: values.max_total_output_tokens, timeout_seconds: values.timeout_seconds,
          source_submission_approved: false });
      if (previewGate.current.current(ticket)) {
        setPreview(result); setPreviewDisclosureOpened(false); form.setFieldValue("source_submission_approved", false);
      }
    } catch (e) {
      if (previewGate.current.current(ticket)) setPreviewError(String(e));
    } finally {
      if (previewGate.current.current(ticket)) setPreviewBusy(false);
    }
  };
  return <Card title="模型辅助候选调查">
    {contextHolder}
    {!ready ? <Alert type="warning" showIcon message="模型服务尚未配置" description={(agentStatus?.missing?.length ? "Worker 环境缺少：" + agentStatus.missing.join(", ") : "请由服务管理员配置 OHSCANNER_LLM_MODEL 和 OHSCANNER_LLM_API_KEY") + "；密钥不在浏览器或数据库保存。"} /> :
      <Alert type="info" showIcon message={"目的地：" + agentStatus.endpoint_host + " · 模型：" + agentStatus.model} description="先生成本次外发预览；模型、方式、单次输出上限或固定候选变化后，预览与授权都会失效。" />}
    {ready && <Space className="section-gap" wrap>
      <Button loading={providerCheckBusy} onClick={checkProvider}>测试模型服务</Button>
      {providerCheckResult && <Text type="secondary">最近通过：{providerCheckResult.endpoint_host} · {providerCheckResult.model} · {providerCheckResult.duration_ms} ms · 输入/输出 Token {providerCheckResult.usage?.input_tokens ?? "未知"}/{providerCheckResult.usage?.output_tokens ?? "未知"}</Text>}
    </Space>}
    {providerCheckError && <Alert className="section-gap" type="error" showIcon message={providerCheckError} />}
    {previewError && <Alert className="section-gap" type="error" showIcon message={previewError} />}
    <Form name="agent-candidate-investigation" form={form} layout="vertical" initialValues={{ mode: "tool_agent", max_steps: 4, max_total_input_tokens: 128000, max_total_output_tokens: 8000, timeout_seconds: 240, job_id: context.job_id, candidate_id: context.candidate_id, case_id: context.case_id }}
      onValuesChange={(changed) => {
        if (!("source_submission_approved" in changed)) invalidatePreview();
        setPairPreview(null); setPairError(""); setPairDisclosureOpened([]); setPairSubmissionApproved(false);
        if ("experiment_id" in changed) setBaselineStatus(null);
      }}
      onFinish={(values) => {
        const agentValues = { ...values };
        delete agentValues.r0_reviewer; delete agentValues.r0_disposition;
        delete agentValues.r0_elapsed_seconds; delete agentValues.r0_notes;
        delete agentValues.r0_obligation_reviews; delete agentValues.r0_obligations_acknowledged;
        if (!preview) { setPreviewError("请先预览本次外发内容"); return; }
        void submit("/operations/agent-investigations", { ...agentValues, experiment_id: values.experiment_id?.trim() || undefined, consent_sha256: preview.consent_sha256, consent_nonce: preview.consent_nonce });
      }}>
      <Form.Item name="job_id" label="已完成扫描任务 ID" rules={[{ required: true }]}><Input readOnly /></Form.Item>
      <Form.Item name="candidate_id" label="扫描候选 ID" rules={[{ required: true }]}><Input readOnly /></Form.Item>
      <Form.Item name="max_steps" hidden><InputNumber /></Form.Item>
      <Alert className="section-gap" type="info" message="单次模型输出额度统一在系统设置 → 智能审计策略与资源预算中配置；本次外发预览会显示实际额度。" />
      <Form.Item name="max_total_input_tokens" hidden><InputNumber /></Form.Item>
      <Form.Item name="max_total_output_tokens" hidden><InputNumber /></Form.Item>
      <Form.Item name="timeout_seconds" hidden><InputNumber /></Form.Item>
      <Alert className="section-gap" type="info" showIcon message="智能调查会持续追查，不因累计用量停止"
        description="平台不设累计 Token、模型调用、工具步骤、调查时长或费用上限。调查会在模型完成、连续没有新增源码证据、服务商/API 出错或你手动取消时结束；实际账户额度和费用由模型服务商决定。" />

      <Collapse className="section-gap" items={[{ key: "research-settings", label: "研究实验设置（可选）", children: <>
        <Form.Item name="experiment_id" label="实验批次 ID" extra="仅用于人工基线或模型对照实验；普通单次调查可留空。">
          <Input maxLength={64} placeholder="例如 OH-2026-10-dsoftbus-core-frame" />
        </Form.Item>
        {!experimentId && <Alert className="section-gap" type="warning" showIcon
          message="留空即可进行普通单次调查。填写实验批次后，需先记录人工静态基线才能创建配对实验。" />}
        {experimentId && <Alert className="section-gap" type="info" showIcon
          message={"人工基线将绑定到实验批次：" + experimentId}
          description="请先完成并保存该候选的静态人工审阅，再为同一批次创建模型对照；保存后不能补写或修改。" />}
      </> }]} />
      <Card size="small" title="本次扫描候选证据">
        <Alert type="info" showIcon message="这里展示扫描报告、候选信息和绑定源码，供你判断是否需要继续调查；不会展示模型结论。" />
        {staticPreviewBusy && <Text type="secondary">正在读取本次扫描证据……</Text>}
        {staticPreviewError && <Alert className="section-gap" type="error" showIcon message={"静态审阅材料加载失败：" + staticPreviewError} />}
        {staticCandidate && <Descriptions className="section-gap" bordered size="small" column={2}>
          <Descriptions.Item label="仓库 / 扫描代码版本">{staticCandidate.binding?.repository || "未知"} @ {staticCandidate.binding?.commit || "未知"}</Descriptions.Item>
          <Descriptions.Item label="报告 SHA-256">{staticCandidate.binding?.report_sha256 || "未知"}</Descriptions.Item>
          <Descriptions.Item label="规则 / 版本">{staticCandidate.detector_id || "未知"} · {staticCandidate.detector_version || "未知"} · {staticCandidate.rule_id || "未知"}</Descriptions.Item>
          <Descriptions.Item label="源码 SHA-256">{staticCandidate.source_sha256 || "未知"}</Descriptions.Item>
          <Descriptions.Item label="静态严重度 / 置信度">{staticCandidate.severity || "unassessed"} / {staticCandidate.confidence || "unassessed"}</Descriptions.Item>
          <Descriptions.Item label="扫描 / 检测器 / 文件分析状态" span={2}>
            扫描：{triageStateLabel(staticCandidate.scan_status || "unknown")}；检测器覆盖：{coverageStatusLabel(staticCandidate.detector_coverage?.status || "unknown")}；文件分析：{analysisStatusLabel(staticCandidate.analysis_status || "unknown")}
          </Descriptions.Item>
          <Descriptions.Item label="检测器文件覆盖（完整 / 部分 / 未分析 / 失败）" span={2}>
            {staticCandidate.detector_coverage?.analyzed_files ?? "未知"} / {staticCandidate.detector_coverage?.partially_inspected_files ?? "未知"} / {staticCandidate.detector_coverage?.not_analyzed_files ?? "未知"} / {staticCandidate.detector_coverage?.failed_files ?? "未知"}
          </Descriptions.Item>
          <Descriptions.Item label="文件 / 行" span={2}>{staticCandidate.file}:{staticCandidate.line}</Descriptions.Item>
        </Descriptions>}
        {staticAnalysisIncomplete && <Alert className="section-gap" type="warning" showIcon
          message={"扫描或解析覆盖不完整。文件分析状态：" + analysisStatusLabel(staticCandidate?.analysis_status || "unknown") + "。未分析范围必须保持未知，不能视为安全；这条发现仍是待复核候选。"} />}
        {evidenceRouting && <Alert className="section-gap" type={agentSourceActionable ? "info" : "warning"} showIcon
          message={"建议下一步：" + (routingLabels[evidenceRouting.route] || "保持未知并交人工复核")}
          description={<Space direction="vertical" size={2}>
            <Text>Agent 可协助的本次源码核查事项（只收集线索，不作语义判定）：</Text>
            {formatObligationDetails(evidenceRouting.agent_source_review_indices).map((item: string, index: number) => <Text key={index}>{item}</Text>)}
            <Text>必须由人工或动态验证的义务：</Text>
            {formatObligationDetails(evidenceRouting.human_or_runtime_review_indices).map((item: string, index: number) => <Text key={index}>{item}</Text>)}
            {evidenceRouting.unclassified_indices?.length > 0 && <Text type="warning">以下义务类型当前未分类，保守交人工：{formatObligationDetails(evidenceRouting.unclassified_indices).join("；")}</Text>}
            <Text type="secondary">这是基于义务类型的分流提示，不会关闭义务或改变 candidate 状态。</Text>
            {!agentSourceActionable && <Text type="warning">没有可由 Agent 补充的未决源码义务；创建模型任务会额外外发源码但不能回答当前问题，因此系统将阻止提交。</Text>}
          </Space>} />}
        {staticCandidate && <><Text strong>扫描器原始诊断（静态候选；原文）</Text>
          <pre className="raw">{staticCandidate.message || "扫描报告未提供诊断文本。"}</pre>
          <Text strong>静态扫描证据义务（不是漏洞结论）</Text>
          <pre className="raw">{JSON.stringify(staticCandidate.evidence?.obligations || [], null, 2)}</pre>
          <Text strong>本次扫描源码片段（第 {staticCandidate.source?.start_line}–{staticCandidate.source?.end_line} 行）</Text>
          {staticReviewReady ? <pre className="raw">{staticExcerpt}</pre> :
            <Alert className="section-gap" type="error" showIcon message="源码 SHA-256 与候选记录不匹配；无法完成可信的人工静态复核。" />}
          {staticCandidate.source?.truncated && <Alert className="section-gap" type="warning" showIcon message="源码预览达到 32 KiB 上限；只显示源码片段的一部分，继续前请在扫描源码页面核对完整上下文。" />}
        </>}
      </Card>
      <Collapse className="section-gap" items={[{ key: "research-baseline", label: "人工静态基线与模型对照（高级研究）", children: <Card size="small" title="人工静态基线">
        <Alert type="info" showIcon message="仅记录人工静态分诊和复核耗时，不是漏洞真值。开始调查方式对照前先保存该基线；保存后不能补写。" />
        <Space wrap className="section-gap">
          <Form.Item name="r0_reviewer" label="R0 复核人" rules={[{ required: Boolean(experimentId), max: 100 }]}><Input maxLength={100} /></Form.Item>
          <Form.Item name="r0_disposition" label="静态分诊" rules={[{ required: Boolean(experimentId) }]}>
            <Select style={{ width: 200 }} options={[
              { value: "investigate", label: "值得继续调查" },
              { value: "likely_noise", label: "倾向噪声" },
              { value: "unknown", label: "仅凭静态证据未知" },
            ]} />
          </Form.Item>
          <Form.Item name="r0_elapsed_seconds" label="静态人工复核耗时（秒）"><InputNumber min={0} max={7200} /></Form.Item>
        </Space>
        <Form.Item name="r0_notes" label="总体静态依据和未知项"><Input.TextArea rows={2} maxLength={1200} /></Form.Item>
        {staticCandidate?.evidence?.obligations?.length > 0 && <>
          <Text strong>逐项人工判断（调查方式对照基线）</Text>
          {staticCandidate.evidence.obligations_truncated && <Alert className="section-gap" type="warning" showIcon
            message="静态义务超过 40 项；人工基线与自动调查本轮都只处理预览中的前 40 项。" />}
          <Alert className="section-gap" type="warning" showIcon
            message="每条义务必须单独判断；有证据或反向证据时必须引用已展示的本次扫描源码行。无法仅凭现有片段判断时先补读同一文件的行范围；仍无法判断就选 unresolved，不要猜测。" />
          <Space wrap className="section-gap" align="end">
            <Form.Item label="补读源码的起始行"><InputNumber min={1} max={staticCandidate?.source_line_count || 1}
              value={r0SourceStart} onChange={(value) => setR0SourceStart(typeof value === "number" ? value : null)} /></Form.Item>
            <Form.Item label="行数（最多 40）"><InputNumber min={1} max={40}
              value={r0SourceCount} onChange={(value) => setR0SourceCount(typeof value === "number" ? value : 20)} /></Form.Item>
            <Button loading={r0SourceBusy} disabled={!staticReviewReady || !staticCandidate?.source_line_count}
              onClick={() => void loadR0SourceRange()}>读取该扫描版本中的文件行范围</Button>
          </Space>
          <Text type="secondary">补读只访问扫描报告绑定的同一文件与源码 SHA，不调用 Provider。服务端保存 R0 时会再次核对每条引文的原文和行号。</Text>
          {r0SourceError && <Alert className="section-gap" type="error" showIcon message={r0SourceError} />}
          {r0SourceRanges.map((item) => <Card key={item.start_line + ":" + item.end_line} className="section-gap" size="small"
            title={"已读取源码范围 " + item.file + ":" + item.start_line + "–" + item.end_line}>
            <pre className="raw">{item.text}</pre>
          </Card>)}
          <Form.List name="r0_obligation_reviews">
            {(fields) => <Space direction="vertical" className="section-gap" style={{ width: "100%" }}>
              {fields.map((field) => {
                const obligation = staticCandidate.evidence.obligations[field.name] || {};
                const kind = typeof obligation.kind === "string" ? obligation.kind : "未知类型";
                const description = typeof obligation.description === "string" ? obligation.description : String(obligation);
                return <Card key={field.key} size="small" title={"#" + (field.name + 1) + " " + kind}>
                  <Text>{description}</Text>
                  <Form.Item name={[field.name, "obligation_index"]} hidden><InputNumber /></Form.Item>
                  <Form.Item name={[field.name, "disposition"]} label="人工静态判断" rules={[{ required: true }]}>
                    <Select options={[
                      { value: "evidence_found", label: "在本次扫描源码中找到支持证据" },
                      { value: "contrary_evidence", label: "在本次扫描源码中找到反向证据" },
                      { value: "unresolved", label: "当前源码片段无法判断，保持未知" },
                    ]} />
                  </Form.Item>
                  <Space wrap>
                    <Form.Item name={[field.name, "source_line"]} label="原文行号（支持/反向判断必填）"
                      dependencies={[["r0_obligation_reviews", field.name, "disposition"]]}
                      rules={[{ validator: (_, value) => {
                        const disposition = form.getFieldValue(["r0_obligation_reviews", field.name, "disposition"]);
                        return disposition !== "unresolved" && !Number.isInteger(value)
                          ? Promise.reject(new Error("请填写本次扫描源码行号")) : Promise.resolve();
                      }}]}>
                      <InputNumber min={1} max={staticCandidate.source_line_count || 1} />
                    </Form.Item>
                    <Form.Item name={[field.name, "quote"]} label="逐字源码引用（支持/反向判断必填）"
                      dependencies={[["r0_obligation_reviews", field.name, "disposition"]]}
                      rules={[{ validator: (_, value) => {
                        const disposition = form.getFieldValue(["r0_obligation_reviews", field.name, "disposition"]);
                        return disposition !== "unresolved" && (typeof value !== "string" || value.trim().length < 8)
                          ? Promise.reject(new Error("请提供至少 8 个字符的原文引用")) : Promise.resolve();
                      }}]}>
                      <Input.TextArea rows={2} maxLength={500} />
                    </Form.Item>
                  </Space>
                  <Form.Item name={[field.name, "notes"]} label="逐项说明（可选）"><Input maxLength={800} /></Form.Item>
                </Card>;
              })}
            </Space>}
          </Form.List>
          <Form.Item name="r0_obligations_acknowledged" valuePropName="checked"
            rules={[{ validator: (_, value) => value ? Promise.resolve() : Promise.reject(new Error("请确认已逐项查看义务")) }]}>
            <Checkbox>我已逐条查看上面的本次源码核查事项，并独立记录判断；无法由当前源码片段判断的项目保留 unresolved。</Checkbox>
          </Form.Item>
        </>}
        {baselineError && <Alert type="error" showIcon message={baselineError} />}
        {baselineStatus && <Alert className="section-gap" type="success" showIcon message={"人工静态基线已保存：" + baselineStatus.disposition + " · 逐项复核 " + (baselineStatus.obligations_reviewed ?? 0) + " 项 · " + baselineStatus.record_sha256} />}
        <Button className="section-gap" loading={baselineBusy} disabled={!experimentId || !context.job_id || !context.candidate_id || !staticReviewReady || staticPreviewBusy}
          onClick={() => void recordBaseline()}>保存人工静态基线</Button>
        <Button className="section-gap" loading={pairBusy} disabled={!ready || !experimentId || !context.job_id || !context.candidate_id || !staticReviewReady || staticPreviewBusy || !agentSourceActionable}
          onClick={() => void requestPairPreview()}>预览两种调查方式并启动对照</Button>
        {pairError && <Alert className="section-gap" type="error" showIcon message={pairError} />}
      </Card> }]} />
      <Modal title="调查方式对照的源码发送预览" open={Boolean(pairPreview)} width={900}
        confirmLoading={pairBusy} okText="批准并创建两种调查任务" cancelText="取消"
        okButtonProps={{ disabled: !pairDisclosureReviewed || !pairSubmissionApproved }}
        onOk={() => void enqueuePair()} onCancel={() => { setPairPreview(null); setPairDisclosureOpened([]); setPairSubmissionApproved(false); }}>
        {pairPreview && <>
          <Alert type="warning" showIcon message="确认后会对同一候选分别运行单轮模型研判和跨文件工具调查。必须先有同来源的人工静态基线；结果仍是待复核候选，盲审完成前不要比较哪种方式更好。" />
          <Descriptions className="section-gap" bordered size="small" column={2}>
            <Descriptions.Item label="实验批次">{pairPreview.experiment_id}</Descriptions.Item>
            <Descriptions.Item label="模型端点">{pairPreview.provider?.endpoint_host} · {pairPreview.provider?.model}</Descriptions.Item>
            <Descriptions.Item label="固定候选" span={2}>{pairPreview.candidate?.repository} @ {pairPreview.candidate?.commit} · {pairPreview.candidate?.candidate_id}</Descriptions.Item>
            <Descriptions.Item label="AI 初步分析">每候选一个 Provider 请求，单次输出上限 {pairPreview.aggregate_budget?.single_shot_max_output_tokens_per_request == null ? "无本地上限，由服务商决定" : String(pairPreview.aggregate_budget.single_shot_max_output_tokens_per_request) + " tokens"}，45 秒超时</Descriptions.Item>
            <Descriptions.Item label="跨文件工具调查">平台不设累计 Token、调用次数、费用或总时长上限；每次请求仍有输出上限和 45 秒超时，可随时取消</Descriptions.Item>
          </Descriptions>
          <Text type="secondary">整组预览 SHA-256：{pairPreview.consent_sha256}</Text>
          {pairPreview.arms?.map((arm: any) => <Card key={arm.mode} className="section-gap" size="small" title={arm.mode === "single_shot" ? "AI 初步分析" : "AI 深入追查"}>
            <Text>上下文 UTF-8 字节：{arm.preview?.initial_context_utf8_bytes} · 工具思考：{arm.preview?.inference_settings?.tool_call_reasoning_effort || "无"} · 结构化输出思考：{arm.preview?.inference_settings?.structured_output_reasoning_effort || "服务商默认"} · 单次输出上限：{arm.preview?.budgets?.max_output_tokens_per_request == null && arm.preview?.budgets?.max_output_tokens == null ? "无本地上限，由服务商决定" : String(arm.preview?.budgets?.max_output_tokens_per_request ?? arm.preview?.budgets?.max_output_tokens) + " tokens"} · 源码 SHA-256：{arm.preview?.binding?.source_sha256}</Text>
            <Alert type="warning" showIcon message="自动脱敏不是完整 DLP，请检查本组完整外发预览"
              description={redactionNotice(arm.preview)} />
            <Collapse activeKey={pairDisclosureOpened.includes(String(arm.mode)) ? [String(arm.mode)] : []}
              onChange={(keys) => {
                const opened = Array.isArray(keys) ? keys.map(String) : [String(keys)];
                const next = pairDisclosureOpened.filter((key) => key !== String(arm.mode));
                if (opened.includes(String(arm.mode))) next.push(String(arm.mode));
                setPairDisclosureOpened(next);
                if (!disclosureReviewed(next, pairRequiredDisclosureKeys)) setPairSubmissionApproved(false);
              }}
              items={[{ key: arm.mode, label: "展开该组完整发送上下文与只读工具范围", children: <><pre className="raw">{JSON.stringify(arm.preview?.initial_context || {}, null, 2)}</pre><Text type="secondary">追加工具范围：{(arm.preview?.additional_tool_data_scope || []).join(" ") || "无"}</Text></> }]} />
          </Card>)}
          <ul>{pairPreview.disclosure?.map((line: string) => <li key={line}>{line}</li>)}</ul>
          <Checkbox checked={pairSubmissionApproved} disabled={!pairDisclosureReviewed}
            onChange={(event) => setPairSubmissionApproved(event.target.checked)}>
            我已展开并检查两种调查的完整发送内容和只读工具范围，允许按此预览发送给模型
          </Checkbox>
        </>}
      </Modal>
      <Form.Item name="case_id" label="关联案例（可选）"><Select allowClear placeholder="选择后纳入案例报告导出" options={linkedCases.map((item: any) => ({ value: item.id, label: item.title }))} /></Form.Item>
      <Form.Item name="mode" label="调查方式"><Radio.Group options={[
        { value: "single_shot", label: "模型辅助研判（单轮）" },
        { value: "tool_agent", label: "工具增强调查（固定源码只读）" },
      ]} /></Form.Item>

      <Collapse className="section-gap" items={[{ key: "execution-budget", label: "单次请求设置", children: <Space wrap>
        <Text type="secondary">单次输出额度统一使用系统设置中的智能审计策略。</Text>
      </Space> }]} />
      <Text type="secondary">工具增强调查不设累计 Token、模型/工具调用、总时长或费用上限；每次请求仍受单次输出 Token 设置、上下文长度和 45 秒 Provider 超时约束。工具只读并限定在本次固定候选及扫描源码范围；连续 3 轮没有新增源码证据时会请求总结，用户也可随时取消。实际账单与账户配额由 Provider 决定。</Text>
      <Button className="section-gap" loading={previewBusy} disabled={!ready || !context.job_id || !context.candidate_id}
        onClick={() => void requestPreview()}>预览本次将发送的数据</Button>
      {preview && <Card className="section-gap" size="small" title="外发预览：仅限本次扫描候选">
        <Space direction="vertical" style={{ width: "100%" }}>
          <Descriptions bordered size="small" column={{ xs: 1, md: 2 }}>
            <Descriptions.Item label="目的地">{preview.provider.endpoint_host} · {preview.provider.model}</Descriptions.Item>
            <Descriptions.Item label="方式">{preview.mode === "single_shot" ? "单轮模型研判" : "工具增强只读调查"}</Descriptions.Item>
            <Descriptions.Item label="推理强度">工具调用 {preview.inference_settings?.tool_call_reasoning_effort || "无"}；结构化输出 {preview.inference_settings?.structured_output_reasoning_effort || "服务商默认"}</Descriptions.Item>
            <Descriptions.Item label="结构化修复上限">{preview.budgets?.max_validation_repairs ?? 0} 次；每次按单请求输出上限执行</Descriptions.Item>
            <Descriptions.Item label="Skeptic 请求">{preview.budgets?.max_skeptic_calls ?? 0} 次；与修复调用分别计数</Descriptions.Item>
            <Descriptions.Item label="费用边界">{preview.budget_cost_estimate?.status === "unbounded_local_usage"
              ? "本地无累计费用上限，费用按服务商实际计费与账户额度执行；此信息不是账单或费用预测。"
              : preview.budget_cost_estimate?.status === "budget_based_upper_estimate"
              ? <Space wrap><Text>≤ USD {preview.budget_cost_estimate.maximum_usd}{preview.budget_cost_estimate.maximum_cny ? " / CNY " + preview.budget_cost_estimate.maximum_cny : ""}；{preview.budget_cost_estimate.maximum_cny ? "USD/CNY 为独立官方价目参考；" : ""}按{preview.budget_cost_estimate.basis === "realtime_payg_all_input_uncached" ? "实时按量费率、输入全部按缓存未命中" : "峰值费率、输入全部按缓存未命中"}估算；费率快照 {preview.budget_cost_estimate.rate_card_id}</Text><a href={preview.budget_cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
              : "费用未知（该 Provider / 模型没有匹配的已知费率）"}</Descriptions.Item>
            <Descriptions.Item label="本次扫描来源">{preview.binding.repository} @ {preview.binding.commit}</Descriptions.Item>
            <Descriptions.Item label="候选">{preview.binding.candidate_id}</Descriptions.Item>
            <Descriptions.Item label="文件">{preview.binding.file}</Descriptions.Item>
            <Descriptions.Item label="初始上下文字节">{preview.initial_context_utf8_bytes}</Descriptions.Item>
            <Descriptions.Item label="上下文 SHA-256" span={2}><Text code>{preview.initial_context_sha256}</Text></Descriptions.Item>
            <Descriptions.Item label="授权预览 SHA-256" span={2}><Text code>{preview.consent_sha256}</Text></Descriptions.Item>
          </Descriptions>
          <Alert type="info" showIcon message="独立反证阶段与授权范围"
            description={preview.stage_disclosure} />
          {preview.agent_execution && !preview.agent_execution.eligible && <Alert type="error" showIcon
            message="该候选不适合发送给模型" description={preview.agent_execution.reason} />}
          <Alert type="warning" showIcon message="自动脱敏不是完整 DLP，请检查完整外发预览"
            description={redactionNotice(preview)} />
          <Text strong>将发送的候选上下文</Text>
          <Collapse activeKey={previewDisclosureOpened ? ["initial-context"] : []}
            onChange={(keys) => {
              const opened = Array.isArray(keys) ? keys.includes("initial-context") : keys === "initial-context";
              setPreviewDisclosureOpened(opened);
              if (!opened) form.setFieldValue("source_submission_approved", false);
            }}
            items={[{ key: "initial-context", label: "展开实际发送的元数据、证据义务和源码摘录",
              children: <pre className="raw">{JSON.stringify(preview.initial_context, null, 2)}</pre> }]} />
          {preview.additional_tool_data_scope?.length > 0 && <Alert type="warning" showIcon message="只读调查可能追加发送的数据范围"
            description={<ul>{preview.additional_tool_data_scope.map((item: string) => <li key={item}>{item}</li>)}</ul>} />}
          <Text type="secondary">单轮研判只发送上方初始上下文；工具增强调查的源码或历史输出取决于模型实际请求，并限制在预览列出的提交范围内。案例 ID 和 API Key 不发送给模型。</Text>
        </Space>
      </Card>}
      <Form.Item name="source_submission_approved" valuePropName="checked" rules={[{ validator: (_, value) => value ? Promise.resolve() : Promise.reject(new Error("请检查预览并确认本次源码外发")) }]}>
        <Checkbox disabled={!canApproveSourceSubmission({ ready, preview, disclosureOpened: previewDisclosureOpened })}>我已检查上方预览，并允许本次调查按列出的范围向该模型服务发送数据</Checkbox>
      </Form.Item>
      {preview && !previewDisclosureOpened && <Text type="secondary">请先展开并检查实际发送的完整上下文，授权选项才会启用。</Text>}
      <Alert className="section-gap" type="warning" showIcon message="模型仅给出分诊倾向，不会改变漏洞状态" description="模型可判断倾向真阳性、倾向误报、需更多证据或未知；系统漏洞状态仍保持 candidate。工具只读本次扫描 SHA，不执行任意命令、不跑 PoC、不改案例结论。人工审核仍是必需步骤。" />
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy}
        disabled={!canCreateAgentInvestigation({ ready, jobId: context.job_id, candidateId: context.candidate_id, preview, disclosureOpened: previewDisclosureOpened, approved: sourceSubmissionApproved })}>创建模型调查</Button>
    </Form>
  </Card>;
}

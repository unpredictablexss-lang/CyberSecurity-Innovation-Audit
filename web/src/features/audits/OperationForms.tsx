import React, { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Collapse, Descriptions, Form, Input, InputNumber, Modal, Radio, Select, Space, Tabs, Typography, message } from "antd";
import { api } from "../../api";
import { Hash, go } from "../../components";
import { analysisStatusLabel, coverageStatusLabel, triageStateLabel } from "../workbench/riskLabels.js";
import { auditDefaults, RepositoryField, RefField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import { approvedDetectorIds, datePreviewPayload, operationPayload, recentRange, requestGate } from "./model";
import { canApproveSourceSubmission, canCreateAgentInvestigation, disclosureReviewed, disclosureSelectionMatches, redactionNotice } from "./egressDisclosure.js";
const { Text } = Typography;
export type SourceContext = { job_id?: string; candidate_id?: string; repository_id?: string; case_id?: string };
export type OperationFormProps = { context?: SourceContext; repos: any[]; detectors: any[]; cases: any[]; busy: boolean; submit: (path: string, payload: any) => Promise<void> };
export function ComparisonForm({ kind, repos, detectors, cases, busy, submit, context = {} }: OperationFormProps & { kind: "date" | "branches" | "range" | "matrix" }) {
  const [form] = Form.useForm(); const repository = Form.useWatch("repository_id", form); const auditMode = Form.useWatch("audit_mode", form) || "standard_review";
  const { refs, error: refError } = useRepositoryRefs(repository);
  const [preview, setPreview] = useState<any>(null); const [previewBusy, setPreviewBusy] = useState(false);
  const [error, setError] = useState(""); const gate = useRef(requestGate());
  const [smartPreview, setSmartPreview] = useState<any>(null);
  const [smartApproved, setSmartApproved] = useState(false);
  const [smartBusy, setSmartBusy] = useState(false);
  let ready = false; try { ready = approvedDetectorIds(detectors).length > 0; } catch { /* blocked */ }
  const submitLabel = kind === "date" ? "固定区间并创建任务" : kind === "matrix" ? "创建版本矩阵" : "扫描并比较两个端点";
  const invalidate = () => {
    gate.current.invalidate(); setPreview(null); setPreviewBusy(false); setSmartPreview(null);
    setSmartApproved(false); setSmartBusy(false); setError("");
  };
  return <Card title={kind === "date" ? "时间范围与固定端点" : kind === "matrix" ? "关联案例的版本矩阵" : "选择两个版本"}>
    {kind !== "matrix" && <ScopeAvailability />}
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {refError && <Alert type="warning" message={refError} />}
    <Form name={"audit-" + kind} form={form} layout="vertical" initialValues={{ ...auditDefaults, timezone: "Asia/Shanghai", repository_id: context.repository_id }} onValuesChange={invalidate}
      onFinish={async (values) => {
        try {
          const payload = operationPayload(kind, values, detectors);
          if (payload.auto_triage) {
            if (!smartPreview || !smartApproved) throw new Error("请先查看两个或多个固定版本的模型外发范围并明确授权。");
            payload.triage_approvals = smartPreview.endpoints.map((item: any) => ({
              consent_sha256: item.consent_sha256, consent_nonce: item.consent_nonce,
            }));
          }
          await submit(kind === "date" ? "/operations/date-ranges" : kind === "matrix" ? "/operations/version-matrices" : kind === "range" ? "/operations/revision-ranges" : "/operations/branch-comparisons", payload);
        }
        catch (e) { setError(String(e)); }
      }}>
      <Form.Item name="audit_mode" label="审计方式">
        <Radio.Group>
          <Space direction="vertical">
            <Radio value="static_only">静态扫描：查看代码证据并人工复核</Radio>
            <Radio value="standard_review">智能审计：自动追查源码证据</Radio>
          </Space>
        </Radio.Group>
      </Form.Item>
      <Alert className="section-gap" type="info" showIcon
        message={auditMode === "standard_review" ? "静态扫描后自动 AI 追查（需授权）" : "本次只运行静态扫描"}
        description={auditMode === "standard_review"
          ? "先固定所有比较端点，再核对模型目的地和源码范围并授权；扫描后会自动追查可由源码回答的候选。模型结果仍需人工复核。"
          : "纯静态模式不会调用模型或发送源码。"} />
      <RepositoryField repos={repos} onChange={() => {
        form.setFieldsValue({ branch: undefined, baseline_ref: undefined, endpoint_ref: undefined, baseline: undefined, endpoint: undefined, commits_text: undefined }); invalidate();
      }} />
      {kind === "date" ? <>
        <RefField name="branch" label="分支或标签" refs={refs} />
        <div className="form-shortcuts"><Text type="secondary">快捷时间范围</Text><Space wrap>{[7, 15, 30].map((days) => <Button key={days} onClick={() => { invalidate(); form.setFieldsValue(recentRange(days, form.getFieldValue("timezone") || "Asia/Shanghai")); }}>近 {days} 天</Button>)}</Space></div>
        <Form.Item name="start" label="开始时间（包含）" rules={[{ required: true }]}><Input type="datetime-local" step={1} onInput={(event) => { form.setFieldValue("start", event.currentTarget.value); invalidate(); }} /></Form.Item>
        <Form.Item name="end" label="结束时间（不包含）" rules={[{ required: true }]}><Input type="datetime-local" step={1} onInput={(event) => { form.setFieldValue("end", event.currentTarget.value); invalidate(); }} /></Form.Item>
        <Form.Item name="timezone" label="所选时间的时区" rules={[{ required: true }]}><Select options={["Asia/Shanghai", "UTC", "America/Los_Angeles", "Europe/London"].map((value) => ({ value, label: value }))} /></Form.Item>
        <Alert type="info" message="按提交者时间与 first-parent 选择 [开始, 结束) 区间；当前扫描固定两端。" description="不等于逐提交扫描、合入时间审计或完整增量引擎。预览可能包含拓扑跨度内的区间外提交。" />
        <Button aria-label="预览时间区间" className="section-gap" loading={previewBusy} onClick={async () => {
          const ticket = gate.current.next(); setPreviewBusy(true); setPreview(null); setError("");
          try {
            const values = await form.validateFields(["repository_id", "branch", "start", "end", "timezone"]);
            const result = await api("/operations/date-ranges/preview", datePreviewPayload(values));
            if (gate.current.current(ticket)) setPreview(result);
          } catch (e) { if (gate.current.current(ticket)) setError(String(e)); }
          finally { if (gate.current.current(ticket)) setPreviewBusy(false); }
        }}>预览时间区间</Button>
        {preview && <Alert className="section-gap" type="success" showIcon message={`命中 ${preview.selected_commits.length} 个提交 · 拓扑跨度外 ${preview.intervening_outside_date.length} 个`}
          description={<Space direction="vertical"><Text>{preview.branch} · {preview.timezone} · [{preview.start}, {preview.end})</Text><Space wrap>基线 <Hash value={preview.baseline} /> 终点 <Hash value={preview.endpoint} /></Space>
            <Text type="secondary">预览不创建任务；若 Ref 在提交前移动，最终以入队时固定的 SHA 为准。</Text></Space>} />}
      </> : kind === "branches" ? <><RefField name="baseline_ref" label="基准版本" refs={refs} /><RefField name="endpoint_ref" label="对比版本" refs={refs} />
        <Alert type="info" message="支持分支、Tag、完整 SHA；入队时固定两个端点，不要求祖先关系。" />
      </> : kind === "range" ? <><Form.Item name="baseline" label="Baseline 完整 SHA" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="endpoint" label="Endpoint 完整 SHA" rules={[{ required: true }]}><Input /></Form.Item></> : <>
        <Form.Item name="case_id" label="调查案例" rules={[{ required: true }]}><Select placeholder="案例必须已关联所选仓库的候选" options={cases.map((c) => ({ value: c.id, label: c.title }))} /></Form.Item>
        <Form.Item name="commits_text" label="2–8 个完整 SHA（每行一个或逗号分隔）" rules={[{ required: true }]}><Input.TextArea rows={3} /></Form.Item>
        {!cases.length && <Alert type="info" message="请先从风险候选建立调查案例，再创建版本矩阵。" action={<Button size="small" onClick={() => go("/risks")}>查看风险</Button>} />}
      </>}
      <ScopeBudget /><RuleNotice detectors={detectors} />
      {auditMode === "standard_review" && <div className="section-gap">
        <Button loading={smartBusy} onClick={async () => {
          const ticket = gate.current.next(); setSmartBusy(true); setSmartPreview(null); setSmartApproved(false); setError("");
          try {
            const values = await form.validateFields();
            const payload = operationPayload(kind, values, detectors);
            if (!payload.auto_triage) throw new Error("请先选择智能审计，或直接提交静态扫描。");
            const result = await api("/operations/intelligent-previews", { kind, payload });
            if (gate.current.current(ticket)) setSmartPreview(result);
          } catch (e) { if (gate.current.current(ticket)) setError(String(e)); }
          finally { if (gate.current.current(ticket)) setSmartBusy(false); }
        }}>检查智能审计授权范围</Button>
        {smartPreview && <Card size="small" className="section-gap" title={"智能研判授权确认 · " + smartPreview.endpoint_count + " 个固定版本"}>
          <Alert type="warning" showIcon message="每个固定版本分别授权；模型结果仍是候选"
            description="按服务商按量计费；OHScanner 不设本次累计 Token、请求数或金额上限。实际费用请查看服务商账单；调查可随时取消。" />
          {smartPreview.endpoints.map((item: any, index: number) => <Descriptions key={index} size="small" bordered column={1} className="section-gap">
            <Descriptions.Item label={"固定版本 " + (index + 1)}><Hash value={item.commit} /></Descriptions.Item>
            <Descriptions.Item label="模型目的地">{item.provider?.endpoint_host || "未配置"} · {item.provider?.model || "未知"}</Descriptions.Item>
            <Descriptions.Item label="源码范围">{(item.manifest?.binding?.include_paths || []).join(", ")}</Descriptions.Item>
            <Descriptions.Item label="发送内容">候选摘要、固定源码摘录和证据义务；后续只读追查仍限定在此版本</Descriptions.Item>
          </Descriptions>)}
          <Checkbox checked={smartApproved} onChange={(e) => setSmartApproved(e.target.checked)}>
            我已核对所有版本的来源、模型目的地和发送范围，并授权按量调用模型
          </Checkbox>
        </Card>}
      </div>}
      <Button aria-label={submitLabel} className="section-gap" type="primary" htmlType="submit" size="large" loading={busy} disabled={!ready || !repos.length || (kind === "matrix" && !cases.length) || (auditMode === "standard_review" && (!smartApproved || !smartPreview))}>{auditMode === "standard_review" ? "开始智能审计" : submitLabel}</Button>
    </Form>
  </Card>;
}
export function SyncForm({ busy, submit }: Pick<OperationFormProps, "busy" | "submit">) {
  return <Card title="显式同步源码"><Form name="source-sync" layout="vertical" initialValues={{ timeout_seconds: 900 }} onFinish={(v) => void submit("/operations/source-sync", v)}>
    <Form.Item name="repository" label="OpenHarmony 仓库名" rules={[{ required: true }]}><Input placeholder="openharmony/commonlibrary_c_utils" /></Form.Item>
    <Form.Item name="url" label="HTTPS 地址（GitHub / Gitee / GitCode 的 OpenHarmony 仓库）" rules={[{ required: true }]}><Input placeholder="https://gitee.com/openharmony/commonlibrary_c_utils.git" /></Form.Item>
    <Form.Item name="timeout_seconds" label="同步超时（秒）"><InputNumber min={10} max={3600} /></Form.Item>
    <Alert type="info" message="仅抓取 Git 对象；不构建源码，也不自动开始扫描。来源 allowlist 不等于官方仓库身份已核验。" />
    <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>排队同步</Button>
  </Form></Card>;
}
export function InvestigationForm({ busy, submit, context = {} }: Pick<OperationFormProps, "busy" | "submit" | "context">) {
  return <Card title="启动只读候选调查"><Form name="candidate-investigation" layout="vertical" initialValues={{ max_output_bytes: 65536, job_id: context.job_id, candidate_id: context.candidate_id }} onFinish={(v) => void submit("/operations/investigations", v)}>
    <Form.Item name="job_id" label="已完成扫描任务 ID" rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item name="candidate_id" label="候选 ID" rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item name="max_output_bytes" label="最大输出字节数"><InputNumber min={1024} max={262144} /></Form.Item>
    <Alert type="info" message="只读调查不调用模型" description="当前只读取固定源码摘录、证据义务、Git 历史和符号；如需真实模型辅助，请切换到 LLM Agent 并逐次预览、授权源码外发。该只读步骤不执行任意命令，也不自动确认漏洞。" />
    <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>创建只读调查</Button>
  </Form></Card>;
}
export function ValidationForm({ repos, cases, busy, submit, context = {} }: Omit<OperationFormProps, "detectors">) {
  const target = repos.filter((r) => r.name === "openharmony/inputmethod_imf");
  const support = repos.filter((r) => r.name === "openharmony/commonlibrary_c_utils");
  return <Card title="受控 AUTH-01 验证计划">{context.candidate_id && <Alert className="section-gap" type="info" message={"来源候选 " + context.candidate_id} description="须先关联适用案例。当前仅有固定 AUTH-01 Harness，其他家族尚未接入此验证入口。" action={<Button onClick={() => go("/tasks/" + context.job_id)}>返回来源任务</Button>} />}<Alert type="warning" showIcon message="仅限注册的 Docker Harness；组件复现不等于产品漏洞确认。" description="缺少 Docker daemon 或固定镜像时 Worker 会返回 blocked。当前未提供通用 PoC 上传、任意命令执行或产品确认能力。" />
    <Form name="validation-plan" className="section-gap" layout="vertical" initialValues={{ harness_id: "auth01_descriptor_bypass", repeats: 3 }} onFinish={({ approval, ...payload }) => void submit("/operations/validations", payload)}>
      <Form.Item name="case_id" label="调查案例" rules={[{ required: true }]}><Select options={cases.map((c) => ({ value: c.id, label: c.title }))} /></Form.Item>
      <Form.Item name="harness_id" label="已注册 Harness"><Select options={[{ value: "auth01_descriptor_bypass", label: "AUTH-01 描述符边界" }]} /></Form.Item>
      <Form.Item name="target_repository_id" label="inputmethod_imf 仓库" rules={[{ required: true }]}><Select options={target.map((r) => ({ value: r.id, label: r.path }))} /></Form.Item>
      <Form.Item name="target_commit" label="Harness 固定目标 SHA" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="cutils_repository_id" label="commonlibrary_c_utils 仓库" rules={[{ required: true }]}><Select options={support.map((r) => ({ value: r.id, label: r.path }))} /></Form.Item>
      <Form.Item name="cutils_commit" label="支持源码完整 SHA" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="repeats" label="每个攻击/控制用例重复次数"><InputNumber min={3} max={3} /></Form.Item>
      <Form.Item name="approval" valuePropName="checked" rules={[{ validator: (_, v) => v ? Promise.resolve() : Promise.reject(new Error("请确认审阅验证对象和环境限制")) }]}>
        <Radio>已审阅所选来源与注册 Harness，仅申请受控组件验证</Radio>
      </Form.Item>
      {(!target.length || !support.length || !cases.length) && <Alert type="info" message="需先登记固定目标/支持源码，并关联满足 Harness 要求的案例。" />}
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy} disabled={!target.length || !support.length || !cases.length}>提交隔离验证任务</Button>
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
    agent_source_review_with_human_followup: "Agent 可协助固定源码调查，但仍需人工或动态验证",
    agent_source_review: "可用只读 Agent 收集固定源码线索；仍需人工复核",
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
    content: "将向已配置的模型服务发送一条固定测试文本；请求正文不含仓库、候选或源码，但认证头会携带该服务的 API key。服务商仍可能按其规则计费。",
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
        throw new Error("补读源码与当前候选的固定报告/源码身份不匹配");
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
        "case_id", "max_steps", "max_output_tokens", "max_total_input_tokens",
        "max_total_output_tokens", "timeout_seconds"]);
      if (!values.experiment_id?.trim()) throw new Error("请先填写实验批次 ID");
      const result = await api("/operations/agent-investigations/paired/preview", {
        job_id: values.job_id, candidate_id: values.candidate_id,
        experiment_id: values.experiment_id?.trim(), case_id: values.case_id || undefined,
        max_steps: values.max_steps, max_output_tokens: values.max_output_tokens,
        max_total_input_tokens: values.max_total_input_tokens,
        max_total_output_tokens: values.max_total_output_tokens,
        timeout_seconds: values.timeout_seconds,
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
        max_steps: form.getFieldValue("max_steps"),
        max_output_tokens: form.getFieldValue("max_output_tokens"),
        max_total_input_tokens: form.getFieldValue("max_total_input_tokens"),
        max_total_output_tokens: form.getFieldValue("max_total_output_tokens"),
        timeout_seconds: form.getFieldValue("timeout_seconds"),
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
      const values = await form.validateFields(["job_id", "candidate_id", "experiment_id", "case_id", "mode", "max_steps",
        "max_output_tokens", "max_total_input_tokens", "max_total_output_tokens", "timeout_seconds"]);
      const result = await api("/operations/agent-investigations/preview",
        { ...values, source_submission_approved: false });
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
      <Alert type="info" showIcon message={"目的地：" + agentStatus.endpoint_host + " · 模型：" + agentStatus.model} description="先生成本次外发预览；模型、方式、预算或固定候选变化后，预览与授权都会失效。" />}
    {ready && <Space className="section-gap" wrap>
      <Button loading={providerCheckBusy} onClick={checkProvider}>测试模型服务连通性（无源码）</Button>
      {providerCheckResult && <Text type="secondary">最近通过：{providerCheckResult.endpoint_host} · {providerCheckResult.model} · {providerCheckResult.duration_ms} ms · 输入/输出 Token {providerCheckResult.usage?.input_tokens ?? "未知"}/{providerCheckResult.usage?.output_tokens ?? "未知"}</Text>}
    </Space>}
    {providerCheckError && <Alert className="section-gap" type="error" showIcon message={providerCheckError} />}
    {previewError && <Alert className="section-gap" type="error" showIcon message={previewError} />}
    <Form name="agent-candidate-investigation" form={form} layout="vertical" initialValues={{ mode: "tool_agent", max_steps: 4, max_output_tokens: 1200, max_total_input_tokens: 24000, max_total_output_tokens: 4000, timeout_seconds: 240, job_id: context.job_id, candidate_id: context.candidate_id, case_id: context.case_id }}
      onValuesChange={(changed) => {
        if (!("source_submission_approved" in changed)) invalidatePreview();
        setPairPreview(null); setPairError(""); setPairDisclosureOpened([]); setPairSubmissionApproved(false);
        if ("experiment_id" in changed) setBaselineStatus(null);
      }}
      onFinish={(values) => {
        const { r0_reviewer, r0_disposition, r0_elapsed_seconds, r0_notes, r0_obligation_reviews, r0_obligations_acknowledged, ...agentValues } = values;
        if (!preview) { setPreviewError("请先预览本次外发内容"); return; }
        void submit("/operations/agent-investigations", { ...agentValues, experiment_id: values.experiment_id?.trim() || undefined, consent_sha256: preview.consent_sha256, consent_nonce: preview.consent_nonce });
      }}>
      <Form.Item name="job_id" label="已完成扫描任务 ID" rules={[{ required: true }]}><Input readOnly /></Form.Item>
      <Form.Item name="candidate_id" label="扫描候选 ID" rules={[{ required: true }]}><Input readOnly /></Form.Item>
      <Collapse className="section-gap" items={[{ key: "research-settings", label: "研究实验设置（可选）", children: <>
        <Form.Item name="experiment_id" label="实验批次 ID" extra="仅用于人工基线或模型对照实验；普通单次调查可留空。">
          <Input maxLength={64} placeholder="例如 OH-2026-10-dsoftbus-core-frame" />
        </Form.Item>
        {!experimentId && <Alert className="section-gap" type="warning" showIcon
          message="留空即可进行普通单次调查。填写实验批次后，需先记录人工静态基线才能创建配对实验。" />}
        {experimentId && <Alert className="section-gap" type="info" showIcon
          message={"人工基线将绑定到实验批次：" + experimentId}
          description="请先完成并保存这条固定候选的静态人工审阅，再为同一批次创建模型对照；基线保存后不能补写或改写。" />}
      </> }]} />
      <Card size="small" title="固定扫描候选证据">
        <Alert type="info" showIcon message="这里展示扫描报告、候选信息和绑定源码，供你判断是否需要继续调查；不会展示模型结论。" />
        {staticPreviewBusy && <Text type="secondary">正在读取固定扫描证据……</Text>}
        {staticPreviewError && <Alert className="section-gap" type="error" showIcon message={"静态审阅材料加载失败：" + staticPreviewError} />}
        {staticCandidate && <Descriptions className="section-gap" bordered size="small" column={2}>
          <Descriptions.Item label="仓库 / 固定提交">{staticCandidate.binding?.repository || "未知"} @ {staticCandidate.binding?.commit || "未知"}</Descriptions.Item>
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
            <Text>Agent 可协助的固定源码义务（只收集线索，不作语义判定）：</Text>
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
          <Text strong>固定提交源码片段（第 {staticCandidate.source?.start_line}–{staticCandidate.source?.end_line} 行）</Text>
          {staticReviewReady ? <pre className="raw">{staticExcerpt}</pre> :
            <Alert className="section-gap" type="error" showIcon message="源码 SHA-256 与候选记录不匹配；无法完成可信的人工静态复核。" />}
          {staticCandidate.source?.truncated && <Alert className="section-gap" type="warning" showIcon message="源码预览达到 32 KiB 上限；只显示固定片段的一部分，继续前请在扫描源码页面核对完整上下文。" />}
        </>}
      </Card>
      <Collapse className="section-gap" items={[{ key: "research-baseline", label: "人工静态基线与模型对照（高级研究）", children: <Card size="small" title="人工静态基线">
        <Alert type="info" showIcon message="仅记录静态证据下的人工分诊和耗时，不是漏洞真值。带实验批次运行 R1/R2 前必须先保存该记录；保存后该批次不能再补写 R0。" />
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
          <Text strong>逐项 R0 人工判断（作为 R1/R2 对照基线）</Text>
          {staticCandidate.evidence.obligations_truncated && <Alert className="section-gap" type="warning" showIcon
            message="静态义务超过 40 项；R0 与 Agent 本轮都只处理预览中的前 40 项。" />}
          <Alert className="section-gap" type="warning" showIcon
            message="每条义务必须单独判断；有证据或反向证据时必须引用已展示的固定源码行。无法仅凭现有片段判断时先补读同一文件的固定行范围；仍无法判断就选 unresolved，不要猜测。" />
          <Space wrap className="section-gap" align="end">
            <Form.Item label="补读固定源码起始行"><InputNumber min={1} max={staticCandidate?.source_line_count || 1}
              value={r0SourceStart} onChange={(value) => setR0SourceStart(typeof value === "number" ? value : null)} /></Form.Item>
            <Form.Item label="行数（最多 40）"><InputNumber min={1} max={40}
              value={r0SourceCount} onChange={(value) => setR0SourceCount(typeof value === "number" ? value : 20)} /></Form.Item>
            <Button loading={r0SourceBusy} disabled={!staticReviewReady || !staticCandidate?.source_line_count}
              onClick={() => void loadR0SourceRange()}>读取该固定文件行范围</Button>
          </Space>
          <Text type="secondary">补读只访问扫描报告绑定的同一文件与源码 SHA，不调用 Provider。服务端保存 R0 时会再次核对每条引文的原文和行号。</Text>
          {r0SourceError && <Alert className="section-gap" type="error" showIcon message={r0SourceError} />}
          {r0SourceRanges.map((item) => <Card key={item.start_line + ":" + item.end_line} className="section-gap" size="small"
            title={"已补读固定源码 " + item.file + ":" + item.start_line + "–" + item.end_line}>
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
                      { value: "evidence_found", label: "在固定源码中找到支持证据" },
                      { value: "contrary_evidence", label: "在固定源码中找到反向证据" },
                      { value: "unresolved", label: "当前源码片段无法判断，保持未知" },
                    ]} />
                  </Form.Item>
                  <Space wrap>
                    <Form.Item name={[field.name, "source_line"]} label="原文行号（支持/反向判断必填）"
                      dependencies={[["r0_obligation_reviews", field.name, "disposition"]]}
                      rules={[{ validator: (_, value) => {
                        const disposition = form.getFieldValue(["r0_obligation_reviews", field.name, "disposition"]);
                        return disposition !== "unresolved" && !Number.isInteger(value)
                          ? Promise.reject(new Error("请填写固定源码行号")) : Promise.resolve();
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
            <Checkbox>我已逐条查看上面的固定源码义务，并独立记录判断；无法由当前源码片段判断的项目保留 unresolved。</Checkbox>
          </Form.Item>
        </>}
        {baselineError && <Alert type="error" showIcon message={baselineError} />}
        {baselineStatus && <Alert className="section-gap" type="success" showIcon message={"R0 已记录：" + baselineStatus.disposition + " · 逐项复核 " + (baselineStatus.obligations_reviewed ?? 0) + " 项 · " + baselineStatus.record_sha256} />}
        <Button className="section-gap" loading={baselineBusy} disabled={!experimentId || !context.job_id || !context.candidate_id || !staticReviewReady || staticPreviewBusy}
          onClick={() => void recordBaseline()}>追加 R0 静态基线</Button>
        <Button className="section-gap" loading={pairBusy} disabled={!ready || !experimentId || !context.job_id || !context.candidate_id || !staticReviewReady || staticPreviewBusy || !agentSourceActionable}
          onClick={() => void requestPairPreview()}>预览并创建 R1/R2 配对实验</Button>
        {pairError && <Alert className="section-gap" type="error" showIcon message={pairError} />}
      </Card> }]} />
      <Modal title="R1/R2 配对源码外发预览" open={Boolean(pairPreview)} width={900}
        confirmLoading={pairBusy} okText="批准并原子创建两组任务" cancelText="取消"
        okButtonProps={{ disabled: !pairDisclosureReviewed || !pairSubmissionApproved }}
        onOk={() => void enqueuePair()} onCancel={() => { setPairPreview(null); setPairDisclosureOpened([]); setPairSubmissionApproved(false); }}>
        {pairPreview && <>
          <Alert type="warning" showIcon message="确认后为同一候选创建 R1 单轮和 R2 工具 Agent 两个任务。必须已有同来源 R0；模型结果仍是候选，盲审完成前不要比较哪组更好。" />
          <Descriptions className="section-gap" bordered size="small" column={2}>
            <Descriptions.Item label="实验批次">{pairPreview.experiment_id}</Descriptions.Item>
            <Descriptions.Item label="模型端点">{pairPreview.provider?.endpoint_host} · {pairPreview.provider?.model}</Descriptions.Item>
            <Descriptions.Item label="固定候选" span={2}>{pairPreview.candidate?.repository} @ {pairPreview.candidate?.commit} · {pairPreview.candidate?.candidate_id}</Descriptions.Item>
            <Descriptions.Item label="总模型调用上限">{pairPreview.aggregate_budget?.max_model_calls}</Descriptions.Item>
            <Descriptions.Item label="结构化修复调用上限">{pairPreview.aggregate_budget?.max_validation_repair_calls}</Descriptions.Item>
            <Descriptions.Item label="总输入 Token 上限">{pairPreview.aggregate_budget?.max_total_input_tokens}</Descriptions.Item>
            <Descriptions.Item label="总输出 Token 上限">{pairPreview.aggregate_budget?.max_total_output_tokens}</Descriptions.Item>
            <Descriptions.Item label="顺序执行最坏耗时（秒）">{pairPreview.aggregate_budget?.max_wall_seconds_sequential}</Descriptions.Item>
            <Descriptions.Item label="整组预算费用最高估算（非硬上限）">{pairPreview.aggregate_budget_cost_estimate
              ? <Space wrap><Text>≤ USD {pairPreview.aggregate_budget_cost_estimate.maximum_usd}{pairPreview.aggregate_budget_cost_estimate.maximum_cny ? " / CNY " + pairPreview.aggregate_budget_cost_estimate.maximum_cny : ""}；{pairPreview.aggregate_budget_cost_estimate.candidate_or_arm_count} 个任务；{pairPreview.aggregate_budget_cost_estimate.maximum_cny ? "USD/CNY 为独立官方价目参考；" : ""}按{pairPreview.aggregate_budget_cost_estimate.basis === "realtime_payg_all_input_uncached" ? "实时按量费率、输入全部按缓存未命中" : "峰值费率、输入全部按缓存未命中"}</Text><a href={pairPreview.aggregate_budget_cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
              : "费用未知（该 Provider / 模型没有匹配的已知费率）"}</Descriptions.Item>
          </Descriptions>
          <Text type="secondary">整组预览 SHA-256：{pairPreview.consent_sha256}</Text>
          {pairPreview.arms?.map((arm: any) => <Card key={arm.mode} className="section-gap" size="small" title={arm.mode === "single_shot" ? "R1 单轮模型复核" : "R2 工具型 Agent"}>
            <Text>上下文 UTF-8 字节：{arm.preview?.initial_context_utf8_bytes} · 工具思考：{arm.preview?.inference_settings?.tool_call_reasoning_effort || "无"} · 结构化输出思考：{arm.preview?.inference_settings?.structured_output_reasoning_effort || "服务商默认"} · 单次输出上限：{arm.preview?.budgets?.max_output_tokens} tokens · 源码 SHA-256：{arm.preview?.binding?.source_sha256}</Text>
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
            我已逐组展开并检查 R1、R2 的完整外发上下文与工具范围，允许按此预览向模型发送
          </Checkbox>
        </>}
      </Modal>
      <Form.Item name="case_id" label="关联案例（可选）"><Select allowClear placeholder="选择后纳入案例报告导出" options={linkedCases.map((item: any) => ({ value: item.id, label: item.title }))} /></Form.Item>
      <Form.Item name="mode" label="调查方式"><Radio.Group options={[
        { value: "single_shot", label: "模型辅助研判（单轮）" },
        { value: "tool_agent", label: "工具增强调查（有界只读）" },
      ]} /></Form.Item>

      <Collapse className="section-gap" items={[{ key: "execution-budget", label: "高级设置：调查步数、Token 与超时", children: <Space wrap>
        {mode === "tool_agent" && <Form.Item name="max_steps" label="工具步骤上限"><InputNumber min={1} max={6} /></Form.Item>}
        <Form.Item name="max_output_tokens" label="单次输出 Token 上限"><InputNumber min={128} max={3000} /></Form.Item>
        <Form.Item name="max_total_input_tokens" label="总输入 Token 上限（UTF-8 请求字节预检）"><InputNumber min={1000} max={64000} /></Form.Item>
        <Form.Item name="max_total_output_tokens" label="总输出 Token 上限"><InputNumber min={512} max={12000} /></Form.Item>
        <Form.Item name="timeout_seconds" label="超时（秒）"><InputNumber min={90} max={480} /></Form.Item>
      </Space> }]} />
      <Text type="secondary">默认预算已设上限；生成预览后可查看本次数据范围和费用估算。</Text>
      <Button className="section-gap" loading={previewBusy} disabled={!ready || !context.job_id || !context.candidate_id}
        onClick={() => void requestPreview()}>预览本次将发送的数据</Button>
      {preview && <Card className="section-gap" size="small" title="外发预览：仅限本次固定候选">
        <Space direction="vertical" style={{ width: "100%" }}>
          <Descriptions bordered size="small" column={{ xs: 1, md: 2 }}>
            <Descriptions.Item label="目的地">{preview.provider.endpoint_host} · {preview.provider.model}</Descriptions.Item>
            <Descriptions.Item label="方式">{preview.mode === "single_shot" ? "单轮模型研判" : "工具增强只读调查"}</Descriptions.Item>
            <Descriptions.Item label="推理强度">工具调用 {preview.inference_settings?.tool_call_reasoning_effort || "无"}；结构化输出 {preview.inference_settings?.structured_output_reasoning_effort || "服务商默认"}</Descriptions.Item>
            <Descriptions.Item label="结构化修复上限">{preview.budgets?.max_validation_repairs ?? 0} 次（受总调用、Token 和时限预算约束）</Descriptions.Item>
            <Descriptions.Item label="预算费用暴露估算（非硬上限）">{preview.budget_cost_estimate?.status === "budget_based_upper_estimate"
              ? <Space wrap><Text>≤ USD {preview.budget_cost_estimate.maximum_usd}{preview.budget_cost_estimate.maximum_cny ? " / CNY " + preview.budget_cost_estimate.maximum_cny : ""}；{preview.budget_cost_estimate.maximum_cny ? "USD/CNY 为独立官方价目参考；" : ""}按{preview.budget_cost_estimate.basis === "realtime_payg_all_input_uncached" ? "实时按量费率、输入全部按缓存未命中" : "峰值费率、输入全部按缓存未命中"}估算；费率快照 {preview.budget_cost_estimate.rate_card_id}</Text><a href={preview.budget_cost_estimate.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></Space>
              : "费用未知（该 Provider / 模型没有匹配的已知费率）"}</Descriptions.Item>
            <Descriptions.Item label="固定来源">{preview.binding.repository} @ {preview.binding.commit}</Descriptions.Item>
            <Descriptions.Item label="候选">{preview.binding.candidate_id}</Descriptions.Item>
            <Descriptions.Item label="文件">{preview.binding.file}</Descriptions.Item>
            <Descriptions.Item label="初始上下文字节">{preview.initial_context_utf8_bytes}</Descriptions.Item>
            <Descriptions.Item label="上下文 SHA-256" span={2}><Text code>{preview.initial_context_sha256}</Text></Descriptions.Item>
            <Descriptions.Item label="授权预览 SHA-256" span={2}><Text code>{preview.consent_sha256}</Text></Descriptions.Item>
          </Descriptions>
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
          <Text type="secondary">单轮研判只发送上方初始上下文；工具增强调查的源码或历史输出取决于模型实际请求，并限制在预览列出的固定提交范围内。案例 ID 和 API Key 不发送给模型。</Text>
        </Space>
      </Card>}
      <Form.Item name="source_submission_approved" valuePropName="checked" rules={[{ validator: (_, value) => value ? Promise.resolve() : Promise.reject(new Error("请检查预览并确认本次源码外发")) }]}>
        <Checkbox disabled={!canApproveSourceSubmission({ ready, preview, disclosureOpened: previewDisclosureOpened })}>我已检查上方预览，并允许本次调查按列出的范围向该模型服务发送数据</Checkbox>
      </Form.Item>
      {preview && !previewDisclosureOpened && <Text type="secondary">请先展开并检查实际发送的完整上下文，授权选项才会启用。</Text>}
      <Alert className="section-gap" type="warning" showIcon message="模型仅给出分诊倾向，不会改变漏洞状态" description="模型可判断倾向真阳性、倾向误报、需更多证据或未知；系统漏洞状态仍保持 candidate。工具只读固定扫描 SHA，不执行任意命令、不跑 PoC、不改案例结论。人工审核仍是必需步骤。" />
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy}
        disabled={!canCreateAgentInvestigation({ ready, jobId: context.job_id, candidateId: context.candidate_id, preview, disclosureOpened: previewDisclosureOpened, approved: sourceSubmissionApproved })}>创建模型调查</Button>
    </Form>
  </Card>;
}

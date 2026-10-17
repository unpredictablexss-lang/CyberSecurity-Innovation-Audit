import React, { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Collapse, Descriptions, Form, Input, InputNumber, Radio, Select, Space, Tabs, Typography } from "antd";
import { api } from "../../api";
import { Hash, go } from "../../components";
import { auditDefaults, RepositoryField, RefField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import { approvedDetectorIds, datePreviewPayload, operationPayload, recentRange, requestGate } from "./model";
const { Text } = Typography;
export type SourceContext = { job_id?: string; candidate_id?: string; repository_id?: string; case_id?: string };
export type OperationFormProps = { context?: SourceContext; repos: any[]; detectors: any[]; cases: any[]; busy: boolean; submit: (path: string, payload: any) => Promise<void> };
export function ComparisonForm({ kind, repos, detectors, cases, busy, submit, context = {} }: OperationFormProps & { kind: "date" | "branches" | "range" | "matrix" }) {
  const [form] = Form.useForm(); const repository = Form.useWatch("repository_id", form);
  const { refs, error: refError } = useRepositoryRefs(repository);
  const [preview, setPreview] = useState<any>(null); const [previewBusy, setPreviewBusy] = useState(false);
  const [error, setError] = useState(""); const gate = useRef(requestGate());
  let ready = false; try { ready = approvedDetectorIds(detectors).length > 0; } catch { /* blocked */ }
  const submitLabel = kind === "date" ? "固定区间并创建任务" : kind === "matrix" ? "创建版本矩阵" : "扫描并比较两个端点";
  const invalidate = () => { gate.current.invalidate(); setPreview(null); setPreviewBusy(false); setError(""); };
  return <Card title={kind === "date" ? "时间范围与固定端点" : kind === "matrix" ? "关联案例的版本矩阵" : "选择两个版本"}>
    {kind !== "matrix" && <ScopeAvailability />}
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {refError && <Alert type="warning" message={refError} />}
    <Form name={"audit-" + kind} form={form} layout="vertical" initialValues={{ ...auditDefaults, timezone: "Asia/Shanghai", repository_id: context.repository_id }} onValuesChange={invalidate}
      onFinish={async (values) => {
        try { await submit(kind === "date" ? "/operations/date-ranges" : kind === "matrix" ? "/operations/version-matrices" : kind === "range" ? "/operations/revision-ranges" : "/operations/branch-comparisons", operationPayload(kind, values, detectors)); }
        catch (e) { setError(String(e)); }
      }}>
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
      <Button aria-label={submitLabel} className="section-gap" type="primary" htmlType="submit" size="large" loading={busy} disabled={!ready || !repos.length || (kind === "matrix" && !cases.length)}>{submitLabel}</Button>
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
    <Alert type="info" message="真实模型尚未连接" description="当前调用固定源码摘录、证据义务、Git 历史和符号工具；不执行任意命令，不自动确认漏洞。" />
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
  const mode = Form.useWatch("mode", form) || "tool_agent";
  const experimentId = Form.useWatch("experiment_id", form);
  const [preview, setPreview] = useState<any>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [previewError, setPreviewError] = useState("");
  const [baselineBusy, setBaselineBusy] = useState(false);
  const [baselineStatus, setBaselineStatus] = useState<any>(null);
  const [baselineError, setBaselineError] = useState("");
  const previewGate = useRef(requestGate());
  const ready = Boolean(agentStatus?.configured);
  const linkedCases = cases.filter((item: any) =>
    item.links?.some((link: any) => link.job_id === context.job_id && link.candidate_id === context.candidate_id));
  const invalidatePreview = () => {
    previewGate.current.invalidate(); setPreview(null); setPreviewBusy(false); setPreviewError("");
    form.setFieldValue("source_submission_approved", false);
  };
  useEffect(() => {
    form.setFieldsValue({ job_id: context.job_id, candidate_id: context.candidate_id,
      case_id: context.case_id, source_submission_approved: false,
      r0_reviewer: undefined, r0_disposition: undefined, r0_elapsed_seconds: undefined, r0_notes: undefined });
    invalidatePreview(); setBaselineStatus(null); setBaselineError("");
  }, [context.job_id, context.candidate_id, context.case_id, agentStatus?.model, agentStatus?.endpoint_host]);

  const recordBaseline = async () => {
    setBaselineBusy(true); setBaselineError("");
    try {
      const values = await form.validateFields(["job_id", "candidate_id", "experiment_id",
        "r0_reviewer", "r0_disposition", "r0_elapsed_seconds", "r0_notes"]);
      const result = await api("/agent/baseline-reviews", {
        job_id: values.job_id, candidate_id: values.candidate_id,
        experiment_id: values.experiment_id?.trim(), reviewer: values.r0_reviewer,
        disposition: values.r0_disposition, elapsed_seconds: values.r0_elapsed_seconds,
        notes: values.r0_notes || "",
      });
      setBaselineStatus(result);
    } catch (e) { setBaselineError(String(e)); }
    finally { setBaselineBusy(false); }
  };

  const requestPreview = async () => {
    const ticket = previewGate.current.next(); setPreviewBusy(true); setPreview(null); setPreviewError("");
    try {
      const values = await form.validateFields(["job_id", "candidate_id", "mode", "max_steps",
        "max_output_tokens", "max_total_input_tokens", "max_total_output_tokens", "timeout_seconds"]);
      const result = await api("/operations/agent-investigations/preview",
        { ...values, source_submission_approved: false });
      if (previewGate.current.current(ticket)) {
        setPreview(result); form.setFieldValue("source_submission_approved", false);
      }
    } catch (e) {
      if (previewGate.current.current(ticket)) setPreviewError(String(e));
    } finally {
      if (previewGate.current.current(ticket)) setPreviewBusy(false);
    }
  };
  return <Card title="真实模型 Agent 候选调查">
    {!ready ? <Alert type="warning" showIcon message="模型服务尚未配置" description={agentStatus?.missing?.length ? "Worker 环境缺少：" + agentStatus.missing.join(", ") : "请由服务管理员配置 OHSCANNER_LLM_MODEL 和 OHSCANNER_LLM_API_KEY；密钥不在浏览器或数据库保存。"} /> :
      <Alert type="info" showIcon message={"目的地：" + agentStatus.endpoint_host + " · 模型：" + agentStatus.model} description="先生成本次外发预览；模型、模式、预算或固定候选变化后，预览与授权都会失效。" />}
    {previewError && <Alert className="section-gap" type="error" showIcon message={previewError} />}
    <Form name="agent-candidate-investigation" form={form} layout="vertical" initialValues={{ mode: "tool_agent", max_steps: 4, max_output_tokens: 1200, max_total_input_tokens: 24000, max_total_output_tokens: 4000, timeout_seconds: 240, job_id: context.job_id, candidate_id: context.candidate_id, case_id: context.case_id }}
      onValuesChange={(changed) => {
        if (!("source_submission_approved" in changed)) invalidatePreview();
        if ("experiment_id" in changed) setBaselineStatus(null);
      }}
      onFinish={(values) => {
        const { r0_reviewer, r0_disposition, r0_elapsed_seconds, r0_notes, ...agentValues } = values;
        if (!preview) { setPreviewError("请先预览本次外发内容"); return; }
        void submit("/operations/agent-investigations", { ...agentValues, experiment_id: values.experiment_id?.trim() || undefined, consent_sha256: preview.consent_sha256 });
      }}>
      <Form.Item name="job_id" label="已完成扫描任务 ID" rules={[{ required: true }]}><Input readOnly /></Form.Item>
      <Form.Item name="candidate_id" label="扫描候选 ID" rules={[{ required: true }]}><Input readOnly /></Form.Item>
      <Card size="small" title="R0 静态人工基线（先于模型调查）">
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
        <Form.Item name="r0_notes" label="静态依据和未知项"><Input.TextArea rows={2} maxLength={1200} /></Form.Item>
        {baselineError && <Alert type="error" showIcon message={baselineError} />}
        {baselineStatus && <Alert className="section-gap" type="success" showIcon message={"R0 已记录：" + baselineStatus.disposition + " · " + baselineStatus.record_sha256} />}
        <Button className="section-gap" loading={baselineBusy} disabled={!experimentId || !context.job_id || !context.candidate_id}
          onClick={() => void recordBaseline()}>追加 R0 静态基线</Button>
      </Card>
      <Form.Item name="case_id" label="关联案例（可选）"><Select allowClear placeholder="选择后纳入案例报告导出" options={linkedCases.map((item: any) => ({ value: item.id, label: item.title }))} /></Form.Item>
      <Form.Item name="mode" label="调查方式"><Radio.Group options={[
        { value: "single_shot", label: "单轮模型复核（R1）" },
        { value: "tool_agent", label: "工具型 Agent（R2）" },
      ]} /></Form.Item>
      <Form.Item name="experiment_id" label="实验批次 ID（可选）" extra="同一候选做 R1/R2 配对时，两个任务填写相同 ID；留空则不纳入配对比较。">
        <Input maxLength={64} placeholder="例如 OH-2026-01" />
      </Form.Item>
      <Space wrap>
        {mode === "tool_agent" && <Form.Item name="max_steps" label="工具步骤上限"><InputNumber min={1} max={6} /></Form.Item>}
        <Form.Item name="max_output_tokens" label="单次输出 token 上限"><InputNumber min={128} max={3000} /></Form.Item>
        <Form.Item name="max_total_input_tokens" label="总输入 token 上限（UTF-8 请求字节保守预检）"><InputNumber min={1000} max={64000} /></Form.Item>
        <Form.Item name="max_total_output_tokens" label="总输出 token 上限"><InputNumber min={512} max={12000} /></Form.Item>
        <Form.Item name="timeout_seconds" label="超时（秒）"><InputNumber min={90} max={480} /></Form.Item>
      </Space>
      <Button className="section-gap" loading={previewBusy} disabled={!ready || !context.job_id || !context.candidate_id}
        onClick={() => void requestPreview()}>预览本次将发送的数据</Button>
      {preview && <Card className="section-gap" size="small" title="外发预览：仅限本次固定候选">
        <Space direction="vertical" style={{ width: "100%" }}>
          <Descriptions bordered size="small" column={{ xs: 1, md: 2 }}>
            <Descriptions.Item label="目的地">{preview.provider.endpoint_host} · {preview.provider.model}</Descriptions.Item>
            <Descriptions.Item label="方式">{preview.mode === "single_shot" ? "R1 单轮复核" : "R2 有界工具 Agent"}</Descriptions.Item>
            <Descriptions.Item label="固定来源">{preview.binding.repository} @ {preview.binding.commit}</Descriptions.Item>
            <Descriptions.Item label="候选">{preview.binding.candidate_id}</Descriptions.Item>
            <Descriptions.Item label="文件">{preview.binding.file}</Descriptions.Item>
            <Descriptions.Item label="初始上下文字节">{preview.initial_context_utf8_bytes}</Descriptions.Item>
            <Descriptions.Item label="上下文 SHA-256" span={2}><Text code>{preview.initial_context_sha256}</Text></Descriptions.Item>
            <Descriptions.Item label="授权预览 SHA-256" span={2}><Text code>{preview.consent_sha256}</Text></Descriptions.Item>
          </Descriptions>
          {preview.sensitive_redactions?.length > 0 && <Alert type="warning" showIcon message="检测到凭据样式内容，已在模型外发前自动脱敏" description={"识别类别：" + preview.sensitive_redactions.join("、") + "。预览和上下文哈希对应脱敏后的实际发送内容；脱敏规则不是完整 DLP，仍需人工检查源码。"} />}
          <Text strong>将发送的候选上下文</Text>
          <Collapse items={[{ key: "initial-context", label: "展开实际发送的元数据、证据义务和源码摘录",
            children: <pre className="raw">{JSON.stringify(preview.initial_context, null, 2)}</pre> }]} />
          {preview.additional_tool_data_scope?.length > 0 && <Alert type="warning" showIcon message="R2 后续工具可能追加发送的数据范围"
            description={<ul>{preview.additional_tool_data_scope.map((item: string) => <li key={item}>{item}</li>)}</ul>} />}
          <Text type="secondary">R1 仅发送上方初始上下文；R2 的源码/历史工具输出取决于模型实际请求，并限制在预览列出的固定提交范围内。案例 ID 和 API key 不发送给模型。</Text>
        </Space>
      </Card>}
      <Form.Item name="source_submission_approved" valuePropName="checked" rules={[{ validator: (_, value) => value ? Promise.resolve() : Promise.reject(new Error("请检查预览并确认本次源码外发")) }]}>
        <Checkbox disabled={!ready || !preview}>我已检查上方预览，并允许本次调查按列出的范围向该模型服务发送数据</Checkbox>
      </Form.Item>
      <Alert className="section-gap" type="warning" showIcon message="Agent 给出分诊倾向，不改变漏洞状态" description="模型可判断倾向真阳性、倾向误报、需更多证据或未知；系统漏洞状态仍保持 candidate。工具只读固定扫描 SHA，不执行任意命令、不跑 PoC、不改案例结论。人工审核仍是必需步骤。" />
      <Button className="section-gap" type="primary" htmlType="submit" loading={busy} disabled={!ready || !context.job_id || !context.candidate_id || !preview}>创建 Agent 调查</Button>
    </Form>
  </Card>;
}

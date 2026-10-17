import React, { useRef, useState } from "react";
import { Alert, Button, Card, Form, Input, InputNumber, Radio, Select, Space, Tabs, Typography } from "antd";
import { api } from "../../api";
import { Hash, go } from "../../components";
import { auditDefaults, RepositoryField, RefField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import { approvedDetectorIds, datePreviewPayload, operationPayload, recentRange, requestGate } from "./model";
const { Text } = Typography;
export type OperationFormProps = { repos: any[]; detectors: any[]; cases: any[]; busy: boolean; submit: (path: string, payload: any) => Promise<void> };
export function ComparisonForm({ kind, repos, detectors, cases, busy, submit }: OperationFormProps & { kind: "date" | "branches" | "range" | "matrix" }) {
  const [form] = Form.useForm(); const repository = Form.useWatch("repository_id", form);
  const { refs, error: refError } = useRepositoryRefs(repository);
  const [preview, setPreview] = useState<any>(null); const [previewBusy, setPreviewBusy] = useState(false);
  const [error, setError] = useState(""); const gate = useRef(requestGate());
  let ready = false; try { ready = approvedDetectorIds(detectors).length > 0; } catch { /* blocked */ }
  const invalidate = () => { gate.current.invalidate(); setPreview(null); setPreviewBusy(false); setError(""); };
  return <Card title={kind === "date" ? "时间范围与固定端点" : kind === "matrix" ? "关联案例的版本矩阵" : "选择两个版本"}>
    {kind !== "matrix" && <ScopeAvailability />}
    {error && <Alert className="section-gap" type="error" showIcon message={error} />}
    {refError && <Alert type="warning" message={refError} />}
    <Form form={form} layout="vertical" initialValues={{ ...auditDefaults, timezone: "Asia/Shanghai" }} onValuesChange={invalidate}
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
        <Button className="section-gap" loading={previewBusy} onClick={async () => {
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
      <Button className="section-gap" type="primary" htmlType="submit" size="large" loading={busy} disabled={!ready || !repos.length || (kind === "matrix" && !cases.length)}>{kind === "date" ? "固定区间并创建任务" : kind === "matrix" ? "创建版本矩阵" : "扫描并比较两个端点"}</Button>
    </Form>
  </Card>;
}
export function SyncForm({ busy, submit }: Pick<OperationFormProps, "busy" | "submit">) {
  return <Card title="显式同步源码"><Form layout="vertical" initialValues={{ timeout_seconds: 900 }} onFinish={(v) => void submit("/operations/source-sync", v)}>
    <Form.Item name="repository" label="OpenHarmony 仓库名" rules={[{ required: true }]}><Input placeholder="openharmony/commonlibrary_c_utils" /></Form.Item>
    <Form.Item name="url" label="HTTPS 地址（GitHub / Gitee / GitCode 的 OpenHarmony 仓库）" rules={[{ required: true }]}><Input placeholder="https://gitee.com/openharmony/commonlibrary_c_utils.git" /></Form.Item>
    <Form.Item name="timeout_seconds" label="同步超时（秒）"><InputNumber min={10} max={3600} /></Form.Item>
    <Alert type="info" message="仅抓取 Git 对象；不构建源码，也不自动开始扫描。来源 allowlist 不等于官方仓库身份已核验。" />
    <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>排队同步</Button>
  </Form></Card>;
}
export function InvestigationForm({ busy, submit }: Pick<OperationFormProps, "busy" | "submit">) {
  return <Card title="启动只读候选调查"><Form layout="vertical" initialValues={{ max_output_bytes: 65536 }} onFinish={(v) => void submit("/operations/investigations", v)}>
    <Form.Item name="job_id" label="已完成扫描任务 ID" rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item name="candidate_id" label="候选 ID" rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item name="max_output_bytes" label="最大输出字节数"><InputNumber min={1024} max={262144} /></Form.Item>
    <Alert type="info" message="真实模型尚未连接" description="当前调用固定源码摘录、证据义务、Git 历史和符号工具；不执行任意命令，不自动确认漏洞。" />
    <Button className="section-gap" type="primary" htmlType="submit" loading={busy}>创建只读调查</Button>
  </Form></Card>;
}
export function ValidationForm({ repos, cases, busy, submit }: Omit<OperationFormProps, "detectors">) {
  const target = repos.filter((r) => r.name === "openharmony/inputmethod_imf");
  const support = repos.filter((r) => r.name === "openharmony/commonlibrary_c_utils");
  return <Card title="受控 AUTH-01 验证计划"><Alert type="warning" showIcon message="仅限注册的 Docker Harness；组件复现不等于产品漏洞确认。" description="缺少 Docker daemon 或固定镜像时 Worker 会返回 blocked。当前未提供通用 PoC 上传、任意命令执行或产品确认能力。" />
    <Form className="section-gap" layout="vertical" initialValues={{ harness_id: "auth01_descriptor_bypass", repeats: 3 }} onFinish={({ approval, ...payload }) => void submit("/operations/validations", payload)}>
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

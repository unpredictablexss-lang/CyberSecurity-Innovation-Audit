import React, { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Col, Form, InputNumber, Radio, Row, Space, Typography } from "antd";
import { api } from "../../api";
import { go, Header } from "../../components";
import { approvedDetectorIds, auditErrorMessage, defaultRepositoryRevision, isValidTaskCostBudget, snapshotPayload, planPayload, requestGate, taskAuthorizationPayload } from "./model";
import { AuditProps, auditDefaults, RefField, RepositoryField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import AuditPlanView from "./AuditPlanView";
export default function RepositoryAudit({ repos, detectors, refresh, health }: AuditProps & { health?: any }) {
  const [form] = Form.useForm(); const repository = Form.useWatch("repository_id", form);
  const selectedRevision = Form.useWatch("revision", form);
  const auditMode = Form.useWatch("audit_mode", form) || "standard_review";
  const autoTriage = Form.useWatch("auto_triage", form) === true;
  const maxTriageCandidates = Form.useWatch("max_triage_candidates", form) || 3;
  const autoR2 = Form.useWatch("auto_r2", form) === true;
  const maxR2Candidates = Number(Form.useWatch("max_r2_candidates", form) ?? 2);
  const authorizeAutoTriage = auditMode === "standard_review" && autoTriage;
  const authorizedR2Candidates = authorizeAutoTriage && autoR2 ? Number(maxR2Candidates) : 0;
  const { refs, error: refsError, loading, loadedFor: refsLoadedFor } = useRepositoryRefs(repository);
  const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const [includeSensitiveExposure, setIncludeSensitiveExposure] = useState(false);
  const [includeKnownCves, setIncludeKnownCves] = useState(false);
  const [includeArkRuntime, setIncludeArkRuntime] = useState(false);
  const provider = health?.capabilities?.agent_provider;
  const sensitiveExposureId = "ohscanner.data.sensitive_exposure";
  const knownCvesId = "ohscanner.known_disclosed_cves";
  const arkRuntimeId = "ohscanner.ark.runtime.type_safety";
  const explicitIds = [
    ...(includeSensitiveExposure ? [sensitiveExposureId] : []),
    ...(includeKnownCves ? [knownCvesId] : []),
    ...(includeArkRuntime ? [arkRuntimeId] : []),
  ];
  const [plan, setPlan] = useState<any>(null); const [planning, setPlanning] = useState(false);
  const gate = useRef(requestGate());
  const defaultedRepository = useRef<string | null>(null);
  const invalidate = () => { gate.current.invalidate(); setPlan(null); setPlanning(false); };
  useEffect(() => {
    if (!repository || refsLoadedFor !== repository || defaultedRepository.current === repository) return;
    defaultedRepository.current = repository;
    const suggested = defaultRepositoryRevision(refs);
    if (suggested && !String(form.getFieldValue("revision") || "").trim()) {
      form.setFieldValue("revision", suggested);
    }
  }, [form, refs, refsLoadedFor, repository, selectedRevision]);
  async function preview() {
    const ticket = gate.current.next(); setPlanning(true); setError(""); setPlan(null);
    try { const values = await form.validateFields();
      const result = await api("/audit-plans", {
        ...planPayload(values, detectors, explicitIds),
        ...taskAuthorizationPayload(values),
      });
      if (gate.current.current(ticket)) setPlan(result);
    } catch (e) { if (gate.current.current(ticket)) setError(auditErrorMessage(e)); }
    finally { if (gate.current.current(ticket)) setPlanning(false); }
  }
  let ready = false; try { ready = approvedDetectorIds(detectors, explicitIds).length > 0; } catch { /* blocked */ }
  return <>
    <Header title="智能安全审计" description="选择固定源码后执行静态检测；经明确授权，自动进入证据驱动的 AI 追查工作流。" />
    <Row gutter={24}><Col xs={24} xl={16}><Card title="配置源码审计">
      <ScopeAvailability />
      {auditMode === "standard_review" ? <>
        <Alert className="section-gap" type="info" showIcon
          message="静态检测 + AI 证据追查（无需理解模型内部阶段）"
          description={autoTriage
            ? "确认源码外发与费用预算后，扫描最多自动研判 " + maxTriageCandidates + " 条优先候选。"
              + (authorizedR2Candidates ? "高危且证据不完整的候选中，最多 " + authorizedR2Candidates + " 条会继续跨文件追查。" : "本次不启动跨文件追查。")
              + "未入选候选仍未研判。关闭授权时，扫描只保存静态报告，之后仍可逐批查看实际外发内容再授权。"
            : "扫描本身不会把源码发送给模型。报告保存后，可选择候选，查看固定源码、模型目的地、实际外发内容和预算，再单独同意创建研判任务；未选、未授权或未配置模型时，静态报告仍可使用。"} />
        {provider && !provider.configured && <Alert className="section-gap" type="warning" showIcon
          message="当前未配置模型服务"
          description="静态审计可正常执行；完成后可在“设置 → Agent / LLM”配置服务，再发起需单独授权的模型辅助研判。" />}
        {provider?.configured && <Alert className="section-gap" type="success" showIcon
          message={"已配置模型服务：" + provider.endpoint_host + " · " + provider.model}
          description="配置状态不代表已连通或已授权。默认不外发；可在提交时授权自动智能追查，也可以扫描完成后逐批查看实际披露内容再授权。" />}
      </> : <Alert className="section-gap" type="info" showIcon
        message="本次仅创建静态扫描任务"
        description="不计划模型研判。扫描结果、覆盖限制和证据义务照常保存。" />}
      {error && <Alert className="section-gap" type="error" showIcon message={error} />}
      {refsError && <Alert className="section-gap" type="warning" message={refsError} />}
      <Form name="repository-audit" form={form} layout="vertical" initialValues={{ ...auditDefaults, auto_triage: false, max_triage_candidates: 5, auto_r2: true, max_r2_candidates: 3, max_cost_usd: "5.00" }} onValuesChange={invalidate} onFinish={async (values) => {
        if (!plan?.plan_sha256) { setError("请先预览扫描计划；预览后若修改仓库、版本或范围，需要重新预览。"); return; }
        setBusy(true); setError("");
        try { const job = await api("/scans", {
          ...snapshotPayload(values, detectors, explicitIds),
          expected_plan_sha256: plan.plan_sha256,
          expected_workflow_sha256: plan.workflow_sha256,
          ...taskAuthorizationPayload(values),
          ...(values.audit_mode === "standard_review" && values.auto_triage === true ? {
            expected_triage_consent_sha256: plan.triage_authorization_preview?.consent_sha256,
            triage_consent_nonce: plan.triage_authorization_preview?.consent_nonce,
          } : {}),
        }); await refresh(); go("/tasks/" + job.id); }
        catch (e) { setError(String(e)); } finally { setBusy(false); }
      }}>
        {auditMode === "standard_review" && provider?.configured && <>
          <Form.Item name="auto_triage" valuePropName="checked">
            <Checkbox>本次授权扫描完成后自动运行 AI 证据追查工作流</Checkbox>
          </Form.Item>
          {autoTriage && <>
            <Form.Item name="max_triage_candidates" label="最多自动研判候选数">
              <InputNumber min={1} max={5} precision={0} />
            </Form.Item>
            <Form.Item name="max_cost_usd" label="自动研判费用预算上限（USD）"
              extra="按当前固定官方费率卡的最坏 Token 用量估算；超出预算会在授权前阻止。Provider 实际账单不受本机控制。"
              rules={[{ required: true, message: "请输入本次任务可接受的费用预算上限" },
                { validator: (_, value) => isValidTaskCostBudget(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error("请输入大于 0 的 USD 金额（最多 6 位整数、8 位小数）")) }]}>
              <InputNumber stringMode min="0.00000001" max="999999" step="0.01"
                style={{ width: 240 }} addonBefore="USD" />
            </Form.Item>
            <Form.Item name="auto_r2" valuePropName="checked"
              extra="允许在同一授权源码范围内按需继续深入调查；模型只能使用已审查的只读工具和预算。">
              <Checkbox>授权后允许按证据缺口自动继续跨文件追查</Checkbox>
            </Form.Item>
            {autoR2 && <Form.Item name="max_r2_candidates" label="最多深入追查候选数">
              <InputNumber min={0} max={maxTriageCandidates} precision={0} />
            </Form.Item>}
            {plan?.triage_authorization_preview?.eligible && <Alert className="section-gap" type="warning" showIcon
              message={"任务级源码外发授权预览 · " + plan.triage_authorization_preview.provider.endpoint_host + " · " + plan.triage_authorization_preview.provider.model}
              description={<>
                <div>最多 {plan.triage_authorization_preview.manifest.budgets.max_requests} 次 HTTP 请求（模型请求最多 {plan.triage_authorization_preview.manifest.budgets.r1_max_model_calls + plan.triage_authorization_preview.manifest.budgets.r2_max_model_calls} 次；每次最多重试一次）。</div>
                <div>初步研判每条输入预算不超过 {plan.triage_authorization_preview.manifest.per_candidate_budgets.r1.max_total_input_tokens} tokens、输出不超过 {plan.triage_authorization_preview.manifest.per_candidate_budgets.r1.max_total_output_tokens} tokens。{authorizedR2Candidates ? "跨文件深入追查每条输入预算不超过 " + plan.triage_authorization_preview.manifest.per_candidate_budgets.r2.max_total_input_tokens + " tokens、输出不超过 " + plan.triage_authorization_preview.manifest.per_candidate_budgets.r2.max_total_output_tokens + " tokens。" : ""}</div>
                <div>{plan.triage_authorization_preview.manifest.source_disclosure.join(" ")}</div>
                <div>费用估算：{plan.triage_authorization_preview.estimated_cost?.maximum_usd
                  ? <>USD {plan.triage_authorization_preview.estimated_cost.maximum_usd}{plan.triage_authorization_preview.estimated_cost.maximum_cny ? " / CNY " + plan.triage_authorization_preview.estimated_cost.maximum_cny : ""}；按{plan.triage_authorization_preview.estimated_cost.basis === "realtime_payg_all_input_uncached" ? "实时按量费率、输入全部按缓存未命中" : "峰值费率、输入全部按缓存未命中"}估算；费率快照 {plan.triage_authorization_preview.estimated_cost.rate_card_id} <a href={plan.triage_authorization_preview.estimated_cost.rate_source_url} target="_blank" rel="noreferrer">费率来源</a></>
                  : "当前 Provider 无匹配费率卡，费用未知"}。USD/CNY 是独立官方价目参考，账号实际结算币种和金额以 Provider 账单为准；工作台会按固定费率卡核对本次预算，但不能限制 Provider 账单。</div>
                <div>本次工作台预算封顶：USD {plan.triage_authorization_preview.cost_budget?.maximum_usd}；已按固定费率卡核对最坏估算。Provider 实际账单仍需以服务商账单为准。</div>
              </>} />}
          </>}
        </>}
        <Form.Item name="audit_mode" label="审计方式">
          <Radio.Group>
            <Space direction="vertical">
              <Radio value="standard_review">智能安全审计（标准研判）</Radio>
              <Radio value="static_only">仅静态扫描</Radio>
            </Space>
          </Radio.Group>
        </Form.Item>
        <RepositoryField repos={repos} refresh={refresh} onChange={() => { defaultedRepository.current = null; form.setFieldValue("revision", undefined); setError(""); invalidate(); }} />
        <RefField name="revision" label={loading ? "正在加载当前仓库版本…" : "审计版本"} refs={refs} />
        <ScopeBudget />
        {(detectors.some((d) => d.id === sensitiveExposureId) || detectors.some((d) => d.id === knownCvesId) || detectors.some((d) => d.id === arkRuntimeId)) && <Form.Item label="实验研究规则">
          <Space direction="vertical">
            {detectors.some((d) => d.id === sensitiveExposureId) && <Checkbox checked={includeSensitiveExposure} onChange={(event) => {
              setIncludeSensitiveExposure(event.target.checked); invalidate();
            }}>D 敏感数据进入日志（实验候选规则；partial / blocked 表示未知）</Checkbox>}
            {detectors.some((d) => d.id === knownCvesId) && <Checkbox checked={includeKnownCves} onChange={(event) => {
              setIncludeKnownCves(event.target.checked); invalidate();
            }}>D 已披露 CVE 组件源码规则（显式研究候选；不代表产品受影响）</Checkbox>}
            {detectors.some((d) => d.id === arkRuntimeId) && <Checkbox checked={includeArkRuntime} onChange={(event) => {
              setIncludeArkRuntime(event.target.checked); invalidate();
            }}>C Ark Runtime TypedArray（绑定源码研究候选；默认关闭）</Checkbox>}
          </Space>
        </Form.Item>}
        {includeSensitiveExposure && <Alert className="section-gap" type="info" showIcon
          message="D 规则会随本次固定版本扫描运行"
          description="候选和源码证据会出现在任务详情与 report.json / report.md 中。报告可给出源码级复现步骤和修复建议；静态命中不等于产品漏洞确认，也不会生成可利用产品 PoC。" />}
        {includeKnownCves && <Alert className="section-gap" type="warning" showIcon
          message="已披露 CVE 规则只用于源码候选筛查"
          description="规则不会自动启用。命中表示固定源码包含已知缺陷形态或受影响组件标记；必须另行核对产品构建、可达路径和影响。没有命中、解析不完整或规则未覆盖均不能证明安全。" />}
        {includeArkRuntime && <Alert className="section-gap" type="info" showIcon
          message="Ark Runtime 仅进行绑定源码的研究候选扫描"
          description="只适用于模型登记的仓库、提交和文件 blob；其他版本会保持未分析。partial / blocked 仍表示 unknown，候选不代表产品受影响或漏洞已确认。" />}
        <RuleNotice detectors={detectors} />
        <Button className="section-gap" onClick={() => void preview()} loading={planning} disabled={!ready || busy || !repos.length}>预览审计计划</Button>
        <AuditPlanView plan={plan} auditMode={auditMode} />
        <Button aria-label="冻结版本并开始扫描" className="section-gap" type="primary" htmlType="submit" size="large" loading={busy}
          disabled={!ready || !repos.length || !plan?.plan_sha256 || !plan?.workflow_sha256 ||
            (authorizeAutoTriage && !plan?.triage_authorization_preview?.consent_sha256)}>开始安全审计</Button>
      </Form>
    </Card></Col><Col xs={24} xl={8}><Card title="本次审计将保存">
      <ol className="audit-checklist"><li>完整 Commit 与 Git Tree</li><li>实际规则与版本</li><li>纳入范围、解析及执行覆盖</li><li>候选、证据义务与报告哈希</li></ol>
      <Alert type="warning" showIcon message="执行完成不代表组件安全" description="0 条候选、未分析范围和中断任务都不能证明没有漏洞。" />
      <Typography.Paragraph className="section-gap" type="secondary">当前扫描不执行被审计源码；动态验证必须另走受控验证流程。</Typography.Paragraph>
    </Card></Col></Row>
  </>;
}

import React, { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Col, Form, InputNumber, Radio, Row, Space, Typography } from "antd";
import { api } from "../../api";
import { go, Header } from "../../components";
import { approvedDetectorIds, auditErrorMessage, defaultRepositoryRevision, snapshotPayload, planPayload, requestGate, taskAuthorizationPayload } from "./model";
import { AuditProps, auditDefaults, RefField, RepositoryField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import AuditPlanView from "./AuditPlanView";
export default function RepositoryAudit({ repos, detectors, refresh, health }: AuditProps & { health?: any }) {
  const [form] = Form.useForm(); const repository = Form.useWatch("repository_id", form);
  const selectedRevision = Form.useWatch("revision", form);
  const auditMode = Form.useWatch("audit_mode", form) || "standard_review";
  const authorizeAutoTriage = auditMode === "standard_review";
  const [smartApproved, setSmartApproved] = useState(false);
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
  const invalidate = () => {
    gate.current.invalidate(); setPlan(null); setPlanning(false); setSmartApproved(false);
  };
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
    <Header title="智能安全审计" description="固定仓库版本，先完成静态证据扫描，再由你决定是否授权模型辅助研判。" />
    <Row gutter={24}><Col xs={24} xl={16}><Card title="配置源码审计">
      <ScopeAvailability />
      {auditMode === "standard_review" ? <Alert className="section-gap" type="info" showIcon
        message="智能审计：先静态扫描，再自动追查固定源码证据"
        description="扫描不会在授权前外发源码。预览并确认模型目的地和源码范围后，扫描完成会自动调查可由源码证据回答的候选；无法回答的部分保留为待人工验证。" />
        : <Alert className="section-gap" type="info" showIcon
          message="静态扫描：生成代码证据供人工复核"
          description="仅扫描并保存固定版本的静态证据，不调用模型，也不发送源码。" />}
      {provider && !provider.configured && <Alert className="section-gap" type="warning" showIcon
        message="模型服务尚未配置"
        description="静态扫描仍可使用；选择智能审计前，请在“设置 → Agent / LLM”完成配置。" />}
      {provider?.configured && authorizeAutoTriage && <Alert className="section-gap" type="success" showIcon
        message={"已配置模型服务：" + provider.endpoint_host + " · " + provider.model}
        description="配置状态不代表已经授权。智能审计会在此任务中按量调用模型，实际费用以服务商账单为准。" />}
      {error && <Alert className="section-gap" type="error" showIcon message={error} />}
      {refsError && <Alert className="section-gap" type="warning" message={refsError} />}
      <Form name="repository-audit" form={form} layout="vertical" initialValues={{ ...auditDefaults }} onValuesChange={invalidate} onFinish={async (values) => {
        if (!plan?.plan_sha256) { setError("请先预览扫描计划；预览后若修改仓库、版本或范围，需要重新预览。"); return; }
        if (authorizeAutoTriage && !smartApproved) { setError("请先核对并授权本次源码外发。"); return; }
        setBusy(true); setError("");
        try { const job = await api("/scans", {
          ...snapshotPayload(values, detectors, explicitIds),
          expected_plan_sha256: plan.plan_sha256,
          expected_workflow_sha256: plan.workflow_sha256,
          ...taskAuthorizationPayload(values),
          ...(authorizeAutoTriage ? {
            expected_triage_consent_sha256: plan.triage_authorization_preview?.consent_sha256,
            triage_consent_nonce: plan.triage_authorization_preview?.consent_nonce,
          } : {}),
        }); await refresh(); go("/tasks/" + job.id); }
        catch (e) { setError(String(e)); } finally { setBusy(false); }
      }}>
        <Form.Item name="audit_mode" label="审计方式">
          <Radio.Group>
            <Space direction="vertical">
              <Radio value="static_only">静态扫描：查看代码证据并人工复核</Radio>
              <Radio value="standard_review">智能审计：自动追查源码证据</Radio>
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
        {authorizeAutoTriage && plan?.triage_authorization_preview?.eligible && <Alert className="section-gap" type="warning" showIcon
          message={"智能审计授权确认 · " + plan.triage_authorization_preview.provider.endpoint_host + " · " + plan.triage_authorization_preview.provider.model}
          description={<>
            <div>本次固定版本：<code>{plan.commit}</code></div>
            <div>源码范围：{(plan.triage_authorization_preview.manifest.binding.include_paths || []).join(", ")}</div>
            <div>按服务商按量计费；OHScanner 不设本次累计 Token 或金额上限。实际费用请查看服务商账单。你可以随时取消调查。</div>
            <div>仅在明确授权后发送候选摘要、固定源码摘录及证据义务；自动调查只读已扫描版本。模型结论仍为候选，需人工复核。</div>
            <Checkbox checked={smartApproved} onChange={(event) => setSmartApproved(event.target.checked)}>
              我已核对来源、模型目的地和发送范围，并授权本次智能审计按量调用模型
            </Checkbox>
          </>} />}
        <Button aria-label="冻结版本并开始扫描" className="section-gap" type="primary" htmlType="submit" size="large" loading={busy}
          disabled={!ready || !repos.length || !plan?.plan_sha256 || !plan?.workflow_sha256 ||
            (authorizeAutoTriage && (!plan?.triage_authorization_preview?.consent_sha256 || !smartApproved))}>固定版本并创建审计任务</Button>
      </Form>
    </Card></Col><Col xs={24} xl={8}><Card title="本次审计将保存">
      <ol className="audit-checklist"><li>完整 Commit 与 Git Tree</li><li>实际规则与版本</li><li>纳入范围、解析及执行覆盖</li><li>候选、证据义务与报告哈希</li></ol>
      <Alert type="warning" showIcon message="执行完成不代表组件安全" description="0 条候选、未分析范围和中断任务都不能证明没有漏洞。" />
      <Typography.Paragraph className="section-gap" type="secondary">当前扫描不执行被审计源码；动态验证必须另走受控验证流程。</Typography.Paragraph>
    </Card></Col></Row>
  </>;
}

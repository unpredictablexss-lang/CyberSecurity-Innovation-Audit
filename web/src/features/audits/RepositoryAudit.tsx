import CandidateScope from "./CandidateScope";
import React, { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Collapse, Col, Form, InputNumber, Row, Space, Typography } from "antd";
import { api } from "../../api";
import { go, Header } from "../../components";
import { approvedDetectorIds, defaultRepositoryRevision, snapshotPayload, planPayload, requestGate, taskAuthorizationPayload, selectedAuditModeValues } from "./model";
import { AuditProps, AuditModeSelector, auditDefaults, PolicyBudgetNotice, RefField, RepositoryField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import AuditPlanView from "./AuditPlanView";
import TaskTriageConsentModal from "./TaskTriageConsentModal";

export default function RepositoryAudit({ repos, detectors, refresh, health }: AuditProps & { health?: any }) {
  const [form] = Form.useForm();
  const repository = Form.useWatch("repository_id", form);
  const selectedRevision = Form.useWatch("revision", form);
  const auditMode = Form.useWatch("audit_mode", form) || "static_only";
  const { refs, error: refsError, loading, loadedFor: refsLoadedFor } = useRepositoryRefs(repository);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [plan, setPlan] = useState<any>(null);
  const [consentPreview, setConsentPreview] = useState<any>(null);
  const [consentOpen, setConsentOpen] = useState(false);
  const gate = useRef(requestGate());
  const pendingValues = useRef<any>(null);
  const defaultedRepository = useRef<string | null>(null);
  const provider = health?.capabilities?.agent_provider;
  const invalidate = () => {
    gate.current.invalidate();
    setPlan(null);
    setConsentPreview(null);
    setConsentOpen(false);
    pendingValues.current = null;
    setBusy(false);
  };
  useEffect(() => {
    if (!repository || refsLoadedFor !== repository || defaultedRepository.current === repository) return;
    defaultedRepository.current = repository;
    const suggested = defaultRepositoryRevision(refs);
    if (suggested && !String(form.getFieldValue("revision") || "").trim()) {
      form.setFieldValue("revision", suggested);
    }
  }, [form, refs, refsLoadedFor, repository, selectedRevision]);

  let ready = false;
  try { ready = approvedDetectorIds(detectors).length > 0; } catch { /* blocked */ }

  async function createScan(values: any, planned: any) {
    const authorization = taskAuthorizationPayload(values);
    const job = await api("/scans", {
      ...snapshotPayload(values, detectors),
      expected_plan_sha256: planned.plan_sha256,
      expected_workflow_sha256: planned.workflow_sha256,
      ...authorization,
      ...(authorization.auto_triage ? {
        expected_triage_consent_sha256: consentPreview?.consent_sha256,
        triage_consent_nonce: consentPreview?.consent_nonce,
      } : {}),
    });
    await refresh();
    go("/tasks/" + job.id);
  }

  async function onFinish(rawValues: any) {
    const ticket = gate.current.next();
    setBusy(true);
    setError("");
    try {
      const values = selectedAuditModeValues(rawValues);
      const authorization = taskAuthorizationPayload(values);
      if (authorization.auto_triage && provider?.configured === false) {
        throw new Error("模型服务尚未配置。请先配置模型，或切换到静态审计。");
      }
      const planned = await api("/audit-plans", {
        ...planPayload(values, detectors),
        ...authorization,
      });
      if (!gate.current.current(ticket)) return;
      setPlan(planned);
      if (authorization.auto_triage) {
        const preview = planned.triage_authorization_preview;
        if (!preview?.eligible || !preview?.consent_sha256 || !preview?.consent_nonce) {
          throw new Error(preview?.reason || "服务端没有返回完整的智能审计授权预览，没有创建任务。");
        }
        pendingValues.current = values;
        setConsentPreview(preview);
        setConsentOpen(true);
        return;
      }
      await createScan(values, planned);
    } catch (e) {
      if (gate.current.current(ticket)) setError(String(e));
    } finally {
      if (gate.current.current(ticket)) setBusy(false);
    }
  }

  async function authorizeAndStart() {
    const values = pendingValues.current;
    if (!values || !plan?.plan_sha256 || !consentPreview?.eligible) return;
    setBusy(true);
    setError("");
    try {
      await createScan(values, plan);
    } catch (e) {
      setError(String(e));
      setConsentOpen(false);
      setConsentPreview(null);
    } finally {
      setBusy(false);
    }
  }

  return <>
    <Header title="仓库审计" description="选择已登记仓库和固定版本，再选择静态审计或智能审计。" />
    <Row gutter={24}><Col xs={24} xl={16}><Card title="配置仓库审计">
      <ScopeAvailability />
      {auditMode === "standard_review"
        ? <Alert className="section-gap" type={provider?.configured ? "info" : "warning"} showIcon
            message="智能审计：静态扫描后进行 AI 候选调查"
            description={provider?.configured
              ? "开始前会先展示固定仓库、版本、模型目的地和源码范围。只有你在弹窗中明确同意，扫描完成后才会把限定候选证据发送给模型；模型结论仍需人工复核。"
              : "当前未配置模型服务。可切换为静态审计；配置完成后再使用智能审计。"}
          />
        : <Alert className="section-gap" type="info" showIcon message="静态审计：仅运行本地检测器"
            description="不会调用模型或发送源码。扫描报告保留候选、证据和覆盖情况，供你人工复核。" />}
      {error && <Alert className="section-gap" type="error" showIcon message={error} />}
      {refsError && <Alert className="section-gap" type="warning" message={refsError} />}
      <Form name="repository-audit" form={form}
        layout="vertical"
        initialValues={{ ...auditDefaults, audit_mode: "static_only", auto_triage: false, auto_r2: true }}
        onValuesChange={invalidate}
        onFinish={onFinish}>
        <AuditModeSelector />
        {auditMode === "standard_review" && <PolicyBudgetNotice />}
        <RepositoryField repos={repos} refresh={refresh} onChange={() => {
          defaultedRepository.current = null;
          form.setFieldValue("revision", undefined);
          setError("");
          invalidate();
        }} />
        <RefField name="revision" label={loading ? "正在加载当前仓库版本…" : "审计版本"} refs={refs} />
        <Collapse className="audit-options" items={[{ key: "advanced", label: "高级范围与规则设置", children: <>
          <ScopeBudget />
          {auditMode === "standard_review" && provider?.configured && <>
            <CandidateScope />
            <Form.Item name="auto_r2" valuePropName="checked"
              extra="符合证据条件时，允许模型在固定源码范围内继续只读跨文件追查。">
              <Checkbox>允许深入追查</Checkbox>
            </Form.Item>
          </>}
          <RuleNotice detectors={detectors} />
        </> }]} />
        <Button className="section-gap" type="primary" htmlType="submit" size="large" loading={busy}
          disabled={!ready || busy || !repos.length || (auditMode === "standard_review" && provider?.configured === false)}>
          {auditMode === "standard_review" ? "预览授权并开始智能审计" : "开始静态审计"}
        </Button>
        {plan && <Collapse className="section-gap" items={[{ key: "plan", label: "技术详情：本次固定扫描计划", children:
          <AuditPlanView plan={plan} auditMode={auditMode} />
        }]} />}
      </Form>
    </Card></Col><Col xs={24} xl={8}><Card title="本次审计将保存">
      <ol className="audit-checklist"><li>固定仓库版本和扫描规则</li><li>纳入范围、解析及执行覆盖</li><li>候选、证据义务和报告</li></ol>
      <Alert type="warning" showIcon message="执行完成不代表组件安全" description="0 条候选、未分析范围和中断任务都不能证明没有漏洞。" />
      <Typography.Paragraph className="section-gap" type="secondary">当前扫描不执行被审计源码；动态验证必须另走受控验证流程。</Typography.Paragraph>
    </Card></Col></Row>
    <TaskTriageConsentModal open={consentOpen} preview={consentPreview} loading={busy}
      onCancel={() => { setConsentOpen(false); pendingValues.current = null; setConsentPreview(null); }}
      onConfirm={() => void authorizeAndStart()} />
  </>;
}

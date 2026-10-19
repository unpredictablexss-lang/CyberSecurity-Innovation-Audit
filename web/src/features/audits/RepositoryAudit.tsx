import React, { useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Col, Form, Row, Space, Typography } from "antd";
import { api } from "../../api";
import { go, Header } from "../../components";
import { approvedDetectorIds, snapshotPayload, planPayload, requestGate } from "./model";
import { AuditProps, auditDefaults, RefField, RepositoryField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
import AuditPlanView from "./AuditPlanView";
export default function RepositoryAudit({ repos, detectors, refresh }: AuditProps) {
  const [form] = Form.useForm(); const repository = Form.useWatch("repository_id", form);
  const { refs, error: refsError, loading } = useRepositoryRefs(repository);
  const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const [includeSensitiveExposure, setIncludeSensitiveExposure] = useState(false);
  const [includeKnownCves, setIncludeKnownCves] = useState(false);
  const sensitiveExposureId = "ohscanner.data.sensitive_exposure";
  const knownCvesId = "ohscanner.known_disclosed_cves";
  const explicitIds = [
    ...(includeSensitiveExposure ? [sensitiveExposureId] : []),
    ...(includeKnownCves ? [knownCvesId] : []),
  ];
  const [plan, setPlan] = useState<any>(null); const [planning, setPlanning] = useState(false);
  const gate = useRef(requestGate());
  const invalidate = () => { gate.current.invalidate(); setPlan(null); setPlanning(false); };
  async function preview() {
    const ticket = gate.current.next(); setPlanning(true); setError(""); setPlan(null);
    try { const values = await form.validateFields();
      const result = await api("/audit-plans", planPayload(values, detectors, explicitIds));
      if (gate.current.current(ticket)) setPlan(result);
    } catch (e) { if (gate.current.current(ticket)) setError(String(e)); }
    finally { if (gate.current.current(ticket)) setPlanning(false); }
  }
  let ready = false; try { ready = approvedDetectorIds(detectors, explicitIds).length > 0; } catch { /* blocked */ }
  return <>
    <Header title="仓库安全扫描" description="选择仓库与版本，冻结源码快照，查看真实覆盖和候选证据。" />
    <Row gutter={24}><Col xs={24} xl={16}><Card title="配置源码审计">
      <ScopeAvailability />
      {error && <Alert className="section-gap" type="error" showIcon message={error} />}
      {refsError && <Alert className="section-gap" type="warning" message={refsError} />}
      <Form name="repository-audit" form={form} layout="vertical" initialValues={{ ...auditDefaults }} onValuesChange={invalidate} onFinish={async (values) => {
        setBusy(true); setError("");
        try { const job = await api("/scans", { ...snapshotPayload(values, detectors, explicitIds), ...(plan ? { expected_plan_sha256: plan.plan_sha256 } : {}) }); await refresh(); go("/tasks/" + job.id); }
        catch (e) { setError(String(e)); } finally { setBusy(false); }
      }}>
        <RepositoryField repos={repos} refresh={refresh} onChange={() => { form.setFieldValue("revision", undefined); setError(""); invalidate(); }} />
        <RefField name="revision" label={loading ? "正在加载当前仓库版本…" : "审计版本"} refs={refs} />
        <ScopeBudget />
        {(detectors.some((d) => d.id === sensitiveExposureId) || detectors.some((d) => d.id === knownCvesId)) && <Form.Item label="实验研究规则">
          <Space direction="vertical">
            {detectors.some((d) => d.id === sensitiveExposureId) && <Checkbox checked={includeSensitiveExposure} onChange={(event) => {
              setIncludeSensitiveExposure(event.target.checked); invalidate();
            }}>D 敏感数据进入日志（实验候选规则；partial / blocked 表示未知）</Checkbox>}
            {detectors.some((d) => d.id === knownCvesId) && <Checkbox checked={includeKnownCves} onChange={(event) => {
              setIncludeKnownCves(event.target.checked); invalidate();
            }}>D 已披露 CVE 组件源码规则（显式研究候选；不代表产品受影响）</Checkbox>}
          </Space>
        </Form.Item>}
        {includeSensitiveExposure && <Alert className="section-gap" type="info" showIcon
          message="D 规则会随本次固定版本扫描运行"
          description="候选和源码证据会出现在任务详情与 report.json / report.md 中。报告可给出源码级复现步骤和修复建议；静态命中不等于产品漏洞确认，也不会生成可利用产品 PoC。" />}
        {includeKnownCves && <Alert className="section-gap" type="warning" showIcon
          message="已披露 CVE 规则只用于源码候选筛查"
          description="规则不会自动启用。命中表示固定源码包含已知缺陷形态或受影响组件标记；必须另行核对产品构建、可达路径和影响。没有命中、解析不完整或规则未覆盖均不能证明安全。" />}
        <RuleNotice detectors={detectors} />
        <Button className="section-gap" onClick={() => void preview()} loading={planning} disabled={!ready || busy || !repos.length}>预览适用规则</Button>
        <AuditPlanView plan={plan} />
        <Button aria-label="冻结版本并开始扫描" className="section-gap" type="primary" htmlType="submit" size="large" loading={busy} disabled={!ready || !repos.length}>冻结版本并开始扫描</Button>
      </Form>
    </Card></Col><Col xs={24} xl={8}><Card title="本次审计将保存">
      <ol className="audit-checklist"><li>完整 Commit 与 Git Tree</li><li>实际规则与版本</li><li>纳入范围、解析及执行覆盖</li><li>候选、证据义务与报告哈希</li></ol>
      <Alert type="warning" showIcon message="执行完成不代表组件安全" description="0 条候选、未分析范围和中断任务都不能证明没有漏洞。" />
      <Typography.Paragraph className="section-gap" type="secondary">当前扫描不执行被审计源码；动态验证必须另走受控验证流程。</Typography.Paragraph>
    </Card></Col></Row>
  </>;
}

import React, { useState } from "react";
import { Alert, Button, Card, Col, Form, Row, Space, Typography } from "antd";
import { api } from "../../api";
import { go, Header } from "../../components";
import { approvedDetectorIds, snapshotPayload } from "./model";
import { AuditProps, auditDefaults, RefField, RepositoryField, RuleNotice, ScopeAvailability, ScopeBudget, useRepositoryRefs } from "./AuditFields";
export default function RepositoryAudit({ repos, detectors, refresh }: AuditProps) {
  const [form] = Form.useForm(); const repository = Form.useWatch("repository_id", form);
  const { refs, error: refsError, loading } = useRepositoryRefs(repository);
  const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  let ready = false; try { ready = approvedDetectorIds(detectors).length > 0; } catch { /* blocked */ }
  return <>
    <Header title="仓库安全扫描" description="选择仓库与版本，冻结源码快照，查看真实覆盖和候选证据。" />
    <Row gutter={24}><Col xs={24} xl={16}><Card title="配置源码审计">
      <ScopeAvailability />
      {error && <Alert className="section-gap" type="error" showIcon message={error} />}
      {refsError && <Alert className="section-gap" type="warning" message={refsError} />}
      <Form name="repository-audit" form={form} layout="vertical" initialValues={{ ...auditDefaults }} onFinish={async (values) => {
        setBusy(true); setError("");
        try { const job = await api("/scans", snapshotPayload(values, detectors)); await refresh(); go("/tasks/" + job.id); }
        catch (e) { setError(String(e)); } finally { setBusy(false); }
      }}>
        <RepositoryField repos={repos} refresh={refresh} onChange={() => { form.setFieldValue("revision", undefined); setError(""); }} />
        <RefField name="revision" label={loading ? "正在加载当前仓库版本…" : "审计版本"} refs={refs} />
        <ScopeBudget /><RuleNotice detectors={detectors} />
        <Button aria-label="冻结版本并开始扫描" className="section-gap" type="primary" htmlType="submit" size="large" loading={busy} disabled={!ready || !repos.length}>冻结版本并开始扫描</Button>
      </Form>
    </Card></Col><Col xs={24} xl={8}><Card title="本次审计将保存">
      <ol className="audit-checklist"><li>完整 Commit 与 Git Tree</li><li>实际规则与版本</li><li>纳入范围、解析及执行覆盖</li><li>候选、证据义务与报告哈希</li></ol>
      <Alert type="warning" showIcon message="执行完成不代表组件安全" description="0 条候选、未分析范围和中断任务都不能证明没有漏洞。" />
      <Typography.Paragraph className="section-gap" type="secondary">当前扫描不执行被审计源码；动态验证必须另走受控验证流程。</Typography.Paragraph>
    </Card></Col></Row>
  </>;
}

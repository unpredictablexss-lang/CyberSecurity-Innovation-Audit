import React, { useEffect, useState } from "react";
import { Tag, Typography } from "antd";
import { api } from "../../api";
import { auditProgress, isIntelligentAudit } from "./auditProgress.js";

// Each visible task row follows its own AI work after the scan has ended.
export default function AuditTaskStatus({ job }: { job: any }) {
  const [summary, setSummary] = useState<any>(null);
  const intelligent = isIntelligentAudit(job);
  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setSummary(null);
    if (!intelligent || !job.report_sha256) return;
    async function load() {
      try {
        const result = await api("/scans/" + job.id + "/triage");
        if (!live) return;
        setSummary(result);
        if (auditProgress(job, result).poll) timer = setTimeout(() => void load(), 3000);
      } catch {
        if (!live) return;
        setSummary(null);
        timer = setTimeout(() => void load(), 5000);
      }
    }
    void load();
    return () => { live = false; clearTimeout(timer); };
  }, [job.id, job.report_sha256, job.status, intelligent]);
  const progress = auditProgress(job, summary);
  return <div style={{ minWidth: 270 }}>
    <Tag color={progress.color}>{progress.label}</Tag>
    {progress.phases.map((phase) => <div key={phase.label}>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>{phase.text}</Typography.Text>
    </div>)}
    {intelligent && job.report_sha256 && <div><Typography.Text type="secondary" style={{ fontSize: 12 }}>静态扫描已结束；此处显示整个智能审计进度。</Typography.Text></div>}
  </div>;
}

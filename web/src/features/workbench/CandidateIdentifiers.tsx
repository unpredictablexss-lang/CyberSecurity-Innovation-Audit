import React from "react";
import { Space, Tag } from "antd";

function identifiers(values: unknown[], pattern: RegExp): string[] {
  return [...new Set(values.flatMap((value) => {
    if (Array.isArray(value)) return identifiers(value, pattern);
    return typeof value === "string" ? value.toUpperCase().match(pattern) || [] : [];
  }))];
}

export function candidateSourceKey(item: any): string {
  return JSON.stringify([item.detector_id, item.detector_version, item.rule_id,
    item.file, item.line, item.symbol ?? null, item.source_sha256]);
}

export function reportCandidateIndex(report: any): Map<string, any[]> {
  const index = new Map<string, any[]>();
  for (const run of report?.detector_runs || []) {
    const proofs = new Map<string, any>((report.detector_coverage?.detectors?.[run.tool]?.evidence_obligations || [])
      .map((proof: any) => [proof.diagnostic_id, proof]));
    for (const diagnostic of run.diagnostics || []) {
      const item = { ...diagnostic, detector_id: run.tool, detector_version: run.tool_version,
        risk_assessment: proofs.get(diagnostic.diagnostic_id)?.risk_assessment };
      const key = candidateSourceKey(item);
      index.set(key, [...(index.get(key) || []), item]);
    }
  }
  return index;
}

export default function CandidateIdentifiers({ candidate, related = [] }: { candidate: any; related?: any[] }) {
  const items = [candidate, ...related].filter(Boolean);
  const cwes = identifiers(items.flatMap((item) => [item.candidate_cwe, item.risk_assessment?.cwe]), /\bCWE-\d+\b/g);
  const cves = identifiers(items.flatMap((item) => [item.candidate_cve, item.cve, item.cve_ids,
    item.symbol, item.risk_assessment?.identifier]), /\bCVE-\d{4}-\d{4,}\b/g);
  if (!cwes.length && !cves.length) return null;
  return <Space wrap size={[4, 4]} style={{ marginTop: 6 }} aria-label="CWE / CVE 候选标识">
    {cwes.map((id) => <Tag key={id} color="blue" style={{ marginInlineEnd: 0, fontWeight: 600 }}
      title="报告中的候选弱点类型；不代表漏洞已确认">{id}</Tag>)}
    {cves.map((id) => <Tag key={id} color="purple" style={{ marginInlineEnd: 0, fontWeight: 600 }}
      title="报告中的已披露 CVE 候选映射；产品适用性仍须核验">{id}</Tag>)}
  </Space>;
}

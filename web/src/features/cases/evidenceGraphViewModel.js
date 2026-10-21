const isRecord = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const text = (value) => typeof value === "string" ? value : "";
const integer = (value) => Number.isInteger(value) && value > 0 ? value : null;

const STAGE_LABELS = {
  collect_fixed_source_evidence: "读取固定版本源码",
  primary_source_triage: "AI 初步分析",
  independent_skeptic: "独立反证检查",
  candidate_report_and_poc_draft: "报告与 PoC 草案",
  validate_report: "校验引用与报告",
};

const STATUS_LABELS = {
  completed: "已完成",
  accepted: "已通过结构校验",
  running: "进行中",
  incomplete: "未完成",
  failed: "失败",
  rejected: "未通过校验",
  unknown: "未知",
};

const EDGE_LABELS = {
  validated_citation_reference: "AI 分析引用",
  counterevidence_candidate_reference: "反证检查引用",
  draft_citation_reference: "报告草案引用",
};

function sourceLocation(node) {
  const binding = isRecord(node?.source_binding) ? node.source_binding : {};
  const files = Array.isArray(binding.files) ? binding.files : [];
  return files.filter(isRecord).map((file) => {
    const name = text(file.file);
    if (!name) return null;
    const start = integer(file.start_line);
    const end = integer(file.end_line);
    return {
      file: name,
      line: start,
      endLine: end,
      label: name + (start ? ":" + start + (end && end !== start ? "–" + end : "") : ""),
      status: text(file.binding_status) || "unknown",
    };
  }).filter(Boolean);
}

export function buildEvidenceGraphView(value) {
  if (!isRecord(value)) return null;
  const nodes = Array.isArray(value.nodes) ? value.nodes.filter(isRecord) : [];
  const edges = Array.isArray(value.edges) ? value.edges.filter(isRecord) : [];
  if (!nodes.length && !edges.length) return null;

  const nodeById = new Map(nodes.map((node) => [text(node.id), node]).filter(([id]) => id));
  const stages = nodes.filter((node) => node.node_type === "workflow_stage")
    .sort((left, right) => {
      const order = Object.keys(STAGE_LABELS);
      return order.indexOf(left.stage_id) - order.indexOf(right.stage_id);
    }).map((node) => ({
      id: text(node.stage_id) || text(node.id),
      label: STAGE_LABELS[node.stage_id] || text(node.stage_id) || "调查阶段",
      status: text(node.status) || "unknown",
      statusLabel: STATUS_LABELS[node.status] || "未记录",
      epistemicStatus: text(node.epistemic_status) || "unknown",
    }));

  const evidence = nodes.filter((node) => ["fixed_source_evidence", "context_or_incomplete_evidence"].includes(node.node_type))
    .map((node) => ({
      id: text(node.id),
      evidenceId: text(node.evidence_id),
      kind: text(node.evidence_kind) || "unknown",
      status: text(node.status) || "unknown",
      locations: sourceLocation(node),
    }));
  const evidenceById = new Map(evidence.map((item) => [item.id, item]));
  const citations = edges.filter((edge) => EDGE_LABELS[edge.type]).map((edge) => {
    const target = evidenceById.get(text(edge.target));
    const file = text(edge.file);
    const start = integer(edge.line_start);
    const end = integer(edge.line_end);
    const location = file ? file + (start ? ":" + start + (end && end !== start ? "–" + end : "") : "") :
      target?.locations?.[0]?.label || "固定源码位置未记录";
    const sourceStage = text(edge.source).replace(/^stage:/, "");
    return {
      id: text(edge.edge_id) || [edge.type, edge.source, edge.target, location].join(":"),
      type: text(edge.type),
      label: EDGE_LABELS[edge.type],
      stageLabel: STAGE_LABELS[sourceStage] || sourceStage || "调查阶段",
      evidenceId: target?.evidenceId || "",
      file,
      line: start,
      endLine: end,
      location,
      semanticSupport: text(edge.semantic_support) || "unknown",
    };
  });
  const unresolved = Array.isArray(value.unresolved_references)
    ? value.unresolved_references.filter(isRecord).map((item) => ({
      stageLabel: STAGE_LABELS[item.stage_id] || text(item.stage_id) || "调查阶段",
      file: text(item.file),
      reason: text(item.reason) || "引用未能绑定到固定源码",
    })) : [];
  const binding = isRecord(value.binding) ? value.binding : {};
  const complete = stages.length > 0 && stages.every((stage) => ["completed", "accepted"].includes(stage.status));

  return {
    binding: {
      repository: text(binding.repository),
      commit: text(binding.commit),
      candidateId: text(binding.candidate_id),
    },
    stages,
    evidence,
    citations,
    unresolved,
    complete,
    statusLabel: unresolved.length ? "有引用待核对" : complete ? "调查阶段已完成" : "调查未完整结束",
    boundary: text(value.interpretation_boundary)
      || "来源绑定和引用关系可复核，但不证明引用在语义上支持结论，也不代表产品漏洞已确认。",
    productState: text(value.product_state) || "candidate",
    validatedVulnerability: Number.isInteger(value.validated_vulnerability) ? value.validated_vulnerability : 0,
  };
}

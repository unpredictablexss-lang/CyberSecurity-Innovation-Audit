const FULL_COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const SHA256 = /^[a-f0-9]{64}$/i;
const GIT_OID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;

const text = (value) => typeof value === "string" ? value.trim() : "";
const list = (value) => Array.isArray(value) ? value : [];

const STATUS_LABELS = {
  unknown: "待确认",
  missing: "待补充证据",
  satisfied: "已有支持记录（仍需复核）",
  not_applicable: "待人工确认不适用",
  evidence_found: "已找到线索（尚不代表义务满足）",
  unassessed: "尚未评估",
  pending: "待处理",
  queued: "排队中",
  running: "进行中",
  completed: "已结束",
  completed_with_limitations: "已结束（有未解决限制）",
  blocked: "受阻",
  failed: "失败",
  interrupted: "中断",
  cancelled: "已取消",
};

const KIND_LABELS = {
  reachability: "入口与调用链",
  impact: "潜在安全影响",
  authorization: "权限边界",
  trigger: "触发条件",
  dataflow: "数据流",
  ownership: "对象归属",
  concurrency: "并发条件",
  bounds: "长度与边界",
  "evidence-obligation": "待核实事项",
};

const MISSING_LABELS = {
  repository: "仓库名称",
  "full commit SHA": "完整提交标识",
  "report SHA-256": "扫描报告摘要",
  "candidate ID": "候选标识",
  "candidate file": "候选文件路径",
  "candidate line": "候选代码行",
  "source snapshot SHA-256": "源码快照摘要",
  "Git tree OID": "Git 树对象标识",
  "source Git blob OID": "Git 文件对象标识",
  "candidate source SHA-256": "候选源码摘要",
  "scan profile ID": "扫描配置标识",
  "detector ID": "检测器标识",
  "detector version": "检测器版本",
  "rule ID": "规则标识",
  "rule version": "规则版本",
  "valid source byte range": "源码字节范围",
  "source binding status is not bound": "来源绑定状态",
  "source repository mismatch": "来源记录中的仓库不一致",
  "source commit mismatch": "来源记录中的提交不一致",
  "source file mismatch": "来源记录中的文件不一致",
  "candidate/source-binding SHA-256 mismatch": "候选与来源记录中的源码摘要不一致",
};

function statusLabel(status) {
  const value = text(status).toLowerCase();
  return STATUS_LABELS[value] || "待确认";
}

function sourceLabel(source) {
  const value = text(source);
  if (value === "scanner candidate") return "静态扫描候选";
  if (value.startsWith("matching intelligent investigation operation ")) return "绑定到本候选的智能调查";
  return "来源待确认";
}

function identityStatusLabel(status) {
  if (status === "bound") return "来源字段已记录";
  if (status === "unbound") return "来源字段不完整";
  return "来源状态待确认";
}

function sourceBinding(row = {}) {
  const candidate = row.candidate && typeof row.candidate === "object" ? row.candidate : {};
  const identity = candidate.finding_identity?.source_binding || candidate.source_binding || {};
  const candidateSourceSha = text(candidate.source_sha256);
  const identitySourceSha = text(identity.source_sha256);
  const binding = {
    repository: text(row.repository),
    commit: text(row.commit),
    reportSha256: text(row.report_sha256),
    candidateId: text(candidate.id),
    file: text(candidate.file),
    line: Number.isInteger(candidate.line) && candidate.line > 0 ? candidate.line : null,
    snapshotSha256: text(identity.snapshot_sha256 || candidate.snapshot_sha256 || row.snapshot_sha256),
    treeOid: text(identity.tree_oid || candidate.tree_oid || row.tree_oid),
    sourceBlobOid: text(identity.source_blob_oid || candidate.source_blob_oid),
    sourceSha256: candidateSourceSha || identitySourceSha,
    profileId: text(identity.profile_id || candidate.profile_id || row.profile_id),
    detectorId: text(candidate.detector_id || identity.detector_id),
    detectorVersion: text(candidate.detector_version || identity.detector_version),
    ruleId: text(candidate.rule_id || identity.rule_id),
    ruleVersion: text(candidate.rule_version || identity.rule_version),
    byteStart: Number.isInteger(identity.byte_start) ? identity.byte_start : null,
    byteEnd: Number.isInteger(identity.byte_end) ? identity.byte_end : null,
    identityStatus: text(identity.status) || "unknown",
    identityStatusLabel: identityStatusLabel(text(identity.status)),
    verification: text(identity.verification) || "未记录",
  };
  const missing = [];
  if (!binding.repository) missing.push("repository");
  if (!FULL_COMMIT.test(binding.commit)) missing.push("full commit SHA");
  if (!SHA256.test(binding.reportSha256)) missing.push("report SHA-256");
  if (!binding.candidateId) missing.push("candidate ID");
  if (!binding.file) missing.push("candidate file");
  if (binding.line === null) missing.push("candidate line");
  if (!SHA256.test(binding.snapshotSha256)) missing.push("source snapshot SHA-256");
  if (!GIT_OID.test(binding.treeOid)) missing.push("Git tree OID");
  if (!GIT_OID.test(binding.sourceBlobOid)) missing.push("source Git blob OID");
  if (!SHA256.test(binding.sourceSha256)) missing.push("candidate source SHA-256");
  if (!binding.profileId) missing.push("scan profile ID");
  if (!binding.detectorId) missing.push("detector ID");
  if (!binding.detectorVersion) missing.push("detector version");
  if (!binding.ruleId) missing.push("rule ID");
  if (!binding.ruleVersion) missing.push("rule version");
  if (binding.byteStart === null || binding.byteStart < 0
      || binding.byteEnd === null || binding.byteEnd <= binding.byteStart) {
    missing.push("valid source byte range");
  }
  if (binding.identityStatus !== "bound") missing.push("source binding status is not bound");
  if (identity.repository && identity.repository !== binding.repository) missing.push("source repository mismatch");
  if (identity.commit && identity.commit !== binding.commit) missing.push("source commit mismatch");
  if (identity.file && identity.file !== binding.file) missing.push("source file mismatch");
  if (identitySourceSha && candidateSourceSha && identitySourceSha !== candidateSourceSha) {
    missing.push("candidate/source-binding SHA-256 mismatch");
  }
  return { binding, missing };
}

function operationMatchesCandidate(operation, binding) {
  if (!operation || operation.kind !== "agent_investigation") return false;
  const triage = operation.agent_triage || {};
  const agentBinding = triage.binding || {};
  const context = triage.initial_evidence?.context || {};
  return Boolean(binding.repository && binding.commit && binding.candidateId && binding.file
    && agentBinding.repository === binding.repository
    && agentBinding.commit === binding.commit
    && agentBinding.candidate_id === binding.candidateId
    && agentBinding.file === binding.file
    && (!context.file || context.file === binding.file)
    && (!context.source_sha256 || context.source_sha256 === binding.sourceSha256));
}

function matchingValidationContext(operation, binding) {
  const evidence = operation?.validation_evidence || {};
  return Boolean(operation?.kind === "validation"
    && binding.repository && binding.commit
    && evidence.target_repository === binding.repository
    && evidence.target_commit === binding.commit);
}

function normalizeObligation(item, source, index) {
  if (typeof item === "string" && item.trim()) {
    return { kind: "unknown", kindLabel: "待核实事项", description: item.trim(),
      status: "unknown", statusLabel: statusLabel("unknown"), source, sourceLabel: sourceLabel(source), sourceIndex: index };
  }
  if (!item || typeof item !== "object") return null;
  const description = text(item.description) || text(item.kind);
  if (!description) return null;
  return {
    kind: text(item.kind) || "unknown",
    kindLabel: KIND_LABELS[text(item.kind)] || "待核实事项",
    description,
    status: text(item.status) || "unknown",
    statusLabel: statusLabel(item.status),
    source,
    sourceLabel: sourceLabel(source),
    sourceIndex: index,
  };
}

export function buildPocValidationPlan(candidateRow = {}, operations = []) {
  const candidate = candidateRow.candidate && typeof candidateRow.candidate === "object"
    ? candidateRow.candidate : {};
  const { binding, missing } = sourceBinding(candidateRow);
  const operationRows = list(operations);
  const matchingAgents = operationRows.filter((item) => operationMatchesCandidate(item, binding));
  const validationContext = operationRows.filter((item) => matchingValidationContext(item, binding));

  const obligations = list(candidate.evidence_obligations)
    .map((item, index) => normalizeObligation(item, "scanner candidate", index))
    .filter(Boolean);
  for (const operation of matchingAgents) {
    const agentObligations = list(operation.agent_triage?.initial_evidence?.context?.evidence_obligations);
    agentObligations.forEach((item, index) => {
      const normalized = normalizeObligation(item, `matching intelligent investigation operation ${operation.id || "unknown"}`, index);
      if (normalized) obligations.push(normalized);
    });
  }

  const sourceEvidence = list(candidateRow.source_evidence)
    .filter((item) => item && typeof item === "object" && Boolean(binding.file) && item.file === binding.file)
    .map((item) => ({
      id: text(item.id) || "未记录证据 ID",
      file: text(item.file) || binding.file,
      startLine: Number.isInteger(item.start_line) ? item.start_line : null,
      endLine: Number.isInteger(item.end_line) ? item.end_line : null,
      note: text(item.note) || text(item.observation) || "未记录观察说明",
      kind: text(item.kind) || "人工登记的源码说明",
    }));

  const unknowns = [];
  if (missing.length) unknowns.push("来源记录不完整，尚不能完整核对候选对应的源码对象；可展开“高级来源详情”查看缺项。");
  if (!obligations.length) unknowns.push("还没有记录需要验证的安全前提；请先由人工依据候选源码列出核对事项。");
  if (!sourceEvidence.length) unknowns.push("还没有人工标注的候选源码位置；需要先核对候选位置和周边逻辑。");
  unknowns.push("项目构建目标和所需工具链尚未确认。");
  unknowns.push("测试输入和触发时应观察到的现象尚未确定；本计划不会自动生成测试输入。");
  unknowns.push("尚无绑定到本候选的修复版本与修复前后对照结果。");
  unknowns.push("产品入口是否可达、谁能触发及可能影响，仍需独立核实和人工复核。");

  return {
    title: "验证计划草案（未执行）",
    executionStatus: "not_executed",
    findingState: "候选 / 未知",
    sourceBinding: binding,
    sourceBindingComplete: missing.length === 0,
    bindingMissing: missing,
    bindingMissingLabels: missing.map((field) => MISSING_LABELS[field] || "其他来源字段"),
    obligations,
    sourceEvidence,
    matchingAgentOperationIds: matchingAgents.map((item) => item.id).filter(Boolean),
    validationContext: validationContext.map((operation) => ({
      id: operation.id || "unknown",
      status: text(operation.status) || "unknown",
      statusLabel: statusLabel(operation.status),
      harnessId: text(operation.validation_evidence?.harness_id) || "unknown",
      targetRepository: text(operation.validation_evidence?.target_repository),
      targetCommit: text(operation.validation_evidence?.target_commit),
      candidateBound: false,
    })),
    sections: [
      {
        title: "固定源码与构建",
        detail: missing.length
          ? "先补齐精确仓库、完整提交、报告、候选和文件内容哈希，再只在该固定源码副本中确认项目构建目标与工具链。"
          : `基线固定为 ${binding.repository} @ ${binding.commit}，文件 ${binding.file}:${binding.line}，源码 SHA-256 ${binding.sourceSha256}。在隔离副本中按项目受支持的构建入口确认构建；本计划不包含命令。`,
      },
      {
        title: "输入与安全控制",
        detail: "输入规格仍未知；由人工依据上述证据义务和固定隔离测试环境的已审查清单确定，不在此生成测试输入。使用一次性离线环境、无生产凭据和外部副作用、资源限额，并记录基线/产物哈希。",
      },
      {
        title: "触发与观测",
        detail: "待人工把候选根因映射到可观察的返回值、状态变化或受控副作用；记录每个正向与安全控制用例的预期、实际结果、日志和哈希。具体观测值尚未知。",
      },
      {
        title: "修复前后对照",
        detail: "修复前仅指上方绑定的候选提交。修复提交、补丁身份和后修复观测均未绑定到本候选，因此当前不能声称已修复或已复现；后续必须对两个固定版本使用同一组受审输入和观测标准。",
      },
      {
        title: "成功判据",
        detail: "先验证仓库/提交/文件哈希一致且构建可复现；再由审查者批准正向、负向及修复后控制用例，结果稳定符合预先记录的预期，并保存可审计日志与产物哈希。只有这些组件级结果仍不能单独证明产品入口可达、影响成立或漏洞已确认。",
      },
    ],
    unknowns,
    generatedExecutable: false,
    executed: false,
  };
}

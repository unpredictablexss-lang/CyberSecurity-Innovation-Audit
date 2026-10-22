const scanTerminal = new Set(['completed', 'completed_with_limitations', 'failed', 'blocked', 'cancelled', 'interrupted', 'timed_out']);
const number = (value) => Number.isInteger(value) && value >= 0 ? value : 0;

export function isIntelligentAudit(job) {
  return job?.spec?.audit_mode === 'standard_review' || Boolean(job?.spec?.triage_authorization);
}

function stage(batches, key, label) {
  const rows = batches.map((batch) => batch[key]).filter(Boolean);
  if (!rows.length) return null;
  const sum = (field) => rows.reduce((total, row) => total + number(row[field]), 0);
  const limited = sum('completed_with_limitations_count');
  const phase = { label, total: sum('operation_count'), completed: sum('completed_count') + limited,
    limited, running: sum('running_count'), queued: sum('queued_count'),
    failed: sum('failed_count'), blocked: sum('blocked_count'),
    interrupted: sum('interrupted_count'), cancelled: sum('cancelled_count') };
  phase.text = `${label}：已完成 ${phase.completed}/${phase.total} 条 · 运行中 ${phase.running} 条 · 排队 ${phase.queued} 条 · 失败 ${phase.failed} 条`
    + (phase.limited ? `（完成中 ${phase.limited} 条有限制）` : '')
    + (phase.blocked ? ` · 受阻 ${phase.blocked} 条` : '')
    + (phase.interrupted ? ` · 中断 ${phase.interrupted} 条` : '')
    + (phase.cancelled ? ` · 已停止 ${phase.cancelled} 条` : '');
  return phase;
}

export function auditProgress(job, summary) {
  const intelligent = isIntelligentAudit(job);
  const terminal = scanTerminal.has(job?.status);
  const base = { label: '任务状态未知', color: 'default', poll: !terminal, phases: [], active: false };
  if (!intelligent) {
    const labels = { queued: '等待静态扫描', running: '正在静态扫描', completed: '静态审计完成',
      completed_with_limitations: '静态审计完成（有限制）', failed: '静态扫描失败', blocked: '静态扫描受阻',
      cancelled: '静态扫描已停止', interrupted: '静态扫描中断', timed_out: '静态扫描超时' };
    return { ...base, label: labels[job?.status] || base.label,
      color: !terminal ? 'processing' : job?.status === 'completed' ? 'success' : 'warning' };
  }
  if (!terminal) return { ...base, label: job?.status === 'queued' ? '等待静态扫描' : '正在静态扫描', color: 'processing', active: true };
  if (!job?.report_sha256) return { ...base, label: '静态扫描未完成，AI 未启动', color: 'warning' };
  if (!summary) return { ...base, label: '静态扫描已结束，正在核对 AI 进度', color: 'processing', poll: true };
  const batches = Array.isArray(summary.batches) ? summary.batches : [];
  const phases = [stage(batches, 'r1_progress', '初步分析'), stage(batches, 'r2_progress', '深入追查')].filter(Boolean);
  const state = summary.triage_status || summary.triage_progress?.state || summary.state;
  const progress = summary.triage_progress || {};
  const ongoing = number(progress.pending_count) > 0 || number(progress.queued_count) > 0
    || number(progress.running_count) > 0 || number(progress.r2_waiting_count) > 0
    || phases.some((phase) => phase.running + phase.queued > 0);
  const view = { ...base, phases };
  if (state === 'stopping' || (summary.authorization?.revoked && ongoing)) {
    return { ...view, label: '正在停止 AI 调查', color: 'warning', active: true, poll: true };
  }
  if (ongoing || ['in_progress', 'queued', 'running', 'waiting_for_scan'].includes(state)) {
    const deep = phases.find((phase) => phase.label === '深入追查' && phase.running + phase.queued > 0);
    const initial = phases.find((phase) => phase.label === '初步分析' && phase.running + phase.queued > 0);
    const label = deep ? (deep.running ? '正在深入追查' : '深入追查排队中')
      : initial ? (initial.running ? '正在初步分析' : '初步分析排队中')
        : '正在准备下一步 AI 调查';
    return { ...view, label, color: 'processing', active: true, poll: true };
  }
  const labels = {
    completed: '智能审计完成', completed_with_limitations: '智能审计完成（有限制）',
    partially_completed: 'AI 调查部分完成，请查看未完成项', failed: 'AI 调查失败', timed_out: 'AI 调查超时',
    interrupted: 'AI 调查中断', cancelled: 'AI 调查已停止', stopped: 'AI 调查授权已撤销',
    blocked: 'AI 调查受阻', blocked_authorization_changed: 'AI 授权已变化，调查受阻',
    waiting_for_authorization: '静态扫描已结束，等待 AI 授权',
    no_eligible_candidates: '静态扫描已结束，无可自动分析的候选',
    candidate_limit_exceeded: 'AI 未启动：候选超出上限', queue_limit_exceeded: 'AI 未启动：队列已满',
    not_requested: '静态扫描已结束，未启动 AI 调查',
  };
  return { ...view, label: labels[state] || '静态扫描已结束，AI 状态待核对',
    color: state === 'completed' ? 'success' : 'warning', poll: !labels[state] };
}

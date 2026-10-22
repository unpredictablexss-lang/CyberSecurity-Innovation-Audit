export function batchEligibility(preview) {
  if (!preview) return { eligible: false, blocked: [], reason: '请先生成并检查发送内容预览。' };
  const candidates = Array.isArray(preview.candidates) ? preview.candidates : [];
  const blockedIds = new Set(Array.isArray(preview.blocked_candidate_ids) ? preview.blocked_candidate_ids.map(String) : []);
  const blocked = candidates.filter((item) => blockedIds.has(String(item.candidate_id))
    || item.preview?.agent_execution?.eligible !== true).map((item) => ({
    id: String(item.candidate_id), file: item.file || item.preview?.binding?.file || '',
    reason: item.preview?.agent_execution?.reason || '该候选的源码调查条件尚未通过，请核对证据或转人工/运行时验证。',
  }));
  for (const id of blockedIds) if (!blocked.some((item) => item.id === id)) {
    blocked.push({ id, file: '', reason: '服务端拒绝将该候选发送给模型，请重新核对预览。' });
  }
  const complete = candidates.length > 0 && preview.candidate_count === candidates.length;
  return { eligible: complete && blocked.length === 0, blocked,
    reason: blocked.length ? `本批 ${blocked.length} 条候选暂不能启动 AI 源码调查。请核对下列原因；系统尚未发送本批源码。`
      : !complete ? '候选预览不完整，请重新生成，尚未启动 AI 调查。' : '' };
}

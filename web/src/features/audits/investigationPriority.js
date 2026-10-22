export function topInvestigationGroups(groups, count, limit) {
  if (!Number.isInteger(limit) || limit < 1) return [];
  const wanted = Math.min(Math.max(0, Math.floor(Number(count) || 0)), limit);
  const ids = [], candidates = new Set();
  for (const group of groups || []) {
    const row = group.representative;
    if (!group.auto_select || !row?.eligible || !row.auto_select || candidates.has(row.candidate_id)) continue;
    if (ids.length >= wanted) break;
    candidates.add(row.candidate_id); ids.push(group.group_id);
  }
  return ids;
}

export function selectedInvestigationCandidates(groups, selected, representatives = {}) {
  const selectedSet = new Set(selected);
  const candidates = [];
  for (const group of groups || []) {
    if (!selectedSet.has(group.group_id)) continue;
    const row = group.members.find(item => item.candidate_id === (representatives[group.group_id] || group.representative.candidate_id));
    if (row?.eligible && !candidates.includes(row.candidate_id)) candidates.push(row.candidate_id);
  }
  return candidates;
}

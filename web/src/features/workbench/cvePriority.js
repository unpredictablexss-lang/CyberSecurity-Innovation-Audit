export function disclosedCves(item) {
  const values = [item?.candidate_cve, item?.cve, item?.cve_ids, item?.symbol, item?.risk_assessment?.identifier];
  return [...new Set(values.flat(Infinity).flatMap((value) => typeof value === 'string'
    ? value.toUpperCase().match(/\bCVE-\d{4}-\d{4,}\b/g) || [] : []))];
}

export function prioritizeDisclosedCves(items) {
  // Display priority never changes evidence confidence, severity, or review status.
  return items.map((item, index) => ({ item, index })).sort((a, b) => {
    const confidence = (row) => ({ high_confidence_candidate: 0, further_validation: 1,
      unknown_source_binding: 2, low_priority_manual: 3 })[row.risk_tier] ?? 2;
    const severity = (row) => ({critical: 5, high: 4, medium: 3, low: 2, info: 1})[
      row.risk_presentation?.severity || row.severity] || 0;
    const deprioritized = (row) => row.risk_tier === 'low_priority_manual'
      || ['refuted', 'likely_false_positive'].includes(row.review_status || row.human_review_status) ? 1 : 0;
    return deprioritized(a.item) - deprioritized(b.item) || confidence(a.item) - confidence(b.item)
      || Number(disclosedCves(b.item).length > 0) - Number(disclosedCves(a.item).length > 0)
      || severity(b.item) - severity(a.item) || a.index - b.index;
  }).map(({ item }) => item);
}

export function prioritizeWithRiskEvidence(items, riskItems) {
  const risks = new Map(riskItems.map((row) => [row.candidate_id, row]));
  const views = items.map((item) => {
    const risk = risks.get(item.id || item.candidate_id);
    return { ...item, risk_tier: risk?.risk_tier || item.risk_tier,
      human_review_status: risk?.human_review_status || item.human_review_status, original: item };
  });
  return prioritizeDisclosedCves(views).map(({ original }) => original);
}

export async function loadCandidatePages(request, path) {
  const items = [];
  let first;
  for (let offset = 0; ; offset += 200) {
    const page = await request(`${path}${path.includes('?') ? '&' : '?'}offset=${offset}&limit=200`);
    if (!Array.isArray(page.items) || !Number.isInteger(page.total) || page.total < 0) throw new Error('候选列表数据不完整，请刷新。');
    first ||= page;
    if (page.total !== first.total) throw new Error('候选列表在读取期间发生变化，请刷新。');
    items.push(...page.items);
    if (items.length >= page.total) break;
    if (!page.items.length) throw new Error('候选分页读取中断，未使用不完整列表进行排序。');
  }
  return { ...first, items: prioritizeDisclosedCves(items) };
}

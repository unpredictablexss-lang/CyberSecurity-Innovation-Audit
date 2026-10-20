const COMPLETED = new Set(["completed", "completed_with_limitations"]);
const ARMS = ["single_shot", "tool_agent"];

function fallbackPairKey(spec) {
  const identity = ["job_id", "candidate_id", "source_commit", "report_sha256", "candidate_source_sha256"]
    .map((key) => spec?.[key]);
  if (identity.some((value) => value === undefined || value === null || value === "")) return null;
  return JSON.stringify(identity);
}

export function blindReviewPairs(operations, experimentId) {
  const eligible = (Array.isArray(operations) ? operations : []).filter((item) =>
    item?.kind === "agent_investigation"
    && COMPLETED.has(item.status)
    && Boolean(item.result_sha256)
    && item.spec?.experiment_id === experimentId
    && ARMS.includes(item.spec?.mode));
  const groups = new Map();
  for (const operation of eligible) {
    const spec = operation.spec || {};
    const fallback = fallbackPairKey(spec);
    const identity = spec.pair_id ? `pair:${spec.pair_id}` : fallback && `candidate:${fallback}`;
    if (!identity) continue;
    if (!groups.has(identity)) groups.set(identity, { identity, operations: [] });
    groups.get(identity).operations.push(operation);
  }

  const pairs = [];
  let incompletePairCount = 0;
  let ambiguousPairCount = 0;
  for (const group of groups.values()) {
    const byArm = Object.fromEntries(ARMS.map((arm) => [arm,
      group.operations.filter((operation) => operation.spec.mode === arm)]));
    if (byArm.single_shot.length !== 1 || byArm.tool_agent.length !== 1) {
      if (byArm.single_shot.length > 1 || byArm.tool_agent.length > 1) ambiguousPairCount++;
      else incompletePairCount++;
      continue;
    }
    const operationsByArm = Object.fromEntries(ARMS.map((arm) => [arm, byArm[arm][0]]));
    const spec = operationsByArm.single_shot.spec;
    const candidate = spec.candidate_id || "候选";
    const commit = spec.source_commit || "未知版本";
    pairs.push({
      key: group.identity,
      operationIds: ARMS.map((arm) => operationsByArm[arm].id),
      label: `${candidate.length > 20 ? `${candidate.slice(0, 17)}…` : candidate} · ${commit.slice(0, 12)} · R1/R2 完成`,
    });
  }
  pairs.sort((left, right) => left.label.localeCompare(right.label, "zh-CN"));
  return { eligibleOperationCount: eligible.length, pairs, incompletePairCount, ambiguousPairCount };
}

export function blindReviewOperationIds(pairKeys, pairs) {
  const selected = new Set(Array.isArray(pairKeys) ? pairKeys : []);
  return (Array.isArray(pairs) ? pairs : [])
    .filter((pair) => selected.has(pair.key))
    .flatMap((pair) => pair.operationIds);
}

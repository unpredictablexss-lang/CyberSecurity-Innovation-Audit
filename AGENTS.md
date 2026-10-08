# Project development constraints

Read `docs/architecture_2026.md`, `docs/strategy/team_parallel_multi_scanner_plan.md`,
and `PROGRAM_STATUS.md` before extending the system. The architecture describes
the target system; PROGRAM_STATUS describes implemented capabilities.

- Keep the funnel: candidate discovery -> program analysis -> evidence review ->
  runtime validation -> impact/patch revalidation -> reporting. This branch is
  limited to historical static benchmarks and evidence normalization.
- Providers normalize existing tool output. They do not execute tools or decide
  whether candidates are vulnerabilities. CLI code orchestrates; benchmark
  modules validate and classify; report modules render results.
- Bind benchmark evidence to sample, repository, exact commit, revision, tool,
  scope and source artifact. Do not mix vulnerable/fixed or unrelated runs.
- Missing or failed analysis is unknown; an explicitly evidenced incompatible
  analysis unit is not_applicable. An unexecuted scanner is never a miss.
- Rule matches and file/symbol overlap remain candidates/possible_hit. Structural
  checks do not prove guard dominance, concurrency, attacker control or impact.
- Keep candidate/draft/unassessed defaults. Do not promote findings, compute
  Precision/Recall from this small corpus, or claim zero false positives/negatives.
- Preserve vendor rule provenance/license. Changes to OH rules need positive,
  fixed and unrelated/safe controls; document known limitations.
- Keep generated experiment artifacts and third-party source out of commits.
  Add meaningful regression tests for evidence mixing and report integration.
- Before EVERY push, report in chat: completed changes, verification results,
  remaining limitations, and the commits/branch about to be pushed. Update
  PROGRAM_STATUS with verified facts. Do not mark a draft PR ready or merge it
  without user authorization.

# Project development constraints

Read `docs/architecture_2026.md`, `PROGRAM_STATUS.md`,
`docs/strategy/ohscanner_three_track_master_plan.md`, and
`docs/contracts/ohscanner_detector_contract_v1.md` before extending the system.
For historical-benchmark assumptions also read
`docs/strategy/team_parallel_multi_scanner_plan.md`. Proposed plugin contracts
are not implemented APIs until corresponding code and tests land. The architecture describes
the target system; PROGRAM_STATUS describes implemented capabilities.

- Keep the funnel: candidate discovery -> program analysis -> evidence review ->
  runtime validation -> impact/patch revalidation -> reporting. The historical
  benchmark remains a separate evidence-only module; new OHScanner self-built
  detectors must not silently import vulnerability verdicts or require external
  scanner tools in their production execution path.
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

## Next-stage three-track development rules (2026-10-09)

- Project owner maintains the shared frontend/IR/ScanContext/registry/ToolRunResult bridge, global CLI, CI, triage, and reporting. Teammate A owns self-built C/C++ detector experiments and modules; teammate B owns OpenHarmony WebView/ArkTS/JS/IPC/permission interface experiments and modules. Neither creates a competing full scanner framework.
- A/B develop locally and submit patches/commit details plus artifact hashes for owner review. Only the project owner decides remote push, PR creation and main merge. The existing codex/cutils-component-pilot branch is reference work, not an automatic merge target.
- New self-built detector contracts are specified in docs/contracts/ohscanner_detector_contract_v1.md; because they are **proposed**, implement M0 fake CPP and interface detectors and CI before calling the contract runnable or frozen.
- Keep offline multi-tool experiments under research and separate from production self-built detection. Do not copy third-party tool code/rules without license/provenance and originality review.
- A new detector PR must include pinned positive/fixed/safe examples, independent holdout design, coverage/failed status, method card, a contract-compatible result, deterministic unit tests and reproducible local commands.
- Interfaces cannot reinterpret `completed` as safe or `possible_hit` as confirmed, or label query-style CodeQL output automatically as dataflow; preserve original build/macro/parse scope.

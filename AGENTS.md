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
- Keep candidate/draft/unassessed as the **default** for fresh, unreviewed output.
  Promotion is expected work, not a forbidden act: a finding moves candidate ->
  confirmed -> reportable only by passing the evidence gate below, and the
  evidence level is recorded on the finding. Compute and report Precision/Recall
  (and per-subtype recall / safe-fixed false-positive rate) whenever the labelled
  sample supports it; do not claim zero false positives/negatives without evidence.
  Never inflate a verdict beyond what the recorded evidence shows.
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
- Preserve original build/macro/parse scope: an interface must not reinterpret
  `completed` as safe, nor automatically relabel query-style CodeQL output as
  dataflow. Promoting `possible_hit` to confirmed is allowed only through the
  evidence gate below — never by silently reinterpreting a provider's raw output.

## High-impact, evidence-backed vulnerability policy (2026-10-09)

- **Impact over alert count.** Prioritize demonstrated security-boundary violations, privilege escalation/authorization bypass, sensitive-data exposure, code execution, exploitable memory-safety faults, and serious availability impact. Do not promote standalone version disclosures, public JS/assets, placeholder values, unsubstantiated protocol/config warnings, or generic lint issues as competitive vulnerability discoveries. An otherwise low-signal issue may matter when a concrete exploit chain and impact are established.
- **Real-world root causes first.** Study verifiable OpenHarmony advisories, public real-world vulnerability cases, patch diffs, affected revisions and look-alike vulnerable variants. Require vulnerable/fixed/safe comparison where possible; historical similarity alone is not proof and a new finding does not require an existing CVE.
- **Evidence gate for confirmed/reportable claims.** Bind target repo/commit/scope; identify realistic entry/attacker control or privilege boundary, guard and reachable sensitive operation, necessary exploitation conditions, and concrete confidentiality/integrity/availability impact. Keep unsupported assumptions in EvidenceObligations. AI speculation, CWE labels and warning counts are not validation. A finding IS promoted to confirmed/reportable once this gate is met — record the evidence level on the finding and disclose any remaining static-only limits; do not hold a gate-passing finding back.
- **Research candidates may be broad; final competition/demo claims must be narrow, reproducible and high-value.** Keep low-impact informational candidates separate from confirmed findings; never delete negative results or claim all undisclosed bugs are high severity. See `docs/strategy/ohscanner_three_track_master_plan.md` §0.1.

## Competition deliverables — must produce (2026-10-10)

The competition (第五届中国研究生网络安全创新大赛 · 揭榜挑战 · 第一题：OpenHarmony
开源代码漏洞挖掘) scores nine dimensions: accuracy, completeness, CVE accuracy,
CWE accuracy, PoC quality, branch/version impact accuracy, remediation quality,
tool performance, and innovation. Producing the deliverables below is the
project's goal — earlier constraints that forbade them are **rescinded**.

- **PoC is required.** A confirmed finding must ship a runnable proof-of-concept
  that triggers under a stated build/environment, plus the command and observed
  effect. Family-specific PoC templates live under `src/ohscanner/poc/`.
- **Dynamic validation is required.** In a local, isolated build of the target
  OpenHarmony component, reproduce the candidate with ASan/UBSan/TSan or an
  equivalent harness and record the dynamic evidence. The one standing limit:
  do not attack live/remote production services.
- **CWE and CVE are deliverables.** Every finding carries a CWE; where a public
  identifier exists, map to the CVE/advisory. New (unpublished) findings go
  through the OpenHarmony vulnerability-reward / disclosure process.
- **Impact scope is a deliverable.** Report affected module, affected
  versions/branches (scan across tagged manifests), and the vulnerable/fixed
  commit boundary.
- **Remediation is a deliverable.** Give a concrete fix — ideally a diff — and
  justify it from the guard/effect relation, not from a template.
- **Performance is a deliverable.** Publish scan time and scale on real
  components (files, LOC, wall-clock) so the tool's cost is demonstrable.
- **Reports are a deliverable.** Findings render into a vulnerability report
  (`src/report/vulnerability_report.py`), not only benchmark-style tables.

### Evidence gate (the discipline we KEEP)

Promotion candidate -> confirmed -> reportable requires, at minimum: bound target
repo + exact commit + scope; an identified entry point with realistic attacker
control or privilege boundary; the reachable sensitive operation and the guard
(or its absence); the necessary exploitation conditions; and a concrete
confidentiality/integrity/availability impact. Unproven assumptions stay in
EvidenceObligations; AI speculation, a CWE label, or a warning count alone is not
validation. Misreporting is penalized by the competition, so a finding is only
promoted as far as its recorded evidence supports. See
`docs/strategy/competition_deliverables_plan.md`.

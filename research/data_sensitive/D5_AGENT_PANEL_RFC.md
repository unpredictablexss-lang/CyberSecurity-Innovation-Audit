# D5 D-to-Agent and panel integration RFC

Status: consumer RFC only. This worktree does not alter the shared Runner,
Catalog, persistence schema, Worker, API, or UI. The current D research replay
does not create a public Runner report, so its candidates cannot currently be
enqueued in the platform Agent review batch.

## Current platform boundary

- The D detector is not in the production Catalog and is not auto-selected.
- Public Runner execution withholds a parse-partial file; the D historical
  research adapter runs outside that path and labels the result blocked/partial.
- The platform has candidate assessment and batch queue infrastructure, but a
  missing model provider leaves work queued; no Agent result is fabricated.
- Existing evidence contracts are suitable only if candidate identity remains
  bound to repository, exact commit/tree/blob, file, line, rule/version, and
  source hash. A research replay JSON alone is not a public-run candidate.

## Proposed integration sequence

1. **After M0**, the platform owner may enable D as an explicitly selected,
   disabled-by-default research detector for complete D fixtures and compatible
   exact-source scans. This keeps the Catalog default unchanged.
2. **After a shared partial-evidence admission decision**, let the public
   Runner emit a local candidate only when the D source/function interval is
   hash-bound and its dependencies are reviewed. Preserve file status as
   `partial`; all unanalysed ranges remain visible. If the current contract
   cannot represent this without marking the entire file complete, do not
   enqueue D partial findings.
3. For each public D candidate, pass the complete stable candidate identity
   and fixed-source evidence view to the existing append-only Agent queue.
   Queue every candidate without Top-K truncation. Provider failure, timeout,
   budget exhaustion, invalid citation, or cancellation leaves the candidate
   queued/unknown and never removes the original finding.
4. Store Agent output as an append-only suggestion (`supports_hypothesis`,
   `supports_false_positive`, `unknown`, or `recommend_human_confirmation`)
   with model/provider identity, timestamps, token/latency usage, exact cited
   blob and line range, support/counterevidence, and unresolved obligations.
   The Agent cannot write `confirmed`, `reportable`, or a validated PoC result.
5. In the panel, separate static candidate, Agent suggestion, and human
   disposition. Show blocked/partial/unknown file coverage, queue backlog, and
   model use beside—not collapsed into—the candidate count. Zero candidates
   and unanalyzed regions remain distinct; do not launch second-pass LLM scans
   for those regions by default.
6. Human confirmation remains behind the existing product-entry, impact,
   controlled-validation, and authorization gates. A component Harness or
   Agent recommendation alone cannot satisfy that gate.

## Required owner acceptance checks

- D remains unavailable to one-click scans and auto-selection until M2 is
  separately reviewed.
- Complete-source and partial-source candidates preserve v1/v2 report
  compatibility and stable IDs; old reports load unchanged.
- Queue backpressure never drops candidates; duplicate submission is
  idempotent; exact-source citations reject stale blobs and out-of-range lines.
- Model outage and invalid citations preserve queued/unknown state and static
  findings. Agent proposals cannot invoke a confirmation write path.
- Panel shows static, Agent, human, coverage, backlog, and usage states
  independently and labels D output `research candidate`.

This RFC is a proposed contract, not evidence that D is integrated or available
in the panel. Shared implementation requires the platform owner to accept the
contract and make the shared-path change on the owner-controlled branch.

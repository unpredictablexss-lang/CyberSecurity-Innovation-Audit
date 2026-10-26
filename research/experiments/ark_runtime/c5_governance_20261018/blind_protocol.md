# Independent evaluation blind protocol

**Status: `preparation_only`; not authorized to select, label, execute, reveal, or score cases.**

## 1. Freeze and admission gates

The governance coordinator keeps this protocol in preparation state until C0–C4 are frozen, a frozen Detector/rule version has a source-identity-independent applicability contract that can process genuinely unseen sources, and two eligible reviewers plus an independent adjudicator are confirmed. The readiness audit identifies the current roster as unsuitable; this protocol does not reuse or expand it.

Before any case is selected, freeze a versioned protocol containing scope, label definitions, handling of partial/unknown inputs, source admission and exclusion criteria, review instructions, ID procedure, adjudication rules, access map, and audit events. Record its SHA-256, approvers, effective timestamp, and superseded version in the audit log. Any later change receives a new version and rationale. Once a source is exposed to a reviewer, material protocol changes require a fresh source set and fresh reviewers; never silently amend an in-flight protocol.

Freeze the Detector implementation, rules, configuration, parser/toolchain, applicability contract, and environment before eligible source selection. Record immutable digests and version identifiers. Any tuning or rule change after freeze creates a new Detector version and requires a new protocol run and untouched source families. Preserve tuning history, including unsuccessful and abandoned changes, with timestamp, author, rationale, input evidence IDs, before/after digests, and approval. Never tune against reviewer labels or adjudications.

## 2. Family/source independence and exclusions

The coordinator and a separate auditor reconcile public and authorized internal development/tuning inventories before candidate selection. The public development exposure register in this directory contains known public C1/C2 family identities for conflict screening only. It is not an eligible-source list. Record every known family and source in the future exclusion ledger; unresolved inventory coverage, uncertain family identity, or suspected overlap excludes the whole family and blocks selection until resolved.

Exclude entire root-cause families that overlap development, tuning, examples, detector implementation, reviewer prior exposure, or previous evaluation. Record reason and evidence reference; retain an exclusion event without deleting or reusing the row. Do not infer independence from different paths, repositories, commits, or filenames where root cause may be shared. No purposive probes or old development examples may be called an evaluation sample. Selection method, eligible frame, and random seed/commitment must be frozen and logged before any source is inspected by a reviewer or detector operator.

An inapplicable source, unsupported profile, missing context, parser-partial source, or detector-not-executed result is not a safe result or a miss. Mark the unit `not_applicable`, `unknown_context`, `partial`, or `not_executed` with evidence and reason. It is excluded from binary performance scoring under the frozen protocol but remains in the audit record. If a whole case lacks target behavior, label `unrelated` only when reviewers can establish that from permitted source evidence. If scope cannot be resolved, use `unknown` and do not force a binary label. Replacements must follow the frozen selection procedure and be logged; do not choose a replacement based on a prediction or reviewer label.

## 3. Random IDs and map custody

After the eligible source manifest and exclusion decisions are frozen, the custodian creates cryptographically random, non-sequential case IDs using an approved CSPRNG. IDs must not encode repository, patch family, chronology, source path, label, or prediction. Generate independently per case, check uniqueness, and log the generation tool/version, timestamp, and a digest of the ID list. Do not publish the random seed or mapping.

The identity map (case ID to source identity, family, provenance, and any selection metadata) is encrypted at rest in an admin-only vault with access limited to the named custodian and one designated backup custodian. Two-person approval is required to read or change the map. Every access is logged. Reviewers receive only their own case IDs and source-only packet; filenames, paths, commit IDs, issue names, patch references, directory structure, and metadata that can reveal family or patch direction are removed or replaced with neutral values. Preserve the source hash in the admin manifest, not in the reviewer packet. Hash each packet and reviewer submission after generation without placing the ID map in the reviewer workspace.

Use a one-time randomized mapping for a run. Re-keying after packet issue invalidates the run and requires explicit incident review; never regenerate IDs to hide a recognition event.

## 4. Reviewer qualification and conflict handling

Obtain a signed declaration from each reviewer and the adjudicator before case access using the accompanying form. The coordinator checks disclosure against authorized development/tuning records and records a reasoned `cleared`, `rejected`, or `pending` outcome. Any Detector/rule development or tuning participation, material case-family/patch/source exposure, prediction/result access, other-reviewer-label access, undisclosed relationship, “unsure” answer, or inability to attest means `pending` or `rejected` until independently resolved. If material exposure is established, replace the person before access; do not turn that person into an exclusion reason for a source.

If a reviewer recognizes a case after opening it, they must stop immediately and disclose the recognition. The coordinator quarantines that submission, records the event, and replaces the reviewer. If any label or prediction was discussed or leaked, stop the run and assess whether the entire affected family/run must be invalidated. A reviewer cannot be both one of the two labelers and the adjudicator.

## 5. Prediction escrow and role separation

The prediction author operates only the frozen Detector against the frozen eligible source manifest after source freeze. The author sees source identities needed to execute but receives no reviewer identities, labels, notes, or adjudications. Predictions are written directly to encrypted escrow under a distinct service account. Before labels are frozen, only the escrow writer may write; no person involved in labeling, adjudication, or protocol audit may read the payload. The writer records a signed digest, execution timestamp, Detector/configuration digest, input-manifest digest, and execution log, then relinquishes access. The escrow key is held by a separate custodian; read access requires the governance coordinator and independent auditor jointly to attest that label adjudication is frozen.

The prediction author cannot label or adjudicate. Reviewers and adjudicator cannot access prediction escrow. No prediction, summary, count, score, log line, or detector candidate is shown to reviewers before final adjudication and label freeze. If role separation cannot be maintained, stop; do not substitute a verbal promise.

## 6. Independent annotation and adjudication

Two cleared reviewers receive separate source-only packets and the frozen rubric. They independently label each unit without communicating or sharing work. For each case, each records exactly one primary label: `vulnerable`, `fixed`, `safe`, `unrelated`, or `unknown`; an applicability/context status; source evidence with line/range; concise reasoning; confidence; and any recognition/recusal flag. A label must be based on the source revision and permitted context, not patch provenance, test names alone, issue titles, Detector behavior, or another reviewer's view. A `fixed` label requires evidence of the target root cause and its correction. `safe` requires evidence the in-scope behavior lacks the target root cause under the stated conditions. `unknown` is required when evidence is insufficient. A partial parse is disclosed and ordinarily remains unknown unless independent source evidence resolves it under the frozen rubric.

Each reviewer signs and submits their own form. The custodian timestamps and SHA-256 freezes each submission before comparing labels. Late edits create a new version, preserve the prior hash, and require a logged reason; no edits are permitted after comparison except through adjudication.

Any label mismatch, applicability mismatch, or unresolved evidence conflict goes to the independent adjudicator. The adjudicator sees only the disputed source-only packet, two blinded submissions under separate reviewer codes, and the rubric. They do not see predictions, Detector/rules, reviewer identities, family IDs, or patch direction. They record the disagreement, evidence for each position, final label and applicability state, rationale, any unresolved uncertainty, signature, and timestamp. The final label may remain `unknown`; adjudication does not require forced consensus. Freeze the adjudication ledger and its digest before prediction reveal. If the adjudicator has any conflict, use a newly qualified third party or stop; do not let the coordinator choose a verdict.

## 7. Audit log and integrity

Maintain an append-only, access-controlled event log. Each event records UTC timestamp, actor and role, action, object identifier, protocol version, prior/new digest where relevant, reason, approval references, and outcome. Required events include protocol freeze/change, role qualification and conflict decisions, family/source inventory reconciliation, exclusions, candidate-frame and selection commitment, source manifest freeze, random-ID generation and map access, packet creation/access, reviewer start/submit/recusal, submission freeze, adjudication, prediction execution/escrow seal/reveal, incident, replacement, and run termination. Hash-chain or sign log exports and retain an offline copy. Never place prediction values or hidden labels in general logs; log object digests and access events only.

At every stage, capture artifact digests and verify that labeler workspaces contain no prediction-related files and that prediction-author workspaces contain no labels. Access-control audit and workspace inventory must pass before a run advances.

## 8. Reveal, stop, and exit conditions

Only after the two submissions and all adjudications are frozen, all exclusions/inapplicability reasons are resolved, and the auditor confirms the log and access separation, may the coordinator and independent auditor jointly authorize escrow reveal. Record both approvals and the reveal timestamp. Any future scoring must be a separate, explicitly authorized step gated by the frozen scoring protocol; nothing in this preparation directory is scoreable.

Stop and quarantine affected artifacts on: accidental prediction or label disclosure; unauthorized access; source or protocol digest mismatch; reviewer recognition or undisclosed conflict; incomplete family history; changed Detector/configuration after freeze; unlogged tuning; broken random-ID map custody; inability to establish applicability; missing or altered submissions; or loss of audit-log integrity. Preserve evidence and access logs. The coordinator and independent auditor decide whether a reviewer, case, family, or entire run is invalid. Never repair a compromised blind by relabeling the same exposed source as fresh.

Exit a future run without performance results if there is no eligible unseen source family, fewer than two qualified reviewers plus an independent adjudicator, unresolved independence, no applicable cases, missing reviewer evidence, unresolved major disagreement, failed integrity checks, or a broken role boundary. Report the run as blocked/not estimable and preserve the reason. Do not compute TP/FP/FN, precision, or recall unless separately authorized scoring gates are satisfied on appropriate independent labelled data.

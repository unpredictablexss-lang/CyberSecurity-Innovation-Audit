# C5 independent-evaluation governance preparation

**Status: `preparation_only`**
**Samples admitted: 0**
**Labels: 0**
**Predictions generated or opened: 0**
**Scores: none**

This directory contains governance materials for a possible future independent assessment of the Ark Runtime detector. It is not an evaluation package, reviewer packet, sample roster, label set, prediction package, or scoring input. Do not pass these files to an evaluation/scoring script. The CSV ledger template deliberately starts with a non-CSV preparation marker; the JSON materials carry explicit preparation-only status and no observation records.

## Gate status and protocol freeze

The existing C1–C4 evidence gates remain blocked or incomplete, as described by the C1–C4 records and the admin readiness audit. This preparation does not change those decisions or the C5 blocker. No recruitment packet, sample, prediction, label, or score may be created under this protocol before all of these conditions are recorded as satisfied:

1. C0 semantic contract and C1–C4 evidence are frozen for a detector/rule release whose applicability contract can process a genuinely unseen source identity. Freeze exact implementation, rules, configuration, parser/toolchain, applicability contract, and their digests.
2. The protocol and label rubric are versioned, independently reviewed, and frozen before any eligible source is selected or exposed. Changes after protocol freeze require a new version and documented approval before selection; changes after any reviewer exposure invalidate the affected run and require a fresh blind cohort and source set.
3. A complete development/tuning family and source inventory is independently checked. Every known and unresolved family is resolved or excluded as a whole; unknown history blocks selection.
4. Candidate sources are selected from eligible unseen families only after the detector freeze and leakage audit. Freeze source identity and hashes before labels or predictions are generated.
5. Two qualified reviewers and one qualified independent adjudicator have signed pre-access declarations and passed conflict checks.
6. Access controls, isolated reviewer workspaces, append-only audit logging, and separate prediction escrow custody are verified.

Until all gates are documented, maintain zero samples and zero scores. In particular, the legacy nine-row purposive roster is not imported, sampled, copied, relabeled, or described as a performance set by these materials.

## Local development-history review

A read-only review of reachable local Ark Runtime detector history found multiple detector-development iterations and separate C-line review/replay refs. This is a partial local-history signal only: it does not reconcile untracked work or external tuning and patch-family history, and it does not establish family closure. C5 remains blocked before source selection until the complete authorized inventory is reconciled. The register records no commit IDs, source paths, source hashes, sample IDs, labels, predictions, or reviewer data.

## Access matrix

| Role | May access | Must not access before label freeze | Separation rule |
|---|---|---|---|
| Governance coordinator / data custodian | Protocol, declarations, public development exposure register, exclusion ledger metadata, randomized-ID map, audit log, source manifest after selection | Raw prediction payload; reviewer identity-to-case work area while adjudicating; ability to edit frozen reviewer submissions | Holds ID map and access log. Does not label or author predictions. If also detector developer, may not select or adjudicate cases. |
| Reviewer A and Reviewer B | Their own randomized source-only packet, rubric, own submission form | Detector implementation/version details beyond neutral scope needed to interpret source; rules, predictions, other reviewer packet/submission, family IDs, patch direction, source selection rationale | Separate workspaces and accounts. No communication about cases until both submissions are frozen. |
| Prediction author / detector operator | Frozen detector, rules, configuration, eligible source manifest after source freeze, execution environment; escrow write access | Reviewer names, submissions, labels, adjudication, ID map | Writes predictions to encrypted escrow, seals digest and timestamp, then loses read access until authorized reveal. Cannot label or adjudicate. |
| Independent adjudicator (Reviewer C) | The two frozen submissions and cited source evidence for disputed cases; rubric; randomized IDs | Predictions, detector/rule output, ID map, reviewer identities and patch-family metadata | No detector development/tuning role and no case-source/patch exposure. Sees only disputed cases. |
| Independent protocol auditor | Protocol versions, declarations status, access-control evidence, event log, artifact digests | Prediction payload and case labels before the authorized reveal; ID map unless needed for a logged integrity investigation | Audits process without becoming a reviewer or seeing outcomes. |

No person may hold both label custody and prediction escrow read access before label freeze. A conflict or accidental access is a stop event, not a disclosure waiver.

## Files

- `admission_gates.md`: ordered admission gates, evidence ownership, and stop rules; preparation only.
- `admission_gate_register.template.json`: blank fail-closed gate register; it contains no approvals or case data.
- `frozen_artifact_register.template.json`: blank digest register for future frozen artifacts; it is not evidence that any artifact is frozen.
- `family_history_reconciliation_request.template.md`: requests completeness evidence from authorized inventory custodians without recording family/source data here.
- `reviewer_access_readiness_request.template.md`: requests reviewer qualification, conflict, and deployed access-control evidence; it grants no access.
- `verify_preparation.py`: read-only structural checker constrained to this directory; it is not a test or evaluation verifier.
- `reviewer_qualification_declaration.template.md`: role qualification and prior-exposure disclosure form.
- `blind_protocol.md`: access-separated workflow, ID custody, dual annotation, adjudication, logging, and stopping rules.
- `family_source_exclusion_ledger.schema.json`: machine-readable schema, marked preparation-only.
- `family_source_exclusion_ledger.template.csv`: intentionally non-ingestible empty ledger template.
- `public_development_exposure_register.json`: only public C1/C2 development-family identity metadata; not a sample list.
- `self_check.md`: field and workflow checks performed on these governance materials.

Every template is blank of reviewer decisions and case observations. The public exposure register records known development contact risks so they can be screened out; it does not nominate evaluation sources.

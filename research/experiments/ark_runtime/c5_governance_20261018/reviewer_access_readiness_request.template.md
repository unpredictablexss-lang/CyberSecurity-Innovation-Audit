# Reviewer qualification and access-control evidence request

**Document status:** `preparation_only`  
**Purpose:** Request evidence of readiness; not a recruitment roster, clearance, or access grant.  
**C5 state:** `blocked_before_sample_selection`; no reviewer access is authorized.

Complete operational identity and security details only in the approved restricted administration system. Do not put names, account IDs, case identifiers, source paths, labels, predictions, or credentials in this public development workspace. This form does not clear any person or certify that a control is deployed.

## Qualification and conflict evidence

For each of the two reviewer roles and the separate adjudicator role, the restricted record must contain:

- A signed, dated qualification and prior-exposure declaration using the C5 declaration template.
- Relevant source-level security/compiler/runtime review experience and ability to apply the frozen rubric, including `unknown` and applicability states.
- Disclosures for detector/rule participation, development/tuning samples, target-family or patch exposure, predictions/results, other reviewers' work, and external/untracked history; `yes`, `unsure`, or incomplete disclosure remains pending until resolved.
- Conflict check against the authorized complete family-history inventory, with evidence reference and reasoned `cleared`, `rejected`, or `pending` decision by the coordinator plus independent auditor review.
- Confirmation that the adjudicator is not either labeler and has no detector development/tuning role or material case exposure.

No personal identity or declaration content is copied into this template. Record only opaque restricted references in the response table.

| Role slot | Declaration reference | Conflict-check reference | Independent decision reference | Status |
|---|---|---|---|---|
| Reviewer A (restricted identity) | `[ ]` | `[ ]` | `[ ]` | `not_started` |
| Reviewer B (restricted identity) | `[ ]` | `[ ]` | `[ ]` | `not_started` |
| Independent adjudicator (restricted identity) | `[ ]` | `[ ]` | `[ ]` | `not_started` |

## Access-control evidence request

Before any source packet is created or opened, request and independently verify evidence for each control. A policy statement without a deployed-control artifact and verification record is insufficient.

| Control | Evidence to provide through restricted admin system | Verification outcome |
|---|---|---|
| Separate reviewer accounts and isolated workspaces | Access-control configuration, workspace inventory, and an auditor-observed access rehearsal showing each reviewer sees only their own source-only packet | `not_started` |
| Prediction escrow separation | Distinct writer/read roles, encryption/key custody record, denied-read evidence for reviewers/adjudicator/operator before joint authorization | `not_started` |
| Identity-map custody | Encrypted storage configuration, two-person approval policy, access log, and backup-custodian check | `not_started` |
| Append-only event log | Configuration, integrity/signing method, retention and offline-copy evidence, and a sample event-chain verification without case content | `not_started` |
| Workspace content boundaries | Auditor inventory confirming no predictions in labeler workspaces and no labels in prediction-operator workspace | `not_started` |
| Reveal authorization | Technical enforcement requiring coordinator and independent auditor approvals after label/adjudication freeze | `not_started` |
| Incident and revocation path | Documented stop/quarantine procedure, access revocation mechanism, responsible roles, and evidence-preservation procedure | `not_started` |

## Readiness disposition

- All three role slots independently cleared before access: `[yes / no / unknown]`
- All listed technical controls deployed and independently verified: `[yes / no / unknown]`
- Access rehearsal passed without exposing case or outcome data: `[yes / no / unknown]`
- Outstanding gaps and stop decision: `[ ]`
- Restricted evidence bundle opaque reference, digest, and audit time: `[ ]`
- Governance coordinator and independent auditor approval references: `[ ]`

**Default disposition:** `blocked`. Any missing declaration, unresolved conflict, shared account, unverified boundary, or failed access rehearsal blocks all case access. Do not substitute a verbal assurance for technical evidence.

# Reviewer qualification and prior-exposure declaration

**Document status:** `preparation_only`
**Protocol version:** `UNFROZEN`
**Reviewer ID:** `[assigned by custodian; do not enter a name in the case workspace]`
**Completed at (UTC):** `[required before any case access]`

This declaration must be completed and signed before the reviewer receives any source packet, case identifier, or case-specific context. A “yes,” “unsure,” or inability to answer a material item triggers a conflict review. A reviewer is not cleared until the independent governance coordinator records a written decision. Do not attach cases, source code, predictions, labels, or review notes to this form.

## Qualification

1. Relevant experience in source-level security review, compiler/runtime analysis, or equivalent: `[describe years, role, and relevant expertise without naming any case]`
2. Can independently assess the frozen scope and distinguish `vulnerable`, `fixed`, `safe`, `unrelated`, and `unknown` under the protocol rubric? `[yes / no / unsure; explain]`
3. Have you participated in, advised, funded, or had a reporting relationship with the Detector, its model, rules, implementation, configuration, or evaluation? `[no / yes / unsure; describe dates and role]`
4. Are you able to work independently, preserve confidentiality, disclose recognition promptly, and submit evidence-based labels without consulting another reviewer? `[yes / no; explain]`

## Prior contact disclosure

For each line select `none`, `yes`, or `unsure`; describe the material and approximate date in the explanation field. Include public and private exposure, direct and indirect exposure, and exposure through meetings, tickets, code review, issue reports, presentations, chats, repositories, or another person.

| Exposure area | None / Yes / Unsure | Details, date, and source (do not include restricted content) |
|---|---|---|
| Detector source, binaries, outputs, applicability behavior, or version history | `[ ]` | `[ ]` |
| Detector rules, semantic contract, rule rationale, thresholds, tuning, or test expectations | `[ ]` | `[ ]` |
| Development samples, fixtures, historical replays, control cases, or tuning examples | `[ ]` | `[ ]` |
| Target patch family, root cause, patch/fix direction, related issue, or source revision | `[ ]` | `[ ]` |
| Any prediction, alert, candidate count, run summary, performance result, or prediction escrow | `[ ]` | `[ ]` |
| Any other reviewer's labels, rationale, notes, submissions, or adjudication | `[ ]` | `[ ]` |
| Any case source, commit, patch, report, or behavior likely to reveal a future case identity | `[ ]` | `[ ]` |
| External/untracked development or tuning material that may bear on family independence | `[ ]` | `[ ]` |

List any additional exposure or relationship that could reasonably affect independence: `[none / details]`.

## Conflict and stop commitments

- I have disclosed all known direct and indirect exposure above and will update the custodian before access if anything changes.
- I will not search for case patches, issue reports, Detector outputs, or other reviewers' work while labeling.
- If I recognize a source, patch, bug, family, prior review, or prediction after packet access, I will stop work immediately, preserve the packet, and notify the custodian without discussing a proposed label.
- I understand that exposure, uncertainty, or conflict may disqualify me; it will not be converted into a case label or silently treated as an exclusion.
- I will use only the assigned isolated workspace and will not export, copy, or discuss case material.

**Reviewer signature:** `[typed legal/approved identity in restricted admin record]`
**Signed at (UTC):** `[ ]`
**Custodian decision:** `pending / cleared / rejected / replaced`
**Decision rationale and conflict check reference:** `[ ]`
**Decision recorded at (UTC):** `[ ]`

`preparation_only` template: no reviewer has signed this form and no reviewer is confirmed or cleared.

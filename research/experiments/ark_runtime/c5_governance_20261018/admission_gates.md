# C5 admission gates and evidence ownership

**Status:** `preparation_only`; the machine-readable register is a blank template, not an approval.  
**Protocol:** `UNFROZEN`  
**Admitted samples / labels / predictions / scores:** `0 / 0 / 0 / 0`

This gate map makes the sequence and evidence required for a future independent assessment explicit. Every referenced evidence item must be immutable, digest-bound, independently checked, and available to the authorized auditor. Missing, stale, partial, contradictory, or `unknown` evidence leaves the gate blocked. No gate in the template is approved by this document.

| Gate | Required evidence to pass | Current preparation finding | Exit condition |
|---|---|---|---|
| G0 — contract and upstream evidence | Frozen C0 semantic contract and complete C1–C4 evidence for the exact detector profile | Upstream evidence has been reported blocked or incomplete; recheck current authoritative records before any transition | Independent audit binds all upstream artifacts and confirms no unresolved prerequisite |
| G1 — detector freeze | Detector, rules, config, parser/toolchain, environment, applicability contract, digests, and pre-selection approval | No independent-evaluation release is frozen here | Independent verifier confirms identity and applicability contract before candidate selection |
| G2 — family closure | Complete authorized tracked, untracked, local, and external tuning/development inventory; whole-family overlap decisions | Only partial reachable local history and public exposure metadata are recorded; external/untracked inventory remains unresolved | Independent auditor attests inventory completeness and every family is resolved or excluded |
| G3 — protocol freeze | Versioned rubric/protocol, independent review, approval, digest and effective time | Current protocol is preparation-only and unfrozen | Freeze precedes source selection and is recorded in append-only log |
| G4 — role and access readiness | Two cleared reviewers, separate adjudicator, declarations/conflicts, isolated workspaces, escrow and log controls | No role has been named or cleared; controls have not been operationally verified | Access rehearsal and independent control review pass before any case access |
| G5 — candidate frame | G0–G4 pass, complete family ledger, whole-family exclusions, frozen frame and selection method | Selection is prohibited while family closure and upstream freezes are unresolved | Auditor approves frame and records selection commitment before inspection |
| G6 — source/ID freeze | Restricted source manifest, content hashes, random-ID digest, encrypted map and two-person custody | Not started; no sources or IDs are recorded | Custodian and auditor verify manifest, IDs, and access boundaries |
| G7 — labels/adjudication freeze | Two independent submissions; all disagreements adjudicated; final ledger digest | Not started; no labels are authorized | Auditor attests submissions, adjudication, and digest before reveal |
| G8 — prediction seal | Frozen detector execution, input digest, execution log and escrow payload digest | Not started; no predictions are authorized | Separate prediction operator seals payload without label access |
| G9 — reveal/scoring | Joint reveal authorization, integrity review, separate scoring approval and scoring protocol | Not started; no reveal or scores are authorized | All preceding gates and independent audit pass; scoring has separate explicit authorization |

## Ownership boundaries

- The governance coordinator owns the gate register and protocol version history but cannot label or author predictions.
- A separate family-inventory auditor confirms completeness and whole-family exclusions; partial local review is insufficient.
- The detector operator freezes and executes the detector but cannot see labels or adjudications.
- Reviewers and adjudicator cannot see detector outputs, predictions, source-family identity, or one another's work before freeze.
- The escrow custodian and the label/map custodian must be distinct. Reveal needs joint authorization from the coordinator and independent auditor after G7 and G8 are verified.

## Stop rules

Keep the run blocked for any incomplete inventory, unresolved family overlap, upstream gate failure, missing approval or digest, protocol/configuration change after freeze, role conflict, access-boundary failure, recognition event, or audit-log integrity failure. Never convert these states into a negative label, safe result, or performance score. Record the stop reason and preserve event evidence; do not repair a compromised blind by reusing exposed sources.

The accompanying `admission_gate_register.template.json` and `frozen_artifact_register.template.json` contain no approvals, source identities, case IDs, or outcome data. Populate operational records only in a separately approved, access-controlled location after the relevant authorization gates pass.

The `family_history_reconciliation_request.template.md` is a request for completeness evidence, not a place to store restricted inventory rows. The `reviewer_access_readiness_request.template.md` asks for pre-access qualification and deployed-control verification. Both default to blocked, and their restricted evidence references must point to approved admin records rather than source or person details in this workspace.

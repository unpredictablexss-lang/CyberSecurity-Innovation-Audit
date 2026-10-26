# Governance template self-check

**Status: `preparation_only`**
**Review date:** 2026-10-19 (Asia/Shanghai)

This check reviewed governance materials only. No holdout manifest, source sample, reviewer packet, prediction escrow payload, hidden label, or scoring script was opened or run.

| Check | Result | Evidence in this package |
|---|---|---|
| Reviewer disclosure covers Detector, rules, development samples, target patch families, predictions/results, other reviewers' labels, and source recognition | Pass | Declaration table has separate exposure rows and requires date/source details. |
| Reviewer eligibility and conflict outcomes are explicit | Pass | Relevant expertise, participation, independence, signed attestation, custodian decision and rationale fields are present. |
| Reviewers cannot see predictions or one another's work before freeze | Pass | Access matrix and blind protocol impose separate workspaces; prediction escrow read is jointly gated until final label freeze. |
| Prediction author cannot see labels and cannot adjudicate | Pass | Access matrix and protocol require distinct roles and no label/ID-map access. |
| Random IDs are uninformative and map custody is admin-only | Pass | CSPRNG IDs, uniqueness/digest log, encrypted map, two-person access, one-time mapping and re-key stop rule are specified. |
| Two independent annotations and third-party adjudication are defined | Pass | Separate submissions are frozen before comparison; only disputes go to a conflict-free third party; `unknown` is allowed. |
| Inapplicable/partial/unknown and reviewer conflicts have defined paths | Pass | Protocol preserves status and reason, excludes unresolved units from binary scoring, and provides stop/replace/invalidate rules. |
| Family/source exclusion ledger is empty and non-ingestible | Pass | CSV has a preparation marker before its header and zero data rows; JSON schema states it is not data. |
| Only public development-family identity metadata is registered | Pass | Exposure register contains three identities cited to the public C7 development README; it contains no source/sample IDs or labels. |
| Protocol freeze and tuning are traceable | Pass | Freeze version/digest/approver/timestamp, controlled amendments, and change-level tuning history are required. |
| Preparation cannot be mistaken for valid score data | Pass | Package status and zero counts are prominent; templates are blank; CSV sentinel invalidates ordinary header parsing; no scorer-compatible observations exist. |
| C5 remains blocked pending C0–C4 and future independence gates | Pass | README states blocked conditions and prohibits sample creation, prediction, reveal, and scoring before all gates pass. |
| Partial local detector-development history is recorded without implying complete family closure | Pass | The exposure register records only an aggregate reachable-history observation and explicitly retains the external/untracked-history blocker; no sample identities or protected evaluation data are added. |

## Self-check limits

This is a document-level governance review, not a technical access-control deployment or a test of the existing scorer. No scoring program was invoked. Operational access controls, named role assignments, qualified reviewers, independent adjudicator, complete external tuning inventory, eligible unseen source families, and C0–C4 freeze evidence remain future gates. The local history observation is partial and cannot prove family closure. Current state remains zero samples, zero labels, zero predictions opened, and zero scores.

## Admission-register supplement (2026-10-19)

The C5-only admission-gate map and two JSON templates were added without opening holdout material or changing any evaluation state. Read-only structural checks confirmed that all four C5 JSON files parse, the admission register has ten ordered gates, and sample/label/prediction/score counts remain `0/0/0/0`. G0–G4 are blocked or incomplete; later gates are not started. These checks establish document structure only; they do not approve a gate, validate operational controls, or replace independent review. No tests or scorer were run.

## Custodian request templates and bounded checker (2026-10-19)

Added a blank request for full development/tuning history coverage and a blank reviewer/access-readiness evidence request. Both require restricted evidence to remain in the authorized admin system and use only opaque references here; neither contains family rows, reviewer identities, or grants. Added `verify_preparation.py`, which resolves all input paths from its own C5 directory and structurally checks C5 JSON, the zero-row sentinel CSV, zero outcome counts, and absence of frozen digests. It reads no data outside C5 and is not a test/evaluation verifier. Run it with `python verify_preparation.py`; a pass is only a preparation-package structure check.

## C-line status refresh (2026-10-19)

C1's selected product target is `hihope/rk3568`. Both exact-profile ARM object targets now build through Ninja under a read-only-root user/mount/network namespace. The build uses a hash-bound Ninja/Python toolchain and Ruby 3.2.3 packages; source is a read-only manifest-snapshot lower layer accessed through a COW view, toolchain/prebuilts/Ruby are read-only, and GN output/evidence are separate writable mounts. The root write probe was rejected; both target commands match the profile argv and returned 0. A preceding COW run completed the remaining prerequisite closure, while the read-only-root replay forced both target object actions. The exact build is incremental and does not produce a full product image; 19 nested gitlink commit trees outside the manifest archive (16 have a declared .gitmodules URL; 3 do not) and one of five exact linkfile sources is missing keep the product/snapshot gate open. Duplicate-output warnings remain. C2 still has 18/18 changed dependencies marked `unknown`; the current-profile census confirms 49 ARM action entries for eight changed `.cpp` files outside the two selected target translation units, but does not establish that those actions affect detector semantics. A full-history audit of all 10,315 refs advertised by the recorded GitCode manifest remote found no exact old Ark pin in 10,420 reachable commits; third-party and unadvertised/unreachable refs remain outside scope. C4 binds 151 inputs with matching expected/declared/observed digest `948783cd288213aed89908b8ab5df4096bc7de401bde5b41b10bb0bbfd0f1e1a`, while C1 full product build, C2 case matrix, and parser binary identity remain blocked. This status refresh is development evidence only: no evaluation material was accessed; sample, label, prediction, and score counts remain `0/0/0/0`.

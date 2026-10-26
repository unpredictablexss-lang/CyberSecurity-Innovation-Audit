# Ark Runtime independent holdout

**Assessment:** `ark-runtime-c-independent-holdout-20261018-v2`  
**State:** **not a valid performance holdout for the frozen detector.** The source roster and detector lock are recorded, but all 9 rows replayed as `not_applicable`; labels and independent-review evidence are absent. No performance metrics are estimable.

This package records a metadata-only candidate roster and a two-reviewer blind-labeling protocol; the roster is not a valid performance holdout for the frozen Ark Runtime detector. It does not claim that the holdout is complete or that any sample has a ground-truth label. The existing 9 rows are purposefully selected probes, not a probability sample. Their source identities are fixed in `admin/holdout_source_manifest.csv`; detector/version/configuration and implementation hashes are in `admin/frozen_detector.json`.

## Freeze record

- Detector: `ohscanner.ark.runtime.type_safety` 0.6.2.
- Rules: `ark.runtime.typedarray-store-type-origin` and `ark.runtime.typedarray-allocation-exception-guard`, both 0.6.2.
- Model digest: `662c74d79b75b2a111f7ec0eca4cb819a8b1f092ea3e9f7e6cff63621a3d8a1a`.
- Scanner commit/tree: `5cceb70e3b00b5e4938bfcee378863a8232931a9` / `33df67ffd1529d098bcbabbba63ac4c9199b01c9`.
- The lock records implementation/parser SHA-256 values and the 18 model input paths. The 9 selected source paths do not overlap those paths. The reproducibility audit rebuilt the scanner archive and matched detector/parser hashes, then fetched each source at its pinned upstream commit and rechecked SHA-256, Git blob SHA-1, byte length, and parse state (see `admin/freeze_verification.json`). The manifest records commit, tree, path, blob and source hashes; parse status is 8 complete and 1 partial. These checks do not prove a reviewer has never seen public patches or tuning results.

## What is and is not established

The previous frozen replay reported 9/9 `blocked` and `not_applicable`, with 0 candidates. Every selected path is outside the frozen model's applicable inputs. This is not detector coverage and cannot be interpreted as safe, a hit, or a miss. No raw prediction is included in reviewer exports. The administrator's replay summary is under `admin/`; it records a raw prediction escrow path and digest, but the escrow file is absent at that path in the current workspace. Treat that old prediction record as unavailable; no reviewer has received any packet, and the escrow was not opened during the current audit.

The selected set has 9 source units, 2 known patch families, 8 complete parses and 1 partial parse. The two known patch families are grouped within this selected roster. A scoped search of available local C1-C6 artifacts found no exact JSStableArray patch identity, while C1/C3 do discuss the related TypedArraySpeciesCreate concept. Five other rows are selection strata, not adjudicated root-cause families. Every audit row is marked incomplete because external/untracked tuning history and root-cause adjudication are missing. See `admin/family_leakage_audit.csv`; reviewer export and scoring fail closed until every family is fully resolved. These facts do not establish vulnerable/fixed/safe/unrelated label coverage. No independent dual labels, exposure declarations, disagreement adjudication, or label snapshot exist yet. Therefore TP/FP/FN, precision and recall remain null.

## Reviewer export and blind protocol

Complete every `scope_complete=no` row in `admin/family_leakage_audit.csv`, resolve the structural strata into root-cause families, and extend the search to external/untracked development materials before reviewer export; if any development/tuning family overlaps, exclude that entire family and create a newly frozen manifest before recruiting reviewers. Have each candidate complete `admin/reviewer_declaration_response_template.json` and sign it before they receive any case material. Then run `python export_reviewers.py --runtime-repo <pinned-local-ark-runtime-git-repo> --scanner-root <clean-frozen-scanner-archive> --family-audit <completed-family-audit.csv> --reviewer1-declaration <signed-r1.json> --reviewer2-declaration <signed-r2.json> --output-dir <private-output-outside-repository>` from this directory. The exporter rejects reviewers who report detector/tuning exposure or prior source/patch exposure, rechecks all commit/tree/blob/source hashes and the exact frozen model/parser implementation and parse states, and writes two separately randomized packets with source-only case files and empty annotation forms. It never reads or emits detector predictions, model rules, patch-family IDs, patch references, commit IDs, source hashes, or the tuning/replay summary. Keep the two reviewer directories separate and give each only their own directory. Reviewers should not have repository/admin access while labeling. Export is one-shot so the reviewer ID key cannot be silently regenerated.

Each reviewer must independently attest before receiving the packet that they did not participate in detector/model/rule design or tuning and have not seen predictions or results for these cases. They must disclose prior exposure to the source, patch, bug report, or case family. Any material exposure or inability to attest means exclude that reviewer and replace them; it does not become a label exclusion. If a reviewer recognizes a case after opening the packet, they must stop, disclose it, and be replaced before continuing. Do not tell reviewers patch direction or pair membership. Public source code can still be recognized; the declaration and exclusion ledger must record this limitation.

Labels:

- `vulnerable`: a concrete defect/root cause is present in this exact source revision, with source evidence and plausible impact.
- `fixed`: the identified root cause is absent because this revision contains a validated correction; cite the evidence for both the root cause and correction.
- `safe`: the reviewed behavior is in scope and the evidence supports absence of the target root cause under the stated conditions.
- `unrelated`: the reviewed unit is outside the target behavior/scope, with a reason.
- `unknown`: available source/context is insufficient. Partial parsing is reported explicitly and normally excludes the unit from binary scoring unless independent evidence resolves its impact.

Each reviewer labels independently and records line/range evidence, rationale, a stable root-cause description (when present), prior-exposure status and submission time. The coordinator records exclusions and reasons without deleting rows. After both submissions, freeze each reviewer file by SHA-256. Compare labels; a third, independent adjudicator records the disagreement, evidence, final label/root-cause mapping, exclusions and timestamp. Freeze the adjudicated ledger by SHA-256 before opening prediction escrow.

## Score gate

`score_holdout.py` is fail-closed. It requires a frozen input manifest, a completed root-cause-family leakage audit, reasoned exclusions, two complete reviewer snapshots joined through the admin-only randomized-ID key, signed no-exposure declarations, a completed adjudication ledger, a prediction reveal timestamp after label freeze, and fresh source identity checks. It counts root-cause observations, not raw finding lines: deduplicate by `(sample identity, adjudicated root cause)`, count TP/FP/FN only on adjudicated, applicable, non-unknown observations, and report excluded/partial/unknown counts separately. It also requires adjudicated `vulnerable`, `fixed`, `safe`, and `unrelated` coverage plus at least one retained parser-incomplete unit, and it reports partial and unknown counts separately. It refuses to calculate if any gate is missing or if the detector did not execute on applicable holdout inputs. Reviewer source/patch exposure invalidates that review; replace the reviewer or explicitly document exclusion and recruit another independent reviewer before scoring.

The present replay fails the applicability gate for all 9 rows. Even after independent labels, it cannot yield target-detector precision/recall. The frozen detector binds its relevant analyses to exact source revisions, while its lock also excludes every model-input path from the holdout; those conditions leave no demonstrated target-applicable holdout sample. Do not broaden the binding or change rules in this assessment: that would create a new detector version and require a new holdout frozen before any case review. This roster remains a protocol/readiness artifact, not an accuracy evaluation.

## Current counts and limitations

| Measure | Current state |
|---|---:|
| Source units (none applicable to frozen rules) | 9 |
| Parser complete / partial | 8 / 1 |
| Detector applicable / not applicable | 0 / 9 |
| Detector blocked | 9 |
| Predicted candidates | 0 reported by historical summary; raw escrow unavailable, not a score |
| Independent labels / adjudications | 0 / 0 |
| Exclusions with recorded reasons | 0 (ledger prepared; no reviews yet) |
| TP / FP / FN / precision / recall | Not estimable |

Adjudicated class coverage for `vulnerable`, `fixed`, `safe`, `unrelated`, and `unknown` is **pending for all 9 rows**. The current source inventory includes one partial parse; this is input coverage, not an `unknown` human label. Do not infer any class count from patch provenance or the 0-candidate replay.

Limitations: purposive sampling; only two patch families; no demonstrably target-positive examples; no target-rule coverage; public upstream source may be recognizable; no qualified reviewers have attested; incomplete parser context; no product build/preprocessing configuration, runtime reachability, or impact validation. Never treat development fixtures, detector predictions, or model self-review as truth.

## Files

- `admin/`: frozen lock, source identity manifest, sample selection metadata, existing blind-run summary, replay/build scripts, and label template. Administrator only.
- `export_reviewers.py` and `score_holdout.py`: source-only reviewer exporter and gated root-cause scorer. `reviewer-packet-export/` contains reviewer protocol templates. Generated reviewer packets belong outside the repository and are not present yet.
- `admin/holdout_source_manifest.csv` is the authoritative sample identity list. The earlier `admin/blind_review_packet.csv` is retained as historical evidence only; it leaks revision metadata and must not be distributed.
- `admin/C-line-independent-holdout-brief.md` and `admin/blind_run_summary.json` are administrator-only and expose replay status. Never share them with reviewers before label freeze.
- `admin/verify_frozen_holdout.py` and `admin/freeze_verification.json` provide a no-prediction recheck of the scanner/source freeze. `admin/package_hashes.json` freezes hashes for the current package files (the hash file itself is excluded to avoid self-reference).


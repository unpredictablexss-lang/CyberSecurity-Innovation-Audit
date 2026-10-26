# D1: bounded C/C++ path source-to-file-sink candidate analysis

## Scope and finding

Implemented `ohscanner.cpp.path_source_file_sink` v0.1.0 as an A-owned, opt-in detector module. It is not registered in the shared Catalog and is not enabled in the production Runner. The change is limited to this detector, its dedicated tests, and this delivery record.

A0 sample 2 used profile `light-ast` and its archived `run_meta.json` fixes the actual detector set to `ohscanner.interface.ipc`, `ohscanner.cpp.lifetime`, and `ohscanner.cpp.shared_ptr_race`. The Contacts repository was a neighboring manual-review object, not the repository scanned by that task. Therefore the defensible baseline statement is that the actual scan omitted a path source-to-file-sink detector; this replay cannot claim an in-run rule failure on the Contacts source.

The A0 finding `ohscanner-contacts-path-traversal-001` is a distinct, manually found CWE-22/CWE-73 candidate with a mechanism PoC. Product image, SELinux domain, affected installed versions, and upstream fix remain unknown/partial per the read-only T1 record. This detector work makes no product vulnerability or impact determination.

## Source and replay identity

| Field | Value |
| --- | --- |
| A0 scanned repo / commit / tree | `openharmony/distributeddatamgr_data_share` / `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd` / `f731230c116c94d7619f5514c828b33ffac69924` |
| A0 profile and actual detector arguments | `light-ast`; `ohscanner.interface.ipc`, `ohscanner.cpp.lifetime`, `ohscanner.cpp.shared_ptr_race` |
| A0 adjacent Contacts repo / commit / tree | `openharmony/applications_standard_contacts_data` / `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` / `2054824c04bb403eeea128a9262edfb3001efa4f` |
| Replayed Contacts path | `dataBusiness/contacts/src/contacts_data_ability.cpp` |
| Expected Git blob / source SHA-256 / size | `c93e950725adc93276916b3c96c5ac7a5bb5b6b7` / `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` / 85,339 bytes |
| Observed checkout SHA-256 / size | `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` / 85,339 bytes |
| Detector source / rule version | `src/ohscanner/detectors/cpp/path_safety_detector.py` / `ohcpp.path-source-file-sink-candidate-001` v0.1.0 |
| Scope | One C++ translation unit; C/C++ source unit; one recognized same-TU reference-output summary |

The observed bytes match the SHA recorded in A0's `evidence/provenance_adjacent.json` and the independent T1 report. A fresh `git rev-parse <commit>:<path>` attempt against the local Contacts clone failed because its `.git/config` is an inaccessible reparse point; this work does not claim to have independently verified the Git object in that clone. The prior A0/T1 object record is preserved as the source identity evidence.

The replay command was an inline Python call constructing a source-bound `SourceUnit` from the exact checkout bytes, with `parse_status="partial"`, then invoking `CppPathSafetyDetector.detect`. It did not invoke the product CLI/Runner, did not fetch source, and did not assign a production parser result. Exact reproducible focused command:

```powershell
python -m unittest tests.detectors.test_cpp_path_safety_detector -v
```

Direct fixed-source replay produced three source-bound candidates at `contacts_data_ability.cpp:792`, `:793`, and `:797`, with per-file outcome `partial` and run `blocked`. Line 792/797 preserve `PortraitFileName` through the one-hop reference-output summary for `GetPortraitValue`; line 793 separately preserves `contactId/rawContactId` through the path construction. Those identifier values may have upstream format constraints not modeled here, so line 793 is a may-flow candidate only. Partial inspected files are listed in `DetectorRun.analyzed_files` so Runner can validate finding provenance; `file_outcomes`/normalized parsing still report `partial`, never complete. A focused `_normalized` regression confirms the candidate survives with `analysis_status=partial`. The measured one-unit lexical run was 61.204 ms over 85,339 UTF-8 bytes; peak RSS was not measured. This is a developer replay, not performance evidence for a whole profile.

## Rule semantics

1. **Sources:** explicit getter model names (`GetStringValueFromDataShareValue`, `GetStringFromValuesBucket`, `GetStringParam`, `GetStringParameter`, `getStringParam`) with at least one literal field/key argument. Generic names such as `GetString` and `GetStringValue` are intentionally not source models. Source keys are carried into findings; that naming evidence still does not prove attacker control.
2. **Propagation:** simple identifier assignments and concatenation within a recognized function body, plus a same-translation-unit, unambiguous summary where a modeled getter assigns directly to a reference/pointer output parameter and a caller passes a local identifier at that output position. This is may-flow evidence, not call binding or reachability proof.
3. **Sinks:** path argument 0 of `unlink`, `remove`, `fopen`, `open`, `openat`; both path arguments for `rename`/`renameat`. The project wrapper `DeleteFile` is modeled only for a receiver declared as `Contacts::FileUtils`; generic same-name members and `RemoveFile`/`OpenFile`/`WriteFile`/`ReadFile` are not file sinks.
4. **No concatenation-only alert:** a tainted path expression without a modeled file sink is not reported.
5. **Narrow safe suppressions:** a local early-return guard whose entire condition is a conjunction of `same_tainted_variable != "safe-basename"` comparisons; extra predicates such as `&& gate`, OR, or unsupported syntax do not suppress. The canonical path suppression requires a `std::filesystem::canonical`/`weakly_canonical` transformed candidate plus canonical root and an early return on failed `starts_with(root + "/")` / separator-bounded `rfind` check. Prefix-only checks do not suppress. Other helpers, normalizers, aliases, APIs, or platform separator conventions remain unknown and are not assumed safe.
6. **Unknown handling:** partial/failed/not-run parsing, macros/variadics, unmodeled transforms, indirect calls and unresolved aliases retain blocked/partial coverage. Lexical candidates found despite partial parse are retained. The implementation never converts an unknown helper into a safe result.
7. **Budgets:** 1 MiB per unit and 32 MiB per run; at most 256 recognized functions, 12,000 lexical calls per unit, 8 MiB aggregate function-body rescanning, and 8 assignment-closure passes. Limit exhaustion fails closed with coverage unknown.

## Regression matrix

| Control | Expected / observed |
| --- | --- |
| DataShare external field → reference-output helper → concat → `unlink` | Candidate; key retained; source SHA bound |
| Canonical candidate + canonical root + separator-bounded early-return guard | No candidate |
| Canonical prefix guard without separator boundary | Candidate retained |
| Literal basename allowlist with early return before sink | No candidate |
| Path concatenation without a file sink | No candidate |
| Same file sink with fixed/unrelated value and no modeled source | No candidate |
| Generic config getter with a same-name sink elsewhere | No candidate |
| Partial parse with direct modeled source→sink | Candidate retained; run blocked; file outcome partial |
| `name != "front.png" && gate` with an unlink reachable when `gate` is false | Candidate retained; partial input remains blocked/partial |
| Typed `Contacts::FileUtils::DeleteFile` / unrelated `Logger::DeleteFile` | Candidate / no candidate |

Targeted verification after the allowlist correction: `python -m unittest tests.detectors.test_cpp_path_safety_detector -v` — 14 tests passed, including Runner normalization of partial candidates, bypass and typed/unrelated method controls. `git diff --check` and `python -m scripts.check_change_scope --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane cpp` passed with zero violations. Earlier broad C++ detector-family results remain as historical run records; they were not rerun for this correction.

## Limitations and integration request

- No CFG/dominance, C++ overload resolution, whole-program call graph, macro expansion, pointer/heap alias model, filesystem semantics, symlink proof, platform-independent canonicalization proof, build context, real entry/permission, or CIA impact.
- `weakly_canonical`/separator checks and allowlist guards are recognized only in narrow lexical shapes. The detector is opt-in and currently not reachable from the production scan profile; shared Catalog/Runner admission is a separate owner review.
- **Owner integration handoff (required for actual 1day/Nday scans):** register/import `CppPathSafetyDetector` in `src/ohscanner/detectors/catalog.py` as `kind="research_candidate"`, `default_enabled=False`, with explicit-selection admission text that says source control/path containment remain unverified. No contract change should be needed; the detector already emits the existing `DetectorRun`/`DetectorFinding` contract, per-file partial outcomes and source SHA. Add catalog/planner/Runner tests proving default scans omit it, explicit selection executes it, and partial run status still retains valid findings. These shared-owner edits are deliberately not part of this A-owned worktree.
- After owner registration, perform an exact CLI replay on a checkout that can read the pinned Git object (the current local Contacts `.git/config` is inaccessible): `python -m src.cli ohscan-run --repo-dir <verified-contacts-checkout> --repository openharmony/applications_standard_contacts_data --commit 341cc3bf41b48e9a5f278dd088f40a2041d2f1c9 --detector ohscanner.cpp.path_source_file_sink --json-out <isolated-out>/contacts-path.json --md-out <isolated-out>/contacts-path.md`. Preserve the actual emitted profile, run status, per-file coverage, findings/source SHA, tree and artifact hashes. Run the same production entrypoint on pinned fixed/safe/unrelated/partial controls (or a committed test fixture target) and compare exact outputs; do not infer product safety or a product vulnerability from this static replay. Until that production-entrypoint replay and admission gate pass, D1 proves only detector-module mechanism regression, not that any 1day/Nday scan currently runs this rule.
- No independent holdout or labelled precision/recall data exists. Candidate count and the three contacts paths do not measure accuracy.
- Reproducible next action: run this detector and the existing production detectors against the same frozen source/profile in an integration-owned harness after Catalog approval; independently review fixed/safe paths and parser coverage. Until that gate, report this as a detector research delivery only.

## Registration safety review (2026-10-19 follow-up)

### Decision

The module is suitable only for an **explicitly selected, opt-in research candidate** after owner integration tests. It is not suitable for default enablement or a claim of general C/C++ path traversal coverage. The detector itself emits candidate-only evidence and handles partial parse as blocked/partial; the allowlist bypass is fixed and the member sink is type constrained. However, source getters remain name/key based, and the declared `openat`/`renameat` sink argument positions are not modeled correctly by the present generic first-argument extraction. These are review limitations that must be made explicit, and should be corrected or removed from the declared sink set before broad static admission.

### Ownership and current reachability

`config/collaboration/ownership.json` lists `src/ohscanner/detectors/catalog.py`, `src/ohscanner/runner.py`, and `src/ohscanner/execution.py` as `shared_owner_only`; `AGENTS.md` assigns Catalog/Runner/contracts to the integration owner. This cpp lane is therefore not authorized to change Registry/Runner/shared admission. The current worktree is `codex/a-path-d1-20261019` at base `db77164fdc2af0da02e4d3efc056d84694fd68e8`, tracking `origin/main`, with no new commit or upstream feature branch to modify. The C++ detector, tests and delivery are local untracked lane files only.

Current CLI reachability was tested with an explicit `--detector ohscanner.cpp.path_source_file_sink`; CLI exits before source loading with `unknown or not-yet-approved detector`. This confirms no current Registry or production CLI path reaches D1. Existing positive/fixed/safe/unrelated/partial controls run through the dedicated detector API and unit harness only. They do not establish CLI behavior.

### Owner-only Catalog patch draft

After the detector-side sink argument model is corrected or the unsupported sink names are removed, the integration owner may apply this minimal entry in `src/ohscanner/detectors/catalog.py`:

```python
from .cpp.path_safety_detector import CppPathSafetyDetector

"ohscanner.cpp.path_source_file_sink": {
    "factory": CppPathSafetyDetector,
    "kind": "research_candidate",
    "default_enabled": False,
    "admission_reason": (
        "explicit_selection_required: lexical source-to-file-sink candidates only; "
        "source control, path containment, filesystem behavior, and product impact "
        "remain unverified; partial coverage is unknown"
    ),
    "summary": (
        "A: bounded C/C++ external-string-to-file-operation candidates; "
        "not a vulnerability verdict"
    ),
},
```

The owner integration should add tests that (1) default IDs exclude the detector, (2) explicit `build_registry((ID,))` constructs it, (3) CLI `ohscan-run --detector ID` executes against a frozen fixture and preserves source SHA/findings, (4) a second run on a fixed/safe source has no finding, (5) unrelated same-name source/sink and no-sink controls do not alert, and (6) partial parse retains the valid candidate and reports blocked/partial coverage. The production CLI should be run against pinned Git blobs, not working-tree bytes. No Catalog/Runner/contracts edit is included in this lane.

### Reproducibility and conflicts

- Positive: `GetStringValueFromDataShareValue(..., "PortraitFileName", ...)` → modeled helper/path → `unlink` or typed Contacts `FileUtils::DeleteFile` yields candidate.
- Fixed/safe: exact closed basename guard yields no finding; guard plus `&& gate` retains candidate; reassignment after the guard retains candidate.
- Unrelated: `Logger::DeleteFile` is not treated as a file sink; path construction without a sink yields no candidate.
- Partial: candidate is preserved while aggregate and per-file coverage remain blocked/partial.
- CLI positive currently cannot execute because the ID is absent from Catalog; explicit invocation reproduces the rejection. Post-registration CLI positive/negative runs remain an owner gate.
- `python -m unittest tests.detectors.test_cpp_path_safety_detector -v`: 14/14 passed. `git diff --check`: passed. `python -m scripts.check_change_scope --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane cpp`: zero violations. No shared path conflict was introduced; this lane has not modified owner-only files.

### Continuing objective

Keep the detector opt-in and unregistered until the owner resolves the `openat`/`renameat` parameter modeling or narrows those declared models, reviews source getter identity, and lands Catalog/CLI integration tests. Then replay fixed pinned Contacts bytes and controls through the production CLI, record exact scope and coverage, and keep candidate-only language unless independent product reachability/impact evidence supports promotion.

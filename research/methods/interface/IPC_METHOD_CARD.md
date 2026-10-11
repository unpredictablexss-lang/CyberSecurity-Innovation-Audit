# IPC method card v0.1
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

- Detector: `ohscanner.interface.ipc` 0.1.0; model: `oh-ipc-2026.10-v1`.
- Input: immutable fixed-Git SourceUnit + shared AST presence/status; C/C++ source, no target execution. Runtime imports no external scanner or historical labels.
- Output: syntax candidates, unassessed confidence, stable root entry/path location, reachability/callee-policy/impact evidence obligations. Any input partial retains inspected candidates and blocks completed coverage.
- Analysis: private Tree-sitter structured branch interpreter, bounded local same-file/class calls (depth2), path budget96 with intersection of proof facts, zero/one loop approximation, explicit caller token vs UID vs self/request sources.
- AUTH-01: request Parcel descriptor equality and rejecting mismatch before handler/forward effect. This is narrow boundary protection, not a full cross-SA relay reconstruction.
- AUTH-02: original caller authorization protecting modeled effect; reviewed service entries include screenshot, camera and telephony controls.
- AUTH-03: token/UID domain, original identity after reset, owner relation and restricted caller class. Direct requested UID safe binding is a known false positive.
- AUTH-04: ignored/late guard, one-branch protection, switch entry/fallthrough; authorization facts must exist on effect-reaching path.
- DATA-01: Parcel length→copy destination-matched nonnegative/upper bound; reviewed transport position subtraction checks. No general bitvector overflow theorem.
- CAP-01: non-null object/FD export with missing caller authorization; public capability policy and ownership remain review obligations.
- Model source provenance: research/corpus/interface/ipc/model_sources.json; original queries and vendor-read provenance: research/experiments/interface/ipc/tool_source_manifest.json. No vendor implementation copied.
- Controls: 29 authored design scenarios across all six families, positive/fixed/safe; tests/test_ipc_detector.py checks bridge, blocked scope, determinism, bounds and identity domains. 218 project tests pass.
- Historical evidence: twelve S2 design roots, one S1 pending patch; no runtime/S3. Candidate count >0→0 in all pairs; seven pairs partial unknown. Do not publish this as independent recall.
- Freeze: research/corpus/interface/ipc/design_freeze.json. Thirteen same-origin generated variations tested after freeze, twelve met, one false positive. Not independent real-world holdout.
- Independent holdout design (not executed): adjudicate remaining advisory patch roots with independent reviewer; split by root/patch lineage and component/time, lock detector/catalog before acquiring holdout inputs, evaluate root-specific vulnerable/fixed/safe behavior and unknown rate separately. Shared PR/CVE aliases cannot cross splits. Prefer unseen components; freeze records, scopes and command manifests before scoring.
- Limits: no macro expansion/full compiler CFG, arbitrary virtual/indirect target binding, cross-file alias ownership, full permission policy, complete runtime reachability or satisfiability proof. Names/API models are assumptions, not security judgments.
- Next work: parser/build context, dispatcher/cross-file relation summaries, requestedUID relationship precision, then targeted SMT constraints and independent historical holdout. No target recall guarantee yet.

Detailed Chinese methods and per-root/tool comparison: docs/research/ipc_scanner_v0_1_2026-10-10.md.

---

# IPC method card v0.5 — contract v2: source binding and the consequence field (2026-10-11)

- Detector: `ohscanner.interface.ipc` **0.3.0** (was 0.2.0); model unchanged
  (`oh-ipc-2026.10-v1`). Contract: **v2**, absorbing three CCRs in one version bump.
- **What changed for a consumer of the output.** Every diagnostic from a first-party detector now
  carries `source_sha256` and a derived `source_binding` (`bound` / `unbound`), and diagnostic IDs
  changed value because the hash is part of their input. The consequence dimension added in v0.3
  is now a **field**, not only message text: `consequence_impact` / `consequence_cwe`.
- **Required vs optional, and why the split is where it is.** The source binding is required *in
  the produced schema*, not at the detector call site: the runner already holds the
  `SourceUnit.sha256` and binds the finding to it, so a detector has nothing to copy and no way to
  copy it wrong. A detector that *does* declare a hash must agree with the unit — a disagreeing
  hash **fails the run**; it is neither rewritten nor downgraded to `unbound`. Correcting a hash is
  forging evidence, whichever direction it is "fixed". The consequence fields stay optional and
  coexist with `candidate_cwe`: mechanism (how the boundary failed) and consequence (what it can
  expose) are two different answers, and neither overwrites the other.
- **`unbound` means unknown, never "passed".** A v1 payload has no hash, loads with
  `source_binding="unbound"`, and must not be handed a hash it never had. The field proves **text
  binding** only: not reachability, not guard dominance, not attacker control, not impact.
- **The catalogue is still the detector's, not the schema's.** `reviewed_consequence()` returns an
  impact only if this detector's versioned catalogue reviewed it, and maps the catalogue's own
  `unknown` sentinel to `None` so no consumer can sort an unclassified consequence as a category.
  The catalogue's internal consistency is asserted at import time, not at the first finding.
- **Cross-version comparison is named, not silently allowed** (`compare.py`): a v1-vs-v2
  comparison runs, records `schema_versions`, and adds a `CROSS-VERSION COMPARISON` limitation —
  row counts and locations stay comparable, IDs do not.
- **What did not change.** Every status semantic of v0.4/v0.3 is restated in contract v2 §4:
  `completed` is not safe, an empty finding list is not proof of safety, an unsupported language is
  `not_applicable` rather than a miss, and a consequence is a possibility until the Evidence gate
  is met. Providers (`src/providers/*`) stay at `schema_version=1`: a third-party tool's raw output
  cannot be claimed as bound to a source revision by us.
- **Tests**: `tests/test_contract_v2_source_binding.py` (25 items covering each bullet of contract
  v2 §7), plus machine-readable assertions in `tests/test_ipc_disclosure_consequence.py`. Full
  suite **323 OK**.
- Limits: a v1 payload still has no binding, and can only be labelled `unbound`; the comparison
  names a version split without blocking it; `source_sha256` binds the *scanned* text and does not
  by itself prove which upstream commit that text came from (the Git-side chain is M1's
  `git_source.py`, not yet joined to this one). Contract: `docs/contracts/ohscanner_detector_contract_v2.md`.

---

# IPC method card v0.4 — bounded macro expansion (2026-10-11)

- Detector: `ohscanner.interface.ipc` 0.2.0; model unchanged (`oh-ipc-2026.10-v1`). New module:
  `src/ohscanner/detectors/interface/cpp_macros.py`. No public contract, schema or CLI change.
- **What it is.** A token-level expander over `#define`s collected from the scan's own sources,
  with a per-character map back to the original line. **What it is not:** a preprocessor.
  `#include` is never followed; conditional definitions are recorded, never selected; variadic /
  stringify / token-paste definitions and conflicting definition variants are refused, not guessed.
- **Why it is here**, stated against the measurement rather than the intention: it was ported to
  close two gaps at once, and on ten real components **one of them did not materialise**.
  - Parse coverage: **+83 complete parses (4,384 → 4,467, +1.9%)**, gained only from expanding
    statement-carrying macro arguments. Made **monotone** by a gate — an expansion that turns a
    parseable file into a partial one is dropped (29 drops corpus-wide), so coverage can never
    regress.
  - The "guard hidden in a macro" false-negative source: **absent in this corpus.** 12,716
    invocations expanded, 3,645 of them carrying control flow (`return` / `if`), and **zero**
    introduced a call the policy models as an authorization guard — hence a candidate delta of
    exactly **0** on all ten components (88 → 88, no rule changed count).
  - The competing explanation was measured and excluded, not assumed away: of **314 refused**
    macro definitions, **0** mention a modelled guard callee. So the pattern is genuinely not
    there, not hidden behind the refusals. OpenHarmony's variadic macros are logging and
    error-code checks (`CHECK_AND_RETURN`-style), whose guard is an error code, not a permission.
- **Deviations from the ported source, both deliberate.** An invocation is replaced whole, argument
  list included (round1 replaced only the macro-name token, so `#define CHECK(x) Allowed(x)`
  invoked as `CHECK(c)` became `Allowed(c)(c)`). And refusals are split into *fatal* (the file
  falls back to its unexpanded bytes) and *refused* (one macro left as written) — round1 collapsed
  both and blocked the whole file, so a single ambiguous `LOG` cost the file every other expansion.
- **Kept for a structural reason, not for a finding.** The mechanism is proven to work where the
  pattern occurs: with expansion off the candidate is reported, with it on it is not, and the
  control source with the macro removed still reports. That makes a class of false positive the
  competition penalises — reporting an unguarded path that the source does guard — structurally
  impossible. **No candidate was added or removed by this round.**
- **Orthogonal to the entry index, measured.** `analysis` parses expanded text while `entry_index`
  parses raw text; a probe builds both on all ten components and compares roots and dispatch edges
  — **0 gained, 0 lost on every component**, including the 186-file, 6,126-invocation
  `security_access_token` and the 497-root `window_window_manager`. The coupling remains a known
  design point; it did not fire on this corpus.
- Limits: the catalogue is the scan's visible sources, never an include resolution; 5 components
  hit the 400-source / 6 MB budget; a guard inside a macro whose callee is outside
  `IpcPolicy.boolean_permissions | result_permissions` (e.g. `IsCallerValid`) still creates no
  authorization fact and stays a `dispatch_binding` obligation. Report:
  `docs/research/ipc_scanner_v0_4_macro_expansion_2026-10-11.md`.

---

# IPC method card v0.3 — consequence dimension (2026-10-11)

- Detector: `ohscanner.interface.ipc`; model `oh-ipc-2026.10-v1` plus a versioned
  **consequence catalogue** in `models.py`. No public contract, schema or CLI change.
- **Why a second dimension.** The competition scores CWE accuracy and completeness
  separately, and a candidate answers two different questions: *how* the trust
  boundary failed (the mechanism) and *what it can expose* (the consequence). The
  mechanism CWE alone cannot answer the second, and the second does not follow the
  family. Of the 39 advisory records in the corpus, **15 name information disclosure
  or an out-of-bounds read as the official impact**, spread over AUTH-02 (10),
  DATA-01 (6), AUTH-03 (5) and AUTH-04 (1); **4 of the 12 verified S2 pairs** are in
  that set.
- **Classification.** `consequence_for(rule, calls)` promotes a finding to
  `information_disclosure` when its modelled operation is one of the reviewed
  read-type APIs (`DISCLOSURE_CALLS`), whatever the mechanism was; otherwise the
  rule's baseline applies (`boundary_bypass`, `unauthorized_effect`,
  `restricted_category_access`, `identity_confusion`, `cross_principal_effect`,
  `out_of_bounds_read`, `capability_exposure`). The call that drove the promotion is
  recorded, so the classification can be reviewed rather than trusted.
- **A CWE only where the catalogue can justify one.** `information_disclosure` →
  CWE-200, `out_of_bounds_read` → CWE-125, `capability_exposure` → CWE-668. The other
  consequences are named without a number, because their CWE depends on what the path
  reaches and asserting one would be over-claiming.
- **The mechanism CWE is unchanged.** `candidate_cwe` still answers *how*; the
  consequence is a second, different answer carried in the finding message and in a
  dedicated `consequence` obligation, never a replacement.
- Measured on production code of ten real components (5,270 files): 88 candidates,
  **0 without a consequence**; `information_disclosure` appears on **two different
  rules** (`ipc.auth.missing` 3, `ipc.relay.descriptor-boundary` 2), which is the
  measured form of "disclosure is not confined to one family".
  Report: `outputs/reports/consequence_dimension.md` (ignored artifact,
  regenerate with `research/experiments/interface/ipc/measure_consequences.py`).
- **A consequence is a possibility, not an established effect.** Calling a read API
  does not show that anything was returned to an unauthorized caller; only the
  evidence gate can promote it. The finding stays `candidate/unassessed`.
- **Known gap, raised as a CCR:** the consequence is only machine-readable through
  the message text, because `DetectorFinding` has a single CWE field. The measurement
  treats a candidate with no recoverable consequence as a hard failure rather than
  silently counting zero. See `docs/contracts/ohscanner_detector_contract_v1_consequence_ccr.md`.

---

# IPC method card v0.2 — entry discovery (2026-10-10)

- Detector: `ohscanner.interface.ipc` 0.2.0; model unchanged (`oh-ipc-2026.10-v1`). New module:
  `src/ohscanner/detectors/interface/entry_index.py`. No public contract, schema or CLI change.
- Entry discovery replaced a hardcoded name allowlist (`OnRemoteRequest` / `*Inner` in `*Stub` /
  `IpcPolicy.service_entries`) with a source-derived dispatch index:
  - **Dispatchers by signature, not by name**: a member taking `(uint32_t code, MessageParcel&,
    MessageParcel&, MessageOption&)`. This is what reaches `IPCObjectStub::SendRequest`, whose class
    does not contain `Stub` and whose name is not `OnRemoteRequest`.
  - **Code-to-handler bindings** recovered from the four shapes that actually occur: a
    member-function-pointer table initialised in a *constructor*, a callable table filled by
    `map[CODE] = std::bind(&Cls::Fn, this, ...)`, `switch (code)` cases (returning the handler or
    calling it with parsed business objects), and `if (code == X) { return Handler(...); }`.
  - **Preprocessor context is recorded, never decided**: a case inside `#ifndef CONFIG_IPC_SINGLE`
    carries that condition on the entry; reachability under a build configuration is not asserted.
  - **Graded evidence**: `source_dispatch` > `source_dispatch_case_call` > `virtual_override` >
    `unresolved_handler`. Ambiguous overloads, unresolvable transaction codes and maps that are
    defined but never dispatched are emitted explicitly; nothing is guessed.
  - **Cross-file and one-hop delegation**: a dispatch-bound handler is admitted as a root even when
    defined in another file; `Type::GetInstance()->Method` is followed only when the receiver type is
    source-backed (object macro or explicit qualified receiver) and the target has exactly one
    definition. No general cross-file name resolution was added, and `resolve()` is still same-file.
- **Dispatcher-level guards are not modelled.** Where a dispatcher guards before dispatch (e.g.
  `IsCallerValid()` / `IsPermissionGranted(code)`), the resulting candidate is classified
  `AUTH-04 / ipc.auth.guard-coverage` — the uncertainty is coverage, not absent authorization — and
  carries a `dispatch_binding` obligation. It is downgraded in classification, never suppressed.
- Measured (ten real components, production code only, 5,270 files): 135 dispatchers, 592 bindings,
  690 source-derived entry roots against 109 for the old predicate; 72 unresolved transaction codes.
  Historical S2 roots indexed at their own revisions: 58 sample×revision records, 33 source-derived,
  25 reachable only because `models.py` names them, 0 unreached.
- Parser fixes required to reach that coverage: statement-carrying macro arguments
  (`ENGINE_CHECK(cond, return ret, "msg")`) and `(this->*(iter->second))(...)` both broke the parse of
  the very functions being sought; both are now normalised byte-for-byte, each recorded as a
  limitation rather than assumed away.
- Limits: no macro expansion, overload resolution or virtual-dispatch proof; `->*` targets are
  confirmed textually because they are error nodes; entries are not reachability; three components
  have no dispatcher source in-repo (IDL-generated). Report:
  `docs/research/ipc_scanner_v0_2_entry_coverage_2026-10-10.md`.

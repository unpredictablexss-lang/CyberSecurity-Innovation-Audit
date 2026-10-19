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

# IPC method card v0.13 — a candidate is read at the revision it was found in (2026-10-14)

The dsoftbus round reviews four candidates, and has to settle which revision they came from
before any judgement. Full record: `docs/research/ipc_dsoftbus_deep_review_2026-10-14.md`.

- **The reading error, and the rule that follows.** The working tree sat at `9f922677` while the
  run declared `652f88e0`; neither is an ancestor of the other and 89 files differ, so reading the
  tree put every line number seven lines out (`ReadInterfaceToken` at 384 rather than 391). The
  candidates' own `source_sha256` settle it, and they match the pinned blob. The tool never had
  this problem — `audit.py` plans with `ls-tree -r -l <commit>` and reads blobs by OID,
  `git_source.py` verifies the commit — so this is a **reading rule, not a code fix**: locate a
  candidate by its recorded hash, read `git -C <repo> show <commit>:<path>`, and treat a working
  tree as unusable as evidence.
- **Two CAP-01 candidates are false positives with a checkable reason.**
  `softbus_server_stub.cpp:2174/2191` anchor on `reply.WriteRemoteObject(object)` inside
  `GetSoftbusSpecObjectInner`/`GetBusCenterExObjInner`, but the guard is one frame up and
  dominates: `:391` compares the interface token, `:403` `CheckPermission(code)` resolves a
  per-code permission at `:294-297` (`DISTRIBUTED_DATASYNC` / `DISTRIBUTED_SOFTBUS_CENTER` /
  `ACCESS_SERVICE_DM`) and verifies it against `IPCSkeleton::GetCallingTokenID()` through
  `SoftBusCheckIsAccessAndRecordAccessToken`, whose body is a real
  `AccessTokenKit::VerifyAccessToken`; `:416` is the only dispatch point, with no path around it.
  Mechanism M4. This confirms the 2026-10-11 review's §2.3 judgement independently and supplies
  the pinned line numbers and the dominance argument.
- **Two AUTH-01 candidates are an external gap, not a false positive.**
  `bus_center_ex_obj_stub.cpp:56` and `trans_spec_object_stub.cpp:62` override `OnRemoteRequest`
  and forward the raw parcel through `dlsym` into `libdsoftbus_server_plugin.z.so`. Four checkable
  items bound the gap: neither symbol is implemented in the tree; no `.gn`/`.gni` builds that
  library; the IPC framework's `SendRequestInner` (`ipc_object_stub.cpp:393-409` @ `bbb92dbb`)
  performs no token check of its own, so overriding the stub is not backstopped; and the in-repo
  `TransSpecObject` answers all 16 methods with `SOFTBUS_NOT_IMPLEMENT`. Reachability is bounded
  from the export side — a caller must pass the §2.1 permission gate to obtain the handle — and
  whether the plugin re-checks per call cannot be decided without it. Both stay
  `plausible but unproven` and are **kept**.
- **Nothing is promoted.** Four candidates remain `evidence_type=syntax`,
  `validated_vulnerability` 0. The two external gaps are not written as vulnerabilities.
- **Two contract questions raised, not applied:** a distinct obligation kind
  `implementation_outside_scope` for the dlopen-forwarder shape (the fact is mechanically
  decidable from the entry index, so the detector can record it instead of leaving
  `guard_effectiveness: unknown`), and separate counting of `false_positive` versus
  `unresolved_external_dependency` — merging them understates accuracy and aims the improvement
  work at the wrong place. Report §3 has both.

> **2026-10-14 状态**：dsoftbus 深审由队友 B 提交，未推送、未合并；两项契约提议待 owner 决定。

---

# IPC method card v0.12 — private-parse coverage raised, without moving a single candidate (2026-10-14)

`normalize_syntax` rewrote a format width macro only when a literal sat on **both** sides, and it
matched the PRI family alone. The common OpenHarmony spelling puts the macro last in the sequence
— `COMM_LOGE(TAG, "count=%{public}" PRIu32, n)`, because the comma follows it — and no SCN form
was matched at all, so `sscanf_s(p, "pkg_%" SCNd64 "_%" SCNd64, ...)` failed twice over. The token
then reached tree-sitter as a bare identifier between literals, the **private** parse (the one that
decides which `function_definition` nodes are inspected) fell to partial, and only the error-free
functions of that file were read.

- **What changed.** The family is now `PRI|SCN` with the `LEAST`/`FAST` widths, and the rule fires
  when a literal *precedes* the token, with or without one following. The replacement is `""` plus
  the same number of spaces, so byte offsets and newlines are unchanged and the original text stays
  intact for evidence.
- **Measured.** Private-parse coverage over the 5261-file corpus **83.3% → 86.0%**; **146 files
  rescued, 0 lost** (strictly monotone); candidate-carrying files go from 8/11 parseable to
  **11/11**. Candidate delta **0**.
- **The zero is established, not assumed.** A baseline re-run with the pre-change rule and an
  otherwise identical driver, over the same four components, commits and scope, produces an
  identical candidate set — same keys, same fields, same `obligations_source`, same messages. The
  detector still walks the error-free functions of a partially parsed file, and none of the current
  23 candidates (sat 3, dsoftbus 4, update 2, wwm 14, kv 0) sits in a function the old rule reached
  differently. This is a coverage fix, not a finding fix.
- **It also settles an attribution.** The deltas against the stale `outputs/reports/` set
  (sat 20 → 3, wwm 15 → 14, and the `driver_synthesized_unknown` → runner-obligations flip) come
  from the **rule/model version** (0.3.0/v1 → 0.5.0/v3, i.e. M1 and the platform change), not from
  this normalization: the same committed comparison that shows zero delta here shows those deltas
  there. Recording a coverage improvement as if it had changed the findings is the misreporting the
  competition penalises.
- **Tests.** Three shapes that must not already parse, four controls that must come back
  byte-identical (`#include <inttypes.h>`, `(int)PRIu32`, `"a" PRIORITY`, `SCANNER`), and offset
  preservation on a real softbus excerpt. The "must not already parse" assertion needs a
  bytes-as-written parse, so the test module grows a `parses_raw` helper — `parses_clean` normalizes
  first and can only state the after condition. Full suite **454 OK**.
- **What is not established.** The rule is a lexical model of a macro that is never expanded; a
  definition legitimately ending a literal sequence without an intervening comma would be rewritten
  too. It raises what the interpreter can *read*, and says nothing about guard meaning, dominance or
  reachability.

> **2026-10-14 状态**：由队友 B 单独提交，未推送、未合并。

---

# IPC method card v0.11 — the CCR's clause (b) landed upstream, and the flip is applied here (2026-10-13)

The owner's platform change (`022c022`, core) records evidence obligations **for a blocked run**
instead of dropping them together with the coverage counters, and separates "inspected but
incomplete" from "never inspected" per file. That is clause (b) of
`docs/contracts/ohscanner_blocked_run_coverage_ccr.md`; §3.2 of that document is a pre-written table
of exactly which assertions must flip when it lands, and this applies it.

- **The driver's behaviour does not change.** Its synthesis gate was already
  `if not entry["obligations"]`, so the "never duplicate recorded evidence" invariant held before
  this commit. What moved is the prose describing the old platform, the assertions that pinned it,
  and a new control that keeps the fallback path itself pinned
  (`test_driver_standing_questions_appear_only_without_a_runner_record`, exercised by stripping the
  runner's record and asserting the driver still fills the gap).
- **`DRIVER_STANDING_OBLIGATIONS`** (was `PARTIAL_ONLY_OBLIGATIONS`) is no longer partial-only: the
  five standing questions are what the driver supplies when, and only when, the runner recorded
  nothing.
- **What stays pinned, deliberately.** `scope_files == 0` on the blocked pass is **not** flipped:
  clauses (a) and (c) are not done, so that zero must still be printed next to the counts that say
  what was actually done.
- **Candidate set and identities unchanged.** Obligations are metadata: this adds and removes
  nothing, and `validated_vulnerability` stays 0. Tests at the time: **451 OK**.

> **2026-10-13 状态**：由队友 B 提交，未推送、未合并；CCR 条款 (a)/(c) 仍未落地。

---

# IPC method card v0.10 — M2: a one-hop same-file relay is not an unguarded boundary unless the callee is the guard (2026-10-12)

v0.9 changed how one comparison is *read*. This changes whether a path is read as
*guarded at all*, in one place: the entry that only forwards the request.
Full record: `docs/research/ipc_m2_relay_guard_2026-10-12.md`; reproducer:
`research/experiments/interface/ipc/m2_platform_delta.py`.

- **What was wrong.** The AUTH-01 relay predicate asked whether *this entry's own state* had
  established a descriptor check. `OnRemoteRequest` that only hands the request to
  `OnRemoteRequestInner(code, data, reply, option)` has no check in its own body by construction, so
  the guard one call away was reported as absent
  (`screen_session_manager_stub.cpp:42`, guard at `OnRemoteRequestInner:50`).
- **What a relay has to satisfy to count.** Five conditions, all structural, all with a fixture that
  breaks exactly one: the callee is in the **same file**; **every argument is one of the caller's own
  parameters** (a substituted literal is a different transaction); the callee has a **top-level**
  comparison of `ReadInterfaceToken()` against a descriptor identity — a nested one does not dominate
  the dispatch; the identity is one M1 **accepts**; and the mismatch branch **leaves** (top-level
  `return`/`throw`) **before** the `switch`. Locals on the way to the comparison are bound
  (`token = data.ReadInterfaceToken();`), so the common two-statement form is read the same way.
- **Three outcomes, M1's vocabulary.** Guarded → the call site is not a boundary and nothing is
  reported. Comparison present but identity not accepted → the candidate is **kept**, its message
  says *present but not accepted*, and both identities are cited with the same obligations M1 added.
  Anything else → the call site stays a candidate.
- **Measured through the official path**, over exactly the scope the M1 platform reports persisted,
  at the same commits: `window_window_manager` **15 → 14** (one AUTH-01 removed, 0 added, 0 reworded);
  the other four components identical item by item (3 → 3, 4 → 4, 2 → 2, 0 → 0). The removed candidate
  is the one M1's report §6 attributed to M2. `commit`, `snapshot_sha256` and the file's
  `source_sha256` are unchanged between the two runs; only the detector version moved 0.4.0 → 0.5.0.
- **Nothing is lost by removing it.** `OnRemoteRequestInner` is already an entry root in its own right
  (`*Inner` in a `*Stub`), so its own observations survive: the file still reports twice
  (`:738` AUTH-02, `:1778` CAP-01).
- **Controls are discriminating, not decorative.** Run the same eight fixtures against the pre-M2
  engine and exactly the two `_fixed` cases plus the wrong-interface message assertion fail, while the
  five pure positives pass both before and after.
- **What is not established.** The corpus exercised only the *guarded* outcome: every real one-hop
  guard compares an identity M1 accepts, so the "present but not accepted" branch and the
  local-variable binding rest on fixtures alone. Cross-file delegation is untouched (that is M6), and
  "top-level + before the switch + the mismatch branch leaves" is a structural rule, not a bounded
  dominance proof (that is M5) — `goto`, exceptions and macro-expanded control flow are not covered.
  A callee reached from other entries is judged per call site, not inferred globally.
- **Rule identity moved:** detector `0.5.0`, model `oh-ipc-2026.10-v3`. Tests: 401 in the interface
  line (10 new, 8 fixtures added to the semantic matrix, manifest 40 → 48 rows).
- **Next, in the owner's order:** M5 (bounded dominance) → M3/M4 → M6.

> **2026-10-12 状态**：M2 由队友 B 单独提交，未推送、未合并；M3–M6 仍待做。

---

# IPC method card v0.9 — M1 landed alone: the descriptor guard is read as an interface identity (2026-10-11)

v0.8 diagnosed M1 but changed no rule. This is M1, as one commit that touches no other family.
Full record: `docs/research/ipc_m1_descriptor_identity_2026-10-11.md`; reproducers:
`research/experiments/interface/ipc/m1_platform_delta.py`, `m1_removal_basis.py`, `m1_record.py`.

- **What changed.** `descriptor_expectation()` reads the comparison as one of four subjects:
  `unqualified`/`self` (accepted), `interface` (accepted, and the message says where the class
  states it), `mismatch` (kept as a candidate that cites *both* sides), `unresolved` (stays
  `unknown` — neither a working guard nor a proven mismatch). The identity comes from the class's
  own `IRemoteStub<T>` base clause, collected recursively by `implemented_interfaces()`, **never
  from the class name**: `IRemoteStub<OnPermissionUsedRecordCallback>` has no `I` prefix, and
  `TokenSyncCallbackStub` implements `ITokenSyncCallback`, not an eponymous interface. An alias base
  yields `unresolved` rather than a guess. `refine()` no longer records an unaccepted comparison as
  a guard; it records it as a `descriptor_issue` so "seen but not established" survives.
- **A correct call is still not a guard.** Four controls pin that M1 did not loosen the path
  semantics: fetch-without-compare, a mismatch branch that only logs, a guard after the operation,
  and a guard on one branch only. All four still report AUTH-01.
- **Measured through the official path**, not a private harness: `python -m src.cli ohscan-run
  --detector ohscanner.interface.ipc` over exactly the baseline's explicit `--include` paths, at the
  same commits, keyed the way the project's own regression script keys candidates
  (file, line, rule_id, source_sha256 — deliberately excluding `rule_version`, with reworded reasons
  reported separately). `security_access_token` **20 → 3** (17 AUTH-01 removed, 0 added, 0 reworded);
  `window_window_manager` 15 → 15, `communication_dsoftbus` 4 → 4, `update_updateservice` 2 → 2,
  `distributeddatamgr_kv_store` 0 → 0 — the other four components are identical item by item, so the
  change is surgical and its boundary is visible.
- **Every removal cites the guard that removed it.** A file can hold several stub classes
  (`accesstoken_callback_stubs.cpp` holds two, each with its own guard), so the citation must come
  from the entry the candidate was reported under, not from the first comparison in the file:
  `TokenSyncCallbackStub::OnRemoteRequest` guard at `:70` → `GetRemoteHapTokenInfoInner` called at
  `:78` → handler body at `:103`; `token_sync_manager_stub.cpp` guard `:42`; privacy's guard `:35`,
  against an interface with no `I` prefix. All 17 verified: identity agrees on both sides, guard
  precedes the candidate, the mismatch branch returns, and the file's bytes match the checksum the
  candidate was bound to.
- **Three of the 17 were M3's mechanism, not M1's.** `token_sync_manager_stub.cpp:83/110/127`
  reported `IsRootCalling` — the authorization predicate — as a handler. M1 removes their AUTH-01
  observation because the entry's guard dominates that path; **M3's defect is not fixed**, and the
  disappearance of the symptom must not be read as the fix.
- **What is not established.** Zero candidates *added* and zero *reworded* means the corpus never
  exercised the new `mismatch`/`unresolved` message branches — those two outcomes rest on fixtures
  only. The 24 survivors are the ones M1 cannot address: a check delegated one call away (M2,
  `screen_session_manager_stub.cpp:42` → `OnRemoteRequestInner:50`), an unmodeled authorization
  predicate (M3), indirect `dlsym` dispatch with no comparison in the analysed file
  (`bus_center_ex_obj_stub.cpp`, `trans_spec_object_stub.cpp`), and dominance (M5). Dominance is
  checked by the same structural rule for all 17, so what a guard *means* beyond identity — whether
  the token could be empty, whether the caller controls it, whether another entry bypasses the
  function — stays in EvidenceObligations.
- **Rule identity moved:** detector `0.4.0`, model `oh-ipc-2026.10-v2`; two new per-observation
  obligations, `descriptor_identity_mismatch` and `descriptor_identity_unresolved`. Tests: 391 in
  the interface line (16 new descriptor-identity tests, 11 fixtures in the semantic matrix,
  manifest 29 → 40 rows); 350 on the integration-based branch.
- **Next, in the owner's order:** M2 (same-file one-hop delegation) → M5 (bounded dominance) →
  M3/M4 → M6. Not started here.

> **2026-10-11 状态**：M1 由队友 B 单独提交，未推送、未合并；M2–M6 仍待做。

---

# IPC method card v0.8 — the first candidate review moved the failure from the candidates to the rules (2026-10-11)

Owner's next step was to stop widening the scan and to review the first representative candidates,
so the review that follows is the deliverable, not more candidates. All 41 were reviewed (not
sampled): **37 likely false positives, 4 plausible-but-unproven, 0 confirmed**. Full record:
`docs/research/ipc_candidate_review_2026-10-11.md`; reproduction scripts:
`research/experiments/interface/ipc/review_*.py`.

- **No rule was changed by this review.** Changing a rule moves the candidate set, so it lands
  separately with its own positive/fixed/safe controls and a five-component re-run. This card is a
  record of *why* the rules misfire, with file:line, not a claim that they are fixed.
- **M1 — the descriptor check is discarded by an identity test aimed at the wrong class.**
  `analysis.py:582-585` accepts `X::GetDescriptor()` only when `X == fn.owner`. A real stub lives in
  `TokenSyncCallbackStub` and implements the interface `ITokenSyncCallback`, so the qualifier never
  matches and the guard becomes `UNKNOWN`. Control experiment (relax only that test, nothing else):
  `security_access_token` goes from **6 AUTH-01 candidates to 0**. Measured: 9 of that component's
  12 descriptor comparisons are interface-qualified — while **all 28 fixtures use the unqualified
  form**, which is why 29 design scenarios passed and the corpus shape was never exercised. The
  interface identity *is* source-derivable (the `IRemoteStub<I>` base-class argument:
  `IRemoteStub<ITokenSyncCallback>`, `IRemoteStub<OnPermissionUsedRecordCallback>`), and a
  name-based `FooStub -> IFoo` guess would **fail** — the second example has no `I` prefix.
- **M2 — the check is delegated one call away.** `screen_session_manager_stub.cpp:42` is a relay;
  the descriptor check is in `OnRemoteRequestInner:50` of the same file, so the root state has none.
  Reproduced with a probe that prints the interpreter's own descriptor set.
- **M3 — the authorization vocabulary is a fixed list of names.** `models.py:130-135` plus the
  hard-coded names in `analysis.py:596-601` cover `CheckPermission`/`VerifyPermission`/
  `VerifyAccessToken`/(`IsSystemAppCalling`, `IsPrivilegedCalling`, `IsAccessTokenCalling`, ...) but
  none of `IsRootCalling`, `IsNativeProcessCalling`, `IsCallerValid`, `IsPermissionGranted`,
  `IsSystemCalling`, `IsSACalling`. The component proves both directions of this in one repo:
  `accesstoken_callback_stubs.cpp` uses `IsAccessTokenCalling()` (recognised) and produces no
  AUTH-02; `token_sync_manager_stub.cpp` uses `IsRootCalling()`/`IsNativeProcessCalling()`
  (unrecognised) and produces three. The rule also misfires *inversely*: AUTH-01 reports the guard
  helper itself as the reached handler (`... reaches ... without interface-descriptor validation:
  TokenSyncManagerStub::IsRootCalling`). "A check exists but was not recognised" is not "no check".
- **M4 — a recognised permission function compared against a project error enum is not recognised.**
  `CheckPermission(code)` is in the vocabulary, but the call site is `if (ret != SOFTBUS_OK)`, and
  `SOFTBUS_OK = 0` is an enum member in *another file* (`softbus_error_code.h:1788`). The success
  test only accepts `0`/`PERMISSION_GRANTED`/`true` literals.
- **M5 — the dispatcher guard's dominance is unproven, and the rule says so.** The
  `update_updateservice` candidates carry `dispatcher-guard-observed`: the detector *saw* the guard
  and still emitted, because dominance over the transaction was not established. Checked by hand:
  the guards really do dominate (`update_service_stub.cpp:421-426` precede the single dispatch at
  `:432`, and the dispatch is a `map.find` + member-pointer call with no bypass). The improvement is
  to *prove* dominance per dispatch shape and to record "dominates" separately from "exists,
  dominance unknown" — not to drop the candidate.
- **M6 — the guard lives in the implementation class, in another translation unit**
  (`window_manager_stub.cpp:389` -> `window_manager_service.cpp:1608`). That is file-local analysis
  behaving as designed, not a defect; the bounded improvement is one controlled hop from a stub
  method to its same-named implementation, recorded with provenance like the alias table.
- **Partial parses are caused by three mechanical shapes, not by `#if` nests.** Reproduced with the
  project's own parser, printing every ERROR node: format-macro string concatenation
  (`PRIu64`/`PRIu32`/`SCNd64`), the member-pointer call `(this->*f)(...)`, and **`return` used as a
  macro argument** (`ENGINE_CHECK(cond, return ret, "...")` — 20 ERROR nodes in one file). None of
  those lines is near the candidates in the same file, and `update_service_stub.cpp`'s candidates
  are anchored on `dispatch=map_member_ptr`, i.e. the entry index recovered the dispatch binding and
  the dispatcher guard *despite* the partial parse. **Partial affects the coverage counters and the
  provenance of obligations; it is not the cause of these candidates.**
- **What the review argues for, in cost order:** fix M1 (removes ~20 of 41 and *raises* accuracy,
  since today it reads "checked" as "unchecked"); prove M5 dominance; extend M3 to local helper
  predicates and record each predicate's own criterion, plus a "is this a dispatch target" test for
  AUTH-01; normalise the three parse shapes; bounded cross-file constants for M4; one hop for M6.
  What it argues against: deleting M1's qualifier test (that would also erase the stronger "compared
  against the wrong interface" finding) and dropping M5's candidates (which are honest).
- **The four candidates worth following — none is a vulnerability claim:** the only export with no
  caller check anywhere on the path (`screen_session_manager_stub.cpp:1778`), `session_stub.cpp:592`,
  and the two dsoftbus stubs that genuinely skip the descriptor check and bypass
  `IRemoteStub<T>`'s default. All four stop at the same wall: the capability surface is outside this
  repository (the dsoftbus plugin `.so`, `foundation/graphics`) and needs cross-repo source or a
  runtime observation.

---

# IPC method card v0.7 — partial candidates carry obligations, identity is bound, counts close (2026-10-11)

Owner decision that produced this card: accept the five-component round as a **real-component audit
experiment**, into pending review — **not** as a formally integrated detector. **Stop expanding
rules.** The owner fixes the shared platform's expression of partial coverage and its retention of
obligations; this branch supplies the counterexamples, the obligations for partial candidates, and
the regression tests. The two-pass scheme is demoted to a **control experiment**, not the long-term
path. Also required: report test count / candidate count / confirmed count **separately**.

- **Partial-only candidates no longer carry a blank obligation list.** The shared runner emits
  obligations only for a `completed` run, so the `blocked` pass's candidates had none — and the CCR
  measured that an empty list reads as "nothing needs proving". The driver now synthesises five
  **standard questions** for any candidate the runner recorded no obligation for:
  `entry_reachability`, `caller_identity_conditions`, `guard_effectiveness`,
  `parse_completeness_impact`, `configuration_path_existence`. Status is `unknown`, origin is
  `audit_driver`, and each is a **question, not an assertion** — which is why a partial file may
  legitimately carry it. The driver fabricates no AST fact. An empty list is never "nothing to
  verify"; `parse_completeness_impact` says so explicitly (a partial AST can hide statements, so
  the candidate is **kept, not cleared**).
- **Candidate identity is now bound to repository, full commit and rule version.** Key:
  `(repository, commit, rule_id, rule_version, file, line, source_sha256)`. `merge_shard_runs`
  records `rule_version` / `model_version` / `observed_detector_versions` / `observed_detector_ids`
  / `sources` per candidate, and `merge_audit_reports()` merges **across reports** on the same key.
  Obligations are **unioned per source** and never overwritten by a later pass.
- **A real identity split, caught by the fixture.** Putting `rule_version` (built from
  `detector_id@version`) into the key split every both-pass candidate into two rows — the fixture
  went 4 → 7 candidates — because the two passes had different detector IDs. The distinction that
  matters is the **interpretation**, not the variant: both passes now declare
  `interpretation_id = "ohscanner.interface.ipc"`, so one interpretation at two scope limits stays
  **one row**, with the variant id kept as recorded metadata. Corollary, and the reason this is
  written down: **a genuinely different algorithm must declare a different `interpretation_id`**,
  or it will be silently merged with this one.
- **File accounting closes, and it is displayed.** `bucket_closure` splits planned files into six
  named buckets — `parse_complete`, `parse_partial`, `parse_failed`, `unclaimed_by_detector`,
  `dropped_by_loader`, `not_run_files` — with the residual in `files_unaccounted` printed
  separately rather than folded into another bucket. Building this found a **real attribution
  bug**: a non-UTF-8 `.cpp` dropped by the shared loader was being counted as "no detector claims
  it" although `cpp` is a declared language; the unclaimed bucket is now **declared-language**
  based and that file lands in `dropped_by_loader`. Across the five components every bucket total
  closes (`files_unaccounted == 0`); `parse_failed` / `dropped_by_loader` / `not_run_files` are 0
  by measurement, not by omission.
- **Report schema v2 counts three things separately.** `counts` gives `source_files_audited`,
  `candidates`, `candidates_with_runner_obligations`,
  `candidates_with_driver_synthesized_obligations`, `confirmed_vulnerabilities`,
  `false_positives_reviewed`; the console prints them on separate lines. Test count, candidate
  count and confirmed count are never collapsed into one number.
- **Artifacts are persisted, with provenance.** Default out-dir `outputs/reports/` (gitignored),
  plus a `*.manifest.json` per component: commit / git tree / snapshot / plan sha, argv, cwd,
  Python + platform + git versions, counts, bucket closure, and the **sha256 of the JSON and MD
  artifacts**. The manifest is written next to the JSON it describes.
- **Shard wording, corrected.** v0.6 said shard invariance "is verified on real code", which reads
  as a general claim. What was actually shown is: **one component under one alternative shard
  configuration yields a consistent candidate set** (`window_window_manager`, `--max-files 600`,
  2 shards vs 1 shard, same 15 candidates, both deltas empty). That is a statement about **that
  configuration**, not a claim that arbitrary sharding is invariant. Component-global rules need
  whole-component evaluation, which this pipeline does not do, and cross-file detection needs an
  explicit **file-local vs component-global** rule-execution semantics that is not yet defined.
  This is the correction to the v0.6 bullet below.
- **Test count and candidate count, stated apart.** `tests/test_component_audit.py` **45 items**
  (+12 this round: 4 closure, 2 cross-report merge, 2 identity/variant, 2 manifest, 1 CLI counts,
  1 manifest placement); full suite **375 OK**. Five components: 4983 files, **41 candidates**
  (26 with runner obligations, 15 driver-synthesised), **0 confirmed**.
- **Still not done:** the platform change itself is the owner's (this branch only files the CCR and
  the regression tests that must flip); the detector is still not in `catalog.py` and has no CLI
  subcommand; the 15 partial-only obligations are **standard questions, not runner evidence**;
  root-cause intersection is `not_measured` in a component audit; artifacts are persisted but
  **not committed**.
- **Next work, per owner priority:** review 5–8 representative candidates (covering complete and
  partial-only) — original code and key context, false positive or not and why, upstream checks /
  call preconditions / configuration limits, how far confirmation goes, whether build or runtime
  validation is feasible. The goal is to **use review results to steer the algorithm**, not to add
  more candidates.

---

# IPC method card v0.6 — auditing a whole component, not just a fixture (2026-10-11)

- Detector: `ohscanner.interface.ipc` unchanged, plus a scope-restricted variant
  `ohscanner.interface.ipc.complete-ast` (same interpretation, `required_facts = ("ast",)`).
  New module: `src/ohscanner/detectors/interface/audit.py`. **No public contract, schema, catalog
  or CLI change.**
- **What it is.** A driver that takes a component at a pinned commit and produces one reviewable
  audit: a deterministic scope plan, an explicit list of what was read and what was not, the
  candidates with the code excerpt they were found in, and the coverage table. It answers
  "what did this component yield, and what did we not look at", for any component — not the
  question "is this component safe", which it refuses to answer.
- **Why two passes.** `ohscanner.interface.ipc` returns `blocked` on any partial parse, and the
  shared runner then does three things at once: `scope_files`/`scope_loc` become 0, every
  applicable file is marked `not_analyzed`, and `evidence_obligations` are not emitted (they are
  gated on `report.status == "completed"`). Measured on `communication_dsoftbus`: 4 candidates
  were still produced while their obligations were an **empty list**. A conservatism that drops
  the proof obligations of findings it did produce is not conservative — it removes the review
  chain. The driver therefore runs the same shard twice: a `complete-ast` pass that *completes*
  (real scope counters, obligations recorded, incomplete files declared `unexamined:
  incomplete_ast:<status>`) and an `all-files` pass that keeps recall from partial trees but is
  `blocked`. Candidates are merged on `(file, line, rule_id, source_sha256)` and each records
  which passes saw it. The blocked pass's zero is printed **next to that pass's real
  applicable/analyzed counts**, with the reason, never alone.
- **The fix belongs to the owner, and is filed as a request, not applied.**
  `docs/contracts/ohscanner_blocked_run_coverage_ccr.md` proposes (c) a third run status
  (`partial`/`completed_with_gaps`, counted as a gap so the overall report stays
  `completed_with_limitations`) plus (b) emitting obligations from the findings rather than
  filtering them by run status. This branch changed none of `contracts.py`, `runner.py`,
  `execution.py`, `catalog.py` or the CLI.
- **Production scope is excluded by whole path segment**, not substring: `test/tests/unittest/
  mock/sample/example/demo/benchmark/fuzz/third_party/...`. A substring rule misses `/tests/`; the
  segment rule is pinned by a regression test. Sharding is deterministic (sorted paths, greedy
  split under the byte/file bounds, sha256 per shard, `plan_sha256`), and shard invariance is
  verified on real code, not only on the fixture **(scope of this claim corrected in v0.7: it is
  "one component under one configuration", not arbitrary sharding)**: `window_window_manager` at `--max-files 600`
  gives 2 shards and the **identical candidate set** (15, both directions empty) and identical
  merged coverage as the 1-shard run.
- **Files no selected detector claims are counted, not lost.** `.js/.ts/.ets` are in
  `SOURCE_LANGUAGES` but outside this detector's `("c","cpp")`, so
  `files_selected` can exceed the parse map. `files_in_scope_without_a_claiming_detector` records
  them — in scope, claimed by nobody, hence neither a miss nor an examined clean file.
- **Measured (five real components, final code, 4983 files / 51,531,827 B, all
  `validated_vulnerability: 0`, one shard each):** `security_access_token` 20 candidates
  (all complete), `window_window_manager` 15 (4 complete / 11 partial-only),
  `communication_dsoftbus` 4 (2/2), `update_updateservice` 2 (both partial-only),
  `distributeddatamgr_kv_store` **0**. Of the 41 total, **26 were seen by both passes
  (obligations recorded) and 15 appear only in partial files (obligations not recorded — flagged
  per candidate in the report)**.
- **Honesty by construction.** Excerpts are read from the pinned blob, never the worktree (a test
  rewrites the worktree and asserts the marker is absent). A shard that raises is reported in
  `shard_errors` and never rendered as "no candidates". Zero candidates renders as "not proof of
  safety". Planned-vs-actually-read is measured (`plan_vs_load`), so a dropped non-UTF-8 blob is
  visible rather than silent.
- **Tests**: `tests/test_component_audit.py` (33 items: scope/exclusion/sharding determinism,
  the two-pass merge, blocked-vs-completed counters, pinned-blob excerpts, shard failure
  reporting, the language gap). Full suite **363 OK**.
- **Not done, stated:** the detector is not registered in `catalog.py`, so the global CLI cannot
  select it (owner's decision); the driver is not a CLI subcommand; the 15 partial-only candidates
  still need manual obligations; the driver costs ~2× wall clock and one interpretation now
  carries two detector IDs (so `diagnostic_id` differs between passes); root-cause intersection is
  `not_measured` in a component audit (no labelled set is bound to a component).

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

# IPC method card v0.14 — privileged grant and observer growth (2026-10-19)

- Detector: `ohscanner.interface.ipc` 0.8.10; model `oh-ipc-2026.10-v16`. This card records two narrowly sourced models added to the B delivery branch. No public runner, contract, or CLI was changed.
- `AUTH-02 / ipc.auth.privileged-app-bypass` detects the reviewed pasteboard grant shape only when the source-backed path binds `PasteboardServiceStub::OnGetPasteData` to `PasteboardService::GetPasteData` and then to `VerifyPermission`, and the `IsDefaultIME` result reaches the grant decision. A helper's empty-allowlist behavior is recorded as evidence, not generalized as a rule based on names or a CVE ID.
- `RESOURCE-01 / ipc.resource.unbounded-observer-registration` reports only when the observer is traced from an IPC entry through `SubscribeObserver` to `AddObserver` and a container insertion is present without a recognized effective pre-insertion aggregate cap. A clear count + limit + early-return shape is a safe control. Missing path or limit facts stay as explicit obligations.
- Synthetic positive, fixed, safe-cap, unrelated-owner, and ambiguous-path controls are covered by 18 focused observer tests plus family-matrix checks. Fixed-source regression runs: CVE-2025-27247 target rule 1→0; CVE-2025-25212 target rule 1→0; CVE-2025-27563 retained AUTH-03 regression 3→0. All three component scopes remain partial and all runs are blocked; total test suite 563 OK after updating the expected detector/model version.
- Boundaries: these are source-level regression candidates against public patches, not independent holdout samples, runtime validation, ordinary-app reachability, product exploitability, or precision/recall measurements. Finding state remains `candidate/unassessed`; `validated_vulnerability` remains 0. The detector does not claim that every registry path or aggregate policy has been resolved.
- Replay JSON and this run's pinned-source identity are in `research/deliveries/ipc/20261019-disclosure-expansion-v0.8.10/`; see `PROGRAM_STATUS.md` §71 for the verification record.


# IPC method card v0.15 — AUTH-06 stays within C translation units (2026-10-19)

- Detector 0.8.11 / model oh-ipc-2026.10-v17. AUTH-06 models the C-language SoftBus authentication callback and must not parse arbitrary C++ headers with the C grammar.
- IpcInterfaceDetector now invokes the callback model only for C SourceUnits. The synthetic AUTH-06 fixtures are parsed as C; a detector-level regression asserts a C++ unit bypasses this model.
- Trigger: the CVE-2023-25176 fixed-pair replay crashed in AUTH-06 while walking a partial C++ TLV header; limiting the model to C removed that crash and allowed the DATA-05 replay to finish at 1→0.
- Remaining C++ parse errors remain partial/unknown for the C++ analysis path. This fix is a parser dispatch boundary, not evidence that the TLV component is fully analyzed or that the disclosed vulnerability is product-confirmed.

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

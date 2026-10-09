# IPC method card v0.1

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

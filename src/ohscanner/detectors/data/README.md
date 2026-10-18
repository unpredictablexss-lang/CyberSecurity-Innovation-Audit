# D: sensitive-material log exposure, v0.11.0 (retain privacy-masked sensitive flows as conditional candidates)

Proposed Detector ID: `ohscanner.data.sensitive_exposure`; first and only rule:
`data.log.sensitive-value` (provisional CWE-532). Owner ID/model review and catalog
registration are pending. Nothing is registered in the panel or global catalog.

Entry: `SensitiveExposureDetector(model=DEFAULT_SOURCE).detect(context, units)`.
Requires the existing `ast` fact. Existing Runner/ToolRunResult v2 and obligations
carry source SHA and trace; no new global schema/CLI/network/scanner invocation.

Exact default repository/commit is in models.py. Other versions are blocked until
reviewed models are supplied. Fixtures explicitly inject a synthetic model.

Algorithm: detailed Tree-sitter statement walk -> typed material fields or reviewed
callback/output argument -> local assignments/copies/formatting -> modeled HiLog operand. Public operands are direct candidates; private/default-private operands remain conditional candidates with a sink_privacy obligation. Per-operand format mapping handles %% and * width/precision;
unsupported formats become partial. No keyword password/token matching. Buffer
contents are not written to diagnostics; only symbol/location dependency steps.
Unknown wrappers retain tentative dependencies and are not assumed sanitizers.
Branch joins are may-flow, never path proof. Type binding, initialization, API
identity, return status, aliases, log runtime configuration/readers and impact
remain unknown obligations. Detailed expression facts need owner frontend review.

Use the project Python environment with requirements.txt. Local test command:
`python -m unittest tests.detectors.data.test_sensitive_exposure -v`.

Offline real-source experiment (explicitly reviewed programmatic registry):
`python -m research.data_sensitive.replay --repo-dir /path/to/pinned/dsoftbus.git --output-dir outputs/reports/d-sensitive`.
The selected paths and hashes are fixed in research/data_sensitive/source_manifest.json.
No third-party source is bundled. Obtain the official Git objects separately and
verify the exact commit; do not substitute an unrelated latest checkout.

D_REVIEW.md, D_LIMITATIONS.md and method_card.md under research/data_sensitive
explain actual results and pending acceptance. No verified real vulnerability,
independent holdout or Precision/Recall is claimed. Do not deploy as complete
whole-component taint analysis. No changes to A/B/C detectors or common platform.

D2: branch exits now explicitly remove non-fallthrough paths; lexical bindings
restore on scope exit; short-circuit/conditional effects use conservative may-flow.
D1 source/sink model semantics remain0.1.0. Old32 controls unchanged, new39 D2 controls.
Read research/data_sensitive/D2_HANDOFF.md for current publication/tests; D1 records
with push=false describe the historical pre-publication snapshot, not current PR #17.

D3 adds an explicitly selected historical profile (0.3.0 detector / 0.2.0-historical.1 model).
The default entry remains compatible. Read research/data_sensitive/D3_HANDOFF.md
for real pre/post experiments, public Runner admission limits and separate user docs.
The real pre-change candidate is research-only; no confirmed vulnerability is claimed.

D7 extends output binding for address-of local destinations and emits an unresolved
escape candidate when a modeled sensitive copy/format/source writes through a
member or otherwise unsupported destination. The change is still syntax-bounded;
it does not establish alias identity, product impact, or a confirmed vulnerability.
See research/data_sensitive/D7_IMPLEMENTATION.md and D7_VALIDATION.json.

D8 adds the fixed-source `TRANS_LOG*` and `COMM_LOG*` families plus their
conditional check-and-return wrappers. D9 adds the upstream HiLog C/C++ public
macro families with pinned format argument positions; formats remain private by
default. Unsupported/dynamic formats keep an unresolved candidate. See
`research/data_sensitive/D8_IMPLEMENTATION.md`, `D9_IMPLEMENTATION.md`, and the
matching validation records. Neither regression fixtures nor macro mapping alone
confirm a product vulnerability.

D12 retains a candidate when a modeled sensitive field is used through a same-name local type whose compiler identity is unresolved; the finding carries a `type_identity` obligation and remains candidate-only. The source model explicitly treats `SessionKey.len` as non-sensitive metadata. See `research/data_sensitive/D12_IMPLEMENTATION.md` and the pinned real-source replay; no new candidate was added to that profile.
D14 adds DSoftBus LNN/CONN/DISC, DFILE/DFINDER and FILLP wrappers plus HiLog base APIs; signatures and format operand positions were checked against pinned upstream headers and covered by regressions. D15 adds an exact-commit, exact-file AccessToken identity profile for source experiments; its one-file replay is partial/blocked and retains candidates only. AccessToken IDs are authorization identities, not bearer secrets. See `research/data_sensitive/D15_ACCESS_TOKEN_REPLAY.md` and its JSON evidence. This profile is not catalog-registered, is not a full component scan, and does not establish a vulnerability or impact.
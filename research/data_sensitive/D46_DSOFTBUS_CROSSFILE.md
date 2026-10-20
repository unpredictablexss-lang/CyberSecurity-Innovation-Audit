# D46 bounded cross-file DSoftBus replay

Date: 2026-10-19

## Scope and identity

This is a development compatibility replay against the exact openharmony/communication_dsoftbus commit 9f922677e147b939d6db899bde181d609d64711b, tree 4b114179868d96c69eedc4520037552ddc3d65dd. Six files were read from pinned Git objects with lazy fetch and network disabled. No checkout or ref was changed. The source snapshot digest is eb8b331388a31fa279d939b607ce322365bb7bccb898988f9b9e228d9e7d9168.

The selected files include the caller auth_hichain.c and auth_session_fsm.c, which defines AuthSessionSaveSessionKey, posts the save-key message, and copies the payload into a MessagePara. The DSoftBus source anchors are checked by the replay script before the model runs.

## Result

Detector ohscanner.data.sensitive_exposure 0.21.0 ran twice. Candidate identities, source hashes, and file outcomes were stable:

- five data.sensitive.unresolved-escape candidates at auth_hichain.c:136 and auth_session_fsm.c:393, :499, :508, and :1902;
- both runs remained blocked; all six selected translation units were partial;
- the clean AuthSessionSaveSessionKey and NewMessagePara body subtrees were used only as bounded may-summaries inside a partial translation unit; the caller candidate remains unresolved and exact translation-unit/build binding remains unknown;
- the trace now covers OnSessionKeyReturned argument 1 through AuthSessionSaveSessionKey, PostMessageToAuthFsm, NewMessagePara, and the memcpy_s into para.data, then reaches LnnFsmPostMessage as an unresolved message-queue boundary;
- a separate SessionKey.value copy into deviceKey.deviceKey reaches AuthInsertDeviceKeyPacked; the persistence/consumer behavior remains unresolved;
- reviewed SoftBusFree and memset_s cleanup calls are excluded as exposure sinks, while pointer/member identity limitations are retained;
- 0.57596/0.54984 seconds, 41,680 KiB process peak RSS;
- validated_vulnerability=0.

The unresolved caller candidate is retained; this replay does not establish that the key is publicly logged, readable, attacker controlled, or exposed by a product. The second candidate is also a static research lead, not a confirmed issue.

## What changed and test boundary

Detector 0.21.0 adds a bounded cross-file function-body resolver with explicit parse and memory budgets. It summarizes a uniquely name/arity-bound helper only when the parsed function body is complete, and preserves unresolved candidates when binding or body evidence is incomplete. Cross-file references make participating files partial. Synthetic tests cover a helper reaching a public log sink, a helper return reaching the caller sink, an ambiguous helper, and a same-name local function that must not be credited as a logging sink. The D1/D2/D3 sensitive-flow subset passed 72/72 tests. The full Python suite passed 944 tests (939 passed, 5 skipped); Web tests passed 18/18 and the TypeScript/production build succeeded.

The real DSoftBus source now yields bounded may-summaries from syntactically clean function subtrees inside a partial translation unit, while preserving unresolved caller and queue-boundary candidates. This is stronger path evidence, but not proof of complete translation-unit binding. The synthetic tests demonstrate analyzer behavior under controlled syntax; neither synthetic nor pinned-source candidates are product findings, independent holdout labels, or accuracy measurements. The replay is not a product PoC or fix validation. No confirmed product vulnerability is established, so a product vulnerability PoC or remediation-effectiveness claim is not supported by this evidence.

The repository audit page already exposes this detector behind an explicit opt-in checkbox; Catalog marks it research_candidate and default-off. D44 verified the plan, Worker, evidence, and report path using a synthetic fixed Git fixture. The current UI uses copy that says static findings do not confirm product vulnerabilities and will not generate an exploitable product PoC.

## Reproduction

Run from the repository root with the project test environment:

python research/data_sensitive/d46_dsoftbus_crossfile_replay.py --git-repo /home/audit/openharmony-targets/communication_dsoftbus

The JSON result records file blobs, hashes, run signatures, coverage, timing, and limitations.

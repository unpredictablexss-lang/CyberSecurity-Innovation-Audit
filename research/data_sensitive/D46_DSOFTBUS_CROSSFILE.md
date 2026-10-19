# D46 bounded cross-file DSoftBus replay

Date: 2026-10-19

## Scope and identity

This is a development compatibility replay against the exact openharmony/communication_dsoftbus commit 9f922677e147b939d6db899bde181d609d64711b, tree 4b114179868d96c69eedc4520037552ddc3d65dd. Six files were read from pinned Git objects with lazy fetch and network disabled. No checkout or ref was changed. The source snapshot digest is eb8b331388a31fa279d939b607ce322365bb7bccb898988f9b9e228d9e7d9168.

The selected files include the caller auth_hichain.c and auth_session_fsm.c, which defines AuthSessionSaveSessionKey, posts the save-key message, and copies the payload into a MessagePara. The DSoftBus source anchors are checked by the replay script before the model runs.

## Result

Detector ohscanner.data.sensitive_exposure 0.20.0 ran twice. Candidate identities, source hashes, and file outcomes were stable:

- two data.sensitive.unresolved-escape candidates: core/authentication/src/auth_hichain.c:136 and core/authentication/src/auth_session_fsm.c:499;
- both runs remained blocked; all six selected translation units were partial;
- the inter-file AuthSessionSaveSessionKey body was not credited because its translation unit is partial, so exact overload/build binding remains unknown;
- the second candidate is a SessionKey.value copy into an object destination that the syntax analyzer cannot bind;
- 0.740/0.721 seconds, 41,300 KiB process peak RSS;
- validated_vulnerability=0.

The unresolved caller candidate is retained; this replay does not establish that the key is publicly logged, readable, attacker controlled, or exposed by a product. The second candidate is also a static research lead, not a confirmed issue.

## What changed and test boundary

Detector 0.20.0 adds a bounded cross-file function-body resolver with explicit parse and memory budgets. It summarizes a uniquely name/arity-bound helper only when the parsed function body is complete, and preserves unresolved candidates when binding or body evidence is incomplete. Cross-file references make participating files partial. Synthetic tests cover a helper reaching a public log sink, a helper return reaching the caller sink, an ambiguous helper, and a same-name local function that must not be credited as a logging sink. The 87-test D1/D2/D3 and owner-admission/integration subset passed.

The real DSoftBus source did not prove a cross-file body summary because the selected translation unit is partial. The synthetic tests demonstrate the analyzer behavior under controlled syntax; they are not source-product findings, independent holdout labels, or accuracy measurements. The replay is not a product PoC or fix validation. No confirmed product vulnerability is established, so a product vulnerability PoC or remediation-effectiveness claim is not supported by this evidence.

The repository audit page already exposes this detector behind an explicit opt-in checkbox; Catalog marks it research_candidate and default-off. D44 verified the plan, Worker, evidence, and report path using a synthetic fixed Git fixture. The current UI uses copy that says static findings do not confirm product vulnerabilities and will not generate an exploitable product PoC.

## Reproduction

Run from the repository root with the project test environment:

python research/data_sensitive/d46_dsoftbus_crossfile_replay.py --git-repo /home/audit/openharmony-targets/communication_dsoftbus

The JSON result records file blobs, hashes, run signatures, coverage, timing, and limitations.

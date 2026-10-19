# T5 independent replay of frozen D6 — 2026-10-19

## Result

**Rule regression: PASS. Case disposition: PARTIAL/BLOCK.** D6 fixes the D5 sink-order false negative in the independent guard probes. The 12 focused tests pass. Exact A0 source replay still produces candidates at lines 789, 790 and 794 with parser status complete and rule version `0.3.0`.

The A0 case remains PARTIAL/BLOCK: no trusted fixed source is bound, the detector is not registered in the owner-controlled Catalog in this checkout, and product build/permission/filesystem reachability are not verified. `identity_quality=complete` remains a stable syntax-observation identity, not proof of source trust, path semantics, product reachability, or vulnerability confirmation.

## Frozen code and independent verification

- D6 freeze: `24b114094886b8d3e606afbbcd7b64af1dfa69ac`
- T5 cherry-pick: `e945781` (`Scope separator guards to preceding file sinks`)
- Prior T5 evidence head: `e352ade28dbbab8b9c13324f6e77cca0a099fe62`
- Rule: `ohcpp-path-traversal-source-to-file-sink-candidate-001`, version `0.3.0`
- Detector file SHA-256 is recorded in the JSON manifest.
- Focused command: `python -m unittest tests.detectors.test_cpp_path_traversal_detector -v`
- Result: 12 passed, 0 failed.
- Guard probe command: `python research/evidence/cpp/a_static_baseline_20261019/contacts-t5-guard-order-probe-20261019.py`

All guard outcomes matched the expected findings: a reject-when-found guard before both sinks yields 0; the same check after `open` and before `unlink` retains the earlier open candidate (1); after both sinks retains both candidates (2); reversed `== npos` polarity retains candidates (2); a guard on a different tainted parameter leaves the path findings (2); and an unrelated receiver in a boolean condition does not sanitize the path (2). The existing 12 focused tests also confirm the guard between two sinks suppresses only the later sink.

## Exact A0 source replay

The source identity is unchanged from the T5 source review: repository `openharmony/applications_contacts_data`, commit `b02aadfc2d801ee30573fcb2d13490298e146fea`, tree `ef183625ccbc842f47b076eb75e68b665d7c21c6`, file `dataBusiness/contacts/src/contacts_data_ability.cpp`, blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`. The exact bytes came from the pinned official fetch and were checked against local `.repo` commit/tree/blob objects.

Re-run the direct-detector command preserved under “Independent exact replay command” in [the D5 replay record](contacts-t5-d5-replay-20261019.md), from the same T5 worktree. The resulting Git blob and raw SHA-256 match; parser is `complete` with 0 issues, 57 functions, 525 calls; run/file outcome are `completed`/`complete`. Three findings appear at lines 789, 790 and 794, all with rule version `0.3.0`, the exact source hash, and complete syntax identity. Their stable fingerprints are unchanged from D5.

The source paths retain their independent meanings: lines 789 and 794 use `PortraitFileName` through `srcFilePath`, matching the A0 disclosed root cause; line 790 uses the distinct `contactId`/`rawContactId`-derived `filePath`. A0 does not prove traversal through the latter fields.

## D5 defect closure and remaining blocks

D5 reported zero findings when a reject-on-separator guard occurred after an earlier file sink. D6 now reports the expected unguarded earlier sink(s), while suppressing only sinks after a correctly polarized same-value guard. The unrelated-receiver and reverse-polarity controls remain candidates, and the safe pre-sink guard remains quiet.

Production CLI integration remains BLOCK because Catalog registration is owner-controlled and absent from this checkout. The case-level result stays PARTIAL/BLOCK pending an exact trusted fixed source and product reachability evidence. Do not report these candidates as confirmed vulnerabilities or as production-scanner coverage.

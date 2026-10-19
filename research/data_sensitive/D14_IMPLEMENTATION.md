# D14 high-recall privacy-sink candidate retention

## Change

The detector previously discarded sensitive flows whenever a modeled log format marked the operand private, including sinks whose default format was private. That encoded a safety conclusion the source model cannot prove: product logging configuration, privacy overrides, collection policy, and reader permissions are outside this static analysis.

D14 retains these flows as conditional data.log.sensitive-value candidates and adds a sink_privacy evidence obligation. The message explicitly says exposure is not established. Sinks with no sensitive flow remain clean controls. Detector version is 0.10.0; sink-model version is 0.4.0. Additional read-only upstream header review found DSoftBus LNN/CONN/DISC, DFILE/DFINDER and FILLP wrappers, plus HiLog base APIs; those sink signatures and format positions are now modeled and regression-tested. Historical source and product evidence are not promoted.

## Validation

The D data suite passed 57/57. The full Python suite passed 891 tests (886 passed, 5 skipped). The pinned D5 replay was rerun against local Git objects with detector implementation SHA-256 values recorded in each report:

- Before d33177135ec6c6aaf4a4c42de1f6878652b330e3: 1 candidate at trans_tcp_direct_message.c:671; 4/10 complete, 6/10 partial; run blocked.
- After 63efce3ff7f2708527eb29216decaf5fe2dc33d0: 0 candidates; 4/10 complete, 6/10 partial; run blocked.

The old/new candidate delta reproduces the source difference under the fixed historical model. Both runs are offline research replays, not public Runner success. The exact reports are D14_D5_HISTORICAL_BEFORE.json and D14_D5_HISTORICAL_AFTER.json; summary is D14_VALIDATION.json.

## Security boundary

This adjustment increases recall and may increase review workload. A private marker can be a valid mitigation when product configuration makes it effective, but the scanner cannot decide that from syntax alone. Agent/human triage must resolve the new obligation. Findings remain candidates; validated_vulnerability=0. No product image, runtime log, unauthorized reader, affected release, or product patch was tested.


## Additional upstream interface check

Read-only shallow clones and exact HEAD pins are recorded in [D14_EXTERNAL_SOURCE_CHECK.md](D14_EXTERNAL_SOURCE_CHECK.md). Header signatures were used only to extend sink-call modeling and tests; no sensitive-source model was inferred from these repositories.

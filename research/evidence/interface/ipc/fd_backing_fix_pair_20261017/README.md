# Pasteboard fd backing regression pair (2026-10-17)

`pair.json` binds two fixed local Git commits and selected source blobs to the new IPC static rule and to an isolated component Harness rebuilt from the pinned c_utils Git objects. The source checkout was dirty with tracked files deleted; the scripts read commit objects only and did not touch that worktree.

- Vulnerable: `3287e85450f16d3f41801040abe35701131ad6f4`
- Fixed: `ddee7c00d97d54423c6168fac994d3ef6204f385`
- Static scope: the `ReadRawData` implementation and `PasteboardEntryGetterStub` caller.
- Static result: one `ipc.parcel.fd-backing-size` candidate at the real caller on the vulnerable revision; zero on the fixed revision. One translation unit is partial, so the candidate carries a parse-completeness obligation.
- Harness: vulnerable/fixed native binaries were rebuilt using `git archive` of c_utils `3bdc11e00e7bf6e577cee300ad51045ca9958efd`; the generated input manifest binds 67 materialized source/header files, five compiled source files, flags, compiler, harness and shim digests. The A/B descriptor, short backing, small payload, and parcel size mismatch scenarios matched their expected outcomes.
- The static and Harness results do not prove an attacker can reach the transaction, provide the descriptor, cross the privilege boundary, or cause product CIA impact. `validated_vulnerability` remains 0.

All generated binaries, archived dependencies and run outputs stayed under `/home/audit/wtmp/parcel_harness/ipc-panel-integration-20261017/`; no third-party source was added to this repository.

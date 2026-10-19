# D30 — Samgr current IPC detector replay

**Lane:** development/replay (no detector code change; IPC rule ownership remains B)  
**Baseline:** `3aa6acc13ab7f39b0ebaee092a3e3e5b9b83bfa2`  
**Continuous objective:** provide exact-source, current-production-rule hit/miss evidence for every source-bindable disclosed A-line candidate; preserve unresolved cases and queue state until independent acceptance.

D30 independently invoked the current CLI on the pinned Samgr commit. Invocation ID is `git-index:08e2a552b839:5c9865cdc829:ohscanner.interface.ipc`; the CLI JSON SHA-256 is `036c457ef2bb385466d5aad454dd54469ba04ca4005515ff70751ef02893e02a`. All eight CR-0219–CR-0226 expected `ipc.capability.export` source locations were reported. The target file remains parser/analysis partial, no trusted fixed source or product caller/SELinux/build evidence is available, and no target-derived harness was run. This establishes candidate coverage but not vulnerability confirmation or a safe result. No current-rule gap was reproduced; no detector code changed and no B-owner request is needed on this evidence.

All eight A0 rows retain `not_reproduced / queued_not_reproduced`. Run `python research/evidence/cpp/verify_a_d30_samgr_ipc_replay.py` to validate the per-ID map and queue states; run the A0 verifier to validate all 345 original rows. Full report: [D30 replay](a_d30_samgr_ipc_replay_20261021.md), [machine-readable record](a_d30_samgr_ipc_replay_20261021.json), [raw CLI JSON](a_d30_samgr_ipc_cli_20261021.json). Replay JSON SHA-256: `900b1ca69114300038c866e5b35d031bd2eef2622bd1aa5356fa747facd29a89`; Markdown report SHA-256: `ab447a9ba7c75fd8a16b2b3166034a698b5d485240819beb68a5eccc14c9a216`.

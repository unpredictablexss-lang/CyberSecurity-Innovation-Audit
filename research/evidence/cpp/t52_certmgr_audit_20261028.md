# T52 — security_certificate_manager CR-0315/CR-0316 independent static replay

## Scope and source binding

This audit independently replays the current `ohscanner.cpp.shared_ptr_race` and `ohscanner.interface.ipc` detectors against the exact A0 source objects. Both rows bind to `openharmony/security_certificate_manager` commit `5fcc0b6379567a70176307c281360be2ba281d6b`, tree `f3e078b356ac0724d8ab267d73ab85e69b9b44ad`. Per-file blob IDs and SHA-256 values are recorded in `t52_certmgr_context_identity_20261028.json`; the original queue rows and statuses remain unchanged.

| A0 ID | Source | Current detector result | Parsing / coverage | Assessment |
|---|---|---|---|---|
| CR-0315 | `cmdline/certmgr/src/certmgr_command.cpp:364` | `ohscanner.cpp.shared_ptr_race` 0.5.1: 0 findings | complete / complete | PARTIAL/BLOCK |
| CR-0316 | `frameworks/cert_manager_standard/main/os_dependency/cm_ipc/src/cm_ipc_dialog_client.cpp:127` | `ohscanner.interface.ipc` 0.12.12: one `ipc.relay.descriptor-boundary` candidate at line 127 | partial / partial (`detector_model_incomplete`) | PARTIAL/BLOCK |

## Source review

**CR-0315.** The flagged `std::shared_ptr<std::promise<int32_t>>` is retained by `AdminAuthCallback`; the callback resolves the promise from `OnResult`. `AuthenticateAdmin` creates the callback, requests the named `ohos.privilege.manage_global_scope_certificate` authorization, checks the synchronous error, and blocks on `future.get()`. This is consistent with an asynchronous authorization response path; the candidate line itself does not show an unsynchronized shared-pointer mutation. However, the exact callback scheduling/thread guarantees, all runtime caller/command reachability and the shipped product profile were not established. Zero findings on a complete file is not a safety result. No trusted fixed source was bound.

**CR-0316.** The flagged entry is a client callback stub returned to the service as the reply endpoint for a UKey dialog request. At line 127 it reads a single `int32_t` result and calls `Deliver`; `Deliver` gates exactly-once delivery with an atomic flag and invokes the client callback. The IPC client creates the stub, sends it with a serialized request, cancels it on synchronous failure, or retains it until delivery. The dialog API validates non-null arguments and blob metadata before serializing. The IPC source is included by the component static-library GN target. These source facts make descriptor relay/forwarding at this callback site unsupported by the inspected body, but the replay remains partial, so this is not an exclusion or safety finding. Caller authorization and effective product dispatch/build conditions are not independently established; no trusted fixed source was bound.

## Replays and verification

- Shared-pointer replay: `python` calling `run_fixed_commit_scan` on the exact bare project-object repository, selecting only `cmdline/certmgr/src/certmgr_command.cpp` and `ohscanner.cpp.shared_ptr_race`; raw result `t52_certmgr_cr0315_shared_ptr_cli_20261028.json`.
- IPC replay: same pinned source commit, selecting only `frameworks/cert_manager_standard/main/os_dependency/cm_ipc/src/cm_ipc_dialog_client.cpp` and `ohscanner.interface.ipc`; raw result `t52_certmgr_cr0316_ipc_cli_20261028.json`.
- `verify_t52_certmgr_audit_20261028.py` checks the source commit/tree, source blob/SHA bindings, both CLI identities/results, queue CSV/JSON agreement, 345 unique A0 rows, and preservation of CR-0315/0316 original and queue states.
- No detector, test, fixture, or A0 queue was modified. No fixed-source comparison was fabricated. Both cases remain PARTIAL/BLOCK.

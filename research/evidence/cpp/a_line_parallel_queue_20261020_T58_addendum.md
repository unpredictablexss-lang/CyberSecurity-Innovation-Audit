# T58 addendum — mechbody controller IPC (CR-0116–CR-0118)

- Independent replay binds all three frozen A0 candidates to commit `6e875a2dc5a7748bfdcbec1ccf9f1153574fa03e`, tree `d34e2a24b6e121f5a06a0b91d377c3558f803ca3`; all three current IPC candidates reproduce at their frozen source lines with complete parsing of the selected files.
- Dispatchers check a custom token before member-function dispatch, but the custom token differs from their declared interface descriptor. This supports the static descriptor-boundary candidate; caller authorization, product inclusion, reachable entry, and unauthorized impact are not proven.
- ANI/N-API/service Stubs belong to production-shaped GN shared-library targets; fuzz harnesses referencing these sources are `testonly = true`. Product configuration and service reachability remain unknown.
- All A0 statuses remain `not_testable / paused_pending_evidence`; disposition is PARTIAL/BLOCK. See [T58 audit](t58_mechbody_controller_ipc_audit_20261029.md), [JSON](t58_mechbody_controller_ipc_audit_20261029.json), and [replay verifier](t58_mechbody_controller_ipc_audit_20261029.py).

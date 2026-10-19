# D5 patch and remediation review

The available upstream change removes a `SoftBusLog` call from the receive/decrypt path between the pinned old and new source revisions. It is described as log hardening; there is no evidence here that it was announced as a security fix. No independent source patch has been authored or applied, and neither historical product revision has been built.

A new isolated component experiment compiled the exact manifest-pinned `ProcessReceivedData` function from both revisions with deterministic crypto/parser/processor/logger stubs. The synthetic secret marker reached the stub logger in the old function and did not reach it in the post-hardening function; ordinary reply processing continued, and decrypt failure logged without the marker. This is component behavior only, not a product patch or end-to-end regression proof. Full details and hashes are in `D5_COMPONENT_HARNESS.json`.

The risk hypothesis remains conditional: a request may carry `SESSION_KEY` in JSON; the receive path may decrypt that payload and log it before request/reply dispatch; the selected build and log level must emit the record; and a reader outside the authorized security boundary must obtain it. Source review and the stub harness support only the function-level data path. Runtime output, production build selection, reader access, and concrete impact remain unknown.

The recommended remediation is to avoid logging raw decrypted payloads. Keep only non-sensitive metadata needed for diagnostics, such as message kind, length, and a stable error code. If payload diagnostics are essential, redact the sensitive field before formatting and cover both success and error paths.

| Item | Evidence/status |
|---|---|
| Old/new source identity | Recorded in `D5_REAL_REPLAY.md` and `D5_COMPONENT_HARNESS.json`; exact Git trees and blobs verified |
| Upstream change | Removal of a log call; hardening interpretation only |
| Extracted-function component behavior | Compiled and isolated old/new comparison passed; synthetic marker was logged only by old body |
| Independent patch authored | No |
| Product patch applicability / compile | Not run |
| Full product functional regression | Not run; component stubs are not the product |
| Product affected/fixed releases | Unknown; no product release/build mapping |
| Security impact / unauthorized reader | Unknown; no product runtime or access-control proof |
| Vulnerability state | Candidate only; `validated_vulnerability=0` |

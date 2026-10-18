# D5 patch and remediation review

The available evidence is an upstream historical deletion of the
`SoftBusLog` call from the receive/decrypt path between the pinned old and
new source revisions. It is accurately described as a log-hardening change;
there is no evidence here that it was announced as a security fix. This D5
work has not authored or applied an independent source patch, and has not
compiled either historical product revision.

The risk hypothesis is conditional: a request may carry `SESSION_KEY` in JSON;
the receive path may decrypt that payload and log it before request/reply
dispatch; the selected build and log level must emit the record; and a reader
outside the authorized security boundary must obtain it. The source review
supports parts of the request/decrypt/log ordering, but runtime output,
production build selection, reader access, and concrete impact remain unknown.

The recommended remediation is to avoid logging raw decrypted payloads. Keep
only non-sensitive metadata needed for diagnostics, such as message kind,
length, and a stable error code. If payload diagnostics are essential, redact
the sensitive field before formatting and cover both success and error paths.
The old/new upstream diff is evidence of a source change, not proof that the
deployed product uses it or that normal communication still works afterward.

| Item | Evidence/status |
|---|---|
| Old/new source identity | Recorded in `D5_REAL_REPLAY.md`; exact Git trees and blobs required |
| Upstream change | Removal of a log call; hardening interpretation only |
| Independent patch authored | No |
| Patch applicability / compile | Not run; no independent patch |
| Functional regression | Not run; no isolated component build |
| Product affected/fixed releases | Unknown; no product release/build mapping |
| Security impact / unauthorized reader | Unknown; no runtime or access-control proof |
| Vulnerability state | Candidate only; `validated_vulnerability=0` |

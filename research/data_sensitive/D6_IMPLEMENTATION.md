# D6 implementation: bounded helper flow and unresolved candidates

Status: local research branch only. The detector remains unregistered and is not
eligible for default scanning. Findings remain candidates or unknown; this work
contains no product vulnerability confirmation.

## Changes

- The detector version is `0.3.0`. The reviewed source model and its version are
  unchanged.
- Same-file helper bodies are expanded with a recursion/depth bound. Tainted
  arguments flow into helper parameters; simple return values and pointer/reference
  outputs flow back to the caller. Calls with ambiguous same-arity definitions
  analyze each possible body and retain a limitation.
- A sensitive value passed across an unresolved external, unsupported, recursive,
  or arity-unbound call produces `data.sensitive.unresolved-escape` with no CWE.
  This is a review candidate, not proof that the callee logs, persists, or exposes
  the value. The evidence obligations require binding the callee, determining sink
  behavior, verifying log visibility, and establishing impact.
- A modeled logger that receives sensitive data but has a dynamic or unsupported
  format produces `data.log.sensitive-value` with a format-resolution obligation.
  This remains a candidate because the runtime privacy slot is unknown.
- Scalar length APIs (`strlen`, `strnlen`, `strnlen_s`, `wcslen`) are not treated as
  returning the secret material itself. Local definitions and shadowing prevent
  this name-based exception from being applied blindly.
- The frozen historical D3 analyzer was guarded so these general D6 unresolved-call
  semantics do not alter its explicit historical source/sink experiment.

## Limits

This is bounded, same-file, syntax-driven analysis. It does not resolve compiler
overloads, cross-file calls, indirect calls, object identity, general aliases,
full control flow, macros, build configuration, or runtime logging policy. Arity
matching is only a conservative candidate-body selector; it is not exact binding.
The analysis does not execute the target program and does not produce a PoC.
Unsupported or ambiguous behavior must remain visible as a limitation or candidate.

## Evidence boundary

The new tests establish detector behavior on synthetic controls and the public
Runner representation for one unresolved-call family. They do not establish real
product log output, unauthorized read access, affected releases, remediation
success, community recall/precision, or a confirmed vulnerability. D6 restored the
missing D4_SOURCE_MANIFEST.json and reproduced its verifier: 44 source objects and
35 assertions passed. D6 also reproduced the D4 static replay from exact GitHub
commit-ref snapshots, matching every profile entry's size, SHA-256, and Git blob SHA-1.
Both runs remain blocked because six of ten files are partial. The dynamic Harness
and independent real-source holdout remain not run. See D6_REAL_REPLAY.json.

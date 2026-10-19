# D7 implementation: preserve unresolved output flows

Status: local D research branch. The detector remains unregistered and is not
eligible for default scanning. Findings remain candidates or unknown; no product
vulnerability is confirmed.

## Change

- Bumped `SensitiveExposureDetector` from 0.3.0 to 0.4.0. The reviewed source
  model, repository, commit, sink identities, and rule IDs are unchanged.
- Simple address-of local destinations such as `SoftBusGenerateSessionKey(&out,
  32)` now bind to `out`, so the existing same-file flow can reach a later sink.
- Modeled source, copy, and formatting calls that write through an unresolved
  member or pointer destination now retain `data.sensitive.unresolved-escape`.
  These findings have no CWE and carry a `destination_binding` obligation.
- A sensitive input passed to formatting with a dynamic or unsupported format now
  retains an unresolved candidate with a `format_resolution` obligation. It does
  not assume a format, privacy slot, or output alias.
- Added controls for address-of output, member destinations, dynamic formatting,
  and the existing literal/safe cases. Existing helper-flow and historical D3
  behavior remain covered.

## Boundaries

Member aliases remain unresolved; this change records the boundary as a candidate
instead of claiming a flow into a later sink. The candidate alone does not show
that a call logs, stores, or exposes the value. No reachability, runtime log
visibility, product entry point, affected release, impact, or fix is established.
The detector remains bounded same-file Tree-sitter analysis and has no independent
real-source holdout or component build coverage.

## CodeQL experiment

An exploratory parser-only CodeQL database and custom AuthDecrypt-to-SoftBusLog
query were tested against the fixed historical before/after source snapshots. The
query returned zero paths on both snapshots, including the known historical log
site. The selected output-buffer model did not bind the struct-pointer write to
the logger argument in this no-build database. This is a failed model experiment,
not evidence that the historical candidate is absent; no CodeQL result is
integrated into OHScanner.

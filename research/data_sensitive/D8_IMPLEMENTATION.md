# D8 implementation: model DSoftBus log macro families

Status: local D research branch. The detector remains unregistered and disabled
for default scanning. Outputs are candidates or unknown; no product vulnerability
is confirmed.

## Source-backed gap

The exact source model commit is
`0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`. At that commit,
`dfx/interface/include/trans_log.h` defines `TRANS_LOGF/E/W/I/D` and
`COMM_LOGF/E/W/I/D` as macros that forward the source format and variadic
operands to `SOFTBUS_LOG_INNER`. The latter expands through `softbus_log.h` to
`HiLogPrint` or `HILOG_IMPL`, with a public function-name prefix. The own-AST
parser sees the source macro call and does not expand that chain, so sink models
limited to `AUTH_LOG*` and the lower-level HiLog names missed these call sites.

Reviewed GitHub file identities at the model commit:

- `dfx/interface/include/trans_log.h`, blob
  `6589f32dd0334d8aeb73ef3f5d33c81275379d37`.
- `dfx/interface/include/comm_log.h`, blob
  `9495660e0959a1206ec20f0d6a6a10f2a84ffdc2`.
- `dfx/interface/include/softbus_log.h`, blob
  `9c6a0df46b533c97a2419a38323eefc9458aab87`.

## Change

- Bumped `SensitiveExposureDetector` from 0.4.0 to 0.5.0. Source identities,
  source model, and existing rule IDs are unchanged.
- Added source-level sink models for both five-level macro families, with format
  argument index 1 and the existing conservative private-by-default HiLog
  semantics. Explicit public operands remain candidates; explicit private
  operands are not reported by this material-exposure rule.
- Added models for the reviewed conditional `TRANS_CHECK_AND_RETURN_*` and
  `COMM_CHECK_AND_RETURN_*` wrappers using their actual format positions. Their
  condition and selected platform build behavior are not used to claim that the
  branch executes; the result remains a static candidate.
- Added positive controls for public `TRANS_LOG`, `COMM_LOG`, and wrapper calls,
  plus a private-slot negative control.

## Evidence boundary

This expands API-surface modeling. It does not prove a particular macro expands
in a selected product build, that the log level is enabled, that a sensitive
value exists at runtime, or that an unauthorized reader can obtain the record.
The new regressions are synthetic development controls, not a real-source
holdout. D4 historical replay is a separate analyzer and is not changed by this
macro model. See `D8_VALIDATION.json` for tested scope and remaining gates.

# T34 task-tree addendum — libpng CVE-2026-46675 independent replay

## Testing line: T34

T34 independently replayed vulnerable and exact fixed libpng commits with the current `ohscan-run` CLI and reran D12's exact-source function-fragment experiment. The vulnerable/fixed commit, tree, blob, SHA-256 and file-size identities all verified. Both one-file CLI runs used `ohscanner.cpp.resource_lifetime` 0.4.2; both translation units remain partial with 72 parser issues, blocked detector status, and zero findings. For each side, six of seven fragments parse complete; `png_handle_iCCP` remains partial; all fragments are quiet.

This is not a validated vulnerable/fixed differential and does not establish lifecycle closure. The described stale zstream ownership transition spans functions; no cross-function candidate was emitted, and static evidence does not establish product reachability or impact. Keep CVE-2026-46675 **PARTIAL/BLOCK** and preserve all A0 IDs/statuses.

See [T34 audit](t34_libpng46675_independent_audit_20261023.md), [machine record](t34_libpng46675_independent_audit_20261023.json), [CLI artifacts](t34_libpng46675_vulnerable_cli_20261023.md) and [verifier](verify_t34_libpng46675_audit.py).

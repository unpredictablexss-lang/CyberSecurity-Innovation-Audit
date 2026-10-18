# D5 isolated Harness design

Status: design only; execution is `not_run`. No product build, target device,
container image, or explicitly approved isolated runtime has been supplied in
this worktree. The static controls in `tests/fixtures/data_sensitive/` are
synthetic detector regressions and are not the H01–H08 Harness.

The Harness should build only the pinned component revision in an isolated
container with a recorded immutable image digest. Inputs use a synthetic
SESSION_KEY and synthetic request/reply bodies. It must not connect to a
production device, request a real credential, or attempt to read logs outside
the container. The container should have a bounded CPU, memory, wall-time, and
temporary output directory; destruction of that temporary directory is the
cleanup step. The run manifest records source commit, patch hash, image digest,
compiler/build profile, configuration, tool versions, argv, exit code, and
hashes of captured output. Captured output is checked to contain only the
synthetic marker before it is retained.

Each test starts from a fresh process and isolated log sink. It records actual
formatting return values and emitted bytes; expectations are hypotheses, not
assumed outcomes. No case is considered proof of product impact or reader
authorization without a matching product build and access-control evidence.

| ID | Controlled input and observation | Status |
|---|---|---|
| H01 | Valid request containing synthetic SESSION_KEY, below buffer boundary; compare emitted bytes before/after log hardening | `not_run` |
| H02 | Normal reply JSON without SESSION_KEY; confirm no sensitive-material output | `not_run` |
| H03 | Decrypt/Auth failure; observe return status and whether any buffer reaches the logger | `not_run` |
| H04 | Valid JSON without SESSION_KEY | `not_run` |
| H05 | Formatting at boundary−1, boundary, boundary+1; retain actual status and output rather than presuming truncation | `not_run` |
| H06 | Controlled log-level configurations; verify the selected build branch and actual output | `not_run` |
| H07 | Same synthetic input on old, log-hardened, and safe-control builds; verify output and normal communication behavior | `not_run` |
| H08 | Read attempt by explicitly authorized and unauthorized test identities inside the isolated image; record identity, policy, allow/deny | `not_run` |

Execution prerequisite: an approved disposable container/runtime and exact
build recipe with known image digest. If that prerequisite is unavailable, keep
all rows `not_run`; do not substitute host `hilog`, `hdc shell`, or detector
Harness results for these observations.

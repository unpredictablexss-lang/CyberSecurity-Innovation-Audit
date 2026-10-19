# D5 isolated Harness design

Status: a narrow extracted-function component harness has run; the product H01–H08 matrix remains `not_run`. The harness compiles the exact `ProcessReceivedData` function body from two manifest-pinned D4 source files, after verifying file size, SHA-256, and Git blob SHA-1. It uses deterministic stubs for decryption, JSON parsing, message processing, and logging. A synthetic `SESSION_KEY` marker is used; no real credential or device is involved.

Run with `d5_component_harness.py --run-isolated`. GCC builds a static binary; each scenario runs in a rootless user, mount, and no-network namespace. A tmpfs chroot contains only that binary. The report records source identities, extracted function/generated C/binary hashes, compiler, observations, and runtime: `D5_COMPONENT_HARNESS.json`.

Observed component behavior:

- Before log hardening, a valid synthetic secret request reached the stub logger with the marker (`marker=1`); ordinary reply and decrypt-failure cases did not contain the marker.
- After log hardening, neither valid request nor ordinary reply called the stub logger; decrypt failure still emitted one generic log call, with no marker. All three scenarios still followed the expected stub processing/return behavior.
- The assertions passed for both revisions.

This demonstrates only the behavior of the exact extracted function bodies at stubbed boundaries. It does not validate a full product build, actual crypto/parser/log service, persistent log output, production log level, authorized or unauthorized readers, affected releases, or product impact. It is not the H01–H08 product harness, and it does not confirm a vulnerability or a deployed fix. `validated_vulnerability=0`; product impact remains unknown.

| ID | Controlled input and observation | Product status |
|---|---|---|
| H01 | Valid request containing synthetic SESSION_KEY; actual product log output before/after hardening | `not_run` |
| H02 | Normal reply JSON; actual product output | `not_run` |
| H03 | Decrypt/Auth failure; actual product return and output | `not_run` |
| H04 | Valid JSON without SESSION_KEY | `not_run` |
| H05 | Formatting at boundary−1, boundary, boundary+1 | `not_run` |
| H06 | Controlled product log-level configurations | `not_run` |
| H07 | Old, log-hardened, and independently patched product builds; output and communication behavior | `not_run` |
| H08 | Authorized and unauthorized reader access to the product log sink | `not_run` |

The component harness is an additional low-level experiment only. Product H01–H08 still require a reproducible target build and controlled log/read-permission observations. Component results must not be substituted for product evidence.

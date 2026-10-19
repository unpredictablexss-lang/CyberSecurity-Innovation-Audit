# T52 independent acceptance: Pasteboard read permission candidate

- Date: 2026-10-20 (Asia/Shanghai)
- Checkout: `D:/openHarmonyScanner/worktrees/t52-pasteboard-permission-20261020`
- Frozen developer commit: `9d3b1e653a6e56a3f2f6aea376e30ac9f61ef4e`
- Frozen scanner base: `842948084660207fd64399cfd598ed93e5593dcc`
- Role: independent evidence and regression review; no detector, test, fixture, expected-output, or policy files changed.

## Decision

| Dimension | Result | Evidence boundary |
|---|---|---|
| Rule regression | **PASS for the scoped signature behavior** | The pinned component source emits the expected candidate under rule 0.18.0, and independent synthetic guarded/unrelated controls are silent. A partial-parse control retains the candidate and reports blocked coverage. |
| Static source-case acceptance | **PARTIAL** | The candidate and source route are reproducible, but the target stub parses partial and the full run is blocked. No exact upstream fixed source commit is available in the local shallow source repository. |
| Component vulnerability | **UNASSESSED CANDIDATE** | The component path has no visible permission decision in the traced stub/core methods. The external IPC/SystemAbility skeleton boundary is not bound to this source snapshot. |
| Product/CVE status | **UNKNOWN** | No product build, manifest, authorized entry evidence, or product policy was supplied. `validated_vulnerability=0`; blocked or partial evidence does not establish safety. |

The reported line 41 is the opening brace of `PasteboardServiceStub::OnRemoteRequest`, returned by the detector's `_body` offset. It identifies method scope, not the transaction registration or the data-return statement. The source chain is mapped below so the finding is not mistaken for a statement-level location.

## Frozen source and replay identity

The exact source objects were read from `D:/OpenHarmony807/repos/miscservices_pasteboard` without fetching or modifying that repository.

| Item | Independently verified value |
|---|---|
| Repository declaration | `openharmony/miscservices_pasteboard` |
| Commit / tree | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee` |
| Snapshot SHA-256 | `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648` |
| Target file | `services/zidl/src/pasteboard_service_stub.cpp` |
| Target blob / SHA-256 | `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b` / `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| Related core file blob / SHA-256 | `c380ac266a85edd818caa811f11b99722d351788` / `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52` |
| Permission helper blob / SHA-256 | `5e7bf43287374eb21a8200400cbe350e8d234368` / `b1241967b47b12ffbcc980c4f9514e32406d04b0652ff66fa7f88e4bd29f5761` |

Two independent current-version CLI replays produced the same source binding and diagnostics:

```powershell
python -m src.cli.main ohscan-run --repo-dir D:\OpenHarmony807\repos\miscservices_pasteboard --repository openharmony/miscservices_pasteboard --commit dd22c7cb5e5f207a6c38c50f45b7369ee8575840 --detector ohscanner.known_disclosed_cves
```

Both invocations exited 0 and reported the pinned commit, tree, snapshot, `ohscanner.known_disclosed_cves@0.18.0`, 2 unverified findings, and top-level `completed_with_limitations`. The DetectorRun was `blocked`; it scanned 67 C/C++ files / 7,104 LOC. Parse counts were 59 complete, 8 partial, and 1 not run. The target stub itself was partial. Both findings retained the expected source SHA and method-entry line: CVE-2025-25212 at `pasteboard_service.cpp:222`, and CVE-2025-27247 at `pasteboard_service_stub.cpp:41`. `validated_vulnerability=0`.

This current 0.18.0 replay is separate from D50's historical 0.16.0 replay, which reports 57 complete, 10 partial, and 1 not run. Both versions retain the two candidates; their parse counts are not interchangeable.

## Source-to-sink and authorization review

1. `pasteboard_service_stub.cpp:25-37` maps `GET_PASTE_DATA` to `OnGetPasteData`.
2. `OnRemoteRequest` at lines 39-63 validates the Binder interface descriptor, records caller PID/UID for logging, looks up the selector, and invokes the mapped method. The descriptor comparison verifies interface identity; it is not a read-permission decision in this method.
3. `OnGetPasteData` at lines 73-87 calls `GetPasteData(pasteData)` and, on success, serializes the object with `reply.WriteParcelable` (line 82).
4. `PasteboardService::GetPasteData` at `services/core/src/pasteboard_service.cpp:155-177` derives an OS user via `GetUserId`, looks up `clips_[userId]`, copies the data, and returns success. `GetUserId` at lines 211-219 maps the Binder calling UID to an OS account. This is per-user data scoping; no permission allow/deny decision is visible in the traced component path.
5. `PasteboardPermission` helpers exist in the component, but a repository-wide reference search found no call from the traced stub, core read method, proxy, or service registration path. Their existence alone does not establish authorization.
6. The service inherits external `SystemAbility`/IPC framework classes and calls `Publish`. Their implementation and product-side access policy are outside the pinned component tree, so the complete authorization boundary remains unknown.

## Independent controls and tests

Using the read-only `KnownDisclosedCveTests.run_source` helper, I independently reproduced these outcomes without adding or editing test files:

| Control | Result |
|---|---|
| Mapped `GET_PASTE_DATA` → dispatch → data-return handler | Candidate emitted |
| Handler with `CheckPermission()` | No CVE-2025-27247 candidate |
| Handler with `VerifyCallingPermission(PERMISSION_READ_PASTEBOARD)` | No candidate |
| Other public-read selector/name | No candidate |
| Metadata-only `HAS_PASTE_DATA` sibling | No candidate |
| `SET_PASTE_DATA` selector control | No candidate |
| Same candidate shape under `parse_status=partial` | Candidate retained; run blocked with a coverage limitation |

These are synthetic regression controls, not independent holdout labels and not a substitute for an exact fixed-source pair. The source mirror is shallow and contains only the pinned commit (`rev-list --all --count=1`, `--is-shallow-repository=true`, no parent); no exact fixed commit was available to verify.

The focused suite was independently rerun:

```powershell
python -m unittest tests.detectors.test_known_disclosed_cves -q
```

Result: **21 tests passed**. These tests validate rule behavior only; they do not upgrade component or product status.

## Scope, task state, and limitations

The D52 frozen commit changes only these two assigned evidence paths:

- `research/data_sensitive/D52_PASTEBOARD_PERMISSION_20261020.json`
- `research/data_sensitive/D52_PASTEBOARD_PERMISSION_20261020.md`

No shared code, parser, API, Catalog, detector, test, fixture, or expected output was changed. `git diff --check 842948084660207fd64399cfd598ed93e5593dcc 9d3b1e653a6e56a3f2f6aea376e30ac9f61ef4e` passed and the frozen checkout was clean. `check_change_scope` is **N/A** because the frozen `ownership.json` defines no D lane; scope was checked manually against the D52 evidence-only assignment, without substituting another lane or editing policy.

The current product-closure task tree remains `ACTIVE_NOT_ADMITTED`: G12-PC-1 is `IN_PROGRESS_BLOCKED`, PC-2 is `PIPELINE_IMPLEMENTED_NOT_EXECUTED`, PC-3 is `BLOCKED`, PC-4/PC-5 are `NOT_RUN`, and PC-6 is `NOT_ADMITTED`. This acceptance does not close product applicability, attacker reachability, impact, or fixed-product revalidation.

Machine-readable counterpart: [t52_pasteboard_permission_acceptance_20261020.json](t52_pasteboard_permission_acceptance_20261020.json).

# A 线 Ark runtime 历史 CVE 当前重放（2026-10-19）

## 结论

在最新 baseline `db77164fdc2af0da02e4d3efc056d84694fd68e8` 的生产 M2 CLI (`python -m src.cli.main ohscan-run`) 上，按对应 detector 重放真实上游源对象：CVE-2025-0587 vulnerable/fixed 为 **1/0**；CVE-2025-23420 vulnerable/fixed 为 **5/0**。安全 fixed、无关源码控制均为 0；截断源码控制均由 parser 判为 `partial`，detector `blocked`、coverage unknown、0 diagnostics。所有诊断都是候选，两个 CVE 的 `validated_vulnerability` 均为 0。

本轮未改 detector、共享接口或产品源码。精确 commits、trees、目标文件 blob 均在本机 `D:\openHarmonyScanner\arkruntime-holdout-history` Git 对象库可解析。该仓库的 Git 对象绑定本身不认证上游仓库身份、官方发布线或产品构建。

## 固定基线与 detector

- OHScanner baseline / `HEAD` / `origin/main`: `db77164fdc2af0da02e4d3efc056d84694fd68e8`。
- CLI: `python -m src.cli.main ohscan-run`（M2 pinned-source first-party detector execution）。
- CVE-2025-0587 detector: `ohscanner.cpp.integer_bounds` **0.2.0**。
- CVE-2025-23420 detector: `ohscanner.cpp.bounds` **0.2.0**。
- 这两个 detector 在当前 catalog 中默认启用；重放时依照 M2 CLI 要求使用 `--detector` 显式指定对应 ID。报告中的 detector diagnostic 是 source candidate，不代表运行时漏洞。

## 精确源对象与 patch digest

| CVE | 状态 | commit | parent | tree | 路径 | blob | 文件 SHA-256 | bytes |
|---|---|---|---|---|---|---|---|---:|
| 2025-0587 | vulnerable | `cae11f121c030a90ba41d8e4d866f91292f25892` | `60922d265c7893617fd6978dd6d12ff2f9ed6c56` + `d7765f8c2bb7bfbe8cdd64ea996e0028b0f684a5` | `61ff01d9a06b4186125a04e2b790e07640f57198` | `ecmascript/base/atomic_helper.cpp` | `7fd67717571c6d8fe7b10bf294998e952dc61e36` | `f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541` | 7176 |
| 2025-0587 | fixed | `5aa9c035e98911ec7ed28065a2138c2709792a42` | `cae11f121c030a90ba41d8e4d866f91292f25892` | `05ac3902979e37ae08efa2d1e3ed32472a69d0cc` | `ecmascript/base/atomic_helper.cpp` | `80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c` | `39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b` | 6995 |
| 2025-23420 | vulnerable | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `a46b4221baf4c6497901718763f7c5ea45d7c138` + `cb43a6604679a16c1b9692f59bd721ec652793ab` | `0eea26c9eb6846f4d19926be83092c06f0d98692` | `ecmascript/js_array.cpp` | `2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471` | `b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b` | 31896 |
| 2025-23420 | fixed | `1b23531531e768398682582969c2a9f17e72cafe` | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `52f27683e2f6e1ba8272aee7d5202c73059e10b4` | `ecmascript/js_array.cpp` | `58266855967e3dc4af97721d3a2fc5417cb887b6` | `f6325075773451b9c9a314c6fec0c0177331786f5c9e6ce3069974eb4c79b0f6` | 32924 |

The exact file-only Git diff SHA-256 values recomputed from raw `git diff <vulnerable> <fixed> -- <path>` bytes are:

- 2025-0587 `atomic_helper.cpp`: `419c0d324f4468631e7ec56d3a9e8319d9a98cc91a918e99856ffd581ce9191d` (2486 bytes).
- 2025-23420 `js_array.cpp`: `cd4d41e15f5faba29ebe17cb44e08758e3aabcfc088aba12bc1b399cadac1d68` (2969 bytes).

**Digest discrepancy to resolve:** the earlier `A_MEMORY_SAFETY_DELIVERY_20261017.md` states CVE-2025-23420 patch SHA-256 `e0b61dde4058080ee28184d49b3d7da80e4ad428bc2030a04fc5f69bccbc0512`. This value does not match the raw file-only Git diff bytes recomputed above (`cd4d...`). Full commit diff and full commit patch also have different hashes. The old digest is retained as a historical claim, not silently replaced or treated as verified. The fix source object and detector replay remain bound; the exact byte recipe behind the prior patch digest needs reconciliation. Prior report: `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit-c4\research\deliveries\cpp\A_MEMORY_SAFETY_DELIVERY_20261017.md` (sections “CVE-2025-23420” and “CVE-2025-0587 historical binding and control”).

## Current CLI replay matrix

Each JSON/Markdown pair is an unmodified output from the production M2 CLI. Reports are under [`research/evidence/cpp/ark_runtime_replay_20261019/`](../../evidence/cpp/ark_runtime_replay_20261019/). Commands and control source construction are recorded in [`A_ARK_RUNTIME_CVE_REPLAY_COMMANDS_20261019.md`](A_ARK_RUNTIME_CVE_REPLAY_COMMANDS_20261019.md).

| CVE / case | Detector | Candidate diagnostics | Coverage / status | Interpretation |
|---|---|---:|---|---|
| 2025-0587 vulnerable | `ohscanner.cpp.integer_bounds` | 1 | completed | Candidate at `atomic_helper.cpp:71`, `ToIndex`/double narrowing to `int32_t` before bounds/offset arithmetic. |
| 2025-0587 fixed | same | 0 | completed | Fixed-source control quiet. |
| 2025-0587 safe | same | 0 | completed | Identical fixed source material in synthetic control repository. |
| 2025-0587 unrelated | same | 0 | completed | Vulnerable `js_array.cpp` blob used as unrelated control. |
| 2025-0587 partial | same | 0 | `blocked`; parsing partial | 300-byte vulnerable-source prefix; coverage unknown, not safe. |
| 2025-23420 vulnerable | `ohscanner.cpp.bounds` | 5 | completed | Candidate accesses in `JSArray::SortElementsByObject` at lines 650, 653, 665, 666, 668. |
| 2025-23420 fixed | same | 0 | completed | Fixed-source control quiet. |
| 2025-23420 safe | same | 0 | completed | Identical fixed source material in synthetic control repository. |
| 2025-23420 unrelated | same | 0 | completed | Vulnerable `atomic_helper.cpp` blob used as unrelated control. |
| 2025-23420 partial | same | 0 | `blocked`; parsing partial | First 18,000 bytes of vulnerable source; parser reports partial, coverage unknown, not safe. |

Synthetic controls are pinned to a temporary local Git commit (`949874ac2a6d598a3642542da98ddc7f6c613ad7`, tree `c2b46a96694f2e6880820656fae5456ece4ac92f`), repository declaration `synthetic/ark-runtime-controls`. Source files were extracted from the upstream commit blobs listed above; safe controls use fixed blobs; unrelated controls use the other CVE's vulnerable blob; partial controls are byte-truncated excerpts. Synthetic commit identity and declarations are not upstream provenance.

## Focused checks and scope

- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: **17 tests passed**. This exercises bounds/integer detector positive, fixed/safe, unrelated, partial, and budget controls.
- `python -m scripts.check_change_scope --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane cpp`: **0 violations**. The check saw concurrent pre-existing A-line changes as well as this report/evidence; all checked paths were allowed under the baseline policy.
- No source code or shared interface changed in this replay task.

## Evidence boundary / remaining work

- `candidate` means the current static detector emitted a source-pattern diagnostic. It does not establish exploitability, product inclusion, runtime reachability, attacker control, or security impact.
- Partial controls are correctly `blocked`/unknown; their zero diagnostic counts are not misses or safe results.
- Historical counts (0587 1/0, 23420 5/0) served only as leads. Current CLI reports independently reproduce these counts against the pinned source objects.
- Next: reconcile the prior 23420 patch digest recipe; independently establish upstream repository/release provenance; retain product build/version and runtime evidence as unknown until separately sourced.

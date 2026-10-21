# A 线代表案例：Ark Runtime CVE-2025-0587

日期：2026-10-21（Asia/Shanghai）

## 结论与证据边界

选择此案例作为评委代表案例：A 线生产 CLI 在精确的 vulnerable/fixed 上游源码对象上分别产生 1/0 个 `ohscanner.cpp.integer_bounds` 候选；候选位置所在函数有精确补丁差分。源码层结果为 bounded static PASS。运行时验证未完成，状态为 **not_run**；本报告不声称 PoC 触发了越界读写，也不把源码差分当成动态结果。`validated_vulnerability=0`。真实入口可达性、攻击者输入路径、产品构建配置和运行影响仍 unknown。

选择依据是已有对照包含真正的上游 vulnerable/fixed commit，而不是测试专用修复变体。另有 Contacts 隔离文件删除 PoC，留在 `contacts_demo/`；其修复对照是 PoC-only guard，没有可信上游 fixed commit，因此不把它当成本案例的 fixed-source PoC。

## 固定来源与候选绑定

组件为 `openharmony/arkcompiler_ets_runtime`，文件 `ecmascript/base/atomic_helper.cpp`，函数 `AtomicHelper::ValidateAtomicAccess`。

| 项 | Vulnerable | Fixed |
|---|---|---|
| Commit | `cae11f121c030a90ba41d8e4d866f91292f25892` | `5aa9c035e98911ec7ed28065a2138c2709792a42` |
| Tree | `61ff01d9a06b4186125a04e2b790e07640f57198` | `05ac3902979e37ae08efa2d1e3ed32472a69d0cc` |
| Blob | `7fd67717571c6d8fe7b10bf294998e952dc61e36` | `80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c` |
| File SHA-256 | `f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541` | `39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b` |
| Snapshot SHA-256 | `3dbcf1026af41de48c9ed318a2fab2d1d1e3e6f30b922899bf34dbe911d9e512` | `b90f87a0b1a4adcface27e3178ca1920ff0a5e5c0a42b4c2cb717ddb4c0ad452` |
| CLI candidates | `1` | `0` |

Detector: `ohscanner.cpp.integer_bounds` **0.2.0**. Rule: `ohcpp-integer-bounds-narrow-index-candidate-003` **0.2.0**. Vulnerable diagnostic ID: `ohscanner.cpp.integer_bounds:b7b2f77b4f18fb3d`, line 71. CLI JSON and Markdown evidence is in `research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_{vulnerable,fixed}.{json,md}`. Those files report complete parsing on both selected source files and `validated_vulnerability=0`.

The vulnerable function narrows array length to signed `int32_t` and narrows the `ToIndex` result through `DoubleInRangeInt32` before bounds checking. The fixed function keeps length unsigned, converts the index to `uint64_t`, checks it before offset arithmetic, and multiplies in the wide type. The exact file-only patch SHA-256 is `419c0d324f4468631e7ec56d3a9e8319d9a98cc91a918e99856ffd581ce9191d` (2,486 raw diff bytes). This patch-to-candidate correspondence supports source-level root-cause review, not runtime impact.

## Runtime attempt

An isolated WSL build attempt was made against the available Ark Runtime component checkout:

```bash
cd /mnt/d/openHarmonyScanner/tmp/arkruntime-d1a58d5
./build.sh --product-name rk3568 --build-target ark_js_runtime_core
```

Exit status: **127**. The log records `./build.sh: No such file or directory`. The checkout is the component repository and has no top-level OpenHarmony product build driver/profile; an Ark Runtime component/product build and executable PoC could not be run from this environment. This is a concrete build prerequisite blocker, not a successful test. Full stdout/stderr and exit status are preserved in `runtime_attempt.log`; result: **runtime not_run**.

The failed attempt establishes only that the requested component build command is unavailable in this checkout. It does not show the input is unreachable or the bug harmless. No test-only arithmetic reproduction is substituted for executing the component implementation.

## Reproduction

From the OHScanner repository root, verify the immutable Git objects and file mapping:

```powershell
$repo = 'D:\openHarmonyScanner\arkruntime-holdout-history'
git -C $repo show -s --format='commit=%H tree=%T' cae11f121c030a90ba41d8e4d866f91292f25892
git -C $repo show -s --format='commit=%H tree=%T' 5aa9c035e98911ec7ed28065a2138c2709792a42
git -C $repo ls-tree cae11f121c030a90ba41d8e4d866f91292f25892 ecmascript/base/atomic_helper.cpp
git -C $repo ls-tree 5aa9c035e98911ec7ed28065a2138c2709792a42 ecmascript/base/atomic_helper.cpp
```

Replay the production CLI pair from the repository root:

```powershell
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_vulnerable.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_vulnerable.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit 5aa9c035e98911ec7ed28065a2138c2709792a42 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_fixed.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_fixed.md
```

Run the recorded product-build attempt in WSL to reproduce its current blocker:

```bash
cd /mnt/d/openHarmonyScanner/tmp/arkruntime-d1a58d5
./build.sh --product-name rk3568 --build-target ark_js_runtime_core
```

The existing Contacts PoC, including compile/run logs, source extraction binding and PoC-only guard comparison, remains available at `research/evidence/cpp/a_final_closeout_20261020/contacts_demo/CONTACTS_PATH_TRAVERSAL_DEMO_20261021.md` as a separate component demonstration. It is not evidence for CVE-2025-0587 and does not supply an upstream Contacts fix.

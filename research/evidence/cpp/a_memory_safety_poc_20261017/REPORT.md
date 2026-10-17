# A memory-safety isolated PoC and historical replay package

更新：2026-10-17。源代码是本仓库自编 synthetic controls，不是直接构建的 OpenHarmony 产品。运行只使用本地 WSL `g++ 11.4.0`、C++17、ASan/UBSan；没有网络、没有外部扫描器、没有线上服务。

Exact command:

```text
bash validation/cpp_memory_safety_poc/run.sh /mnt/e/网安/CyberSecurity-Innovation-Audit/outputs/poc/a_memory_safety_20261017_runtime
```

## Generic controls

- `bounds_vulnerable.cpp`: exit `1`，ASan `stack-buffer-overflow`，`memcpy` 写入 16 bytes 到 8-byte stack destination。
- `bounds_fixed.cpp`: exit `0`，输出 `rejected oversized copy`。
- `integer_vulnerable.cpp`: exit `0`，输出 `allocated=0`，`uint32_t input=UINT32_MAX; uint32_t bytes=input+1` 发生回绕；本机 0-byte allocator 未触发 ASan，不声称动态崩溃。
- `integer_fixed.cpp`: exit `0`，输出 `rejected overflowing addition`。

## CVE-2025-23420 mechanism PoC

Historical source binding is recorded in `../a_historical_memory_replay_20261017/summary.json`:

- repository `openharmony/arkcompiler_ets_runtime`
- vulnerable `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11`, tree `0eea26c9eb6846f4d19926be83092c06f0d98692`
- fixed `1b23531531e768398682582969c2a9f17e72cafe`, tree `52f27683e2f6e1ba8272aee7d5202c73059e10b4`
- affected module `ecmascript/js_array.cpp`, symbol `JSArray::SortElementsByObject`
- fixed commit message identifies the OpenHarmony 5.0.2 cherry-pick line; exact local branch/ref is unknown
- patch SHA-256 `e0b61dde4058080ee28184d49b3d7da80e4ad428bc2030a04fc5f69bccbc0512`

The isolated C++ harness models the published root cause: comparator execution mutates/frees the backing store while insertion sort continues using a stale element accessor.

- `cve_2025_23420_vulnerable.cpp`: exit `1`，ASan `heap-use-after-free` in `ElementAccessor::Set` after comparator-driven backing-store release.
- `cve_2025_23420_fixed.cpp`: exit `0`，每次访问重查 `index < values.size()` 并走安全 fallback，输出 `fixed path completed size=1`。

This is a runnable mechanism PoC and fix/revalidation control. It is not a direct ArkCompiler product build or a newly discovered vulnerability. The exact vulnerable/fixed upstream source, commit/tree/blob/source hashes and detector replay (5 direct element-access candidates -> 0 after fix) are retained in the historical replay package.

## Boundary

`CVE-2025-23420` is historical published ground truth, not a new finding. No product build, permission boundary, attacker trace or CIA analysis is re-proven by this mechanism harness. The report therefore distinguishes: known historical CVE reproduced at mechanism level; new OpenHarmony candidates remain `candidate/unknown` and `validated_vulnerability=0`.

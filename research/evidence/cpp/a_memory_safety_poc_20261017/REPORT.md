# A memory-safety isolated PoC package

更新：2026-10-17。源代码是本仓库自编 synthetic controls，不是 OpenHarmony 产品漏洞或产品构建。运行只使用本地 WSL `g++ 11.4.0`、C++17、ASan/UBSan；没有网络、没有外部扫描器、没有产品入口。

Exact command:

```text
bash validation/cpp_memory_safety_poc/run.sh /mnt/e/网安/CyberSecurity-Innovation-Audit/outputs/poc/a_memory_safety_20261017_runtime
```

## Results

- `bounds_vulnerable.cpp`: exit `1`，ASan `stack-buffer-overflow`，`memcpy` 写入 16 bytes 到 8-byte stack destination。
- `bounds_fixed.cpp`: exit `0`，输出 `rejected oversized copy`，长度守卫拒绝超限 copy。
- `integer_vulnerable.cpp`: exit `0`，输出 `allocated=0`，`uint32_t input=UINT32_MAX; uint32_t bytes=input+1` 发生回绕；本机 allocator 对 0-byte allocation 的后续写未触发 ASan，不能声称动态崩溃。
- `integer_fixed.cpp`: exit `0`，输出 `rejected overflowing addition`，显式拒绝 `UINT32_MAX + 1`。

## Boundary

bounds PoC 证明的是 synthetic lexical bug shape 可在隔离编译器/ASan 下重现；integer PoC 证明确定性算术回绕和修复控制，不证明 OpenHarmony 产品可利用。没有产品入口、权限边界、触发 trace、产品构建、CIA 影响、CVE 或上游修复验证，故 `validated_vulnerability=0`。

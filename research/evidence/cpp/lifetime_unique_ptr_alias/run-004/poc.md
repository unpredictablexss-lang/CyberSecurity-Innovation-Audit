# unique_ptr raw-alias lifetime PoC

> controlled component-level dynamic evidence；结果保持 candidate/unassessed。

- detector: `ohscanner.cpp.lifetime` `0.3.0`
- harness SHA-256: `e617b9d4e9dd3efdc9c02e8604cb6d228fdd37977995ae0c4ae6ba536dfc3aad`
- outcome: **stable_reproduced_and_patch_revalidated**
- `validated_vulnerability`: 0

## Runtime

| variant | repeat | outcome | ASan |
|---|---:|---|---|
| `reset_vulnerable` | 1 | sanitizer_triggered | True |
| `null_assignment_vulnerable` | 1 | sanitizer_triggered | True |
| `replacement_vulnerable` | 1 | sanitizer_triggered | True |
| `move_transfer_vulnerable` | 1 | sanitizer_triggered | True |
| `fixed_rebind` | 1 | clean | False |
| `safe_use_before_reset` | 1 | clean | False |
| `reset_vulnerable` | 2 | sanitizer_triggered | True |
| `null_assignment_vulnerable` | 2 | sanitizer_triggered | True |
| `replacement_vulnerable` | 2 | sanitizer_triggered | True |
| `move_transfer_vulnerable` | 2 | sanitizer_triggered | True |
| `fixed_rebind` | 2 | clean | False |
| `safe_use_before_reset` | 2 | clean | False |
| `reset_vulnerable` | 3 | sanitizer_triggered | True |
| `null_assignment_vulnerable` | 3 | sanitizer_triggered | True |
| `replacement_vulnerable` | 3 | sanitizer_triggered | True |
| `move_transfer_vulnerable` | 3 | sanitizer_triggered | True |
| `fixed_rebind` | 3 | clean | False |
| `safe_use_before_reset` | 3 | clean | False |

## Interpretation boundary

本记录提供 self-authored controlled dynamic evidence；不证明真实产品入口、攻击者控制、CIA 影响或可利用性。候选不自动升级。

## Remaining limitations

- PoC 是自编最小 workload，不是真实 OpenHarmony 产品组件；产品入口、权限边界、攻击者控制和 CIA 影响均未证明。
- AddressSanitizer 触发证明受控生命周期破坏行为，不自动等于稳定可利用漏洞。
- fixed_rebind 与 safe_use_before_reset 是本地控制/修复重验变体，不是上游补丁。
- CFG、异常/提前返回、析构时序、跨函数 alias 转移和真实构建配置仍由检测器作为 unknown 保留。

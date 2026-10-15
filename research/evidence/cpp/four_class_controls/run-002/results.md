# C/C++ four-class detector controls

> Synthetic development controls only; not an independent holdout and not accuracy data.

- package: `cpp-detector-four-class-controls-20261015`
- manifest SHA-256: `8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2`
- snapshot SHA-256: `d4333621872fcd3d135d08b95fae32d4d7035fc88735bcf90a36236a255d28b7`
- detector matrix: 20 passed, 0 failed
- native controls: 20 passed, 0 failed
- family PoC harnesses: passed
- `validated_vulnerability`: 0

## Controls

| id | class | detector findings | native result | status |
|---|---|---:|---|---|
| `shared-vulnerable-delayed-singleton-plain` | vulnerable | 1 | sanitizer_triggered,sanitizer_triggered,sanitizer_triggered | passed |
| `shared-vulnerable-atomic-exchange-mixed` | vulnerable | 1 | sanitizer_triggered,sanitizer_triggered,sanitizer_triggered | passed |
| `shared-vulnerable-compare-exchange-mixed` | vulnerable | 1 | sanitizer_triggered,sanitizer_triggered,sanitizer_triggered | passed |
| `shared-fixed-delayed-singleton-explicit-lock` | fixed | 0 | clean,clean,clean | passed |
| `shared-fixed-atomic-exchange-protocol` | fixed | 0 | clean,clean,clean | passed |
| `shared-safe-explicit-lock-common-fp` | safe | 0 | clean,clean,clean | passed |
| `shared-safe-cross-class-same-member-name` | safe | 0 | clean,clean,clean | passed |
| `shared-unrelated-plain-pointer` | unrelated | 0 | clean,clean,clean | passed |
| `lifetime-vulnerable-reset-raw-alias` | vulnerable | 1 | sanitizer_triggered,sanitizer_triggered,sanitizer_triggered | passed |
| `lifetime-vulnerable-owner-null-assignment` | vulnerable | 1 | sanitizer_triggered,sanitizer_triggered,sanitizer_triggered | passed |
| `lifetime-vulnerable-owner-replacement` | vulnerable | 1 | sanitizer_triggered,sanitizer_triggered,sanitizer_triggered | passed |
| `lifetime-vulnerable-restricted-move-transfer` | vulnerable | 1 | sanitizer_triggered,sanitizer_triggered,sanitizer_triggered | passed |
| `lifetime-fixed-reset-rebind-patch` | fixed | 0 | clean,clean,clean | passed |
| `lifetime-fixed-owner-null-rebind-patch` | fixed | 0 | clean,clean,clean | passed |
| `lifetime-fixed-owner-replacement-rebind-patch` | fixed | 0 | clean,clean,clean | passed |
| `lifetime-fixed-move-scope-patch` | fixed | 0 | clean,clean,clean | passed |
| `lifetime-safe-stable-owner-pointer` | safe | 0 | clean,clean,clean | passed |
| `lifetime-safe-shadowed-bindings` | safe | 0 | clean,clean,clean | passed |
| `lifetime-safe-comment-false-positive` | safe | 0 | clean,clean,clean | passed |
| `lifetime-unrelated-raw-pointer` | unrelated | 0 | clean,clean,clean | passed |

## Patch revalidation

| control | patch kind | upstream status | result |
|---|---|---|---|
| `shared-vulnerable-delayed-singleton-plain` | n/a | n/a | not_applicable |
| `shared-vulnerable-atomic-exchange-mixed` | n/a | n/a | not_applicable |
| `shared-vulnerable-compare-exchange-mixed` | n/a | n/a | not_applicable |
| `shared-fixed-delayed-singleton-explicit-lock` | authored_control_remediation_patch | not_claimed_as_upstream_product_patch | passed |
| `shared-fixed-atomic-exchange-protocol` | authored_control_remediation_patch | not_claimed_as_upstream_product_patch | passed |
| `shared-safe-explicit-lock-common-fp` | n/a | n/a | not_applicable |
| `shared-safe-cross-class-same-member-name` | n/a | n/a | not_applicable |
| `shared-unrelated-plain-pointer` | n/a | n/a | not_applicable |
| `lifetime-vulnerable-reset-raw-alias` | n/a | n/a | not_applicable |
| `lifetime-vulnerable-owner-null-assignment` | n/a | n/a | not_applicable |
| `lifetime-vulnerable-owner-replacement` | n/a | n/a | not_applicable |
| `lifetime-vulnerable-restricted-move-transfer` | n/a | n/a | not_applicable |
| `lifetime-fixed-reset-rebind-patch` | authored_control_remediation_patch | not_claimed_as_upstream_product_patch | passed |
| `lifetime-fixed-owner-null-rebind-patch` | authored_control_remediation_patch | not_claimed_as_upstream_product_patch | passed |
| `lifetime-fixed-owner-replacement-rebind-patch` | authored_control_remediation_patch | not_claimed_as_upstream_product_patch | passed |
| `lifetime-fixed-move-scope-patch` | authored_control_remediation_patch | not_claimed_as_upstream_product_patch | passed |
| `lifetime-safe-stable-owner-pointer` | n/a | n/a | not_applicable |
| `lifetime-safe-shadowed-bindings` | n/a | n/a | not_applicable |
| `lifetime-safe-comment-false-positive` | n/a | n/a | not_applicable |
| `lifetime-unrelated-raw-pointer` | n/a | n/a | not_applicable |

## Interpretation boundary

`safe`/`unrelated` 的 0 告警只表示当前窄规则未观察到目标形状，不是安全结论，也不按告警数量强判 miss。`fixed` 使用可复核的authorship remediation patch 稳定拒绝；它不冒充上游产品补丁。

## Limitations

- 所有样本为自编 synthetic development controls，不是独立 holdout，也不能计算 Precision/Recall。
- fixed 项绑定可执行、零 fuzz 的 authored_control_remediation_patch，并要求 Detector 稳定拒绝；不冒充上游产品补丁。
- TSan/ASan 只证明受控 workload 中的局部内存/并发行为，不证明真实产品入口、攻击者控制、CIA 影响或可利用性。
- shared_ptr Detector 的原子 API 和互斥身份仍是窄词法模型，跨函数协议、锁别名、模板实例化和真实构建配置保持 unknown。
- lifetime Detector 不建模完整 CFG、异常、析构时序、跨函数 alias 或真实所有权图；0 告警不是安全证明。
- sanitizer 结果受编译器、调度、迭代数和 allocator 影响；必须记录 exact argv、版本、重复次数和全部运行。

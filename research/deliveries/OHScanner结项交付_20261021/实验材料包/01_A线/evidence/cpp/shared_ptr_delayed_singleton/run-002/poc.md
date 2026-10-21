# shared_ptr DelayedSingleton PoC

> controlled component-level dynamic evidence；结果保持 candidate/unassessed。

- package: `cpp-shared-ptr-delayed-singleton-20261014`
- detector: `ohscanner.cpp.shared_ptr_race` `0.4.0`
- source binding: `preserved_artifact_hash_verified`
- outcome: **stable_reproduced_mixed_fix_residual**
- evidence level: `controlled_dynamic_reproduction`
- `validated_vulnerability`: 0

## Source binding

- `upstream_fix`: commit `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7`, path `outputs/reports/static_baselines/c_utils_singleton_uaf.fixed.codeql/source/base/include/singleton.h`, SHA-256 `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606`
- `vulnerable`: commit `bdfafdaafddb01ab7ae13354ce2ada9555d7935c`, path `outputs/reports/static_baselines/c_utils_singleton_uaf.vulnerable.codeql/source/base/include/singleton.h`, SHA-256 `ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4`

## Builds

| revision | outcome | exit |
|---|---|---:|
| `vulnerable` | build_success | 0 |
| `upstream_fix` | build_success | 0 |
| `fully_atomic_patch` | build_success | 0 |

## Runtime

| revision | mode | outcome | TSan |
|---|---|---|---|
| `vulnerable` | single | clean | False |
| `upstream_fix` | single | clean | False |
| `fully_atomic_patch` | single | clean | False |
| `vulnerable` | race | sanitizer_triggered | True |
| `upstream_fix` | race | sanitizer_triggered | True |
| `fully_atomic_patch` | race | clean | False |
| `vulnerable` | race | sanitizer_triggered | True |
| `upstream_fix` | race | sanitizer_triggered | True |
| `fully_atomic_patch` | race | clean | False |
| `vulnerable` | race | sanitizer_triggered | True |
| `upstream_fix` | race | sanitizer_triggered | True |
| `fully_atomic_patch` | race | clean | False |

## Detector linkage

- `fully_atomic_patch`: `ohscanner.cpp.shared_ptr_race` `0.4.0`, status `completed`, findings `0`
- `upstream_fix`: `ohscanner.cpp.shared_ptr_race` `0.4.0`, status `completed`, findings `3`
- `vulnerable`: `ohscanner.cpp.shared_ptr_race` `0.4.0`, status `completed`, findings `2`

## Interpretation boundary

本记录提供 controlled component-level dynamic evidence；它不证明产品入口、权限/身份边界、攻击者控制、具体 CIA 影响或可利用性。候选不自动升级。

## Remaining limitations

- 当前本地 commonlibrary_c_utils Git 对象库缺少两个历史提交，Git object provenance 保持 unknown；只验证保留源码字节、SHA-256 和关键代码引文。
- PoC 使用自编 workload 调用未修改的 singleton.h，证明组件级并发行为，不证明 OpenHarmony 产品入口、权限边界或攻击者控制。
- ThreadSanitizer 数据竞争不等价于稳定 use-after-free 崩溃；CWE-416 仍只是可能后果。
- fully_atomic_patch 是本地修复重验变体，不是上游补丁，也不自动构成 reportable 修复建议。
- 线程调度、迭代规模、编译器和 sanitizer 版本会影响动态复现；原始日志和环境必须随结果保存。

# RC-JSPROXY 真实产品闭环最小验证包

- 最终状态：`candidate/unknown`
- `validated_vulnerability`：`0`
- 候选组：`RC-JSPROXY`
- 本包不修改历史候选、review、报告或漏洞状态；只有产品级强制义务全部满足并经负责人/独立复核授权后，才进入 confirmed/reportable 审核。

## 1. 固定身份与候选级证据

- repository：`openharmony/distributeddatamgr_kv_store`
- commit/tree：`acfb22aac16161d8fb0cefb6cc9b92f04f489a80` / `3b92c53fde616d5a3f9487b0c295670a42c63023`
- source：`frameworks/common/js_proxy.h` blob `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46` SHA-256 `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`
- 组件级三方复验：`met`；证据级别：`controlled_component_dynamic_reproduction`

## 2. 真实产品构建方式和产物 hash

- 构建入口：`bash build/build_scripts/build.sh --product-name rk3568 --build-variant user --build-target //foundation/distributeddatamgr/kv_store/interfaces/jskits/distributedkvstore:distributedkvstore`
- 目标：`//foundation/distributeddatamgr/kv_store/interfaces/jskits/distributedkvstore:distributedkvstore`；产品：`rk3568`；variant：`user`
- 方法状态：`source_derived_unexecuted`；当前 preflight：`blocked`
- 产品构建义务：`unknown`
- 当前真实构建产物 hash：未生成/未证明。缺任何 vulnerable/fixed/patched 产物的 path、SHA-256、size、install path，必须保持 unknown。

## 3. 真实入口、调用链、权限/身份/部署边界

- 源码可见链：`getResultSet -> NapiQueue::AsyncWork -> SetInstance`、`getEntry -> GetInstance`、`closeResultSet -> NapiQueue::AsyncWork -> GetInstance/SetInstance(nullptr)/CloseResultSet`。
- 产品入口/边界义务：`unknown`。
- 当前只能证明源码可见入口；产品包解析、app identity、permission grant/deny、user/sandbox、跨应用/IPC/remote 面仍是 unknown，不能作为攻击者控制证明。

## 4. 可重复触发条件和产品级交错 trace

- 固定触发序列：同一应用先 `getResultSet`，在 JS 线程持续 `getEntry`，同时异步 `closeResultSet` 的 execute 与读取重叠。
- 产品交错 trace 义务：`unknown`。
- 产品 trace 必须记录每轮 thread ID、JS/async queue、`SetInstance/GetInstance`、`closeResultSet/getEntry` 源位置、重叠起止事件和产品 artifact SHA-256。Harness TSan trace 不是产品 trace。

## 5. CIA 影响

| 维度 | 要求 | 当前状态 |
|---|---|---|
| 可用性 | 产品进程/API 失败率、崩溃或稳定无故障测量 | 产品级 unknown；Harness 仅证明 race |
| 完整性 | 返回 entry/状态是否偏移、损坏或误读 | unknown |
| 机密性 | 同应用、跨应用、跨设备数据暴露边界 | 未证明，不作泄露声明 |

- CIA 义务：`unknown`。

## 6. vulnerable / fixed / patched 三方重复验证

| variant | 组件级 close_get_entry | 产品级重复 |
|---|---|---|
| `vulnerable` | `['sanitizer_triggered', 'sanitizer_triggered', 'sanitizer_triggered']` | 3 次产品级 trace 要求，当前未证明 |
| `fixed_control_mutex` | `['clean', 'clean', 'clean']` | 3 次产品级 trace 要求，当前未证明 |
| `patched_atomic_minimal` | `['clean', 'clean', 'clean']` | 3 次产品级 trace 要求，当前未证明 |

组件级已有证据是 exact-header Harness/PoC：vulnerable 3/3 TSan 触发，mutex fixed control 3/3 clean，atomic patch 3/3 clean。它不能替代真实产品构建/运行。

## 7. 影响模块、版本、分支和修复重验

- 影响模块候选：`frameworks/common/js_proxy.h`、`js_single_kv_store.cpp`、`js_kv_store_resultset.cpp`、`napi_queue.cpp`。
- 精确 commit/tree 是已绑定事实；版本和分支成员关系必须用固定 tag/branch/product image manifest 证明，当前保持 unknown。
- 修复/范围义务：`unknown`。
- proposed atomic patch 与 fixed mutex control 必须在相同真实产品 build/profile 下分别构建并重验，不能只用组件级 clean 代替。

## 8. CWE/CVE 绑定依据

- 主绑定：`CWE-362`，依据是同一 `shared_ptr` owner 的非同步写/读及 TSan race；不是仅凭 AST 命中。
- `CWE-416` 只有在产品级 UAF/内存生命周期证据成立时才可作为后果；当前不绑定为已证实后果。
- CVE：本地证据没有 assigned CVE。必须保存 CVE/NVD/上游公告检索范围和检索时间；无 assignment 不等于无漏洞。
- CWE/CVE 义务：`unknown`。

## 9. 审计产物与剩余 unknown

- `product-build` [critical]：真实产品/组件构建命令、完整依赖/工具链 manifest、三 variant 构建产物 hash/install path 未证明
- `product-entry` [critical]：真实产品进程中的 JS/NAPI entry 与部署包解析未证明
- `permission-identity` [critical]：permission grant/deny、app identity、uid/user/sandbox 边界未证明
- `product-trace` [critical]：产品级 thread/queue/source-bound CloseResultSet/getEntry 交错 trace 未证明
- `cia-impact` [high]：产品级 availability/integrity/confidentiality 实测未完成
- `scope` [high]：受影响版本、分支和产品 image 范围未证明
- `cve` [medium]：CVE assignment/上游公告/检索范围尚未审计
- `exploitability` [high]：stable crash、memory corruption、UAF 与可利用性未证明

### 产物

- `fixed_control_mutex.patch` SHA-256 `f4b976fa8fd1b60f8ffc3d51e8262c5da3f2144d19cd51dab999ec80c415bf9a`（independent safe control）
- `patched_atomic_minimal.patch` SHA-256 `3b04fd4e5575e224df35f77be487f3cd90d0a40501b1ff65f5d01886037124c9`（minimal proposed repair）
- `validation.json`：机器可读义务矩阵、输入 hash 和 fail-closed 结论。
- `package-manifest.json`：本目录产物 hash 清单。

## 重放

```text
python -m src.ohscanner.poc.rc_jsproxy_product_gate \
  --candidate-manifest src/ohscanner/poc/harnesses/cpp_shared_ptr_jsproxy/manifest.json \
  --component-poc outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json \
  --product-evidence research/evidence/cpp/rc_jsproxy_product_gate_20261015/product-evidence.json \
  --product-source-root E:/网安/_product_targets \
  --source-repo E:/网安/audit-sources-20261014/home/audit/openharmony-audit/perf-corpus/distributeddatamgr_kv_store \
  --output-dir outputs/reports/rc-jsproxy-product-gate-20261015
```

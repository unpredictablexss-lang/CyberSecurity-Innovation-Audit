# 限制说明

## 产品证据缺失

- 当前产品 preflight 只有 `build`、`manifest`、`vendor_hihope` 和固定 `distributeddatamgr_kv_store` 局部 checkout；没有完整 OpenHarmony `.gn`、`foundation/distributeddatamgr/kv_store/BUILD.gn`、`device/board/hihope/rk3568`、`prebuilts/build-tools` 或 `prebuilts/python`。
- 没有完整 pinned source manifest、toolchain manifest 或 GN/NAPI/device/prebuilts 依赖闭包。`default_small.xml` 对 `distributeddatamgr_kv_store` 记录的是 `revision=master`，不能作为固定产品源码清单。
- 产品构建命令执行 2 次均失败：第一次是 CRLF `build.sh` 解析失败；第二次在内存中规范化换行后因产品源码树不存在而失败。没有生成任何产品 artifact，因此绝不填写产品 artifact hash、size 或 install path。
- `vulnerable / fixed_control_mutex / patched_atomic_minimal` 的当前 hash 只对应组件 Harness 产物和组件变体源文件。它们不能写入产品 `artifact.sha256`。
- 没有真实产品 image、package、JS/NAPI runtime symbol、app identity、UID、permission grant/deny、user/sandbox、exported surface 或安装路径证据。
- 没有产品级 `CloseResultSet` 与 `getEntry` 交错 trace。组件 trace 只记录模型化 thread/queue 调用形态。
- availability / integrity / confidentiality 均没有产品级测量；不能把组件 TSan race 写成 DoS、状态破坏或泄露。
- 受影响模块只有源码绑定候选；版本、产品 image 和分支成员关系保持 unknown。目标 checkout 是 detached HEAD，`git branch -a --contains HEAD` 只有 synthetic `source/acfb22...` 名称，没有 audited product branch/tag membership。
- 没有 CVE/NVD/上游公告检索范围、查询、时间和结果记录，因此 CVE 保持 unknown；不伪造 assignment。
- `CWE-362` 依据是非同步 `shared_ptr` owner 读写和组件 TSan race。`CWE-416` 只是可能后果，不能当产品 UAF 证据。

## 组件结果的边界

- 组件 PoC 为 exact-header Harness，不是 OpenHarmony、KV store backend 或 live product service。
- ThreadSanitizer 可以证明受控 owner race，不证明稳定 crash、UAF、内存破坏、数据泄露、权限提升或稳定可利用性。
- `fixed_control_mutex` 是独立安全控制，`patched_atomic_minimal` 是本地拟议补丁，不是上游修复。
- 0 findings 只表示窄 Detector 规则不再命中，不表示全局安全。

## 运行环境和工作树

- 执行环境：WSL2 Ubuntu 22.04，Python 3.10.12，Ubuntu clang 14.0.0，ThreadSanitizer；网络动作均为 none。
- 项目 checkout：`codex/full-runtime-performance-audit-20261014`，HEAD `38b93d30ed4be71af4a8245ed18198d999c3ee18`，dirty worktree 被保留，未 push。
- `git diff --check` 当前失败于两个先前已存在的 dirty 文件 EOF 空行；本任务没有修改这些文件，失败原因记录在 `logs/git-diff-check.log`。
- 未执行任何远程 fetch、CVE 查询、设备连接或产品动态攻击。

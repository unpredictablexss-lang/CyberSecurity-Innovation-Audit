# T45 — safwk ExpireLruCache shared_ptr 候选复核 CR-0231–CR-0240

## 来源与当前 CLI

10 条 A0 记录均绑定 `openharmony/systemabilitymgr_safwk` commit `21c83c874a34e8d28e6a355a3b56e5167252ed27`、tree `e115202d315867371b3b7c885b4f017e10cb163f`、`interfaces/innerkits/safwk/expire_lru_cache.h` blob `3e004bca071eb51d0e108845addf5ec3e25dbc65`、SHA-256 `9eb5ce4db56c91311de4351d639949d56566733ede610f5039a39ff0148265e3`。逐行 ID、候选键及原状态在 [机器映射](t45_safwk_expire_lru_cache_audit_20261027.json) 中。

当前 `ohscanner.cpp.shared_ptr_race` 0.5.1 CLI 对该精确头文件执行一次完整解析：1/1 complete，194 LOC，0 diagnostics，0 validated vulnerabilities。CR-0231–0240 的所有 A0 行均没有同一行当前告警。CLI 原始结果：[JSON](d42_safwk_expire_lru_cache_20261027.json)、[Markdown](d42_safwk_expire_lru_cache_20261027.md)。精确重放命令：

```powershell
python -m src.cli.main ohscan-run --repo-dir <safwk exact commit checkout> --repository openharmony/systemabilitymgr_safwk --commit 21c83c874a34e8d28e6a355a3b56e5167252ed27 --detector ohscanner.cpp.shared_ptr_race --include interfaces/innerkits/safwk/expire_lru_cache.h --json-out research/evidence/cpp/d42_safwk_expire_lru_cache_20261027.json --md-out research/evidence/cpp/d42_safwk_expire_lru_cache_20261027.md
```

## 读写和同步证据

`ExpireLruCache::data_` 是 `map<TKey, shared_ptr<TValue>>`。`DoAdd` 插入、替换或淘汰元素；`DoGet` 查找并在过期时删除、未过期时返回 shared_ptr 副本；`DoRemove` 删除，`DoClear` 清空，`DoClearExpiredCache` 遍历时间表并清除过期项。公开 `Add/Get/Remove/Clear` 均在调用对应私有 `Do*` 前持有同一实例的 `lock_`（目标文件 41–66 行）；精确头文件中私有 helper 没有其他调用点。与这份零诊断结果相符，当前规则仅记录 `data_` 的只读访问，不组成潜在冲突对。`Get` 返回的值对象在锁释放后可被调用方使用，但本证据没有显示其与缓存 map wrapper 并发写入；TValue 的外部可变性也不等同于 `data_` 成员 race。

调用者 `ApiCacheManager` 再以 `cachesMutex_` 包围 cache map 查找和 inner `Get/Add/Clear` 调用。`AddCacheApi`、`DelCacheApi`、三个 `ClearCache` 重载、`PreSendRequest`、`PostSendRequest` 都在访问 `caches_` 时持锁；其中 `PreSendRequest` 转调 `Get`，`PostSendRequest` 转调 `Add`。`api_cache_manager.h`、实现文件和两处 GN 文件身份均由机器映射 SHA/blob 固定。`interfaces/innerkits/safwk/BUILD.gn` 注册 `ohos_shared_library("api_cache_manager")` 并列出 `api_cache_manager.cpp`；单测 GN 注册 `ohos_unittest("ExpireLruCacheTest")`。单测使用 `#define private public` 直接检查 `data_`，但检查是顺序调用；这不能作为生产并发证据。

## 判定与限制

语法候选及 A0 队列观察没有重现为当前同一行 finding；目前精确实现的公开调用路径显示内外两层锁。没有基于当前资料证明存在未同步的同对象并发访问，因此不应由这些语法候选推导 data race。所有 10 行继续保持 `not_testable / paused_pending_evidence`，本次标为 `PARTIAL/BLOCK`；这不是漏洞确认，也不是无漏洞结论。产品 profile、具体运行实例/调用线程时序、系统级构建配置和实际产品行为仍未绑定；未运行产品或动态 TSan 验证。

验证器：`python research/evidence/cpp/verify_t45_safwk_expire_lru_cache_audit_20261027.py --source-repo <safwk exact commit checkout>`。本次未改 detector、tests、fixtures、API、schema 或 A0 队列状态。

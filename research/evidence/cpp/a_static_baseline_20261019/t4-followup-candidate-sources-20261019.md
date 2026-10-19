# T4 独立来源与静态复跑补充记录

日期：2026-10-19
工作树：`D:\openHarmonyScanner\worktrees\a-t1-audit-pr30-20261019`
PR #30 基线：`8ec5f56a12e90bba56953b39eb17faa20e154da9`
本次检测器：`ohscanner.cpp.resource_lifetime` v0.1.0；profile `light-ast`

## 结果概览

| 案例 | 来源与修复情况 | 本次 PR30 复跑 | 状态 |
|---|---|---|---|
| libpng CVE-2026-46675 | 有精确漏洞版本与官方修复提交；修复提交 tree 未取得 | 漏洞、修复父提交、官方修复文件、OH 生成文件均 0 finding；各目标文件 parse partial | PARTIAL |
| libpng CVE-2026-33416 | 官方 1.6.55/1.6.56 源码与四个文件的 commit/tree/blob/SHA256 已绑定 | 1.6.55/1.6.56 两侧均 0 finding；4/4 文件 parse partial | PARTIAL |
| cJSON CVE-2026-67215 | 精确绑定 OH 1.7.19 组件源码；没有符合根因的上游 fixed source | 2 文件 0 finding；cJSON.c partial，cJSON_Utils.c complete；整体 blocked | PARTIAL |
| cJSON CVE-2026-67216 | 精确绑定 OH 1.7.19 cJSON.c；没有符合复杂度根因的 fixed source | 与 67215 共用的 2 文件 replay；0 finding，cJSON.c partial | PARTIAL |

本工作树的 resource lifetime detector 是 0.1.0。更晚的独立材料记录 libpng 33416 在 detector 0.1.9 上有 2/0 候选差分，但 4/4 仍 partial。两次结果绑定不同 scanner 版本，不能混合成一个 before 结果。全部 raw JSON/Markdown 结果以 `t4-` 为前缀保存在本目录。

## CVE-2026-46675 / GHSA-qvg3-h654-xq3j

官方 libpng advisory 描述未完整解压 zTXt/iTXt/iCCP 后执行 `png_read_info()` 再执行 `png_read_end()`、且未读取行数据的悬空 zlib 输入指针问题；当前 advisory 将 1.6.59 列为修复版本。漏洞对象为 upstream v1.6.55 commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`、tree `e01f5780f93eaa6d74cca003bb39b427c8f1e910`、`pngrutil.c` blob `a4eda54c8cb3d36cf1651dba159067b65030e3aa`、SHA256 `b328fb05352226866b1e44c8cddd3e03df35413f1f38f4d81ba51afe4f2333a5e`。

官方 fix commit 为 `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`，修复父提交为 `4eeb825ab26605ed34cd74495d4cce920939fe9f`。其 `pngrutil.c` 的 blob/SHA256 分别为 `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a` / `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`，和 `5513951681f52da994ba72c96af135bfede5393e` / `f67dbcc82dce533ec0a768184a142216f6ac3d9e68f2a35d5cd90c4667b24d1c`。上游 tree 未从可用官方文件接口取得，未以 synthetic snapshot tree 冒充。

本次四条 CLI 复跑见 `t4-libpng46675-{vuln,parent,fixed,oh}.json`：每份单文件均 0 finding、parse partial、detector blocked。既有 ASan 证据在独立组件构建上重现了漏洞版无读行序列的 UAF；修复移植版未出现同一 ASan 报告，但它不是字节级官方 fixed tree 构建。该运行时证据不弥补 scanner 的解析阻塞。

## CVE-2026-33416 / GHSA-m4pc-p4q3-4c7j

官方 advisory 将受影响范围列为 1.6.55 及以前、修复版本 1.6.56。漏洞版本为 v1.6.55 commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`、tree `e01f5780f93eaa6d74cca003bb39b427c8f1e910`；修复版为 v1.6.56 commit `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33`、tree `a28bb962645843af84063c77f574f6d88da79f76`。对应 `pngset.c`、`png.c`、`pngread.c`、`pngrtran.c` 的 upstream Git blob 与源 SHA256 逐文件列在配套 JSON manifest 中。T4 通过官方 GitHub `github_fetch_file` 对上述 8 个精确 commit/path 取得 blob OID，八个值均与 synthetic scan snapshot 对象一致。

T4 用每个 source snapshot 相同的四文件 scope 重跑：v1.6.55 0 finding / 4 partial，v1.6.56 0 finding / 4 partial。D3 后的后续独立报告用 resource_lifetime 0.1.9 得到 2/0 候选差分（`pngrtran.c:1187`、`:1228`），但同样 4/4 partial。ASan 组件安全/修复序列另有记录；未把 partial parse 的静态结果判成 PASS 或 safe。

## cJSON CVE-2026-67215 与 CVE-2026-67216

两案共用 exact OpenHarmony cJSON 1.7.19 component commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748` / tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`。`cJSON.c` blob/SHA256 为 `152b2caa479c9f448001652913c980a6dafb82e0` / `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`；`cJSON_Utils.c` 为 `8fa24f8e9bf452cf1ba49d1325c85423ce742c74` / `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`。T4 synthetic scan snapshot commit/tree 为 `105eaddbf0d0110b07d16bdefc81ffc796e1444a` / `3c07134d5a05aa546b15739e32503a2ca192d258`，仅作为 byte-bound transport wrapper。

CVE-2026-67215 的根因是 JSON Patch add/copy 放大树后递归 `cJSON_Delete` 栈耗尽；官方 Red Hat/GHSA/issue #1073 状态仍没有匹配根因的 confirmed fix。PR #1064 修 MergePatch 路径，PR #1078 的递归深度限制也不是 JSON Patch 增树后删除的修复。CVE-2026-67216 的根因是嵌套 `cJSON_Compare` 指数级工作；同一 PR #1078 不是 CPU work bound，depth-14 基准与易受影响本地源仍相近。两案都没有可信 fixed source，不能伪造漏洞/修复差分。

本次共享两文件 CLI 结果为 0 finding，cJSON.c parse partial，cJSON_Utils.c parse complete，但 detector run blocked/partial。组件级历史运行时材料含有受限线程栈与早期不匹配快速退出控件，不能替代 scanner safe/unrelated source control。当前状态 PARTIAL；修复对照子项 BLOCK。

## 逐条复跑命令

工作目录为 `D:\openHarmonyScanner\worktrees\a-t1-audit-pr30-20261019`：

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-scan-20261019 --repository pnggroup/libpng --commit e283ed5d3a74c0112f092ddb1003c97e0e9a4717 --include vulnerable-1.6.55/pngrutil.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-vuln.json --md-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-vuln.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-scan-20261019 --repository pnggroup/libpng --commit e283ed5d3a74c0112f092ddb1003c97e0e9a4717 --include parent-fix/pngrutil.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-parent.json --md-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-parent.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-scan-20261019 --repository pnggroup/libpng --commit e283ed5d3a74c0112f092ddb1003c97e0e9a4717 --include fixed/pngrutil.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-fixed.json --md-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-fixed.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-scan-20261019 --repository pnggroup/libpng --commit e283ed5d3a74c0112f092ddb1003c97e0e9a4717 --include openharmony-generated/pngrutil.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-oh.json --md-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng46675-oh.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-cve-2026-33416-current-m2-20261019 --repository pnggroup/libpng --commit afad740f043acd9bee412677d0a5ff1e046aaa24 --include pngset.c --include png.c --include pngread.c --include pngrtran.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng33416-vuln.json --md-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng33416-vuln.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-cve-2026-33416-current-m2-20261019 --repository pnggroup/libpng --commit dcd78000a2e39558bd0b9340633d7acff796d37b --include pngset.c --include png.c --include pngread.c --include pngrtran.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng33416-fixed.json --md-out research/evidence/cpp/a_static_baseline_20261019/t4-libpng33416-fixed.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\cjson-cve67215-current-replay-20261019 --repository openharmony/third_party_cjson --commit 105eaddbf0d0110b07d16bdefc81ffc796e1444a --include third_party/cjson/cJSON.c --include third_party/cjson/cJSON_Utils.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/a_static_baseline_20261019/t4-cjson-67215-67216-oh.json --md-out research/evidence/cpp/a_static_baseline_20261019/t4-cjson-67215-67216-oh.md
```

## 复验安排

这些结果只描述 T1 PR #30 frozen-before scanner v0.1.0。D4 已冻结到 `f880613` 且其结果仍 partial/block；T3 应在 D4 独立 checkout 对 46675、33416、两项 cJSON source identity 及各自原 scope 再跑一次，核对规则变化是否产生候选及 parse coverage 是否改变。cJSON fixed/source comparison 当前无适用对象；在真正同根因修复可绑定前，应维持 BLOCK。T4 不修改 detector、tests 或 fixtures。

## 参考来源

- [libpng GHSA-qvg3-h654-xq3j](https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j)
- [libpng GHSA-m4pc-p4q3-4c7j](https://github.com/pnggroup/libpng/security/advisories/GHSA-m4pc-p4q3-4c7j)
- [cJSON GHSA-5q3m-r3x7-8phg](https://github.com/advisories/GHSA-5q3m-r3x7-8phg)
- [cJSON GHSA-ff2v-f99f-wm3f](https://github.com/advisories/GHSA-ff2v-f99f-wm3f)
- [cJSON remediation issue #1073](https://github.com/DaveGamble/cJSON/issues/1073)
- Existing source review artifacts named per case in `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\evidence\cpp\...`; T4 only read those reports. The new T4 deliverable contains its standalone inputs/results and retains their original provenance.

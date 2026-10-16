# A 线半年提交候选 MVP 精简证据摘要

日期：2026-10-16（Asia/Shanghai）。本摘要只记录本轮收口和验证边界，原始逐提交证据保存在本地
`outputs/reports/halfyear_candidate_mvp_commonlibrary_20261016_v3/`，未提交大文件、数据库、环境或原始运行目录。

## Checkout 与来源

- 项目工作区：`E:\网安\CyberSecurity-Innovation-Audit`。
- 分支：`codex/full-runtime-performance-audit-20261014`。
- HEAD：`993cfdc21877440f5d4a4ad345ee9ec236e098fa`。
- `origin/codex/full-runtime-performance-audit-20261014`：`993cfdc21877440f5d4a4ad345ee9ec236e098fa`。
- remote：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`。
- 接管时已有未提交内容：`docs/项目现状与下一步.md`、`src/cli/main.py` 修改；未跟踪
  `src/ohscanner/halfyear.py`、`tests/test_halfyear_candidate_mvp.py` 和四个 `outputs/*.py` 调查脚本。
  执行期间另有并行未提交的 NULL/shared_ptr、cross-version 和 research evidence 改动出现；均未 reset、
  checkout、覆盖或删除。
- 目标仓库：`E:\网安\audit-sources-20261014\home\audit\openharmony-targets\commonlibrary_c_utils`。
- 目标 detached HEAD：`b807d3dadb7dbb7639fe85b3a5f72da18d318da2`；remote：
  `https://github.com/openharmony/commonlibrary_c_utils.git`。本轮没有 fetch，也没有查询网络远端 ref。

## Exact argv

实际目标扫描命令：

```text
wsl.exe -d Ubuntu-22.04 -- bash -lc 'cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m src.cli ohscan-halfyear --repo-dir /mnt/e/网安/audit-sources-20261014/home/audit/openharmony-targets/commonlibrary_c_utils --repository openharmony/commonlibrary_c_utils --branch b807d3dadb7dbb7639fe85b3a5f72da18d318da2 --start 2026-04-15T00:00:00+08:00 --end 2026-10-16T00:00:00+08:00 --timezone Asia/Shanghai --detector ohscanner.cpp.lifetime --detector ohscanner.cpp.shared_ptr_race --detector ohscanner.interface.ipc --max-commits 5000 --out-dir outputs/reports/halfyear_candidate_mvp_commonlibrary_20261016_v3'
```

报告 `invocation.argv` 另存 Python 接收到的 exact `sys.argv`，`argv_exact=true`。Git 策略记录为
`fetch=false`、`checkout=false`、`lazy_fetch=false`、`external_scanners=false`。

## 固定身份与范围

- 窗口：committer time `[2026-04-15T00:00:00+08:00, 2026-10-16T00:00:00+08:00)`。
- topology：`first-parent`；max-commits：5000；selection limit：`within_limit`。
- baseline：`52cf3280c3ac53da1c54032c5e220acfef6ae514`。
- endpoint：`b807d3dadb7dbb7639fe85b3a5f72da18d318da2`。
- endpoint tree：`52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d`。
- profile：`light-ast`；scope：`changed-present-source-paths-per-commit`。
- Detector：`ohscanner.cpp.lifetime` 0.4.0、`ohscanner.cpp.shared_ptr_race` 0.5.0、
  `ohscanner.interface.ipc` 0.5.0（model `oh-ipc-2026.10-v3`）。

| Commit | Tree |
|---|---|
| `b807d3dadb7dbb7639fe85b3a5f72da18d318da2` | `52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d` |
| `8044daa1040218b6b6b2088c3df334d5ae047c1b` | `df1f614b9bff8bac53686a1b8a4c324884a2473b` |
| `17fd98d4189f27738b0656988d4d59611926a4f4` | `b9624b1f05d2bc892545d0a1e48678c26f413b2a` |
| `3bdc11e00e7bf6e577cee300ad51045ca9958efd` | `3ae2784218ab9cb06982d4660e37bababa06055e` |
| `42759ef8cfd6e4649b07103138b7c8006ea63eb5` | `045f95d69d96b8254168eb5bdc8512b8784ce0b8` |
| `513a5984c550a5e08383b4a6781e3bc460895712` | `824046225e203578e8d74b12bee6f220cb8a24a9` |
| `755d3e6c85468d395b8210733456fc8d33f4f5b8` | `fb8d08ed732472d7fa1788fce2443d0ad26c6c6f` |
| `5215d5ce657434df2e23dc9fcc5889066cd6c5b5` | `c173e4eb6a394776bf9aace4b1984890f9331673` |
| `cab0aa65a5c395fef0427919604b9cbfaffe32fe` | `5d423cfbfb16dd955a0c12463305611303accb25` |
| `83b9c41f5579b4bb43b5e0a5e03d44ba21590d2f` | `821b5061232d14c8398c4f3d5017a1d99246bed1` |
| `3c45fe22bade491753637d80c2e9127d1f9c9749` | `b17ada7f503cf6641739d6fe35ca3d4cd8297296` |
| `4a429705bb50f1e3a84fa92363df23f33b2e115d` | `abb9ca7fede6713629b6ac383962642b8d99c4b7` |
| `db2e39f49b414ed5b25b7dcb7a08bca1414fb013` | `3892ae63e8e318f5efa8810d6fe947989ff36407` |
| `2653b25072d31b3a12aad0473c83ff52f8a87dbd` | `f5789e59a5777e1b127913b73019211669cba13b` |
| `93a3549b1e7d1392ba7362cd22be63247f329aff` | `13baeb3d657d37adc77ab2e89395f171cf670962` |

37 个 changed-source 条目均记录 `binding_revision|path|source_blob_oid|source_sha256`，全为 `bound`；
删除项会绑定 parent blob。精确逐项值位于 JSON 的 `commits[].source_manifest`。按报告 commit 顺序、
每提交 path 排序，以 `commit|tree|binding_revision|path|source_blob_oid|source_sha256\n` 拼接后的
SHA-256 为 `72090a866e956df8cc7b80ca1fbbb5f84e9502ed6e8aa328fdafd028c1850890`。

## 结果与文件哈希

- selected 15；scanned 10；no-source/unexecuted 5；blocked 0；failed 0；missing Git object 0。
- coverage：complete 4、partial 6、unexecuted 5；Detector blocked 0。
- accepted/rejected candidate observations：0/0。只有 4 个 complete 提交给出候选计数 0；
  11 个提交的 candidate count 为 unknown。所有状态均为 `candidate/unassessed`，
  `validated_vulnerability=0`、`confirmed=0`、`reportable=0`。
- `halfyear_candidates.json` SHA-256：
  `a733edbcbbcce723355bd6abaf34f834267d566ad7cc69c8b8fda7ea9b73b209`。
- `halfyear_candidates.md` SHA-256：
  `356ac70a59ed6dcb89497e5e9a73397da9d5a3df04045969d51c65ff847cc296`。
- `manifest.json` SHA-256：
  `074bc639e968416925b8358d78728927a4134b827271da036f346f7c39f48204`。
- manifest 含 22 个文件哈希：聚合 JSON/Markdown 和 10 个逐提交 JSON/Markdown。manifest 中的
  report/markdown hash 已独立复算一致。

## 验证、失败与跳过

定向回归：

```text
wsl.exe -d Ubuntu-22.04 -- bash -lc 'cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest tests.test_halfyear_candidate_mvp -v'
```

结果：10/10 通过，覆盖窗口边界、timezone、first-parent/explicit ref、删除、无源码/空提交、
missing object、Detector blocked、partial/failed coverage、schema v2/source binding、manifest/hash、max-commits。

完整回归 exact argv 为 `.venv-web/bin/python -m unittest discover -s tests -q`（在上述 WSL 项目目录）。
结果：654 项执行、644 通过、8 skipped、2 failed、0 error。

- failed：
  `test_cpp_four_class_controls.CppFourClassControlTests.test_implementation_package_preserves_baseline_and_binds_sources`；
  `test_shared_ptr_jsproxy_poc.SharedPtrJsProxyPocTests.test_manifest_binds_candidate_detector_rule_and_git_identity`。
  两项都因并行未提交 `src/ohscanner/detectors/cpp/shared_ptr_race_detector.py` 当前 SHA-256
  `2232de1dbf85a70f076d0c86a0fa34bf70dc96ef64b649bede44670dcc13d43d` 与旧固定值
  `70197fb273054a20e2e6de82aa4eaa6bdeeaf4951ead6d5076b0e9832c65e230` 不一致；不是 halfyear 回归失败。
- skipped 2：AUTH-01 runtime harness 只允许 Docker validation worker 执行。
- skipped 6：pinned source store 不在当前 checkout，无法执行 reachability evidence 回归。

`git -C <target> fsck --no-dangling`、项目仓库 `git fsck --no-dangling`、`git diff --check` 均实际执行并通过；
后两者仅有 CRLF 规范化 warning。未执行 push、PR、Draft Ready 或 merge。

## 结论边界

0 accepted candidate 仅表示三个 approved Detector 在已绑定 changed-source scope 上没有报告观察。
6 个 partial 和 5 个 unexecuted 提交保持 unknown；不证明 safe/miss，不代表组件无漏洞。
本轮没有产品入口/权限/触发/CIA 证据、动态 PoC、Precision/Recall、CWE/CVE、影响版本或修复重验。

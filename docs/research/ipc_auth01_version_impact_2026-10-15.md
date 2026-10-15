# AUTH-01 影响范围：`inputmethod_imf` 的 397 条 ref 逐条判定（2026-10-15）

- 交付件：**#4 影响范围**（`AGENTS.md` Competition deliverables：「Report affected module,
  affected versions/branches (scan across tagged manifests), and the vulnerable/fixed commit
  boundary」）。
- 输入：全量克隆 `/home/audit/openharmony-audit/ipc-research/repos/inputmethod_imf`
  （6,231 commits、57 tag、341 个 `origin` 分支，**非** depth-1）。
- 工具：本轮新建的 `research/experiments/interface/ipc/version_impact.py`（由 A 线
  `shared_ptr_race_version_impact.py` 参数化移植而来，见 §2.3）。
- 结果：**affected 17 / fixed 1 / not_present 317 / unknown 62**（共 397 条 ref）。
- **`validated_vulnerability` 仍为 0。** 本轮不提升任何候选。

## 0. 一句话结论

`platform_callback_stub.cpp` 上，**精确等于漏洞版 blob 的 ref 有 17 条**（6 个 tag：
`v3.0-LTS`…`v3.0.3-LTS`、`v3.0.5-LTS`、`v3.1-Beta`，另 11 条 `origin` 分支）；
**精确等于修复版 blob 的 ref 只有 1 条**（`v3.0.6-LTS`）。
另有 **62 条 `unknown`**——它们带着**第三种变体**的文件，本记录**读不出内容**（见 §4），
按纪律**不得**被读成 `fixed`，也不得被读成 `affected`。

## 1. 数据源与纪律

| 项 | 值 |
|---|---|
| 仓库 | `openharmony/inputmethod_imf`（CVE-2023-0036 / OpenHarmony-SA-2023-0102 所在仓库） |
| 克隆性质 | **`blob:none` 偏克隆**（`remote.origin.promisor=true`、`partialclonefilter=blob:none`），非 shallow |
| 扫描 ref 集 | 全部 57 个 tag + 全部 `refs/remotes/origin/*`（341 个减 `origin/HEAD`）= **397** |
| 漏洞提交 | `e663b47013d534a56165ab7467fbb3e14bf7172b` |
| 修复提交 | `5eaddcab19bc4b22544f4bee1e8894fc2d6505dc`（`e663b470` 是它的祖先，已核） |
| 目标文件 | `services/src/platform_callback_stub.cpp` |
| 漏洞版 blob | `e90a4e77e9beadd066e8acc711fba5ec2664598c`（内容 sha256 `59c980bf…`） |
| 修复版 blob | `0f9ed2f660ecf23d30300f1d551d6b9666f9ec68`（内容 sha256 `b6d7f66a…`） |
| 记录摘要 | `manifest_sha256 = 91f8b454b29944034c116d5138ece913d30f8e2110bb41a0faa042fe58991ea8` |

**两条纪律：**

1. **判定身份是 blob OID，不是相似度、不是日期、不是版本号大小。** 一条 ref 的判定只来自
   `git ls-tree <ref> -- <path>` 给出的那一个 blob。
2. **不做隐式抓取。** 全部读取经 `src/ohscanner/git_source.py:_git`，它显式关闭
   `remote.origin.promisor`、`GIT_NO_LAZY_FETCH` 与全部 transport。偏克隆里缺失的 blob
   **宁可不读**，也不联网去补。

## 2. 方法

### 2.1 四态定义

| 状态 | 含义 |
|---|---|
| `affected` | 该 ref 上的文件 blob **精确等于**漏洞版 blob |
| `fixed` | 该 ref 上的文件 blob **精确等于**修复版 blob |
| `not_present` | 该 ref 上**不存在**这个路径 |
| `unknown` | 该 ref 上路径存在，但 blob 两个边界都不等（**非答案**，不是「安全」） |

### 2.2 为什么边界必须从 commit 派生

`build_version_impact` 用 `git rev-parse <commit>:<path>` **现场推导**两个边界 blob，而不是
从常量读。若文件在某个边界提交上不存在，**直接报错**而不是猜——本轮两条边界都推导成功。
当不给 `--fixed-commit` 时 `fixed_blob` 为空，`fixed` 这一态**在构造上不可达**
（`classify_blob` 里 `fixed_blob` 为空则不比对），并有单测钉住。

### 2.3 相对 A 线原件的两处改动（都是缺陷，不是风格）

1. **`source_path` 没有传下去。** A 线 `build_version_impact` 调 `classify_refs(repo, refs)`，
   没传 `source_path`，于是**无论调用者指定哪个文件，都按模块常量 `base/include/singleton.h`
   判定**。本移植把它贯穿到 `_ref_blob` 与每条记录，并写了回归用例（改读 `b.cpp` 时不得把任何
   ref 判成 `affected`）。
2. **边界是常量。** 改为从 `--vulnerable-commit` / `--fixed-commit` 派生。

另外新增：每条记录带 `blob_sha256`（**离线尽可能**取，见 §4.3）、
`vulnerable_commit_reachable` / `fixed_commit_reachable`（祖先关系，与 blob 判定**分列**，
不参与四态）、以及顶层 `content_digest_coverage`。

## 3. 结果

```
affected 17  (tag 6 / branch 11)
fixed     1  (tag 1 / branch 0)
not_present 317  (tag 36 / branch 281)
unknown   62  (tag 14 / branch 48)
```

### 3.1 `affected`：精确等于漏洞版 blob（全部 17 条）

**tag（6）**：`OpenHarmony-v3.0-LTS`、`v3.0.1-LTS`、`v3.0.2-LTS`、`v3.0.3-LTS`、`v3.0.5-LTS`、
`v3.1-Beta`

**origin 分支（11）**：`OpenHarmony-3.1-Beta`、`revert-merge-21-OpenHarmony-3.0-LTS`、
`weekly_20220105` / `20220111` / `20220118` / `20220125` / `20220201` / `20220208` / `20220215` /
`20220222` / `20220301`

**一致性检查**：这 17 条里 `fixed_commit_reachable` **全为 False**（0/17）——
即没有任何一条「已经包含修复、却还带着漏洞版文件」。这是本记录最重要的一条自洽性检验。

### 3.2 `fixed`：精确等于修复版 blob（唯一 1 条）

`OpenHarmony-v3.0.6-LTS`。

**注意这不是「唯一修好了的版本」**，只是「唯一在文件内容上与修复提交逐字节一致的 ref」。
上游修复提交 `5eaddcab` 落在 `origin/OpenHarmony-3.0-LTS` 线上，其后该文件又被改动过，
所以这条线上更晚的 ref 落进 `unknown`（§4.1）。

### 3.3 `not_present`（317 条）

**不是缺数据，是组件被重构过。** `services/` 目录在 3.2 之后不再存在：

| ref | 顶层目录 | 文件 |
|---|---|---|
| `OpenHarmony-v3.0.6-LTS` | `services/ frameworks/ interfaces/ …` | 存在 |
| `origin/OpenHarmony-3.2-Release` | `common/ frameworks/ interfaces/ …`（无 `services/`） | 不存在 |
| `origin/OpenHarmony-4.0-Release` | `common/ frameworks/ …`（无 `services/`） | 不存在 |
| `origin/OpenHarmony-6.1-Release` | `common/ …` | 不存在 |

因此 3.2+ 的 tag 与分支判为 `not_present`，含义是「**这个路径**在此不存在」，
**不等于**「该版本没有这个接口」——接口可能已随重构搬到别处。本记录不追这条线（见 §6）。

## 4. `unknown` 的 62 条：两种成因必须分开说

62 条只涉及 **6 个不同的 blob**。

### 4.1 修复之后文件又被改动（3 条 ref）

`v3.0.7-LTS`、`v3.0.8-LTS`、`origin/OpenHarmony-3.0-LTS` —— blob `022e5d44f76f`，
`fixed_commit_reachable = True`。

它们**包含修复提交**，但文件内容已不等于修复版 blob。含义只到「修复之后该文件被再次修改」；
究竟那次改动是否保留了描述符守卫，本记录**不作判断**（需要读内容）。

### 4.2 从来没有修复提交的那两条线（59 条 ref）

| blob | 出现于 | `fixed_commit_reachable` |
|---|---|---|
| `352b006d2405` | `v3.1-Release`…`v3.1.4-Release` | False |
| `7d45b1f09d98` | `v3.1.5-Release`…`v3.1.7-Release`、`origin/OpenHarmony-3.1-Release` | False |
| `f34e8ff7d7a9` | `v3.2-Beta1`…`v3.2-Beta3`、`origin/OpenHarmony-3.2-Beta1` 等 38 条 | False |
| `866c0b6a5825` | `v3.2-Beta4` 等 7 条 | False |

这四条线上的文件是**第三、第四种变体**，且**都不含修复提交**。

**这就是一个真实的、尚未回答的研究线索**（`AGENTS.md`：look-alike vulnerable variants）：
3.1 / 3.2 线上的这个文件是否也缺描述符守卫？本记录**不回答**，因为它的 blob 不在本地对象库里
（§4.3），读内容需要另开一次有据的取源，属于**候选复核**，不属于影响范围交付件。

**在拿到内容之前，这 59 条既不是 `affected` 也不是 `fixed`，就是 `unknown`。**

### 4.3 内容摘要为什么有 341 条是空的

```
content_digest_coverage = {"blobs_at_refs": 397, "digests_available": 56, "digests_unavailable": 341}
```

克隆是 `blob:none` 偏克隆：**tree 与 commit 全在本地，blob 按需**。`_git` 禁止惰性抓取，
所以从未落地的 blob 取不到内容摘要，记录里 `blob_sha256` 留空。
**这不影响任何判定**（判定只用 blob OID），但必须写出来，否则会把空串误读成「算过了」。
17 条 `affected` 的摘要 **17/17 全部取到**（它们共用的就是漏洞版那个 blob，已在本地）。

## 5. 与上游公告的关系

公开编号 CVE-2023-0036 / OpenHarmony-SA-2023-0102，PR
<https://gitee.com/openharmony/inputmethod_imf/pulls/228>。本记录独立复算了它的
vulnerable/fixed 提交边界与受影响 ref 集合，**没有**引用公告的版本清单来反推结论；
两者方向一致（3.0-LTS 线早期受影响、`v3.0.6-LTS` 起被修复），但本记录给出的是**逐 ref 的
blob 身份**，不是版本区间推断。

## 6. 没有证明的事

- **`unknown` 不是安全。** 62 条里 59 条属于「从未拿到修复提交」的 3.1/3.2 线，其内容未读。
  不能声称它们已修复，也不能声称它们受影响。
- **`not_present` 不是「没有该接口」。** 3.2+ 组件重构，`services/` 整体消失；接口的新位置
  未追踪（本记录只回答「这个路径在不在」）。
- **blob 身份不是可达性。** 一条 ref 带着漏洞版文件，**不等于**它构建的镜像里这个 SA 可被
  非特权调用者触达。可达性仍是 `partial`（见 PoC harness 的 `reachability.relations`）。
- **没有扫 manifest XML。** 本轮按 ref 扫，没有用 release manifest 把 ref 映射到具体产品版本；
  `product_manifest.py` 是否本地可用未核（属 owner 共享面）。
- **没有覆盖 `refs/heads/*` 本地分支。** ref 集是 tag + `refs/remotes/origin/*`。
- **未做 `unknown` 的内容取源**（§4.2），也未据此提出任何新候选。

## 7. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
R=~/openharmony-audit/ipc-research/repos/inputmethod_imf
cd "$B"

# 单测（19 项，含真仓库的边界回归；离线、秒级）
.venv/bin/python -m unittest tests.test_version_impact

# 全量扫描（397 ref，约 13 秒）
.venv/bin/python research/experiments/interface/ipc/version_impact.py \
  --repo-root "$R" \
  --repository openharmony/inputmethod_imf \
  --kind ipc_auth01_version_impact \
  --source-path services/src/platform_callback_stub.cpp \
  --vulnerable-commit e663b47013d534a56165ab7467fbb3e14bf7172b \
  --fixed-commit 5eaddcab19bc4b22544f4bee1e8894fc2d6505dc \
  --tags --branches \
  --json-out outputs/reports/version_impact_auth01_inputmethod_imf.json
```

不传 `--fixed-commit` 可复算「无上游修复」的姿态（`fixed` 恒为 0）；
`--ref-glob` 可把 ref 集收窄到某一族。产物写在 `outputs/reports/`（gitignored，不入库）。

## 8. 版本绑定

| 项 | 值 |
|---|---|
| 扫描工具 | `research/experiments/interface/ipc/version_impact.py`（本轮新增） |
| 单测 | `tests/test_version_impact.py`（本轮新增，19 项） |
| 记录产物 | `outputs/reports/version_impact_auth01_inputmethod_imf.json`（161 KB，不入库） |
| 记录摘要 | `manifest_sha256 = 91f8b454b29944034c116d5138ece913d30f8e2110bb41a0faa042fe58991ea8` |
| ref 集 | 57 tag + 340 `origin` 分支 = 397 |
| 未归类线索的 blob | 3.1 线 `352b006d2405` / `7d45b1f09d98`；3.2 线 `f34e8ff7d7a9` / `866c0b6a5825` |

所有源码与 blob 一律按固定 ref 从对象库读出，**未把工作树当证据**。

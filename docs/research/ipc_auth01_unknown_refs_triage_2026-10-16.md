# AUTH-01：#4 遗留的 62 条 `unknown` ref 分类追查（2026-10-16）

> 前置：`docs/research/ipc_auth01_version_impact_2026-10-15.md`（交付件 #4）。
> 该记录把 397 个 ref 判成 `affected 17 / fixed 1 / not_present 317 / unknown 62`，
> 并留了一句「62 条只涉 6 个 blob，是 look-alike 线索，**本轮未读内容，不得声称受影响**」。
> 本篇就是去读它。**结论：38 条已结案，24 条仍无从判定。**

## 0. 一句话结论

62 条 `unknown` 中的 **38 条（3.2-Beta1/2/3 + 35 个 weekly）可以结案：不是缺陷版本** ——
它们的文件与修复版**逐字节相同，只差两行 namespace 结尾注释**。
剩下 **24 条（5 个 blob）在离线对象库里没有内容，本轮读不到，维持 `unknown`**。

## 1. 方法：为什么只能读一个，以及为什么不去抓

数据源仍是全量克隆 `/home/audit/openharmony-audit/ipc-research/repos/inputmethod_imf`
（`blob:none` 偏克隆，tree/commit 全在本地、blob 按需）。**所有 git 调用都走项目自己的
`src/ohscanner/git_source.py:_git`**，它显式关闭 promisor / lazy fetch / 全部 transport，
所以本次追查**物理上不可能**触网，也不可能把缺失的 blob 悄悄拉下来。

代价是直接的：6 个 blob 里只有 **1 个**本地有内容。

| blob | 覆盖的 ref（条数） | 本地内容 |
|---|---|---|
| `f34e8ff7d7a91ac2d6ac5cad728b39182c849040` | 3.2 线共 **38** 个 ref（3 tag + 3 Beta 分支 + 26 weekly + 3 monthly + 2 filemanager_develop + 1 feature_IDL） | **有**（3,639 B / 108 行） |
| `022e5d44f76feeea4b56489f37a793f8b40d32ac` | v3.0.7-LTS、v3.0.8-LTS、origin/3.0-LTS（3） | 无 |
| `352b006d2405b1c4c144f5e67740a400283d48b4` | 3.1-Release、3.1.1–3.1.4（7） | 无 |
| `7d45b1f09d986d28284e6af1324f1a4ce2507108` | 3.1.5、3.1.6、3.1.7、origin/3.1-Release（4） | 无 |
| `866c0b6a58254f0deaa92eadcd4768ede2de4e98` | 3.2-Beta4 + weekly 2022-11（7） | 无 |
| `14a849f73d0e382f446948a2bd6a32b43fba466c` | weekly 2022-10-11/18/25（3） | 无 |

**没有去 fetch 那 24 条**，这是刻意的：对象读取的既定纪律是经 `_git` 禁掉全部 transport，
在共享研究克隆上做一次显式 fetch 会改动别的会话依赖的对象库。需要就由 owner 决定，
不由 B 单方面做。

## 2. 自检：我读到的确实是钉住的那两份源码

`src/ohscanner/poc/harnesses/auth01_descriptor_bypass/manifest.json` 钉了两份源码的 sha256。
本次现场重算：

| 修订 | 提交 | 行数 | sha256 与 manifest |
|---|---|---|---|
| vulnerable | `e663b47013d5` | 103 | **MATCH** |
| fixed | `5eaddcab19bc` | 108 | **MATCH** |

对得上，所以下面的逐行差异是在正确对象上做的，不是在某个近似物上。

## 3. 结果一：整个 AUTH-01 修复就是 4 行

`git diff vulnerable fixed`（`services/src/platform_callback_stub.cpp`）**只有 4 行新增**，
无删除、无其他改动：

```diff
     {
+        auto descriptorToken = data.ReadInterfaceToken();
+        if (descriptorToken != GetDescriptor()) {
+            return ErrorCode::ERROR_STATUS_UNKNOWN_TRANSACTION;
+        }
         switch (code) {
             case NOTIFY_EVENT: {
```

这与 harness manifest 的 `defect`/`fix` 描述、以及 B 自撰补丁
（`patch.rationale` 里的 guard/effect 论证）完全一致：缺陷是**这个前置根本没写**，
不是写错了。修复就是把它补上。

## 4. 结果二：38 条 ref 结案 —— 3.2 线的文件就是修复版

`fixed` 与 3.2 线 look-alike 的差异**只有 4 行改动**，且全在文件末尾：

```diff
@@ -106,3 +106,3 @@
-}
-}
+} // namespace MiscServices
+} // namespace OHOS
```

也就是说这 38 个 ref 上的 `platform_callback_stub.cpp` 与修复版**逐字节相同，
只有两个 namespace 结尾注释被补了名字**（典型的格式化/重排改动）。
第 34–43 行的描述符校验**在位**：

```cpp
auto descriptorToken = data.ReadInterfaceToken();
if (descriptorToken != GetDescriptor()) {
    return ErrorCode::ERROR_STATUS_UNKNOWN_TRANSACTION;
}
```

**结论：这 38 条 ref 不携带 AUTH-01 的缺陷。**

覆盖的 ref 共 38 条，按类别清点（由 #4 产物直接统计，非估算）：

| 类别 | 条数 | 例子 |
|---|---:|---|
| tag | 3 | `refs/tags/OpenHarmony-v3.2-Beta1/2/3` |
| Beta 分支 | 3 | `refs/remotes/origin/OpenHarmony-3.2-Beta1/2/3` |
| weekly | 26 | `weekly_20220406` … `weekly_20221004` |
| monthly | 3 | `monthly_20220614`、`monthly_20220816`、`revert-merge-227-monthly_20220816` |
| filemanager_develop | 2 | `OpenHarmony_filemanager_develop_20220505`、`..._20220614` |
| feature_IDL | 1 | `feature_IDL_20220811` |

### 4.1 一个必须写明的保留（不要过度解读）

内容里**有**校验，**不等于**「修复被回合到了 3.2 线」。同样可能是 3.2 线在重构时
本来就带着这个前置。本次追查**只证明**：这些 ref 上不存在 AUTH-01 的缺陷，
**不证明**它是不是由 `5eaddcab` 带过去的。

## 5. 结果三：剩下 24 条仍无从判定

| blob | ref 条数 | vulnerable 可达 | fixed 可达 |
|---|---:|---|---|
| `022e5d44f76f` | 3 | True | True |
| `352b006d2405` | 7 | False | False |
| `7d45b1f09d98` | 4 | False | False |
| `866c0b6a5825` | 7 | False | False |
| `14a849f73d0e` | 3 | False | False |

这些 ref 上的文件**既不是** vulnerable 内容、**也不是** fixed 内容（blob 身份不同），
而内容在离线对象库里读不到 → **维持 `unknown`，本记录不把它们算成受影响，也不算成已修复。**

### 5.1 一条反向推理的禁令

上表后四行 `fixed 可达 = False` 表示 `5eaddcab` 不是这些 ref 的祖先。
**这不能读成「它们没有修」**：第 4 节已经给出反例 —— 3.2 线带着校验，
但它的修复提交（若来自 3.0 线）本来就不在它的祖先链上。
修复可以独立落在不同分支上，所以「修复提交不可达」**既不是**漏洞证据**也不是**安全证据。

## 6. 与四态模型的关系：这里没有「guarded」态

交付件 #4 用的四态是 `affected / fixed / not_present / unknown`，**没有**「内容不同但前置在位」这一格。
本记录对那 38 条 ref 的处理是：

- **不**判成 `fixed` —— 它的 blob 与 `fixed_blob` 逐字节不同，判 `fixed` 会篡改判定语义；
- **不**判成 `affected` —— 缺陷前置在位，判 `affected` 是误报；
- 判定结果**仍是 `unknown`**，但**附上本次读到的内容证据**，说明它是「不同 blob、前置在位」。

换句话说：**`version_impact.py` 的输出一个字没改**（它的判定只看 blob 身份，这是对的）；
变的只是**对 38 条 unknown 的解释**从「未读」升级为「已读且不含缺陷」。
若将来要给四态加第五态，这次的数据就是它的第一份实例 —— 但那是 owner 的契约决定，
B 不在共享面上动它。

## 7. 没有证明的事

- **没有**证明 3.1 线（11 条）与 3.0.7/3.0.8（3 条）是否受影响 —— 内容读不到。
- **没有**证明 3.2-Beta4 与 2022-10/11 的 weekly（10 条）是否受影响 —— 同上。
  注意 3.2-Beta3 是安全的，**推不出** Beta4 安全：内容是另一个 blob。
- **没有**证明这 38 条 ref 的安全性来自上游修复的传播（见 §4.1）。
- **没有**改动 `version_impact.py` 的判定，也**没有**改 #4 的产物。
- **没有**触网：本次全部 git 调用经 `_git`，transport 关闭。

## 8. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
cd "$B"
# 全部经 _git（禁 promisor / lazy fetch / transport），因此离线可复现
.venv/bin/python /home/audit/wtmp/w142.py   # blob 可得性 + 树上邻居 + HEAD 现状
.venv/bin/python /home/audit/wtmp/w143.py   # 读出 3.2 线 look-alike 全文与关键符号
.venv/bin/python /home/audit/wtmp/w144.py   # 三方比对 + 钉住 sha256 自检
```

（三个脚本都在 `/home/audit/wtmp/`，属临时分析脚本，**不入库**；
其内容即上面各节的命令来源。）

## 9. 一条顺带查实的事实

`ipc-research/repos/inputmethod_imf` 的 **HEAD = `7777cba9eb19`（master）上，
`services/src/platform_callback_stub.cpp` 已不存在**：`git rev-parse HEAD:<path>` 直接报
`path does not exist in 'HEAD'`；该 ref 的 `services/src/` 已被 20 个完全不同的文件取代
（`ime_lifecycle_manager.cpp`、`notify_service_impl.cpp`、`push_to_talk_manager.cpp` …）。
这解释了为什么最新 ref 不在 `affected` 里 —— **不是被修掉，是文件被重构掉了**。

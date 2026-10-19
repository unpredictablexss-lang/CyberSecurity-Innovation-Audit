# T81 独立验收：D81 本地产品构建证据清点

## 判定

**ACCEPTED_WITH_LIMITATIONS**。D81 冻结身份正确；脚本重放成功，D53 指向的四仓 HEAD/tree 与 31 个 raw Git blob 的 OID、字节数、SHA-256 全部一致。HiHope 配置关系、build 白名单的元数据性质、D52 历史源码与当前源码之间关系未知、以及 `SOURCE_ONLY` rk3568 组合的限定均表达准确。

限制在“未发现实际 build artifact”的覆盖范围：D81 脚本重放 `D:/OpenHarmony807` 顶层目录清单，并按有限名称检查顶层输出目录；它没有递归搜索 `logs`、`repos`、`scan-results`，也没有按扩展名或 fingerprint 文件名检索这些目录。故可接受的结论是“在 D53/T53 冻结材料及所列顶层快照检查中未识别到可绑定具体产品构建的证据”，不能将其扩展为整个 `D:/OpenHarmony807` 快照内所有层级均无构建产物。D81 明确列出搜索边界且没有声称任意设备/外部存储均不存在产品构建，因此保留该限定后通过。

## 冻结身份和复现

- D81 commit: `c9c29b3d307f4f87c4705befd5b8afe56f087876`
- D81 tree: `60f129a152f5713cf9d7cec410bdc82be02621d1`
- 独立 checkout: `D:/openHarmonyScanner/worktrees/t81-d81-independent-acceptance-20261020`
- D81 script `python scripts/research/build_d81_product_inventory.py` 成功，输出 `verified 31 D53 raw Git objects`。
- `python -m json.tool research/data_sensitive/D81_LOCAL_PRODUCT_BUILD_INVENTORY_20261020.json` 通过。
- `git diff --check` 通过。
- 输出 JSON 与 D81 冻结提交中的 JSON 字节一致（脚本重放后工作区无差异）。

脚本分别重算了 D53 JSON 的冻结字节、四仓当前 HEAD/tree、D53 31 条路径的 blob OID 和 raw `git cat-file blob` 字节长度/SHA-256，以及 D52 历史 commit/tree/blob 身份。所有断言均通过。D81 文档所列的 31/31、0 mismatch 得到了独立重放支持。

## 结论边界核对

- 多个 HiHope 产品**定义**通过继承模板列有 Pasteboard；这些固定仓库快照不是共同锁定的产品 manifest，也不证明执行过构建或出货。
- `indep_component_whitelist.json` 和 `component_compilation_whitelist.json` 是允许清单/target 元数据，不是成功产品构建日志或产物。
- 顶层观察到 `logs`、`repos`、`scan-results`、三个官方源码裸仓以及清单/进度文件；未观察到根目录 `out`、`output`、`outputs`、`images`、`image`、`device`、`flash` 目录。此结果只支持顶层结构结论。
- D81 将 `D:/OpenHarmony807/scan-results/build/report.md` 识别为研究扫描准入报告，且其 hash 可复现；它不是产品构建产物。
- D52 历史源码仓是 `miscservices_pasteboard`，当前仓是 `distributeddatamgr_pasteboard`；迁移/祖先关系及历史代码进入某个产品构建的关系都未证明。
- `SOURCE_ONLY` rk3568 配置组合有明确标签，并明确不是设备、release 或已构建产品；没有把它作为 D52 目标产品。

## 建议的措辞范围

如果在任务树或下游报告引用 D81 的缺失证据结论，建议使用：

> 在 D53/T53 冻结的源码与产品配置证据，以及 D81 记录的 `D:/OpenHarmony807` 顶层结构检查中，未识别到可绑定唯一产品构建/安装状态的 fingerprint、image、输出 manifest 或设备记录。D81 未递归审计此目录下全部子目录，因此它不能证明该快照所有层级或外部设备/存储均没有产品构建资料。

不要缩写成“已搜索整个快照且没有任何构建产物”。如需加强否定性证据，可另行执行并冻结一项边界明确的递归文件名/类型索引；该步骤不是 D81 现有脚本已完成的检查。

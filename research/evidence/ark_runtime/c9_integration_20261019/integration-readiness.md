# Integration readiness

结论：`blocked_for_three_line_merge`。C9 已建立可审计的 local 7af/715e298 集成基线，但 e4e 实现/证据尚不能直接合流。阻塞来自 e4e focused Ark 6 个 TypeOrigin failures、full-suite 环境/manifest 不一致、public Catalog 变更混入、版本身份分歧，以及 strict source-audit input 仍缺。

## 已通过的最小基线

- 715e298 是 7af 的祖先；715→7af 的 Ark implementation/tests 为 0 文件差异，新增的是证据、partial-admission 与 source-audit reconciliation scaffold。
- local Ark Runtime：116 tests / 0 failed / 8 skipped。
- local Runner/Catalog/schema compatibility：64 tests / 0 failed；C++ Runner integration：5 tests / 0 failed。
- 272 tracked Python files `py_compile` 通过；99 tracked JSON 通过。
- Windows `git diff --check` 通过。
- strict reconciliation 在原文根输入缺失时仍 fail-closed：default `blocked_missing_input`，`--strict-input` exit 3，imported entries 0。
- 原文 remote blob 已只读绑定；没有把 remote 原文或 substitute evidence 当成 reconciliation 输入导入。

## 合流阻塞

1. **e4e focused Ark 152 executed / 6 failed。** 6 个失败全部是 TypeOrigin，见 `exact-verification-summary.md`。未清零或逐项裁决前，type-origin 完整 Ark Runtime 回归不成立。
2. **e4e full-suite 环境/manifest 偏差。** committed checkpoint 是 127/1/10；更新 focused universe 是 152/6/4。唯一 committed broad failure 是 dependency manifest expected `ACTUAL_INCLUDE_CLOSURE`，实际是四个不同 unresolved reasons。e4e 与 C9 的 Python/Git 环境也不同，exact broad argv/env 未冻结。
3. **公共 Catalog 差异。** e4e 将 `ArkRuntimeTypeSafetyDetector` 替换为 `ArkRuntimeUnseenTypeSafetyDetector`，4+/4-；公共变更与算法变更必须拆分并加兼容测试。
4. **版本身份冲突。** local detector/model 0.7.0/0.7.0；e4e detector/model 0.6.2/0.8.10。必须明确哪个是发布版本、哪个是 semantic model 版本，并锁定输出 schema/ID。
5. **strict source-audit input 缺口。** remote 原文在 C-line path；reconciliation 期待 root `源码漏洞审查记录_20261018.md`。strict 门继续 blocked。
6. **历史 replay 未执行。** 8 个 Ark tests skip，缺 pinned Ark Git store / `OHSCANNER_ARK_REPO`。
7. **已知机制缺口。** IAO7GO、I7W51D、IB8BCA 没有对应 scanner 规则；0 diagnostics 不得当 pass。

## Readiness matrix

| 维度 | local 7af/715e | remote e4e | readiness |
|---|---|---|---|
| 算法实现连续性 | 715→7af 无算法差异 | 从共同 base 独立演化，Ark 11 files 2175+/789- | blocked_pending_merge |
| type-origin | C3/副作用/partial-owner 修复，116 tests pass_with_skips | Map/Filter 扩展和 unseen selector，但 focused 6 failures | blocked |
| exception guard | allocation guard 完整 local tests；历史 replay skip | allocation + runtime/callback/call-info exception 扩展 | partial |
| receiver guard | 无 | IAO7E8 rule 1→0 evidence | partial |
| size/length | 无 | I7KZJ7 multiplication rule；I7W51D narrowing 仍缺 | partial |
| Runner applicability | 5/5；contract/schema 64/64 | public Catalog factory swap | blocked_public_change |
| source-bound schema v2 | local compatibility pass | same family but version/ID semantics differ | blocked_version_identity |
| fail-closed audit input | strict blocked as required | original available only at remote C-line path | blocked_missing_input |
| docs budget | canonical blob replay pass；HEAD validator missing | not compared | partial_tool_gap |
| product/security conclusion | not assessed | not assessed | candidate/unassessed |

## 下一任务切片

1. 在 e4e 源不变的前提下复现并修复/裁决 6 个 TypeOrigin failures；保存 exact argv/env、156 collected/4 skip 明细。
2. 把 Catalog factory swap 拆成独立公共变更，补 legacy v1/source-bound v2/default-disabled 兼容测试。
3. 固化版本契约：detector version、model semantic version、rule IDs、diagnostic IDs、source binding。
4. 恢复 pinned Ark Git stores，执行 8 个 historical/current-component tests；缺对象继续 fail-closed。
5. 为 IAO7GO/I7W51D/IB8BCA 建立独立最小规则切片和 positive/fixed/safe/unrelated/unknown 控制。
6. 明确 source-audit canonical input 路径或更新 reconciliation manifest；在此之前 strict 仍 exit 3。

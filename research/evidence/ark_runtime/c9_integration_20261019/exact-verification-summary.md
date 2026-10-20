# Exact verification summary

## 1. C9 实际执行环境

- Checkout：`E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019`
- Branch/HEAD：`codex/c-line-scanner-optimization-20261019` / `7af25f5ced471e5d6acc8cf5efd4c696275ce940`
- 算法目标：`715e29884a845a2daa80016f332c70b3db84ca45`，为 HEAD 祖先；715→7af 的 Ark 实现和 Ark tests 为 0 文件差异。
- Remote 只读目标：`origin/codex/c-line-ark-runtime-20261018` / `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`；未 checkout、fetch、reset、push、merge。
- WSL：Ubuntu 22.04，kernel `6.18.54.1-microsoft-standard-WSL2`，`/usr/bin/python3` 3.10.12 (GCC 11.4.0)，tree-sitter 0.26.0。
- Windows Git：2.55.0.windows.5。
- 测试环境为 `env -i` 最小环境：`PATH=/usr/bin:/bin`、`PYTHONPATH=src`、`PYTHONHASHSEED=0`、`PYTHONDONTWRITEBYTECODE=1`、`LC_ALL/LANG=C.UTF-8`、`TZ=Asia/Shanghai`、`SOURCE_DATE_EPOCH=0`；HOME/TMP/PYTHONPYCACHEPREFIX 均限定在 c9 输出目录。

## 2. C9 当前 7af 实际结果

| 检查 | exact argv | exit/status | pass/fail/skip | wall / RSS |
|---|---|---|---|---|
| Ark Runtime full | `/usr/bin/python3 -B -m unittest discover -s tests/detectors/ark_runtime -t . -v` | 0 / pass | 116 run，0 failed，8 skipped | 1.91 s；RSS 见限制 |
| Runner/Catalog/contract compatibility | `/usr/bin/python3 -B -m unittest -v tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_runner_applicability tests.test_ohscanner_m2 tests.test_ohscanner_m2_a_integration` | 0 / pass | 64 run，0 failed，0 skipped | 49.53 s；RSS 见限制 |
| C++ Runner integration | `/usr/bin/python3 -B -m unittest -v tests.detectors.test_cpp_runner_integration` | 0 / pass | 5 run，0 failed，0 skipped | 2.17 s；RSS 见限制 |
| Python compile | `/usr/bin/python3 -B -m py_compile <272 tracked .py paths>` | 0 / pass | 272 paths | 10.64 s；RSS 见限制 |
| JSON parse | `/usr/bin/python3 -B research/evidence/ark_runtime/c9_integration_20261019/validate_json.py --root <repo> --files-from <tracked_json_files.txt> --output <json_validation.json>` | 0 / pass | 99/99 tracked JSON | 0.49 s；RSS 见限制 |
| docs budget，当前 checkout | `/usr/bin/python3 -B scripts/check_docs_context_budget.py` | 2 / fail_missing_tool | `scripts/check_docs_context_budget.py` 不存在于 7af tree | 0.09 s |
| docs budget，固定 canonical blob replay | `/usr/bin/python3 -B research/evidence/ark_runtime/c9_integration_20261019/check_docs_context_budget_from_blob_3aab566.py --root .` | 0 / pass_with_substitute_tool | `default=4088/13500, docs=13293/32500` | 0.26 s / 19,788 KiB |
| git diff check，Windows | `C:\Program Files\Git\cmd\git.exe -C <repo> diff --check` | 0 / pass | 0 bytes stdout/stderr | 0.1066 s；PeakWorkingSet 不可稳定回收 |
| reconciliation default | `/usr/bin/python3 -B research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/reconcile.py` | 0 / expected blocked | `input_status=missing`, `execution_status=blocked_missing_input`, imported entries 0 | 0.47 s；child max RSS 65,888 KiB |
| reconciliation strict | same + `--strict-input` | 3 / expected blocked | `blocked_missing_input`；substitute evidence 未提升 | 0.45 s；child max RSS 65,888 KiB |

RSS 限制：harness 使用 `getrusage(RUSAGE_CHILDREN).ru_maxrss`，它是运行期间的累计 child maximum，不是每个命令隔离峰值；因此只作上界记录，不参与通过判定。docs blob replay 使用 GNU `/usr/bin/time -v`，19,788 KiB 为隔离稳定值。

## 3. Ark Runtime 8 个 skip 原因

- 7 项：`Pinned Ark Git store not supplied; no implicit fetch` 或 `Component Git store not supplied; no implicit fetch`。
- 1 项：`OHSCANNER_ARK_REPO not configured`。
- skip 不是 pass；historical/current-component replay 仍是 blocker。

## 4. e4e focused Ark 结果必须进入合流门

协调事实给出的 e4e focused Ark 结果为 152 executed / 6 failed；按 e4e tree 静态测试清单为 156 collected，其中 4 个 historical/environment skips，因此 152 个实际执行、6 个失败、146 个通过。该运行未在 C9 当前 worktree 重跑，原因是合流前只允许 `git show/diff` 检查 e4e、不得 checkout；e4e committed evidence 也没有保存这次 152/6 的 exact argv，必须作为下一合流门补证。

必须列出的 6 个 TypeOrigin failures：

1. `tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_glue_aware_hclass_read_and_env_builder_overload_keep_origin`
2. `tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_glue_aware_hclass_read_preserves_real_type_origin_mismatch`
3. `tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_reviewed_glue_aware_graph_queries_keep_source_binding`
4. `tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_reviewed_call_builder_constructor_arity_is_supported`
5. `tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_result_type_sample_survives_unrelated_callback_while_result_is_local`
6. `tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_result_type_sample_is_invalidated_when_result_escapes_to_callback`

## 5. e4e full-suite 环境/manifest 偏差

- e4e committed checkpoint 记录的是 `127 passed, 1 failed, 10 skipped in 54.03s`，而协调更新后的 focused universe 是 152 executed / 6 failed；两者命令、收集数、失败集合不一致，不能拼成同一 full-suite 通过记录。
- committed full-suite 的唯一失败是 `ExactSnapshotDependencyManifestTests.test_recomputation_is_stable_and_incomplete_profile_blocks`：expected `unresolved_dependency:ACTUAL_INCLUDE_CLOSURE`，manifest 实际为 `C1_PRODUCT_BUILD_PROFILE, C2_CASE_MATRIX, GENERATED_BUILD_INPUTS, PARSER_BINARY_IDENTITY`。这是 C4-owned manifest 对账失败，不得改 C4 test 来消音。
- e4e reports 记录环境 `Python 3.13.9 / git 2.46.2.windows.1 / tree-sitter 0.26.0`；C9 是 WSL Python 3.10.12、Windows Git 2.55.0。跨环境结果只能并列，不能覆盖同一 manifest。
- e4e `model.py` 同时出现 detector `VERSION='0.6.2'` 与 `RuntimeTypeModel.version='0.8.10'`，而 local 7af 两者均为 0.7.0。版本身份必须显式裁决并用兼容测试锁定。
- e4e Catalog 将 factory 从 `ArkRuntimeTypeSafetyDetector` 改为 `ArkRuntimeUnseenTypeSafetyDetector`，公共 Catalog 有 4+/4- 差异；公共变更必须与算法合流分开。

## 6. 原文与 fail-closed 对账

- 原文已通过 `git show e4e0761:...` 只读取得，身份见 `source_audit_original_identity.json`。
- 本地 reconciliation 硬编码 root 输入 `源码漏洞审查记录_20261018.md`；remote 原文路径是 `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`。没有把 remote 原文或 C3/C4/C7 substitute 自动写回输入。
- default 仍 `blocked_missing_input`，strict 仍 exit 3；这是要求的 fail-closed 行为。

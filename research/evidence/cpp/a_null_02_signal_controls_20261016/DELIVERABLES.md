# A-NULL-02 signal controls delivery record

日期：2026-10-16。范围只包括 A 线 C/C++ NULL dereference detector、控制、回归和
研究记录；未修改公共 contracts、runner 或 catalog。

## 控制清单

| 类别 | 变体 | 预期 |
|---|---|---|
| positive | `positive_parameter_unguarded.cpp` | 1 candidate |
| positive | `positive_local_null_read.cpp` | 1 candidate |
| positive | `positive_member_default_initializer.cpp` | 1 candidate |
| positive | `positive_reference_alias.cpp` | 1 candidate |
| positive | `positive_error_path_falls_through.cpp` | 1 candidate |
| positive | `positive_return_value_unknown.cpp` | 1 candidate, partial |
| fixed | `fixed_error_path_multistatement.cpp` | 0 |
| fixed | `fixed_else_branch.cpp` | 0 |
| fixed | `fixed_alias_early_return.cpp` | 0 |
| fixed | `fixed_local_rebind_nonnull.cpp` | 0 |
| fixed | `fixed_short_circuit.cpp` | 0 |
| safe | `safe_address_of_local.cpp` | 0 |
| safe | `safe_guarded_alias.cpp` | 0 |
| safe | `safe_reference_to_local.cpp` | 0 |
| safe | `safe_nonpointer_member.cpp` | 0 |
| unrelated | `unrelated_null_check_without_sink.cpp` | 0 |
| unrelated | `unrelated_null_words.cpp` | 0 |
| unrelated | `unrelated_integer_branch.cpp` | 0 |
| unrelated | `unrelated_pointer_without_deref.cpp` | 0 |

控制 manifest 绑定每个 fixture 的 UTF-8 source SHA-256、Git blob SHA-1、byte length
和 parse status：`research/tests/a_null_02_controls/control_manifest.json`。
`verify_controls.py --check` 必须先通过。

## 证据和限制

- Finding 默认 `candidate/unassessed`，`evidence_type=syntax`，候选 CWE-476。
- 每个 finding 带 file/source SHA、Detector 0.2.0、rule 1.1.0、lineage、symbol
  identity、AST fingerprint 和八个 EvidenceObligation。
- AST/pattern 证据不声称 ownership、dominance、concurrency、attacker control 或
  CIA impact。partial/failed/not_analyzed 不是 safe 或 miss。
- 1 MiB/unit、32 MiB/run 输入限制是 detector 内部限制；超过限制 fail-closed。
- 未运行产品构建、真实 OpenHarmony 入口、PoC 或动态验证。没有 Precision/Recall、
  zero FP/FN、CVE/CWE 产品影响或 confirmed/reportable 声明。

## 误报分析

本轮 fixed/safe/unrelated 控制覆盖了 guard 不支配、错误路径 fall-through、alias
guard、局部重绑定、地址-of-local、无 sink 文本相似等主要噪声来源。残余风险是宏和
模板展开、跨函数 alias、异常/析构、复杂 switch/goto、隐式转换和成员跨函数状态；
这些仍会按 unknown/partial 保留，而不是用近似文本判 safe。

## 建议的 Catalog 注册变更

建议由公共负责人单独审查 `NULL_DEREFERENCE_METHOD_CARD_V2.md` 中的 0.2.0 /
rule 1.1.0 元数据，显式注册 `research_candidate`，保留 v1 历史 identity，不把
candidate 映射为 confirmed/reportable。本记录不直接修改 catalog。

## 回归记录

- 定向命令：`python -m unittest tests.detectors.test_cpp_null_dereference_detector tests.detectors.test_cpp_null_dereference_signal_controls -v`。
- 完整命令：`python -m unittest discover -s tests -q`。
- 最终定向结果：18 executed / 18 passed / 0 failed / 0 errors / 0 skipped。
- 最终完整结果：673 executed / 665 passed / 0 failed / 0 errors / 8 skipped。
- exact argv、环境、pass/fail/skip、hash 和 wall time 保存在本目录的
  `targeted_test_run.txt`、`full_test_run.txt` 和 `verification.json`。

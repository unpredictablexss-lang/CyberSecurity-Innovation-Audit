# 可重放输入与控制计划
固定输入：OHScanner b011ea0c；C3 model_dependency_comparison.json；C3_SOURCE_EVIDENCE.json；C4_SOURCE_BINDINGS.json；model.py 0.6.2；comparison commit a65a2853。expected/current source objects 缺，明确 unknown。
规则：只读 pinned objects，不 fetch/checkout/外部扫描。每 fixture 记录 source bytes、blob、source SHA-256、parser/model hash、scope/profile、command、exit code、output hash；missing/partial/unresolved 输出 unknown。
逐项 fixture/controls 见 dependency_review.json.rows[].minimal_replay_fixture 与 .controls：
- 001-015：bounded owner/effect call；positive=reviewed effect，fixed=证明等价的重构，safe=scalar/no sensitive effect，unrelated=unsupported/different owner。
- 016：species creation 后 store；positive=different origin，fixed=same-type proof，safe=equal origins，unrelated=different store。
- 017-018：NewTypedArray -> pending exception -> LoadHClass；positive=no guard，fixed=exact guard，safe=proved guard，unrelated=no creator/sink；018 同 bytes 但独立 ID。
建议命令：OHSCANNER_ARK_REPO=<local-pinned-store> python -m unittest discover -s tests/detectors/ark_runtime -t . -v；pytest tests/detectors/ark_runtime tests/test_runner_applicability.py -q -rs；python -m json.tool dependency_review.json；git diff --check。
验收：18 行、四类控制、OID/hash/exit code 完整；缺对象必须记录；skip 不得写 pass；门槛闭合才移除 unknown。
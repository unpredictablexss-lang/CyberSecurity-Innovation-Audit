# B 线：接口/IPC 家族与授权事实

本线是新基线的独立 worktree，不改变 `/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b`。
原 B 本地来源 `feat/interface-ipc-detector@635b3e0449c552f0ccc25118850d245962845568`；PROGRAM_STATUS.md 未提交内容继续原地保留。
本轮远端仍为 `818d3eb8d9760505a67eee7c2cca600ff783e152`，本地新增提交不能冒充已经远端交付或已经合入。

第一交付：将 v0.8.0 的六家族组合及必要的 analysis/index/models/控制样例/测试拆成最小可复审单元。
先做相对本线旧 IPC 实现的依赖清单，再选择性迁入；不覆盖 runner/catalog/API/根状态文档。
控制样例、模型变化与真实组件差异分别报告；旧 0.7.1 的 495 项结果不是本线新运行结果。

关于 sat UID 3020：当前共同基线没有因告警减少而增加全局 trusted_uids 的决定。
若要 credit，需固定目标版本的 UID 分配/服务身份来源、实际调用 body 身份、该 UID 在具体操作上的授权含义与攻击者可控性；
单凭 `ACCESSTOKEN_UID=3020` 的命名、同名函数、Harness 成功不足以建立授权事实。
身份/作用域不明时保留 candidate/unknown，不能为抑制三条候选而泛化全局信任。
若证据成立，提交窄作用域模型及反例测试供负责人定，不要只加一个字符串。

验收：
- 对本次选择的测试写精确 argv；从仓库根运行，不能借 `-I` 隐藏导入问题。
- 覆盖 const 引用、不唯一宿主方法、一跳拒绝 limitation 传播、本地同名 body 遮蔽与非零行号；两侧控制必须都断言。
- 六家族组合前后固定源/范围的候选身份差异逐项解释，记录 refused/credit 与真正候选移动的区别。
- `.venv-web/bin/python -m unittest discover -s tests -q` 和本线范围检查；缺失依赖向集成人申请。
- entry_controlled/CIA/validated_vulnerability 按实际证据，不把语法能力/样例通过当产品确认。

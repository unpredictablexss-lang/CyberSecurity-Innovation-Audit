# cpp.lifetime independent holdout plan

> 当前状态：`pending`。根因分簇、去重和标签访问方案已登记，但独立冻结与
> evaluator 尚未发生，holdout 未收集或执行。当前 12 个 lifetime fixtures
> 全部属于 development/contract fixtures，不能计入独立成绩或泛化结论。

## 1. 隔离单位与数据边界

按 `root_cause_instance_id` 隔离，而不是按 warning line。相同 CVE、backport、
补丁复制、同项目近重复文件或同一 root cause 的变体必须进入同一 split。
development fixtures 的文件名、变量名、wrapper、sync idioms 和 expected
observation 在 detector code 冻结前已参与算法调整，不能再进入 holdout。

当前预登记 hash：

- detector code: `99113d6792b5a6ad2043492d30de1f7cf64dbc36b0af91731b93a959fa9f83ed`
- fixture manifest bytes: `ad3a8bd7e10f9ffcadfea69a17cb9c57c9a9ce616d235b081e6b50b778812737`
- native evidence manifest: `607dbcf7f92857fb3f1495eca157fc0efeca0b52cec96378ae0d4d0cec85cb34`

detector code 以 `src/ohscanner/detectors/cpp/lifetime_detector.py` 的完整文件
SHA-256 表示；review adapter 单独记录为
`a4e33188b4f6d405b3cc4884f8dcb7ed59f68e42b82da85d1f18e5334a17b192`。
正式冻结仍必须记录：

- detector code commit；
- fixture manifest bytes SHA-256 与逐 source SHA-256；
- method card / CCR revision；
- Python 版本、OS、完整命令和 run status。

holdout labels 在 detector 冻结前不得查看。独立 evaluator 控制 label
manifest/hash；开发侧只接收去重后的 root-cause IDs、兼容性状态和盲化输入，
不接收 vulnerable/fixed/safe 标签。不得用 holdout failure 回调修改
当前 rule regex 后继续声称同一 holdout。

候选先按 `root_cause_instance_id` 分簇；CVE/backport/补丁复制/同项目近重复
文件进入同一 cluster，再以完整 source/patch hash 辅助去重。任一 cluster
成员曾参与开发或调参，即污染整个 cluster 并从独立 holdout 排除。标签访问
日志和最终 manifest hash 由 owner 或独立评估者保存，Teammate A 不自行解封。

## 2. 分层要求

每个 split 至少保持：

- vulnerable：显式 unique_ptr owner + raw alias + reset 后 alias use，覆盖
  straight-line、conditional/non-straight-line rebinding 变体；
- fixed：改变 ownership/alias 语义后当前 shape 消失；
- safe/unrelated：相似 API、变量名、锁和 scope，但不组合成 stale-alias shape；
- unknown：partial parse、failed parse、not_run、missing/unresolved symbol、
  incomplete scope、exception/timeout；
- not_applicable：no matching language 或明确 incompatible analysis unit；
- sync variants：同一互斥锁、不同锁、无锁、锁 scope 不覆盖 reset/use；
- failure holdout：宏控制 reset、lambda capture、template alias、复杂
  declarator、跨函数 owner move、析构 callback。

vulnerable、fixed、unrelated、safe、unknown 和 not_applicable 必须作为独立
run/evidence group 输出，禁止混成一个 diagnostic population。

## 3. 推荐 split

- development：当前 synthetic fixtures，仅用于窄语法算法和回归；
- validation：另建不同变量命名、owner 初始化、lock 类型、rebinding 位置和
  dereference spelling；
- holdout：跨项目/跨组件，至少包含不同 smart-pointer wrapper 或
  OpenHarmony idiom；代码冻结前不查看结果；
- failure holdout：只评估 unknown/limitation 处理和 coverage disclosure，
  不把 parser failure 转换成 miss 或 safe。

真实 OpenHarmony 样本必须绑定 repository、完整 commit、revision、tool/version、
analysis scope、source artifact、file blob/source SHA-256 和 build/profile
上下文。合成 fixture 单独标记，不混入历史 benchmark。

## 4. Source binding 与运行要求

每个 finding/evidence record 必须绑定：

- sample/root cause instance；
- repository 与完整 commit/revision；
- tool id/version；
- scope 与 parse/build status；
- source artifact path 与 SHA-256；
- file/line/column、rule_id、evidence_type；
- candidate/unassessed 状态。

公共 contract 当前不携带 finding source hash，因此在
`ohscanner_detector_contract_v1_cpp_lifetime_source_binding_ccr.md` 被实现前，
必须使用经过验证的 review sidecar，并验证 stale hash 和 finding binding ID。

运行顺序：

1. 冻结 code、fixtures、manifest hashes 和 labels access policy；
2. 记录语言选择、parse coverage、exception/timeout 和 analyzed files；
3. 对每个 evidence group 独立运行 detector；
4. 解释 candidate shape、unknown、not_applicable 和 limitations；
5. 保存原始 counts、逐 fixture observation、coverage/failed status 和 ablation；
6. 由独立 evaluator 在绑定 fixed/unrelated 对照后决定 benchmark matching。

## 5. 评价边界

样本量、独立标签和覆盖分母满足
`vulnerability_corpus_bakeoff_protocol.md` 前，不计算 Precision/Recall。
空 findings、`completed`、`no_candidate_shape` 均不表示 safe。
partial/failed/blocked/not_run 不是 miss；no matching language 是
not_applicable；rule hit 仍是 candidate/unassessed。

当前禁止写 holdout pass、泛化能力、误报率、漏报率、真实 OpenHarmony 检出能力、
confirmed vulnerability 或 runtime validation 结论。

## 6. 当前 status

`pending`: 尚无独立评估者接收 sealed manifest，尚无 code freeze，尚无盲测
执行或标签核对。2026-10-10 native vulnerable/fixed/safe replay 是已知开发侧
真实源码证据，不构成独立 holdout，不能用于宣布通过。

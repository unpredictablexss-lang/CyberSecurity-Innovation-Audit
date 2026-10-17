# D2 固定九文件覆盖审计

正式范围/Commit/来源模型保持D1不变。算法0.1→0.2与覆盖变化分开记录。
来源commit：`0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`；tree：`bd915661eedd139df17f249191e2a691e76f7565`。
运行代码HEAD：`3b646c881716eb6b0c86195cdeeb1012ac9c921b`；具体代码SHA/Runner SHA/解析器版本见D2_COVERAGE.json。

| 文件 | AST | 正式分析 | 私有探针函数数 | 原因/事实 |
|---|---|---|---:|---|
| adapter/common/include/softbus_adapter_crypto.h | partial | not_analyzed | 0 | 条件extern C/预处理分支在16–121区域产生ERROR，117闭合处另有错误；只有类型/API声明，没有函数体。需要有构建身份的声明事实，不应当作流扫描成功。 |
| core/authentication/include/auth_session_key.h | partial | not_analyzed | 0 | 条件extern C/预处理包裹在16–72区域产生ERROR，68闭合处另有错误；仅API声明，没有函数体。 |
| core/authentication/src/auth_hichain.c | complete | partial | 29 | AST complete，探针29函数；固定OnSessionKeyReturned参数1是材料来源，日志多为authSeq/len/常量。分支、未知调用、PRI格式/输出成员等仍partial。 |
| core/authentication/src/auth_hichain_adapter.c | complete | partial | 16 | AST complete，探针16函数；当前Source模型未命中材料，不等于不存在材料。存在for循环、未知调用/return及条件效果缺口，保留partial。 |
| core/authentication/src/auth_session_key.c | partial | not_analyzed | 30 | LIST_FOR_EACH_ENTRY宏式循环被语法解析为缺分号（如45、54、111、123行）；公共准入整文件跳过。私有探针30函数中15个不与错误直接交叠，仍缺宏/类型/编译上下文，不能直接准入。 |
| dfx/interface/include/auth_log.h | partial | not_analyzed | 0 | 条件extern C与宏定义结构中出现missing #endif（60行）；宏/标签声明，无函数体。不能据此判定原源码本身编译错误。 |
| dfx/interface/include/softbus_log.h | partial | not_analyzed | 0 | 条件extern C与多构建变体宏结构中出现missing #endif（117行）；没有函数体。构建分支/FORMAT转发仍需模型。 |
| dfx/log/src/auth_log.c | complete | partial | 0 | AST complete但无函数体，主要是日志标签/预处理内容；D1分类为partial，本轮保持相同生产覆盖，没有把无流函数文件改成complete。 |
| interfaces/kits/authentication/auth_session_key_struct.h | partial | not_analyzed | 0 | 条件extern C包裹在16–49产生ERROR、46闭合处错误；SessionKey材料定义是模型依据，没有函数体。 |

## 正式结果与研究探针边界

正式计数complete0/partial3/not_analyzed6/failed0，总数9。D1/D2候选均0，覆盖计数无变化；D2两次同scope观察与覆盖一致。报告原始字节不同可由运行耗时产生，各自SHA记录在JSON，不能声称报告字节完全相同。
私有探针直接检查所有文件，包括正式未准入文件，结果不作为已接入正式扫描。每函数起止、退出、材料来源/日志位置、错误节点与限制都在D2_COVERAGE.json；它不是全程序事实。
尤其15个无直接错误交叠函数不等于15个可安全准入函数，附近宏、类型/全局状态与构建配置仍可能影响语义。

## 最小RFC

优先在auth_session_key.c提供版本/文件SHA绑定的可选函数局部错误区间、赋值/形参事实，保持当前Runner默认不变。负责人决定新的局部准入策略及公共兼容性测试后，D再做适配。头文件优先提供声明与日志宏事实，不强行把声明文件计为数据流complete。

## 复现命令

```bash
cd /home/lzc/projects/OHScanner-teammate-D
/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python -m research.data_sensitive.d2_coverage --repo-dir /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git --output-dir outputs/reports/d-sensitive/d2
```

9文件路径/blob/SHA、源snapshot、模型/算法/解析器版本、双跑报告SHA及全部错误范围见D2_COVERAGE.json。零候选不是安全结论。

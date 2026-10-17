# D2 实现与回归

实现提交：3b646c881716eb6b0c86195cdeeb1012ac9c921b。
D1来源提交：f11d5fdf4ab01a345a1ffb702b18edb6b5109a38。
Detector/单规则执行版本0.1.0→0.2.0；来源与Sink语义模型仍为0.1.0。

## 先反例再修复

先新增33个D2控制，在D1实现上执行，真实出现12个失败子用例（并非12个真实漏洞）；
原因包括丢弃return结果、忽略else_clause、嵌套块退出、短路/条件赋值未传播及局部同名日志指针。
原始日志outputs/logs/d2-before-fix.log的SHA见D2_VALIDATION.json。
随后修复并补足6个实参/状态控制，D2共39个；D1原32个及cases.json未改一字，哈希冻结核对通过。
这些都是开发控制，不是holdout。

## 本模块内部变化

- LocalState明确保存局部值、类型和名称遮蔽；BlockResult返回fallthrough_state/exit_states/limitations。
- return等退出分支没有后继；if/else仅合并存活环境，两个分支都退出时不再执行后续日志。
- 块结束恢复本块声明遮蔽的外层绑定，同时保留对外层变量的实际赋值。
- 支持单语句分支、else-if、局部覆盖顺序；日志之后赋值不会逆向污染此前观察。
- &&/||按已知布尔常量跳过不可执行右侧，其余按may-effects合并并partial；?:按可能分支取值/效果。
- 循环、复杂控制流、未知副作用/返回调用继续partial，不冒充CFG。
- memcpy_s四参数、strcpy_s三参数、snprintf_s格式索引3；状态/长度不自动作秘密。
- 同名局部定义/函数指针/限定调用不套用官方Sink或复制API模型；模型commit/repo不匹配blocked。
- 公开/私有、%%、*宽度精度、位置/PRI/动态格式有正负未知控制。复杂格式继续unknown。
- 可选私有function_audits/source_sites/sink_sites只供研究，不修改公共SourceUnit/Runner协议。

## 结果

D专项16个unittest方法（含旧32和新39控制）通过。
在实现提交上运行全套528项：517通过、11跳过、0失败/错误；compileall通过。
跳过是既有历史来源/性能语料缺失和Docker-only测试，详见D2_VALIDATION.json。
实际命令：

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m unittest tests.detectors.data.test_sensitive_exposure tests.detectors.data.test_d2_semantics -v
TMPDIR="$PWD/.tmp" $PY -m unittest discover -s tests -v
$PY -m compileall -q src/ohscanner/detectors/data tests/detectors/data research/data_sensitive
```

仍是syntax candidate；分支条件可行性、编译器绑定、初始化、日志读取权限和CIA影响未知。
不修改公共内核或旧控制预期。D2_FREEZE.json记录源文件/模型/控制身份。

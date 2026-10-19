# A 线 D1 路径检测器独立代码审查（2026-10-19）

## 审查范围与模块身份

- 审查基线工作树：`D:\openHarmonyScanner\worktrees\a-path-d1-20261019`，HEAD `db77164fdc2af0da02e4d3efc056d84694fd68e8`。
- D1 当前目标模块是 `src/ohscanner/detectors/cpp/path_safety_detector.py`，detector ID `ohscanner.cpp.path_source_file_sink`，rule `ohcpp.path-source-file-sink-candidate-001` v0.1.0；对应回归为 `tests/detectors/test_cpp_path_safety_detector.py`。D1 交付 `20261019-d1-path-source-sink.md` 也采用此身份。
- 此前被审查的 `path_traversal_detector.py` / `ohscanner.cpp.path_traversal` 在另一条 prototype 工作树 `worktrees/a-path-traversal-detector-20261019`，不是当前 D1 的 canonical 模块。prototype 中把 `.filename()` 直接当安全及用分散正则推断 canonical containment 的两个 P1 结论，不应误记到 `path_source_file_sink` 上；canonical 模块没有这两段抑制实现。
- 本交付只记录审查和整改建议；未改 detector、测试、shared catalog、runner 或合同。

## Canonical 模块审查 finding

| ID / 优先级 | 问题 | 证据与影响 | 最小修复方向 |
|---|---|---|---|
| R1 / P1 — 已修复 | allowlist suppression 曾把不完整条件误认为穷尽白名单 | 原实现仅要求至少一个 `variable != "safe literal"` 且条件含 `&&`。`if (name != "front.png" && gate) return;` 会在 `gate == false` 时让任意路径到达 sink，却被抑制为 0 finding / complete。修复后只接受完整匹配同一变量的 `!=` 字面量合取；额外谓词、OR、其他表达式都不再抑制。 | 保持条件语法窄；若 guard 的条件不能被完整解析为封闭 basename 集合，保留候选。 |
| R2 / P2 — 部分缓解 | source 和 sink 名称模型边界不足 | `_SOURCE_GETTERS` 仍按名称识别；原 `DeleteFile` 短名 sink 会把 `Logger::DeleteFile` 认成文件操作。现已移除通用 wrapper sink 名称，并只接受声明为 `Contacts::FileUtils` 的 `DeleteFile` 接收者；C/POSIX 文件 API 保持显式 sink 名称。普通 getter 仍可能作为 source，需在 admission 前绑定数据源身份。 | source getter 模型仍需按所属 API、签名和数据来源核实。未知同名 source 不能作为产品级来源证明；必要时应报 partial/unresolved。 |

R1 的复现源码：

```cpp
void f(Values &v, std::string root, bool gate) {
    auto name = GetStringValueFromDataShareValue(v, "photo", ok);
    if (name != "front.png" && gate) return;
    auto path = root + name;
    unlink(path.c_str());
}
```

R2 的复现形状：

```cpp
std::string GetStringParam(const char *, const char *);
struct Logger { void DeleteFile(const std::string &); };
void f(Logger &log) {
    auto path = GetStringParam("ui", "theme");
    log.DeleteFile(path);
}
```

R2 证明的是规则模型过宽、可能产生无关候选，不表示此代码本身构成产品漏洞。D1 模块目前未注册，也不在默认 profile 中；误报风险应在显式 profile 准入前解决或显式保留为 admission 限制。

## 对旧 prototype 审查的归属说明

旧 prototype 的以下观察仍适用于 prototype 自身，但不适用于当前 canonical 实现：

- 任意 `.filename()` 都抑制，包括输入 `..`；这会造成明确的 false negative。
- canonical candidate、父目录比较、任意 `relative` early-return guard 被分散正则拼成“安全证明”；不证明检查语义与 sink 路径一致。
- prototype 的 `Contacts::FileUtils::DeleteFile` 有显式类型接收者限制，但 fixture 未包含该方法的真实定义。canonical D1 则将 `DeleteFile` 作为名称集合中的一般 sink，需按 R2 收紧。

prototype 的 9 项测试通过不能替代 canonical 模块的审查，也不能作为 `path_source_file_sink` 的回归结果。它们不能与 D1 canonical 模块并列描述为两个已准入的检测器。

## 建议追加的最小回归

| 类别 | 输入控制 | 期望 |
|---|---|---|
| Positive | typed DataShare/source model → reference-output helper → string path construction → `unlink`/已绑定 wrapper | 保留 source-bound candidate，source field、sink、hash 可核对 |
| Fixed | 精确封闭 basename allowlist，拒绝条件对所有非成员均 early return，且同一值在 sink 前未变更 | 无 candidate；仅限静态模型能证明的形状 |
| Fixed control negative | `name != "front.png" && gate` 后 return，其他路径到 `unlink` | 必须保留 candidate，禁止按白名单抑制 |
| Fixed control negative | allowlist guard 后重赋污点值、经别名写回、或在 guard 与 sink 间拼接未验证的新值 | 必须保留 candidate |
| Fixed | canonical candidate 与 canonical root 比较，包含分隔符边界，拒绝越界路径的 guard 支配 sink | 仅当变量身份和 guard 关系确证时无 candidate |
| Safe boundary negative | 仅做 `starts_with(root)`，没有分隔符边界（例如 `/root2` 前缀） | 保留 candidate；已有相近控制应保留 |
| Safe | 路径拼接但没有文件 sink；sink 参数不含任何 modeled source | 无 candidate |
| Unrelated | 同名 `GetStringParam` 来自普通配置对象，或 `DeleteFile` 是 logger/domain API 且未绑定文件操作实现 | 不应被解释成已证明的 source-to-file flow；无关时无 candidate，否则明确 partial/unresolved 并加入误报 review |
| Unknown | `parse_status=partial`，或宏/变参/重载/间接调用让传播无法证明 | 可保留已证明的 candidate；aggregate blocked，file outcome partial；不能成为 clean/safe |
| Budget | 函数/调用/重扫字节数超限 | blocked/not_analyzed，不能报告 complete |

若将旧 prototype 的 basename 能力合并回 canonical 模块，必须增加 `filename("..")` 和 `filename(".")` 的越界/特殊段控制；当前 canonical 对这类转换没有 safe suppression，因此不会复现 prototype 的同一缺陷。

## T3 视角的 admission gates

1. **身份与范围**：确认待审对象唯一指向 `ohscanner.cpp.path_source_file_sink` 与 `path_safety_detector.py`；变更清单不得把 prototype 的 rule ID、测试或交付误算为 canonical D1 结果。当前规则仍未在 shared catalog 注册，默认扫描未执行它。
2. **修复 R1 并独立复现**：补入上述条件绕过负例和 guard 后重赋负例；第三方复跑必须看到 candidate 或 partial，而不是 `complete/0 findings`。再跑封闭白名单 fixed 正例，确保改成保守匹配后仍能维持预期安全控制。
3. **绑定 API 模型（R2）**：为 DataShare source 和通用 sink 定义类型、签名、字段/路径参数位置与模型来源。通过相同 method name、不同 receiver/type/实现的控制，分别证明 source 不会仅凭名字升级、sink 不会仅凭名字算文件操作。Contacts `FileUtils::DeleteFile` 如继续使用，应给出真实定义的精确源码身份及其 `unlink` 语义；无法解析时保留模型假设和 partial。
4. **Coverage 合同**：独立通过 Runner normalization，检查 complete、partial、blocked、failed、not_analyzed 的 per-file 状态和有效候选保留；尤其确认所有不确定安全检查不会抑制候选后又被计成完整 coverage。记录 `parse_status` 是真实解析器产物还是 caller-supplied fixture 值。
5. **配置接入隔离**：owner 在 shared catalog/profile 层单独审核；先保持默认关闭，测试默认 profile 不运行、显式选择才运行、A0 历史 detector 集不变。不得因存在模块或直接 Detector API replay 宣称普通扫描覆盖。
6. **固定源码与正负控制重放**：按 exact Contacts repo/commit/tree/path/blob/source hash 复跑候选，再用修复版、safe、同名 unrelated 和 partial 控制对照。当前本地重放是直接 API 调用、`parse_status` 由 harness 传入且 Git 元数据受本地 reparse point 限制；完成可读 Git 对象的 Runner/CLI 重放后才能验收 profile 覆盖。T1 的产品 build、权限调用者、服务 UID/SELinux、影响范围、版本及官方修复状态仍由独立产品证据负责。
7. **范围与结果审计**：核对 immutable base、scope ownership、diff check 与 `scripts.check_change_scope`；对候选状态、fixture hash、source binding、运行记录逐项对账。未有独立标注集前不报告 precision/recall，不把 candidate 变成 confirmed。

## 整改后实际检查

- `python -m unittest tests.detectors.test_cpp_path_safety_detector -v`：14/14 通过。
- `name != "front.png" && gate` dangerous `unlink` 回归：保留 1 candidate；partial 输入保留 candidate 且 `status=blocked`、文件 outcome 为 `partial`。
- 精确 `front.png` / `back.png` allowlist fixed control：0 candidate；guard 后重赋仍保留 candidate。
- 声明为 `Contacts::FileUtils` 的 `DeleteFile` wrapper 正例保留 candidate；`Logger::DeleteFile` 同名 unrelated method 不再作为 file sink。
- canonical separator-bounded control：原有安全样例输出 0 finding；不完整的 canonical/parent logging 对照仍输出 candidate。
- 修改仅涉及 canonical detector、其私有测试和本交付；未修改 Catalog/Runner/shared API。T1 产品验收尚未执行。

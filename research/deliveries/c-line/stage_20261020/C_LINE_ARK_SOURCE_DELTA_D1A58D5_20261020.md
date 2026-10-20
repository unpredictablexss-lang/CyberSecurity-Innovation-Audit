# C 线 Ark Runtime `TypedArray.set` 源码差异（d1a58d5）

## 身份与可复现绑定

- OHScanner scanner 基线：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`。
- 仓库：`openharmony/arkcompiler_ets_runtime`，Gitee URL `https://gitee.com/openharmony/arkcompiler_ets_runtime.git`。只读 `git ls-remote` 返回 `d1a58d59166777e16574ceed64c15f0b2f44a76c` 同时作为 `HEAD` 和 `refs/heads/master`。
- 新核对的提交：`d1a58d59166777e16574ceed64c15f0b2f44a76c`，tree `2cd854aa7d9f987de89d31a6a512e735779e75b6`，父提交 `c834c91bc3b7d09a746826b7b923ef6b5cfe4994`、`9a9e8c8717c5ab5e818845e3724ae17dcb10b441`。
- 对照提交：`a65a2853ccae13da167d9aa4720ab8b11ec16656`，tree `8781f036a3e7e04d8e0b34970d5f623b42875016`。
- d1 提交对象在本地 Ark Git 对象库中可读取。当前本地 `gitcode/master` tracking ref 仍是 a65；因此 Gitee 的 master 身份由本次 `ls-remote` 独立确认，而非从该陈旧 tracking ref 推断。

下表每项列出 Git blob OID 与从 `git show <commit>:<path> | sha256sum` 得到的完整文件 SHA-256：

| 文件 | a65 blob / SHA-256 | d1a58 blob / SHA-256 |
|---|---|---|
| `ecmascript/builtins/builtins_typedarray.cpp`（含 `BuiltinsTypedArray::Set`） | `0fc27c213e1ea80d93e1e3807eec11baf2634832` / `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` | `83a181766c569d8772eea23dbe2468e9e3ff4c71` / `39889e713573a28c5de63a9d52a7a9b61efea37f26167976f749f50db67c5e84` |
| `ecmascript/base/typed_array_helper.cpp` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` / `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` | `bfb47aa43549b3064347fe2a7ff7f41c3d774f3d` / `73241919e1886b4a8641b708eea3f5cfb2eb128511ee42d90e170eb0b263b82a` |
| `ecmascript/base/typed_array_helper.h` | `92b73cdcf4b4e05453cc21e24f7e9364dd6949ce` / `ced087d43a805171778d0ff49f46c01568588fdb137b3c5583a472d9de83491a` | `49ad15a48e191a2da6994e18e12236e792d0da1e` / `3ac0414e592bd569a174cd0ace7aa245becbfd562d08ea2d3cb7ec26a7663aab` |
| `ecmascript/builtins/builtins_arraybuffer.cpp` (`SetValueInBuffer`, `GetDataPointFromBuffer`) | `2aa22c58803df690a5a2b326451e02297dc5e2f6` / `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` | `7898ad3e299e31d15363a88c3773fc5ffc6134fe` / `f1448ba054b8c3f79aa0ed07acb56cf98d5a3af6058254a924c0c675677a63f7` |
| `ecmascript/js_tagged_value.cpp` (`ToNumber`, `ToInteger`, `ToLength`) | `cc2900c2a5a2fdec4321d6f1f619cf2f2f8dbf4d` / `22ad153b0e5a3a9fa4ea45fc0b5feed83504f124684d44c67dffe39d057e53a4` | `c00958702273a4b6b7f789aa4068d9e999af0a09` / `f24302dae371dd70f00a1b8a406ae0300055cb34ff8babcddb70daabac2fcba3` |
| `ecmascript/base/number_helper.cpp` (`TruncateDouble`) | `afc0ad3513725bf6606256755cb37285f4b97aa8` / `bd0ec62661f7f75236204d4fd3b11874c43981cb8e20245cdb8db45adc076634` | `2e3a331f18344e6981309c4cd4f8e91b07950518` / `d201fcea5cfdaf85358b8852437bebc68156b034853c43e2f7a37e2658bbcd35` |

## 差异结论

**原有非零-byteOffset view-boundary 候选在 d1a58 仍有源码支持；没有在该提交中被修复或反驳。** 这只是静态源代码结论，未运行 Ark Runtime，也不确认任一产品影响。

在 `BuiltinsTypedArray::Set` array-like 分支（d1a58 `builtins_typedarray.cpp:1146` 起），offset 转换与检查位于 `1168-1190`：调用 `JSTaggedValue::ToInteger` 后拒绝负值/正无穷，再转成 `uint64_t targetOffset`。source length 的 `ToLength` 在 `1228-1235`；sum 检查在 `1240`，target byte index/窄化在 `1243-1247`，limit 在 `1253`，循环与 `SetValueInBuffer` 调用在 `1266` 及其循环体。d1 的 `js_tagged_value.cpp:84-123` 包含 `ToNumber`（number primitive 直接返回在 `88-90`，对象到 primitive 再递归转换在 `111-115`）；`203-209` 为 `ToInteger`；`265-276` 为 `ToLength`。`number_helper.cpp:802-819` 为 `TruncateDouble`，有限值通过 `floor/ceil` 向零截断。`builtins_arraybuffer.cpp:380-405` 为 `SetValueInBuffer`，`761-775` 为 `GetDataPointFromBuffer`。a65 与 d1 的 Set conversion、range check、target index、limit 和写调用保持一致；d1 的相关 Set 差异只有 ContentType 读取，以及 typed-array source 类型从 `[[TypedArrayName]]` 重新解析。

辅助文件变化不改变该结论：`typed_array_helper` 的变化涉及 typed-array 名称、ContentType 和构造/复制路径；`builtins_arraybuffer.cpp` 的差异涉及 NaN 转换。d1 的 `SetValueInBuffer` 仍取得 backing buffer 数据指针，再将 `byteIndex` 作为 backing-buffer-relative 写入偏移；`GetDataPointFromBuffer` 对基址加偏移。目标 view 的 `[[ByteOffset]]` 被加入 index，但没有新增对 target view 范围的 clamp/check。此处也不能据此宣称 backing-buffer 越界：需分别看具体回绕后的 index 是否仍落在 backing allocation 内。

对于此前 8 KiB backing、4 KiB sibling `[0,4096)`、target `[4096,8192)`、4 KiB Proxy source 和 offset `18446744073709549568` 的算术 witness，源码推演仍给出写入 index `[2048,6144)`：`[2048,4096)` 位于 target view 之前、但仍在 backing buffer 范围内，且可被 sibling view 观察；`[4096,6144)` 落在 target view 内。该推演只说明 array-like 分支存在跨越 view 边界的写入路径，不是 JS/Runtime 的执行观察。动态写入、实际异常/回绕行为和隔离的 JS 控制仍未运行，保持 `not_run`。

## 检查范围与命令

本次仅检查以下路径的 a65→d1 差异：`builtins_typedarray.cpp`、`typed_array_helper.cpp/.h`、`builtins_arraybuffer.cpp`。确认了 Set array-like 分支、offset 转换、长度/byte-index 运算、`SetValueInBuffer` 和 `GetDataPointFromBuffer`。未改生产代码、未构建、未运行 PoC；没有做全仓库安全审计。

```sh
git ls-remote https://gitee.com/openharmony/arkcompiler_ets_runtime.git HEAD refs/heads/master
git show -s --format='%H%n%T%n%P%n%aI%n%s' d1a58d59166777e16574ceed64c15f0b2f44a76c
git diff --unified=6 a65a2853ccae13da167d9aa4720ab8b11ec16656 d1a58d59166777e16574ceed64c15f0b2f44a76c -- \
  ecmascript/builtins/builtins_typedarray.cpp \
  ecmascript/base/typed_array_helper.cpp ecmascript/base/typed_array_helper.h \
  ecmascript/builtins/builtins_arraybuffer.cpp
```

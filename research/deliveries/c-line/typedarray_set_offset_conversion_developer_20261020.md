# TypedArray.set(arrayLike, offset)：超大 offset 转换可达性核验

日期：2026-10-20（Asia/Shanghai）  
范围：核验 `targetOffset = 2^64 - 2048` 是否可经 JS Number 与固定实现的 `ToInteger` / `double → uint64_t` 到达，以及后续整数检查；不运行 Ark Runtime、不修改生产代码。

## 结论

**转换可达：是。** offset = `18446744073709549568`（`2^64 - 2048`）可由 IEEE-754 binary64 精确表示；它小于 `2^64`，处于 `uint64_t` 可表示范围。实际代码调用 `JSTaggedValue::ToInteger`，不是 `ToIndex`。`ToInteger` 中的 `TruncateDouble` 对该整数保持不变，然后 C++ 转换到 `uint64_t` 得到同一个整数。

**该事实本身不证明越界写。** 后续 `srcLen + targetOffset > targetLength` 的 `uint64_t` 加法确实可能模 `2^64` 回绕，令检查通过；随后 byte index 与 limit 被窄化/计算为 `uint32_t`。对 array-like 分支，若回绕后长度较小，`targetByteIndex` 落在 `uint32_t` 尾部而 `limit` 落在其前面，循环不执行。若长度足够大使循环区间越过尾部，所对应的元素索引也已位于足够大的目标 TypedArray 范围内。静态阅读因此**削弱了“仅凭此 offset 即可造成越界写”的候选解释**，但这不是完整形式化证明，也未执行 runtime；应保留为源码级候选/待独立复验，不能报成 confirmed 或安全结论。

## 固定源码与来源完整性

- 仓库：`openharmony/arkcompiler_ets_runtime`；本地路径 `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime`
- 源码 commit：`a65a2853ccae13da167d9aa4720ab8b11ec16656`（从 checkout 的 `.git/HEAD` 读取；`.git/config` 在环境不可读，故不能声明 checkout clean 或验证 remote）
- `ecmascript/builtins/builtins_typedarray.cpp`：Git blob `0fc27c213e1ea80d93e1e3807eec11baf2634832`；SHA-256 `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c`
- `ecmascript/js_tagged_value.cpp`：Git blob `cc2900c2a5a2fdec4321d6f1f619cf2f2f8dbf4d`；SHA-256 `22ad153b0e5a3a9fa4ea45fc0b5feed83504f124684d44c67dffe39d057e53a4`
- `ecmascript/base/number_helper.cpp`：Git blob `afc0ad3513725bf6606256755cb37285f4b97aa8`；SHA-256 `bd0ec62661f7f75236204d4fd3b11874c43981cb8e20245cdb8db45adc076634`
- blob OID 按 Git blob 规则 `SHA1("blob <length>\0" + bytes)` 从当前 checkout 文件计算；SHA-256 由 Python `hashlib.sha256` 计算。行号依据上述 commit 工作树内容。

## 调用链与整数语义

1. `ecmascript/builtins/builtins_typedarray.cpp:1156-1179`：`TypedArray.prototype.set` 先处理 offset。int tagged value 走单独负数检查；其他值执行 `JSTaggedValue::ToInteger(thread, srcOffset)`，取 `GetNumber()`，拒绝 `< 0` 与正无穷，随后 `static_cast<uint64_t>(rawTargetOffset)`。
2. `ecmascript/js_tagged_value.cpp:204-210`：`ToInteger` 执行 `ToNumber`，再传给 `NumberHelper::TruncateDouble`。
3. `ecmascript/base/number_helper.cpp:804-820`：有限非零数按符号取 `floor` / `ceil`。非负整数 `2^64 - 2048` 保持不变；NaN 变 0，无穷原样返回（正无穷在调用者处抛 RangeError，负无穷因 `< 0` 抛 RangeError）。
4. `2^64 - 2048 = 18446744073709549568`。binary64 在 `[2^63, 2^64)` 的间距为 2048，因此它是精确有限数；它比 `UINT64_MAX` 小 2047，处于 `uint64_t` 范围。不发生超范围浮点转无符号整数的边界转换。
5. array-like 分支 `builtins_typedarray.cpp:1212-1276`：`srcLen` 从 `ToLength(Get(src,"length"))` 转为 `uint64_t`；先检查 `srcLen + targetOffset > targetLength`，之后计算 `targetOffset * targetElementSize + targetByteOffset` 并窄化为 `uint32_t`，再计算 `uint32_t limit`。写循环条件为 `targetByteIndex < limit`。
6. typed-array 分支 `builtins_typedarray.cpp:1304-1339` 也先检查 `srcLength + targetOffset > targetLength`；之后 `targetOffset` 先窄化为 `uint32_t` 再乘元素大小，并窄化/相加为 32 位 byte index 与 limit。后续循环仍以 byte index 与 limit 比较。两处 `ASSERT` 仅在断言开启时提供辅助检查，不视为无条件运行时保护。

## 边界算例

- **正控制（正常可达且成功）：** `new Uint8Array(4).set({length: 1, 0: 7}, 2)`。`2` 走 `ToInteger` 并转成 `uint64_t(2)`；长度和偏移在界内，byte index 2、limit 3，array-like 写循环迭代一次。此为源码演算，不是 Ark Runtime 实测。
- **拒绝边界：** `new Uint8Array(4).set({length: 1, 0: 7}, -1)`。`ToInteger` 得负数，调用点 `< 0` 检查抛 RangeError；`+Infinity` 在显式正无穷检查抛 RangeError。
- **可表示但长度检查抛错的控制：** 同一目标与 length 1，offset `2^53`（binary64 精确整数且可转成 uint64），加法不回绕且大于 `targetLength`，在窄化前抛 RangeError。能转换进 uint64 不等于能通过长度检查。
- **目标值的回绕边界：** array-like 若 `srcLen < 2048`，`srcLen + (2^64-2048)` 不会回绕到小值，长度检查失败。若 `srcLen >= 2048` 且加法回绕后不超过目标长度，窄化后的 byte index 从 `2^32 - 2048 × targetElementSize` 起算；只有当目标 byte capacity 足以覆盖该起点时，32 位 `limit` 才可能大于起点并进入循环。此解释了为何单凭 offset 转换可达不能推出写越界；不同目标类型、长度与 detached/resizable buffer 等条件未穷尽验证。

## 可复现命令

在 `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime`：

```powershell
Get-Content .git\HEAD
rg -n 'targetOffset|ToInteger' ecmascript/builtins/builtins_typedarray.cpp
rg -n 'JSTaggedValue::ToInteger\(' ecmascript/js_tagged_value.cpp
rg -n -F 'TruncateDouble' ecmascript/base/number_helper.cpp
```

计算源 blob OID 与 SHA-256：

```powershell
@'
import hashlib, pathlib
for name in ['ecmascript/builtins/builtins_typedarray.cpp','ecmascript/js_tagged_value.cpp','ecmascript/base/number_helper.cpp']:
    b=pathlib.Path(name).read_bytes()
    print(name, len(b), hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(), hashlib.sha256(b).hexdigest())
'@ | python -
```

本机 `git status` / `git rev-parse` 在上游 checkout 失败，因为 `.git/config` 不可读；HEAD 可读，blob OID 与源文件按 Git blob 规则的哈希一致。OHScanner 开发分支的具体 HEAD 与提交只涵盖报告，见提交历史。

## 状态与限制

- 源码转换路径：`reachable`（源码级结论）。
- exact offset 构造越界影响：`candidate / not confirmed`；静态链条显示后续比较可能阻止循环，需独立复验完整字节容量/运行时语义后再决定关闭或保留。
- Ark Runtime 执行、JS PoC、产品 build/profile、产品可达性与影响：`not_run / unknown`。
- 未运行编译、测试、符号执行，也未将算例提交给 Ark VM。

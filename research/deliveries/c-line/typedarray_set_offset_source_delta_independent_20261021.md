# Ark `TypedArray.set` 源码差异独立复核：a65 → d1a58

日期：2026-10-21（Asia/Shanghai）
OHScanner 基线：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`，tree `764f7698f6babdcccb2cd68eba75ed1b0afefc9e`。本报告只记录该固定 scanner SHA 上的源码审计结果。
Ark Runtime 对照：`a65a2853ccae13da167d9aa4720ab8b11ec16656`，tree `8781f036a3e7e04d8e0b34970d5f623b42875016`。
Ark Runtime 新源码：`d1a58d59166777e16574ceed64c15f0b2f44a76c`，tree `2cd854aa7d9f987de89d31a6a512e735779e75b6`。

## 独立身份与文件绑定

我在源仓库对象库独立读取两个 commit/tree/blob，并重新计算相关完整文件 SHA-256。Gitee `git ls-remote` 当轮响应同时将 d1a58 标为 `HEAD` 和 `refs/heads/master`。本地 checkout `HEAD` / `gitcode/master` 仍为 a65，因此没有用陈旧 tracking ref 推断远端状态。

| 源文件 | a65 blob / SHA-256 | d1a58 blob / SHA-256 |
|---|---|---|
| `ecmascript/builtins/builtins_typedarray.cpp` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` / `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` | `83a181766c569d8772eea23dbe2468e9e3ff4c71` / `39889e713573a28c5de63a9d52a7a9b61efea37f26167976f749f50db67c5e84` |
| `ecmascript/js_tagged_value.cpp` | `cc2900c2a5a2fdec4321d6f1f619cf2f2f8dbf4d` / `22ad153b0e5a3a9fa4ea45fc0b5feed83504f124684d44c67dffe39d057e53a4` | `c00958702273a4b6b7f789aa4068d9e999af0a09` / `f24302dae371dd70f00a1b8a406ae0300055cb34ff8babcddb70daabac2fcba3` |
| `ecmascript/base/number_helper.cpp` | `afc0ad3513725bf6606256755cb37285f4b97aa8` / `bd0ec62661f7f75236204d4fd3b11874c43981cb8e20245cdb8db45adc076634` | `2e3a331f18344e6981309c4cd4f8e91b07950518` / `d201fcea5cfdaf85358b8852437bebc68156b034853c43e2f7a37e2658bbcd35` |
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5a2b326451e02297dc5e2f6` / `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` | `7898ad3e299e31d15363a88c3773fc5ffc6134fe` / `f1448ba054b8c3f79aa0ed07acb56cf98d5a3af6058254a924c0c675677a63f7` |
| `ecmascript/base/typed_array_helper.cpp` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` / `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` | `bfb47aa43549b3064347fe2a7ff7f41c3d774f3d` / `73241919e1886b4a8641b708eea3f5cfb2eb128511ee42d90e170eb0b263b82a` |
| `ecmascript/base/typed_array_helper.h` | `92b73cdcf4b4e05453cc21e24f7e9364dd6949ce` / `ced087d43a805171778d0ff49f46c01568588fdb137b3c5583a472d9de83491a` | `49ad15a48e191a2da6994e18e12236e792d0da1e` / `3ac0414e592bd569a174cd0ace7aa245becbfd562d08ea2d3cb7ec26a7663aab` |

The set implementation is at d1a58 `ecmascript/builtins/builtins_typedarray.cpp:1146`. The conversion chain is `js_tagged_value.cpp:84-123` (`ToNumber`; a number primitive is returned directly at 88-90), `203-209` (`ToInteger`), `265-276` (`ToLength`) and `number_helper.cpp:802-819` (`TruncateDouble`). The write path is `builtins_typedarray.cpp:1266-1285` to `builtins_arraybuffer.cpp:380-406` and `761-779`.

## 独立差异检查

I reviewed the exact a65→d1 Git diff for the typed-array builtin, conversion helpers, typed-array helper and ArrayBuffer writer. In the `Set` array-like path, both commits still:

1. call `ToInteger(offset)`, reject negative and positive infinity, then cast the resulting finite nonnegative double to `uint64_t`;
2. convert source `length` via `ToLength`, cast to `uint64_t`, and check `srcLen + targetOffset > targetLength` in unsigned 64-bit arithmetic;
3. compute `targetOffset * targetElementSize + targetByteOffset` in unsigned 64-bit arithmetic, then narrow the result to `uint32_t`;
4. compute a 32-bit `limit` and loop while `targetByteIndex < limit`, calling `SetValueInBuffer` for each element.

The changed `Set` lines concern ContentType accessor spelling and re-resolving the typed-array source's type from its name; they do not alter the array-like path above. `ToNumber` still returns an already numeric value directly. `ToInteger`, `ToLength` and `TruncateDouble` retain the relevant behavior. `SetValueInBuffer` and `GetDataPointFromBuffer` still obtain the backing store base and add `byteIndex`; I found no new target-view clamp/check in d1. The ArrayBuffer diff changes NaN handling in other conversions, which is immaterial to the Uint8 witness values `0x5a`.

## Witness re-evaluation

Use `x = 2^64 - 2048 = 18446744073709549568`, which is exactly representable as binary64 (`ToInteger` leaves it unchanged and it remains below `UINT64_MAX`). For a `Uint8Array` target view with `targetByteOffset = 4096`, `targetLength = 4096`, and an array-like Proxy with `srcLen = 4096`:

- `(srcLen + x) mod 2^64 = 2048`, so the source range check compares `2048 > 4096` and does not throw.
- `(x + targetByteOffset) mod 2^32 = 2048`, so the narrowed byte write starts at 2048.
- `limit = 2048 + 4096 = 6144`; the loop traverses `[2048,6144)`.
- With an 8192-byte backing buffer and target view `[4096,8192)`, `[2048,4096)` is before the target view, while all writes remain within the backing buffer. A sibling view over `[0,4096)` can observe the first 2048 writes.

A Python integer/binary64 check was used only to verify this arithmetic and exact representability; it is not runtime evidence. The JS witness and controls were not run in this source-delta task.

## Review of developer report and feedback

The developer source-delta report's conclusion agrees with this independent review: the view-boundary candidate persists in d1a58 at source level. I found two concrete documentation gaps during review and requested bounded corrections: first, missing blob/SHA bindings for `js_tagged_value.cpp` and `number_helper.cpp`; second, the Set function start line was listed as 1134 instead of 1146. I independently recalculated all six file hash pairs and checked the corrected line against `git show d1:... | nl -ba`; both corrections are now accurate in developer commit `f77925bfba85184b18463a4678168dcbe72849f5`. No further source-semantic correction was needed.

Classification: source conversion path `reachable`; nonzero-byteOffset target-view-boundary write `candidate`; backing-buffer OOB is not shown by this witness; Ark Runtime execution and product impact remain `not_run` / `unknown`. No production edits, builds or runtime execution were performed.


# AUTH-01 本地隔离复现：CVE-2023-0036（2026-10-17）

`result.json` / `result.md` 由 `src/ohscanner/poc/runner.py` 生成，未手工编辑。
`validated_vulnerability` 为 0；reachability 为 `partial`，见 `result.md` 最后一节。

## 固定输入

| 项 | 值 |
|---|---|
| 目标仓库 | `openharmony/inputmethod_imf` |
| 符号 | `PlatformCallbackStub::OnRemoteRequest`（PR !228） |
| vulnerable | `e663b47013d534a56165ab7467fbb3e14bf7172b` |
| fixed | `5eaddcab19bc4b22544f4bee1e8894fc2d6505dc` |
| Parcel 依赖 | `commonlibrary_c_utils b807d3dadb7dbb7639fe85b3a5f72da18d318da2` |
| manifest | `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/manifest.json` |

每个被编译的 blob 在 `materialize()` 中按 manifest 的 sha256 校验；版本不符会中止而不是
换用工作树内容。两个修订分别编译到独立目录，避免同路径文件互相覆盖。

## 环境

- 镜像 `ohscanner-validation-local:20261016`，
  id `sha256:bfb8cbdda14a4654fccf5d61463d37c0ece1a2bd1af13520b21f7af0e539e712`
- 容器内 Ubuntu clang 14.0.0-1ubuntu1.1，ASan + UBSan，`PATH=/usr/bin:/bin`
- 无网络；`runner.py` 只在 `OHSCANNER_VALIDATION_CONTAINER=1` 且存在 `/.dockerenv` 时运行

## 复现命令

宿主（Windows，Docker Desktop 29.6.2）把暂存目录挂进验证镜像：

```sh
docker run --rm --entrypoint sh -v 'C:\Users\16669\AppData\Local\Temp\ohpoc:/work' \
  -w /work/repo -e OHSCANNER_VALIDATION_CONTAINER=1 -e PYTHONPATH=/work/repo \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
  ohscanner-validation-local:20261016 -c 'python3 /work/run_poc.py'
```

暂存目录内容：

- `/work/repo`：本提交的 `git archive HEAD` 解包
- `/work/imf`：目标仓库 `.git`（浅克隆，两个固定提交都在对象库里）
- `/work/cutils`：`git archive b807d3da…` 解包
- `/work/out`：构建与运行产物（不提交）
- `/work/run_poc.py`：调用 `run_poc()` 并把 `PocResult` 写成 json/md

## 结果

| 修订 | 状态 | `no_token` | `correct_token` | `foreign_token` |
|---|---|---|---|---|
| vulnerable | `stable_reproduced`（重放 3/3） | trigger，`messages_sent=1` | no_trigger | no_trigger |
| fixed | `run_success` / `stable_rejected` | no_trigger，`ret=-74` | trigger | no_trigger，`ret=-74` |

`no_token` 是"伪造请求"负例：入侵者不写接口描述符；`correct_token` 是无害对照，fixed 修订
必须继续服务它。vulnerable 的 `foreign_token` 不触发，与 manifest 的 `expect: any` 一致。

## 没有证明的事

- 没有证明产品入口可达：harness 直接调用 stub。真实 IPC 调用者身份、ability 注册与权限
  状态仍是 EvidenceObligation。
- `MessageHandler::SendMessage` 是记录桩；观测值是"stub 执行了回调并排队消息"。
- 这是 AUTH-01（relay/confused deputy）的真实修复对，**不是** Parcel 族规则的真实修复对；
  DATA-01..03 没有因此获得任何动态证据。

## 哈希

```
20632c697581f55ed33b698467b15dd03cdec3eb22ec15e678343e8c0cd14979  result.json
44047f51fed0c1e91e784e48494edf421058779dff8f5a3a28ff2e8f7f30aefb  result.md
```

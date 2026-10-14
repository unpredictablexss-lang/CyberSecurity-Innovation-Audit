# OHScanner 编译与运行性能标准审查

- 审查日期：2026-10-14（Asia/Shanghai）
- 审查分支：`codex/full-runtime-performance-audit-20261014`
- 代码基线：`60052bd5183f5cd86878e371250a29e86f63f14e`（`Merge mainline status documentation update`）
- 审查原则：技术文档只用于定位命令和边界，不作为性能或通过结论的证据。下述数字均来自本机重新执行的命令输出。

## 1. 结论摘要

- **依赖安装**：通过。`pip install -r requirements-web.txt` 已执行，所需依赖均已满足。
- **代码编译**：通过。Python `compileall` 覆盖 `src`、`tests`、`scripts`、`research`，无语法错误。
- **自动化测试**：通过。根测试目录 `482` 个测试执行，`0` 失败，`2` 跳过；跳过项仍是测试代码中的宿主机直跑保护。实际 Docker Worker 补充验证已另行通过。
- **前端构建**：通过。TypeScript `tsc --noEmit` 与 `node build.mjs` 通过；使用 npm 的完整 `npm ci` 与 `npm run build` 也通过。
- **核心扫描路径**：命令通过。M0 合成契约、M1 固定 Git 索引和 M2 三检测器均实际执行；检测器状态分别为 `blocked / completed / completed`，产生 `0` 个候选、`0` 个已验证漏洞。总体状态是 `completed_with_limitations`，不能解释为安全。
- **工作台集成**：通过。API/Worker/CLI 在固定组件上结果一致（`cli_parity=true`），覆盖计数闭合；本轮为 0 候选，因此源码核验逻辑没有候选样本可核。
- **规模性能**：通过两轮复测。11 个固定组件共 `9,508` 个扫描文件、`107,087,947` 字节、`2,618,176` 行；两轮累计墙钟 `111.30 s` / `110.90 s`，单进程峰值 RSS 最大 `266.3 MB`。
- **容器动态验证**：Docker 29.1.3 与 Podman 3.4.4 已配置；Docker 验证镜像和 AUTH-01 vulnerable/fixed/patched 三方 Worker 已实际运行，组件 Harness gate 通过。产品入口可达性仍未证明，`validated_vulnerability` 保持 `0`。
- **仍未完成**：`scripts/verify_owner_ipc_components.py` 所需历史基线 JSON 不在当前工作区，脚本实际启动后以 `FileNotFoundError` 结束；该项不得写成通过。

## 2. 实际环境

| 项目 | 实测值 |
|---|---|
| OS | Windows 11 10.0.26200 / WSL2 Ubuntu 22.04，Linux 6.18.54.1-microsoft-standard-WSL2 x86_64 |
| Python | 3.10.12（WSL） |
| Python 依赖 | tree-sitter 0.26.0、tree-sitter-c 0.24.2、tree-sitter-cpp 0.23.4、FastAPI 0.143.0、Uvicorn 0.54.0、HTTPX 0.28.1、Starlette 1.7.0 |
| Node | Node 24.19.0（Codex 运行时，直接构建）；Node 26.9.0 / npm 11.19.1（完整 npm 验证） |
| C/C++ | WSL clang 14.0.0、gcc 11.4.0；clang++ 可用 |
| 容器环境 | Docker 29.1.3 / containerd 2.2.1；Podman 3.4.4；Ubuntu 22.04 验证镜像 |
| 缺失工具 | CodeQL、Joern、Semgrep、CMake、Ninja |
| 附带工具 | cppcheck 可用，但本次生产路径没有调用外部扫描器 |

## 3. 验证矩阵

| 验证项 | 命令/入口 | 结果 | 墙钟 | 峰值 RSS | 证据 |
|---|---|---:|---:|---:|---|
| Python 依赖安装 | `python -m pip install -r requirements-web.txt` | PASS，全部依赖已满足 | 13.84 s | 46.3 MB | `main/pip_install.stderr.txt` |
| Python 编译 | `python -m compileall -q src tests scripts research` | PASS | 4.64 s | 13.8 MB | `outputs/logs/full-audit-20261014/main/compileall.stderr.txt` |
| Python 根目录测试 | `python -m unittest discover -s tests -v` | PASS，482 tests / 0 failed / 2 skipped | 87.47 s（runner 内部 80.158 s） | 63.4 MB | `container-setup/postfix-unittest.stderr.txt` |
| TypeScript 检查 | `node node_modules/typescript/bin/tsc --noEmit` | PASS | 0.391 s | 45.5 MB | `main/web_tsc.stderr.txt` |
| 前端打包 | `node build.mjs` | PASS | 0.085 s | 45.1 MB | `main/web_build.stderr.txt` |
| npm 依赖安装 | `npm ci`（Node 26.9.0 / npm 11.19.1） | PASS，77 packages | 458.07 s | 未单独采样 | `main/npm_ci_node26.txt` |
| npm 生产构建 | `npm run build` | PASS | 4.486 s | 未单独采样 | `main/npm_build_node26.txt` |
| M0 合成契约 | `python -m src.cli ohscan ...` | PASS，2 个第一方 run | 0.57 s | 19.9 MB | `main/cli/m0.stderr.txt` |
| M1 固定 Git 索引 | `python -m src.cli ohscan-index ...` | PASS，123 文件 | 1.91 s | 47.7 MB | `main/cli/index.stderr.txt` |
| M2 三检测器 | `python -m src.cli ohscan-run ...` | COMMAND PASS；`blocked/completed/completed`，0 diagnostics | 4.76 s | 163.3 MB | `main/cli/all_detectors.stderr.txt` |
| 历史基准重放 | `python -m src.cli benchmark-historical ...` | PASS，vulnerable/fixed parent match | 0.54 s | 21.9 MB | `main/cli/historical_cutils.stderr.txt` |
| 工作台一致性 | `python -m scripts.verify_workbench ...` | PASS，`cli_parity=true` | 13.81 s（scan 5.80 s） | 190.6 MB | `main/verify_workbench.stdout.txt` |
| 组件规模性能 | `python scripts/perf_scale_scan.py ...` | PASS，两轮 11/11 | 111.30 s / 110.90 s | 266.3 MB max | `main/perf-run{1,2}/perf_scale_scan.json` |

### 测试跳过项与补充执行

根测试目录的 `unittest discover` 不递归进入 `tests/detectors`。对已提交的 detector 测试快照单独执行 `python -m unittest discover -s tests/detectors -v`，`57` tests 全部通过。工作区另有未提交的 A 线 detector 新测试/算法改动；这些并发脏改动不属于本次验证修复提交，已在原位保留。

1. `tests.test_poc_runner.Auth01IntegrationTests.test_attack_triggers_on_the_vulnerable_revision_only`
2. `tests.test_poc_runner.Auth01IntegrationTests.test_record_keeps_validated_vulnerability_at_zero`

原因均为：`AUTH-01 runtime harness must execute only through the Docker validation worker`。本次没有绕过隔离边界在宿主机执行，而是在 Docker Worker 中补充运行，结果见 4.4。

## 4. 模块级观察

### 4.1 OHScanner 核心与检测器

`commonlibrary_c_utils @ b807d3dadb7dbb7639fe85b3a5f72da18d318da2` 的三检测器真实执行结果：

| 检测器 | 版本 | 状态 | 分析范围 | 诊断 |
|---|---|---|---:|---:|
| `ohscanner.cpp.lifetime` | 0.2.0-proposed | blocked | 93 complete-AST 文件 | 0 |
| `ohscanner.cpp.shared_ptr_race` | 0.2.0-proposed | completed | 93 complete-AST 文件 | 0 |
| `ohscanner.interface.ipc` | 0.5.0 | completed | 123 文件 | 0 |

总体：123 个 C++ 文件、1,567,031 字节；解析 `93 complete / 30 partial`。`blocked`、`partial`、`0 diagnostics` 都不是安全结论。报告状态为 `completed_with_limitations`。

### 4.2 Workbench/API/Worker

固定组件验证返回：

- `indexed_files=123`
- `source_bytes=1,567,031`
- `parse=93 complete / 30 partial`
- `candidate_count=0`
- `validated_vulnerability=0`
- `cli_parity=true`
- `scan_seconds=5.795`
- `verification_seconds=10.167`

这证明 API/Worker 与 CLI 的扫描结果、覆盖和源码证据可对齐；它不证明组件安全，也不替代漏洞准确率基准。

### 4.3 规模性能

两轮固定语料均 11/11 成功。下表是两轮平均墙钟，RSS 取两轮较大值：

| 组件 | 平均墙钟 s | 峰值 RSS MB | 文件 | 源码字节 | 树内 C/C++ 行 | 分片 |
|---|---:|---:|---:|---:|---:|---:|
| communication_ipc | 6.72 | 103.7 | 697 | 8,047,192 | 145,562 | 1 |
| inputmethod_imf | 7.00 | 102.0 | 698 | 6,150,477 | 154,966 | 1 |
| multimedia_camera_framework | 17.71 | 238.7 | 1,696 | 17,258,181 | 409,298 | 1 |
| multimedia_player_framework | 18.19 | 246.0 | 1,773 | 17,305,015 | 439,198 | 1 |
| notification_common_event_service | 3.43 | 62.6 | 293 | 3,305,017 | 85,467 | 1 |
| resourceschedule_background_task_mgr | 2.91 | 52.0 | 284 | 2,214,672 | 52,326 | 1 |
| security_access_token | 10.27 | 133.2 | 1,249 | 8,798,780 | 235,117 | 1 |
| telephony_call_manager | 5.41 | 92.4 | 513 | 5,677,034 | 141,361 | 1 |
| update_updateservice | 2.17 | 36.1 | 238 | 888,385 | 22,891 | 1 |
| window_window_manager | 35.12 | 266.3 | 1,944 | 35,876,163 | 884,210 | 7 |
| c_utils_pinned_m2 | 2.17 | 48.7 | 123 | 1,567,031 | 47,780 | 1 |
| **合计** | **111.10 avg** | **266.3 max** | **9,508** | **107,087,947** | **2,618,176** | 17 runs |

平均吞吐约 `85.6 files/s`、`0.96 MB/s`、`23,566 tree LOC/s`。`window_window_manager` 是主要热点，35.12 s、266.3 MB、7 个分片；其余组件墙钟与 RSS 随文件/字节规模单调增长，没有观察到单组件异常膨胀。两轮总量差 `0.40 s`，说明本轮结果在本机负载下可重复。

### 4.4 Docker/Podman 与 AUTH-01 补充验证

- Docker `29.1.3`、containerd `2.2.1` 和 Podman `3.4.4` 已在 WSL2 Ubuntu 22.04 安装，systemd 服务正常。
- Docker Hub 直连拉取 `ubuntu:22.04` 超时；基础镜像通过 `docker.m.daocloud.io/library/ubuntu:22.04` 获取，并按 digest 保存到本地 `ubuntu:22.04`。
- 首次镜像构建失败：Ubuntu 22.04 仓库没有 Dockerfile 中的 `libclang-rt-14-dev`。已改为仓库实际提供的 `libclang-common-14-dev`，该包包含 ASan/UBSan runtime。
- Docker 验证镜像 ID：`sha256:da2be0997cf04e71a80f35c312976bc3ba96399757563f01816f011ef25c12dc`。Docker 与 Podman 均能构建镜像并完成 `clang++ -fsanitize=address,undefined` 编译/运行 smoke。
- Podman 默认 LeakSanitizer 在其进程环境中报 ptrace 限制；设置 `ASAN_OPTIONS=detect_leaks=0` 后 smoke 通过。生产 `run_poc` 对每个 case 已设置该选项。生产 Worker 仍按设计只接受 Docker（`/.dockerenv` 边界），Podman 仅作为兼容性补充，不替代 Docker-only 验证。
- Docker Worker 通过 `src.workbench.validation.execute_validation` 实际执行 AUTH-01，使用 `--network none --cap-drop ALL --no-new-privileges --read-only` 以及内存/CPU/PID/超时限制。

| AUTH-01 修订 | 生命周期 | 3 次攻击重放 | 结果 |
|---|---|---|---|
| vulnerable `e663b470...` | `stable_reproduced` | `trigger/trigger/trigger` | `no_token` 稳定发送 1 条消息 |
| fixed `5eaddcab...` | `run_success` | `no_trigger/no_trigger/no_trigger` | `no_token` 与 `foreign_token` 均拒绝，`correct_token` 保持有效 |
| patched synthetic `04a7c94f...` | `run_success` | `no_trigger/no_trigger/no_trigger` | 上游 fix patch 重放后攻击稳定拒绝 |

- `validation_gate=passed`
- `gate_reason=component harness controls passed; product reachability remains unproven`
- `docker_exit_code=0`
- Worker 墙钟：`48.76 s`
- Patch SHA-256：`3ac3ed31c2324061e5227523c2cb4038446a292be2b11164906f5f03f4256d0e`
- `validated_vulnerability=0`：组件 Harness 能复现/修复，但真实产品入口、权限边界和可利用性仍未建立。

## 5. 发现与风险

### F-01：组件级动态 gate 已通过，但产品可达性仍未知（高）

Docker Worker 已稳定复现 vulnerable attack，并验证 fixed/patched 对攻击稳定拒绝；组件 Harness gate 通过。仍不能确认非特权或无关进程能够取得 callback handle、跨过权限边界并造成产品级 CIA 影响，因此 `validated_vulnerability` 保持 `0`，不能升级为 reportable。

### F-02：owner IPC 回归脚本依赖未入库输入（中）

执行：

```text
python -m scripts.verify_owner_ipc_components \
  --baseline-dir outputs/reports/m1_descriptor_identity
```

实际失败于：

```text
FileNotFoundError: outputs/reports/m1_descriptor_identity/outputs/reports/update_updateservice.json
```

该脚本依赖历史基线 JSON/manifest，当前源码 checkout 不包含这些输入。因此“五组件 owner IPC 对照”不能在干净 checkout 上独立复现；不能把文档中的历史候选数当成本轮验证结果。

### F-03：依赖安装耗时与 npm 策略告警（中）

`npm ci` 在本机耗时 458.07 s，并报告 `esbuild@0.25.12` 的 postinstall 未被 allowScripts 覆盖。构建本身通过，但 CI 的 Node 22 与本机 Node 26/npm 11.19 不完全相同，环境复现时应固定 Node/npm 版本并审查构建脚本策略。

### F-04：外部研究工具未执行（低，范围外）

CodeQL、Joern、Semgrep、Docker 不在当前环境；这些属于历史/研究对照或动态验证基础设施，不在生产自研检测路径。不能用“未执行”推断为 miss、安全或准确率结果。

## 6. 证据完整性

以下 SHA-256 绑定本轮关键本地产物；原始产物位于 `outputs/logs/full-audit-20261014/main/`，该目录是生成实验产物，不纳入提交：

| 产物 | SHA-256 |
|---|---|
| `pip_install.stderr.txt` | `4AE2A92F79D5139D94BC7556DBC3E5A203B95AA19BB8CF8EDA0922495290603F` |
| `compileall.stderr.txt` | `D9B48EDEF1B32531321E2819E76BADEA1787DD6CAD162CA0B5313FA051A795F7` |
| `unittest.stderr.txt` | `6E6AE29094AC71B9459EE2A8719AF9019ECFA9C92E3C3F839D6CB7D7BBB3AFAE` |
| `perf-run1/perf_scale_scan.json` | `E72FCBA3806B3991067BD6A6451D55D1B18EF46CCDCF7262D87CDC604435D67B` |
| `perf-run2/perf_scale_scan.json` | `6B5AF2C9EB9B6F9AF10E1152F7390F3E460F9321CE648D37952568BE2069B987` |
| `verify_workbench.stdout.txt` | `A9C11C3234CC25FA504ED737D757C41BE47197519DAE5988D2F3803257CEBA6D` |
| `cli/all_detectors.json` | `C489F263B8342B5C5500059D3D5CC5B79A0D6948EA3DEE0ECB160EC0B4373DD2` |
| `cli/historical_cutils.json` | `A04B38A1BDC56C00F16C876EE774987D18313951FDC40A16881C1EAEBFA1F253` |
| `npm_ci_node26.txt` | `125CCC096E0B50D61BC2CCE749CE7271D2531D30B85FDA7686A5EA645BA3568F` |
| `npm_build_node26.txt` | `120A45E3854BFA9273B699AEB14D8FEB26F4178443F6999DF8F8AC15342140C5` |
| `container-setup/docker-build-fixed.log` | `4B798CEC72C64B771E9F1C8E5F93D3EB488319D5AFA015D3DA3C84ECDE5847E7` |
| `container-setup/docker-sanitizer-smoke.log` | `1763C171641A46529ABEA142BB78F328F8E74AC9E2937862E2BEFD5744BE3B4B` |
| `container-setup/podman-build.log` | `59B24B7A053683E54FD72914CF373F996AD44E39930EBE3F42F412E4DDD7551A` |
| `container-setup/podman-sanitizer-smoke-noleak.log` | `1763C171641A46529ABEA142BB78F328F8E74AC9E2937862E2BEFD5744BE3B4B` |
| `container-setup/auth01-worker-4/worker-result.json` | `3B2D187F178EB70715A915B786281BC1248A113C8AB5E00DA3A6190BE2EC31A7` |
| `container-setup/postfix-unittest.stderr.txt` | `3A61B45B3681352DD732175A25E12683526250CBD97C0AC1383E62F9BA03D22E` |

## 7. 可复现命令

```bash
python -m pip install -r requirements-web.txt
python -m compileall -q src tests scripts research
python -m unittest discover -s tests -v
npm ci
npm run build

python -m src.cli ohscan \
  --fixture-root tests/fixtures/ohscanner

python -m src.cli ohscan-index \
  --repo-dir /home/audit/openharmony-targets/commonlibrary_c_utils \
  --repository openharmony/commonlibrary_c_utils \
  --commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2

python -m src.cli ohscan-run \
  --repo-dir /home/audit/openharmony-targets/commonlibrary_c_utils \
  --repository openharmony/commonlibrary_c_utils \
  --commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2 \
  --detector ohscanner.cpp.lifetime \
  --detector ohscanner.cpp.shared_ptr_race \
  --detector ohscanner.interface.ipc

python -m scripts.verify_workbench \
  --repo-dir /home/audit/openharmony-targets/commonlibrary_c_utils \
  --repository openharmony/commonlibrary_c_utils \
  --commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2 \
  --data-dir /tmp/ohscanner-main-audit-verify

python scripts/perf_scale_scan.py \
  --manifest benchmarks/perf_scale_corpus_2026-10-10.json \
  --python .venv-web/bin/python \
  --json-out outputs/reports/perf_scale_scan.json \
  --md-out outputs/reports/perf_scale_scan.md
```

## 8. 配套文档

低认知负荷版本：`research/audit/ohscanner_runtime_performance_human_review_2026-10-14.md`。

## 9. 审查判定

- 本轮可以确认：**代码可编译、现有测试可运行、Web 可构建、核心 CLI/Workbench 生产执行路径可运行、固定语料性能可重复**。
- 本轮不能确认：**产品入口/权限可达性、五组件 owner IPC 历史基线对照、外部工具准确率**。
- 因此本报告的最终状态是：**工程运行验证与组件级 Docker 动态 gate 通过，竞赛级产品可达性/历史证据闭环仍未完成**。

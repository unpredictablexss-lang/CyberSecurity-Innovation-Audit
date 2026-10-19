# 队友 D：第一阶段验收文档

日期：2026-10-17。用途：供用户和项目负责人核对本地交付，不替代正式审查或上线验收。

## 一、先看结论

**第一阶段的本地工程原型、合成样例验证、固定真实源码小范围复测和交付材料已完成；真实漏洞有效性验收与平台正式接入尚未完成。**

已经有一个能运行的检测器，不是只有研究方案。它研究“敏感材料如何经局部变量、复制和格式化进入公开日志”，但没有确认真实漏洞，也没有证明检测准确率。

| 核对项 | 当前事实 |
|---|---|
| 拟议检测器 ID | `ohscanner.data.sensitive_exposure`，等待负责人确认 |
| 唯一首发规则 | `data.log.sensitive-value`，版本 `0.1.0` |
| 初步分类 | `CWE-532`，仅作候选分类，不关联猜测的 CVE |
| 分析语言 | Native C/C++ |
| 传播范围 | 同函数内受限语法依赖；不是全程序污点分析 |
| 合成控制 | 32 个，均符合当前测试预期；不是独立 holdout |
| D 新增测试 | 10 个 unittest 方法，包含对 32 个控制的逐项检查 |
| 全项目回归 | 522 项：511 通过、11 跳过，0 失败、0 错误 |
| 真实源码复测 | 固定官方组织仓库提交、指定 9 文件、两次运行一致 |
| 真实结果 | 0 候选；complete 0、partial 3、not_analyzed 6、failed 0 |
| 已确认真实漏洞 | 0 |
| 面板接入 | 未接入，不能在现有面板直接选择 D |
| Git 提交/推送/PR | 本记录完成时尚未发布；后续以草稿 PR 与实际提交回执为准 |

11 项跳过来自缺少历史源码/固定来源库、性能语料，以及必须由 Docker Worker 执行的既有测试；不是 11 项 D 新功能测试被跳过。逐项原因记录在 `research/data_sensitive/validation.json`。

## 二、成果在哪里

### 2.1 独立工作区

```text
/home/lzc/projects/OHScanner-teammate-D
```

开发分支：

```text
feat/teammate-d-sensitive-exposure-20261017
```

固定开发基线：

```text
e510c99c67f31ec6c73365f9ab749c79ca6ff0a1
```

这是基线 SHA，不是 D 新功能已提交后的 SHA。D 的改动目前仍在工作区中。

Windows 文件资源管理器地址：

```text
\\wsl$\Ubuntu-22.04\home\lzc\projects\OHScanner-teammate-D
```

原 B/main 工作区和此前的版本矩阵表单修复保留在 `/home/lzc/projects/CyberSecurity-Innovation-Audit`。本轮没有覆盖它们，也没有重新启动已停止的面板。

### 2.2 关键文件

以下路径均相对于 D 工作区：

| 文件 | 查看目的 |
|---|---|
| `src/ohscanner/detectors/data/models.py` | 敏感来源、日志出口与适用版本模型 |
| `src/ohscanner/detectors/data/sensitive_exposure.py` | 检测算法及真实 Detector 接口 |
| `src/ohscanner/detectors/data/README.md` | 接入方法、运行方式和能力边界 |
| `tests/fixtures/data_sensitive/cases.json` | 32 个合成控制的预期结果与分组 |
| `tests/fixtures/data_sensitive/*.cpp` | 正例、修正/安全/非目标、未知场景代码 |
| `tests/detectors/data/test_sensitive_exposure.py` | 自动化测试与真实 Runner 适配验证 |
| `research/data_sensitive/source_manifest.json` | 来源 commit、blob、文件哈希和大小 |
| `research/data_sensitive/source_locations.json` | 研究依据的源码符号与精确行号 |
| `research/data_sensitive/replay.py` | 离线固定 Git 对象实验入口，不是另建生产 CLI |
| `research/data_sensitive/validation.json` | 实际测试计数、跳过原因和日志哈希 |
| `research/data_sensitive/fixed_scope_summary.json` | 真实复测范围、覆盖、性能和报告哈希 |
| `research/data_sensitive/D_REVIEW.md` | 详细研发审查说明 |
| `research/data_sensitive/D_LIMITATIONS.md` | 已知局限与未完成项 |
| `research/data_sensitive/DRAFT_PR_BODY.md` | 尚未发布的草稿 PR 文案 |

原始大报告和日志留在本地 `outputs/`；第三方源码留在缓存或外部只读 Git 对象库，未打入原创代码交付包。

## 三、目前究竟能检测什么

### 3.1 检测流程

```text
固定仓库及提交
    ↓
识别经过研究的敏感材料来源
    ↓
追踪同函数局部赋值、复制、格式化
    ↓
将日志占位符逐个对应到真实参数
    ↓
发现敏感材料进入显式 public 的日志操作数
    ↓
输出候选、源码 SHA、传播线索和待核查条件
```

例如以下是示意性的合成场景，并非真实漏洞报告：

```cpp
void Example(SessionKey *item)
{
    const char *alias = (const char *)item->value;
    AUTH_LOGE(AUTH_KEY, "%{public}s", alias);
}
```

检测器会尝试关联 `SessionKey.value → alias → 公开日志参数`。类型身份、初始化、执行可达性、生产日志配置及读取权限仍需核查。

### 3.2 已支持的来源和传播

- 研究建模的材料字段：`SessionKey.value`、三类 AES 密钥结构的 `.key`，不把 `.len`、`.keyLen` 或 `.iv` 一起算作密钥材料。
- 受审范围内 `SoftBusGenerateSessionKey` 的输出缓冲区，与其状态返回值分开。
- 固定文件中 `OnSessionKeyReturned` 回调的特定形参，不能把任意同名参数当作凭据。
- 受限局部赋值、别名、覆盖、`memcpy_s`/`strcpy_s`、`snprintf`/`snprintf_s` 的传播。
- 逐参数解析 `%{public}`/`%{private}`、部分 printf 转换与宽度/精度参数。
- 原始变量被常量覆盖、长度/状态/布尔结果等安全或非目标控制。

默认模型绑定到已研究仓库的精确提交。不能直接把任何项目、任何最新版本都当成支持对象；新增版本和来源模型必须重新审查。

### 3.3 主动保留未知的地方

循环、复杂指针/成员写入、跨函数调用、动态格式串、某些宏和 C++ 类型关系尚不完整。分支合并只是“可能传播”，不证明路径一定可执行。未知包装不自动当作脱敏函数。

private/default-private 参数不按“显式 public 敏感材料”规则报警，但运行时隐私配置仍需复核；因此“不报警”不等于已证明安全。

证据类型使用 `syntax`；链路表达局部语法依赖，不声称已经获得编译器级数据流、CFG 或产品可利用性证明。候选中不记录真实敏感值内容。

## 四、我们如何验证

### 4.1 32 个合成控制

覆盖直接输出、局部别名、复制、格式化、回调参数、生成密钥输出、变量覆盖、私有占位符、默认私有、字段混合、长度、状态码、布尔比较、注释、测试范围、函数与类型冒名、函数指针参数、未知转换、复杂格式、作用域和分支/循环等。

这些用例在开发和修复过程中被使用过，属于设计/回归集。即使全部通过，也不能据此报告 Precision、Recall 或真实漏洞检出率。

### 4.2 真实核心对接

测试实际使用项目的 SourceUnit、ScanContext、DetectorRegistry、Runner 和 v2 结果归一化，核对：

- 候选文件 SHA 与输入一致。
- 候选保持 `unassessed`，CWE 为初步分类。
- 证据义务能够进入现有结果侧车。
- 输入快照哈希被篡改时拒绝执行。
- 解析失败/部分解析不被当成完整安全分析。
- 重复运行结果确定。

没有伪造一个仅供测试使用的公共合同来绕过真实平台。

### 4.3 固定真实源码实验

目标：`openharmony/communication_dsoftbus` 的官方组织 GitHub 镜像对象。

```text
Commit: 0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132
Tree:   bd915661eedd139df17f249191e2a691e76f7565
```

日志 API 语义参考 `openharmony/hiviewdfx_hilog`：

```text
393d7e9a690edb76ed27e710b472623daf650dc8
```

选取 9 个来源/日志相关文件，扫描前核对其 Git blob 和 SHA-256，然后在同一提交、范围、模型下运行两次。候选身份和覆盖一致。

| 项目 | 结果 |
|---|---:|
| 纳入文件 | 9 |
| 完整分析 | 0 |
| 部分分析 | 3 |
| 未分析 | 6 |
| 分析失败 | 0 |
| 候选 | 0 |

3 个部分分析文件为 `auth_hichain.c`、`auth_hichain_adapter.c` 和 `auth_log.c`。另外 6 个文件被公共 Runner 的 AST 资格检查挡住，没有进入 D 算法。

这是一个有覆盖缺口的负结果。两次输出一致证明的是复跑一致性，不是算法改进，也不是无漏洞证明。耗时、峰值 RSS 和报告哈希以 `fixed_scope_summary.json` 的实际记录为准。

### 4.4 本机复现命令

在 Ubuntu 中执行：

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python

# D 专项测试：10 个方法，含 32 个控制的检查
$PY -m unittest tests.detectors.data.test_sensitive_exposure -v

# 固定真实 Git 对象的小范围复测
$PY -m research.data_sensitive.replay \
  --repo-dir /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git \
  --output-dir outputs/reports/d-sensitive

# 全项目回归
mkdir -p .tmp
TMPDIR="$PWD/.tmp" $PY -m unittest discover -s tests -v
```

新机器需要重新安装依赖并获取精确源码对象；上述路径只是当前本机路径。

## 五、用户验收核对表

| 核对项 | 怎么看 | 当前状态 |
|---|---|---|
| 确有检测代码 | 打开 sensitive_exposure.py | 已有 |
| 不是关键字报警 | 看 metadata/status/keyword 对照 | 已有回归 |
| 有传播链 | 看 alias/copy/format 正例及输出消息 | 已有 |
| 有修正和安全对照 | 看 private_fixed、overwrite_safe 等 | 已有，仍受语义边界限制 |
| 同名 API 不误当日志 | 看函数定义/函数指针/限定调用控制 | 已有受限处理 |
| 未知没有当安全 | 看 partial、not_analyzed 和义务 | 已记录 |
| 真正调用公共 Runner | 看实际对接测试和 replay.py | 已验证 |
| 真实源码有固定身份 | 看 source_manifest 与 scope summary | 已验证指定范围 |
| 真实危险日志实例 | 必须有敏感来源与暴露证据 | 尚未建立 |
| 官方漏洞修复对 | 有来源的修改前后样本 | 尚未取得 |
| 独立 holdout | 未参与设计调参的独立标注数据 | 尚未执行 |
| 产品级泄露影响 | 量产配置、读取权限和实际影响 | 尚未证明 |
| 面板和 Catalog | 由负责人批准选择性接入 | 尚未接入 |

前三类本地工程交付已具备，但后面真实有效性和集成条件未完成，因此当前不应称“D 已正式上线”或“已确认信息泄露漏洞”。

## 六、验收结论与待确认事项

本地第一阶段原型、合成控制、实际核心对接和固定源码小范围复测已完成，具备代码审查条件。
尚未完成真实漏洞有效性验证、独立 holdout、负责人 ID/模型确认、正式平台注册和远端提交。
本文件记录实际交付，不表示已获负责人验收。

后续研究步骤另见`research_plan_zh.md`；接口申请另见`interface_requirements_zh.md`。

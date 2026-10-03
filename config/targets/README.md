# Target 配置目录

本目录用于保存真实 OpenHarmony 组件的 `TargetSnapshot v0` 配置。

当前项目处于 MVP 候选扫描器之后的真实组件 onboarding 阶段。这里的配置只记录：

- 扫描哪个仓库；
- 使用哪个 commit；
- 扫描哪些源码路径；
- 如何构建；
- 如何运行测试；
- 当前证据状态是什么。

不要把完整 OpenHarmony 源码、构建产物、PoC 运行日志、二进制文件放进本仓库。真实目标源码建议放在：

```text
/home/audit/openharmony-targets/<component>/
```

本目录只保存轻量配置和可复现元数据。

---

## 字段状态约定

如果没有实际运行命令，不要写 `yes`。

建议状态值：

```text
unknown
not_started
in_progress
success
failed
blocked
not_applicable
```

例如：

```yaml
build:
  status: unknown
```

只有执行过构建命令并保存结果后，才能改成：

```yaml
build:
  status: success
```

或：

```yaml
build:
  status: failed
  failure_reason: missing dependency: xxx
```

---

## 当前流程

1. 先在 `docs/targets/target_selection.md` 中筛选 3 个候选组件；
2. 选出主目标后，复制 `template.yaml` 为 `<component>.yaml`；
3. 填入 repo、commit、source paths、build/test 命令；
4. 本地真实执行构建和扫描；
5. 将实际结果回填到该 target config；
6. 再进入 candidate triage、ASan/UBSan 验证和报告。

# Ground Truth：c_utils singleton.h UAF（第一方历史安全修复样本）

> 这是 P1 阶段找到的第一个 OpenHarmony 第一方历史安全修复样本，用作工具能力的 ground truth 与 Benchmark 真阳性样本。

## 漏洞概要

| 项 | 值 |
|---|---|
| 组件 | commonlibrary_c_utils（OpenHarmony 第一方 C++ 基础库） |
| 漏洞类型 | UAF（CWE-416，并发数据竞争导致 use-after-free） |
| 位置 | base/include/singleton.h：`DelayedSingleton<T>::GetInstance()` / `DestroyInstance()` |
| 修复 commit | 9a3f281120307ec7dcce17fae882dcc4e6a6f4d7 |
| 修复前 commit | bdfafdaafddb01ab7ae13354ce2ada9555d7935c |
| Issue | gitcode.com/openharmony/commonlibrary_c_utils/issues/560 |
| PR | #586 |
| 作者 | xingzeng（xingzeng2@huawei.com） |
| 合入日期 | 2026-01-13 |

本地 c_utils 固定 HEAD `3bdc11e` 已包含此修复（singleton.h 已使用 `atomic_load/atomic_store`）。

## 漏洞机理

`DelayedSingleton` 用 `std::shared_ptr<T> instance_` 保存单例。修复前：

- `GetInstance()` 里 `return instance_;` 是对 shared_ptr 的**非原子**拷贝读；
- `DestroyInstance()` 里 `instance_.reset()` 是**非原子**写（refcount 归零后 delete T）。

高并发下，一个线程的 `return instance_`（读出 instance_ 的裸指针后、递增 refcount 前）与另一线程的 `reset()`（refcount 归零、delete T）竞争，导致前者返回指向已释放 T 的 shared_ptr → UAF。

## 修复前 vs 修复后

修复前（bdfafdaa）：

~~~cpp
template<typename T>
std::shared_ptr<T> DelayedSingleton<T>::GetInstance()
{
    if (instance_ == nullptr) {              // 无锁读
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            std::shared_ptr<T> temp(new (std::nothrow) T);
            instance_ = temp;                // 非原子写
        }
    }
    return instance_;                        // 非原子读，与 reset 竞争
}

template<typename T>
void DelayedSingleton<T>::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ != nullptr) {
        instance_.reset();                   // refcount 归零 + delete T
        instance_ = nullptr;
    }
}
~~~

修复后（9a3f2811）：

~~~cpp
template<typename T>
std::shared_ptr<T> DelayedSingleton<T>::GetInstance()
{
    std::shared_ptr<T> ptr = atomic_load(&instance_);   // 原子读
    if (ptr != nullptr) {
        return ptr;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (atomic_load(&instance_) == nullptr) {
        std::shared_ptr<T> temp(new (std::nothrow) T);
        atomic_store(&instance_, temp);                 // 原子写
    }
    return atomic_load(&instance_);                     // 原子读
}

template<typename T>
void DelayedSingleton<T>::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    atomic_store(&instance_, std::shared_ptr<T>(nullptr));  // 原子写
}
~~~

修复用 `<atomic>` 的 free function `atomic_load` / `atomic_store`（对 shared_ptr 有特化）替代对 `instance_` 的非原子读写。

## 作为 ground truth 的用途

1. **验证工具能力**：测试本项目 scanner/triage 能否发现此 UAF。预期：文本 scanner（5 个危险 API 正则）**无法发现**——它不是危险 API 调用，而是 shared_ptr 的并发数据竞争。这暴露了当前工具的真实盲区。
2. **PoC 管线验证**：用修复前 commit（bdfafdaa）+ 多线程 harness + TSan 复现，验证 PoC/验证管线对真 UAF 有效（比 cJSON allocator 失败更有说服力）。
3. **Benchmark 真阳性**：作为已知真阳性样本，衡量后续生命周期/并发分析能力的召回率。

## 对工具能力的要求

这个 UAF 需要的检测手段（当前都不具备）：

- 生命周期分析（识别 shared_ptr 非原子读写）；
- TSan 动态检测（数据竞争 → UAF）；
- 或并发语义理解（识别 lock 保护范围外对共享对象的访问）。

这指向后续的生命周期/并发分析方向，而不是简单堆危险 API 规则。

## 官方措辞观察

Issue 类型经历了 需求→缺陷→安全漏洞→缺陷 的反复，标题从 "UAF 漏洞风险" 改为 "UAF 风险"。说明官方对这个并发 UAF 是否构成可利用安全漏洞持谨慎态度（触发窗口极小、需高并发）。这提示：即便用 TSan 复现，也要谨慎评估其"真实安全影响"，避免把无实际危害的竞态当作高价值漏洞报告（赛题明确不鼓励无实际安全危害的问题）。

## 下一步

1. 在本地 checkout 修复前 commit bdfafdaa，编写多线程 harness（GetInstance 与 DestroyInstance 并发），用 TSan 复现数据竞争/UAF。
2. 确认 scanner/triage 对此样本的输出（预期 0 候选），记录为工具盲区的量化证据。
3. 若时间允许，把这个 UAF 抽象成一条"shared_ptr 非原子读写"规则或生命周期分析目标，纳入 P2 的 AST/生命周期分析。

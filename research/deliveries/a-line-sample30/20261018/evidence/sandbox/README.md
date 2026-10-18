# 沙箱方法与控制说明

所有动态结果均来自固定 Docker 镜像 `sha256:e92d5365460142169ddd21d489bc9157d003c61e3382351c8f8516f3e38f96ae`，容器使用无网络、只读根文件系统、cap-drop ALL、no-new-privileges 和 CPU/内存/进程/时间限制；仅 `/sandbox/out` 可写。

- `copy_range_model.cpp`：从 `communication_wifi` 的 `RemoteOnConfigChanged` 提取 guard 与容量关系的缩约源码模型。攻击长度被拒绝，合法长度成功，ASan/UBSan 三次重放无发现。
- `copy_range_unsafe_control.cpp`：故意缺少上限 guard 的 ASan 阳性控制，三次稳定报告 heap-buffer-overflow。
- `copy_range_safe_control.cpp`：容量匹配的安全控制，三次稳定干净。
- `shared_ptr_tsan_unsafe_control.cpp` / `shared_ptr_tsan_atomic_control.cpp`：generic TSan 阳性/固定控制，三次分别稳定报告数据竞争/干净。

这些控制不是任何被抽样组件的 product PoC。完整 argv、退出码、日志和哈希见 `sandbox_results.json`、`scratch/`、`sandbox_file_hashes.json`。

# D 线第 13 轮：D97/T96 switch 同目标分支合流

D97/T96 在 owner 分支集成。规则0.21.12仅对完整 AST、无预处理、显式 default、每个平面 arm 都将同一指针直接赋值到同一目标并以直接 break 结束的有限形状，合并成精确的同一目标。其它控制流仍保持 unresolved/may-flow。

T96 最初发现 3 个同目标分支控制被保守报为 unresolved，D97 对窄形状完成合流；又发现 partial header 在 Runner 过滤后导致 exact-join guard 与 direct 不一致，开发修订为使用完整 selected scope 校验，修订后 direct/Runner 一致保留 unknown。开发 data 298/298、兼容性62/62；T96独立14项及data312项通过；owner最终data312/312、兼容性62/62。

固定 T85 direct/Runner 仍24条；24条共同ID/message/evidence、638个raw call facts、890/915均不变；三文件仍analysis-partial。coverage差异为detector版本0.21.11→0.21.12字段变化。T96另明确记录 all-return switch 后不可达语句仍被扫描的过候选，状态 `known_gap_not_passed`，未冒充通过。

实现 `ae71c3c8e099c42b1d5df81b1fe9c32cddd2a39a`，selected-scope修订 `4958df655f86c1199bc326138aaf3b4ecaf9587e`，T96独立提交 `f0afee276b1330a94c222bfc3e8e0e136b021598`。D98/T97已启动，专门检查可证明的 all-return 后不可达路径。

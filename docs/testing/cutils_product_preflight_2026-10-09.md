# c_utils 产品配置实验准备与官方入口探测

日期：2026-10-09。分支：`experiment/cutils-product-scan`，基于试点提交 d4570db。
本轮是产品配置 preflight，不是产品扫描验收。历史 PR #4 仍为 draft。

## 实验输入与版本来源

当前工程基线保留四个历史修复对、八个版本单元，以及 c_utils 完整 C/C++ 范围
123 个文件。它足以检查证据绑定、修复对照、工具执行和覆盖记录，不足以评价检测
准确率/误报率，也不是具有完整人工标签的漏洞数据集。本轮没有增加漏洞样本。

官方 manifest 默认来源为 GitCode，固定 manifest 提交
0bc9850031fbe7c20f686cf10206dcf99931a5bc。解析 default.xml 及其包含文件共七份 XML 后，
得到 525 个项目声明；这是 manifest 项目数，不意味着一个 c_utils 实验必须下载全部项目。
以组件 README 的 rk3568 示例作为参考产品，原始配置指定 standard / arm。

从 manifest 指定的 GitCode master 捕获八个项目 ref，形成**部分项目锁**：

| 项目 | 固定提交 |
|---|---|
| build | a2b72e827add764f6312e00173dff0dd3db45e75 |
| commonlibrary_c_utils | 4528aa241f3ad88cee552500f2706f0a745e0fc9 |
| third_party_bounds_checking_function | 2ae82839ecaaa7d031e66ccbd2076d671acfd615 |
| hiviewdfx_hilog | d1cae50959fb23b50f932ad1ef6ed00ba1f080a5 |
| third_party_rust_cxx | 838c2274fe36df840031993db258bdcfdd5b7098 |
| vendor_hihope | 480fc8c7eb815855eb4265ebf2771fea5fc89baa |
| device_board_hihope | 5d368fb765920c2b1cad41eb86164563461a7074 |
| device_soc_rockchip | 0aa6ba16f89844023137fb84ac03189b30c8780b |

每个解析结果保留声明 remote/revision、实际查询 ref、命令和原始输出。master 是浮动
分支，以上是独立捕获的提交，不是官方发行版兼容性保证，也不是完整的传递依赖锁。
项目 ref 解析成功不等于其源码已经下载：实际准备了 manifest、build、c_utils、vendor
四份完整 Git 快照，其余五个选定项目尚未装入探测工作区。

GitHub 镜像与 GitCode 的 commit 不同。逐文件 hash 核验发现，GitCode c_utils
4528aa2 与此前 GitHub b807d3d 的 C/C++ 文件全部一致，仓库差异仅在 .gitattributes。
此前轻量和 host 结果仍保留原始 commit/profile，未改标签冒充新的产品配置运行。

## 官方入口实际结果

按 manifest linkfile 声明生成真实 build.sh、build.py 和 .gn 链接，把固定 build、
c_utils、vendor 源码装入独立工作区，执行官方入口：

```bash
bash build.sh --product-name rk3568 \
  --build-target commonlibrary/c_utils/base:utilsbase \
  --build-only-gn --gn-flags=--export-compile-commands
```

结果为 blocked。预编译 Python 路径缺失，官方脚本随后回落到系统 /bin/python3，
最后因找不到要求的 Node.js 14.21.1 而退出；尚未执行 GN 生成，没有真实
compile_commands.json。未进入对象编译、链接或运行阶段。

固定 build 的预编译配置还声明 Python 3.12.10、GN、Ninja 1.13.2 等工具。
产品继承文件 productdefine/common/inherit/rich.json 和 chipset_common.json 未就绪；
五个选定源码项目及完整传递依赖也未就绪。不能仅安装 Node 后就声称产品环境打通。

首次入口探测暴露了官方脚本的副作用：当预编译 Python realpath 为空时，它可能创建
/bin/python → /bin/python3。已核对并移除此次新建软链，恢复原状；组件源码未修改。
后续探测在 private mount namespace 中将 /usr 和 /root 绑定为只读，同时限定为
Node 缺失的前置检查，不允许进入后续 npm/ohpm 初始化。隔离不可用时不退回裸执行。
隔离重跑仍得到相同环境阻塞，并确认系统 Python 软链没有再次改变。

## 组件级官方路径

build/indep_component_whitelist.json 包含 c_utils，并允许参考产品 rk3568。
官方 indep_build 参数包含 --part、--target-os、--target-cpu、--gn-flags、
--skip-download 和 --skip-prebuilts。这为组件级 GN 实验提供了可研究的路径。

当前独立构建状态仍为 not_run。它还依赖 HPM/package 输入和工具链，必须固定这些
输入并验证与 Git 源码/产品配置的关系，不能因为进入白名单就宣称可独立编译。
下一阶段优先核对这条较小的闭包，再决定是否需要扩大产品源码范围。

## 复跑与验证

源码位于审计仓库之外。快照准备脚本读取本地固定 Git 对象，Git 锁解析脚本显式联网；
归一化和源码映射不隐式下载。partial_lock.json、执行日志和 preflight_isolated.json
保存在 outputs/reports/product_experiment，已加入 Git 忽略。

```bash
python -m scripts.prepare_product_lock \
  --manifest-snapshot /path/to/verified/manifest-snapshot \
  --output outputs/reports/product_experiment/partial_lock.json
python -m scripts.probe_product_configuration \
  --lock outputs/reports/product_experiment/partial_lock.json \
  --snapshots /path/to/build-snapshot /path/to/cutils-snapshot /path/to/vendor-snapshot \
  --workspace /path/to/new/product-workspace \
  --output outputs/reports/product_experiment/preflight.json
python -m unittest discover -s tests -q
```

探测脚本要求 Linux mount namespace 权限、一个新的工作区，以及缺失 Node 的环境。
这是受限的前置条件探测命令，不是未来完整构建的通用启动器。
复现本轮需获取表中的固定 SHA 并使用本轮捕获锁；重新解析 master 会形成新的捕获
时间和可能不同的版本，不能自动当成本轮的重复实验。
完整回归 172 项通过，新增 XML 包含/路径/实体、项目歧义、镜像来源混用、ref 绑定、
缺工具状态，以及只读隔离阻止写入的回归。validated_vulnerability=0，动态验证 not_run。

下一步是组件独立构建的依赖/package 固定与最小工具链准备；若该路径不适合当前源码，
保留失败证据再扩大 rk3568 产品配置闭包。产品级扫描尚未开始，已有 host 实验仍有效。

## 后续核验：远端更新与声明依赖库存

main 的 5bec804 已合并历史基线；历史分支截至 35eee72 新增五个路径校验提交。
已引入实验分支，修改限定 historical.py、report_inputs.py 和对应回归，无冲突。
与 main 的 src/tests 差异仅保留组件实验功能及 CodeQL evidence_type 修正。
没有合并 main 或改变上游分支；历史安全边界已同步。回归从 172 增至 174。

按此前捕获的官方锁拉取三项直接依赖，没有重新解析 master 替换旧 SHA：

| 项目 | 完整固定 SHA | 源码准备结果 |
|---|---|---|
| bounds_checking_function | 2ae82839ecaaa7d031e66ccbd2076d671acfd615 | 56 文件完整快照通过 |
| hilog | d1cae50959fb23b50f932ad1ef6ed00ba1f080a5 | 195 文件完整快照通过 |
| rust_cxx | 838c2274fe36df840031993db258bdcfdd5b7098 | Git 对象已拉取；18 软链接、1 子模块，快照工具拒绝 |

源码位于 E:/网安/_product_targets；前两项验证快照位于
/root/bench-scan/product-experiment/securec-2ae8283 和 hilog-d1cae50。
rust_cxx 未生成 snapshot.json，没有把软链接当普通文件或跳过子模块宣称完整。

新增库存命令验证快照及官方锁的 commit/origin，读取 bundle.json，输出声明依赖边、
每项输入的 commit/tree/bundle hash，保留 hilog → c_utils 的循环并终止遍历。
不执行 bundle 的 install 脚本，不调用 HPM。复跑：

```bash
python -m scripts.inventory_component_dependencies \
  --lock outputs/reports/product_experiment/partial_lock.json \
  --snapshots /root/bench-scan/product-experiment/cutils-4528aa2 \
    /root/bench-scan/product-experiment/securec-2ae8283 \
    /root/bench-scan/product-experiment/hilog-d1cae50 \
  --output outputs/reports/product_experiment/dependency_inventory.json
```

输出 incomplete，未解析 cJSON、ffrt、init、napi、runtime_core、rust_cxx、zlib。
其中前六个非 rust_cxx 项来自 hilog 的声明；不代表 utilsbase 的 GN target 一定需要
全部组件，也不代表声明列表就是完整工具链/二进制闭包。包版本不是二进制来源锁。

固定 build 源码核验进一步发现：

- hb/services/hpm.py 的 run 先注册 HPM 再执行 build；注册阶段调用 hpm -V，
  并启动 npm search 查询。--skip-download 仅在后续 build 检查中起作用。
- indep_configs/scripts/generate_components.py 读取 dependences.json、
  binarys/variants/variants_<variant>/config/build_config.json，且在 main 中调用
  _link_kernel_binarys，直接索引 musl 和 linux 的安装路径。
- indep_configs/scripts/gn_ninja_cmd.py 的 _exec_cmd 在 GN 后继续启动 Ninja；
  不能把这一完整入口描述为只生成数据库的探测命令。

因此独立构建仍 not_run，GN 数据库仍 not_generated。下一步先核验所需 variant、
musl/Linux 与 HPM 二进制的来源、版本和校验值，以及软链接/子模块快照策略；再准备
工具链和限定 GN 阶段的执行方案。新增库存回归后完整测试 178/178 通过。

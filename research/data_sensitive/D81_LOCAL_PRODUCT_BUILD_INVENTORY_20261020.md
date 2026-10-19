# D81 本地产品构建证据清点

## 判定

本地材料能证明若干 HiHope **产品定义**继承的共享配置包含 `pasteboard`，也能证明 build 仓库存在相关白名单对象。当前证据不能确定某个具体产品实际执行过构建、包含了哪个 Pasteboard 源版本，或安装在设备上。D52 的目标产品身份及历史组件是否进入某个产品均为 **unknown**。

本清点按 D53/T53 冻结的四个源码仓库和 `D:/OpenHarmony807` 快照顶层进行有限范围复核。没有把产品配置推断成设备，也没有继续递归遍历整个源码镜像。

## 固定来源和身份复算

- D53 最终修订：commit `3f1c9aa72f245d7d7c6312970f2c3bdd11c3b8f2`，tree `394035ddd60cab02bb783437b20892cdadfdba68`。D53 JSON 的 Git 文件字节 SHA-256 为 `ad84f410fcecd34e10702842a768080b391510643b95593cb4afc41bb03120df`。
- T53 独立验收：commit `92844f7becbbd6dbf41584e1ce21a4c885352bb8`，tree `c5fc312a8c3a6276bc736967889e71eafb2fc1f2`。T53 报告 JSON SHA-256 `77fc96537c94e3345a1cceffd5f1a985595add9d4fd4843575e79ca5721b5d54`，Markdown SHA-256 `2872a421b381c459e1d410b71625a9299b7ac517979eb3ecad9c4a7ba2617a4e`。
- 本次脚本重新核验 D53 JSON 中全部 31 个文件：在固定 HEAD 上重算路径 blob OID，并从 `git cat-file blob` 原始字节计算长度和 SHA-256；同时重算四个仓库 HEAD/tree。复算为 **31/31 一致、0 mismatch**。
- D52 历史源码对象可在本地 `t56-miscservices-official.git` 找到：commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`，tree `e374a0d61c9ec664ddd29fc17002797828c480ee`；`services/zidl/src/pasteboard_service_stub.cpp` blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`，6,288 bytes，SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`。D52 历史仓与当前 `distributeddatamgr_pasteboard` 仓之间的迁移/祖先关系仍未验证。

四个当前源码配置快照为独立仓库 HEAD，并非经锁定 manifest 证明属于同一次产品构建：

| 仓库 | HEAD | Tree | 证据角色 |
|---|---|---|---|
| `distributeddatamgr_pasteboard` | `e73747b227104e6743e957ce31040edf58507221` | `4128cdf9ad11d393c30f2839f43419e97a5a466d` | 当前组件源码、SA/init 和 caller permission 实现 |
| `productdefine_common` | `c9317af4074bf0e445fe3fc3979e53c470687153` | `71f1c83472fbf4b0360bf9fbde23572c529cef21` | 共享产品继承模板 |
| `vendor_hihope` | `b40eabbe69943126c65df1f9ff28057f56e93e46` | `aa95785ef84ddde8d1c3622e2c2d80d6b388caeb` | HiHope 产品定义 |
| `build` | `6b6d6533967db07e8e7d40d140fc63d0faabacbd` | `d58b57c4bc6273a51e1822e2c2d80d6b388caeb` | 组件/编译白名单 |

> build tree 为 `d58b57c4bc6273a51e1822e2c2d80d6b388caeb`。此处仅列仓库固定身份，不表示发生过产品构建。

## HiHope 定义中的 Pasteboard 配置

D53 的 `vendor_hihope` 和 `productdefine_common` 快照记录了以下关系。`是`仅表示产品定义继承的模板在该固定源码中直接列有 `pasteboard`；不表示该产品实际构建或出货。

| 产品定义 | 类型 / board | 继承模板 | 模板直接含 Pasteboard |
|---|---|---|---|
| `2in1_core_system` | standard / rk3568 | `inherit/2in1.json` | 是 |
| `dayu210` | standard / rk3588 | `inherit/rich.json`, `inherit/chipset_common.json` | `rich` 是；`chipset_common` 否 |
| `default_core_system` | standard / rk3568 | `inherit/phone.json` | 是 |
| `rk3568` | standard / rk3568 | `inherit/rich.json`, `inherit/chipset_common.json` | `rich` 是；`chipset_common` 否 |
| `tablet_core_system` | standard / rk3568 | `inherit/tablet.json` | 是 |
| `wearable` | standard / rk3568 | `inherit/wearable.json` | 是 |
| `ipcamera_core_system` | standard / rk3568 | `inherit/ipcamera.json` | 否 |
| `rk3568_mini_system` | standard / rk3568 | `base/standard_system.json` | 否 |
| `tv` | standard / rk3568 | `inherit/tv.json` | 否 |
| `nearlink_dk_3863`, `nearlink_dk_3863_xts`, `nearlink_dk_3863_xts_minimal`, `neptune_iotlink_demo` | mini / 对应 board | 无 | 无继承模板 |

D53/T53 还绑定了 `build` 仓库中的 `indep_component_whitelist.json`（blob `79cef6d85e2566920f2971aab222121910c912f1`）和 `component_compilation_whitelist.json`（blob `832084097de2dd4e6a14dce2246e83668f1f5a86`）。这证明 build 元数据认识 Pasteboard 组件和若干相关 target；它们不是成功执行的产品 target/action/build log。

## 实际构建、镜像和设备证据

`D:/OpenHarmony807` 顶层观察到 `repos`、`logs`、`scan-results`、三个官方源码裸仓、`gitcode-807.xml`、`progress.json` 和 `projects.csv`。顶层没有 `out`、`output`、`images` 或设备记录目录；D53/T53 同样记录未找到产品 image、build output manifest、产品 fingerprint 或 installed-device 记录。

| 所需对象 | 当前本地证据 | 判定 |
|---|---|---|
| 唯一型号/产品名与 release/build ID | 多个互不唯一的 HiHope 配置定义 | 缺失 |
| 锁定产品 manifest，能绑定四仓到一次构建 | 各仓固定 HEAD/tree，但没有同次构建 manifest | 缺失 |
| 产品构建 fingerprint / build.prop | 未发现具名产品构建记录 | 缺失 |
| 产品 image/OTA 与哈希 | 未发现能绑定产品/构建身份的 image 或 OTA | 缺失 |
| 成功 GN/Ninja 构建输出、target/action、args | 只有源码配置与白名单；无已核验产品构建日志/输出 | 缺失 |
| 安装到设备的记录及设备侧版本 | 未发现 | 缺失 |
| D52 历史源版本对产品构建的纳入关系 | 有历史源码 commit/blob；无构建映射，迁移关系也未证 | 缺失 |

`scan-results/build/report.md` SHA-256 为 `9db6c5c40fd86718b6a7bae206a4321562207808f3b533b4de4067969ae8fcaa`。报告称 C/D 被阻止且非 production enabled，并将结果限定为 research candidates；它不是产品构建产物。

## 最强可支持结论与 source-only 目标

可支持的最强结论是：这些固定的 HiHope 产品定义中有多个继承配置列入当前 Pasteboard 组件，build 仓库也含相关白名单元数据；具体产品构建、安装状态、所含组件版本以及 D52 历史代码是否在产品中均未知。因此保留 `D52 target product = unknown`，不升格为产品漏洞结论。

若后续工作需要一个可复现的源码配置研究目标，可显式命名为 **SOURCE_ONLY**：`vendor_hihope@b40eabbe69943126c65df1f9ff28057f56e93e46:rk3568/config.json` + `productdefine_common@c9317af4074bf0e445fe3fc3979e53c470687153:inherit/rich.json` + `distributeddatamgr_pasteboard@e73747b227104e6743e957ce31040edf58507221`。该组合用于研究当前源码与定义关联，仓库并未通过一个锁定产品 manifest 绑定；它不代表实际设备、发行版本或产品构建，也不能证明 D52 历史源码被其包含。

## 复现

在本工作树根目录运行：

```powershell
python scripts/research/build_d81_product_inventory.py
python -m json.tool research/data_sensitive/D81_LOCAL_PRODUCT_BUILD_INVENTORY_20261020.json
```

脚本会验证四仓固定 HEAD/tree 和 D53 清单全部 31 个 raw Git blob 的 OID、字节数、SHA-256，然后重建机器清单。相关只读人工复现命令：

```powershell
Get-ChildItem D:\OpenHarmony807 -Force
git -C D:\OpenHarmony807\repos\distributeddatamgr_pasteboard rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\repos\productdefine_common rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\repos\vendor_hihope rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\repos\build rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\t56-miscservices-official.git cat-file -t dd22c7cb5e5f207a6c38c50f45b7369ee8575840
```

范围是本地 D53/T53 冻结证据、上述四个源码仓和 `D:/OpenHarmony807` 顶层产品构建目录/记录检查。未检查任何外部设备或构建服务；未修改 scanner/product code。

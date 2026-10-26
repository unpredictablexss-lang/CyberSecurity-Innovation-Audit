# 产品侧上下文（source-level，不是产品验证）

这些事实用于说明"该缺陷所在组件会不会进入产品"，不构成任何运行时验证。
来源：2026-10-20 从 OpenHarmony `master` manifest 部分同步的源码树（`vendor/ohemu`、`productdefine`），
同步在组件级工作开始时被中止，因此该树**不是**一次完整、干净的构建输入。

## 1. DataShare ability 声明与权限

`applications/standard/contacts_data/entry/src/main/module.json`：

```json
{
  "name": "ContactsDataAbility",
  "srcEntrance": "./ets/DataShareExtAbility/DataShareExtAbility.ts",
  "readPermission": "ohos.permission.READ_CONTACTS",
  "writePermission": "ohos.permission.WRITE_CONTACTS",
  "type": "dataShare",
  "uri": "datashare://com.ohos.contactsdataability",
  "visible": true,
  "metadata": [{"name": "ohos.extension.dataShare", "resource": "$profile:data_share_config"}]
}
```

`entry/src/main/resources/base/profile/data_share_config.json` 只有 `launchInfos`（cloud 表），
**没有对 URI 路径或字段做白名单**，因此 `contacts/contact_data` 等路径走通用 BatchInsert。

## 2. 权限等级

`ohos.permission.WRITE_CONTACTS`：

- 权限级别：`system_basic`
- 授权方式：`user_grant`
- 归类：**受限开放权限（需 ACL）**

来源：OpenHarmony 文档 `zh-cn/application-dev/security/AccessToken/restricted-permissions.md`。
含义：普通三方应用即使获得用户授权也无法直接申请，需要 ACL 审批（系统/预置/合作方应用）。

## 3. 产品预置（x86_64_virt 标准系统）

`vendor/ohemu/virt/preinstall-config/install_list.json` 中存在：

```json
{ "app_dir" : "/system/app/com.ohos.contacts",             "removable" : false },
{ "app_dir" : "/system/app/com.ohos.contactsdataability",  "removable" : false }
```

`productdefine/common/inherit/rich.json` 包含子系统 `contacts_data` / 组件 `contacts_data`。

`vendor/ohemu/qemu_x86_64_linux_full/config.json`：

```json
{
  "product_name": "x86_64_virt",
  "device_build_path": "device/qemu/x86_64_virt/linux_full",
  "target_cpu": "x86_64",
  "type": "standard",
  "build_selinux": true,
  "inherit": ["productdefine/common/inherit/rich.json", ".../chipset_common.json", "vendor/ohemu/virt/virt_common_x86_64.json"]
}
```

结论：**标准系统产品会预置 Contacts 与 ContactsDataAbility**，且开启 SELinux；
但服务进程 UID、SELinux 域、group 目录布局与实际可写范围仍需在真实镜像中确认（本次未执行）。

## 4. 未完成的产品级路径

`x86_64_virt` 是唯一可在无硬件情况下运行标准系统的 QEMU 产品（`vendor/ohemu`），
启动方式为 `qemu_run.sh` + `hdc tconn 127.0.0.1:5555`。
本次在 `repo sync` 约 40GB 时中止，未构建、未启动、未执行设备侧验证。

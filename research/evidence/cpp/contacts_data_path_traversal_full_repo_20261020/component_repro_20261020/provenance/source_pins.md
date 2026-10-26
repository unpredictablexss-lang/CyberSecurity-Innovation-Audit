# 来源固定记录

采集时间：2026-10-20，WSL2 Ubuntu。

## 1. 仓库与提交

```
$ git -C contacts_data rev-parse HEAD
341cc3bf41b48e9a5f278dd088f40a2041d2f1c9

$ git -C contacts_data rev-parse HEAD^{tree}
2054824c04bb403eeea128a9262edfb3001efa4f

$ git -C contacts_data log -1 --format='%H %ci %s'
341cc3bf41b48e9a5f278dd088f40a2041d2f1c9 2026-10-08 14:53:20 +0800 !336 merge master into master

$ git -C data_share rev-parse HEAD
560c5cdadf08b4beeb691e93d70ff32cc2dca8bd

$ git -C data_share rev-parse HEAD^{tree}
f731230c116c94d7619f5514c828b33ffac69924

$ git -C data_share log -1 --format='%H %ci %s'
560c5cdadf08b4beeb691e93d70ff32cc2dca8bd 2026-10-10 15:36:09 +0800 !1413 merge refactor/datashare-task-executor-singleton into master
```

复现当天 `contacts_data` 的 `origin/master` 与 `HEAD` 相同（`341cc3b`），即该缺陷仍在当前 master 上。

## 2. 被校验文件的 blob 与内容哈希

```
$ git -C contacts_data ls-tree HEAD \
    dataBusiness/contacts/src/contacts_data_ability.cpp \
    dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp \
    ability/common/utils/src/file_utils.cpp
100644 blob 7d39485e3b3f253d474d8e49952e16ced7ccd605  ability/common/utils/src/file_utils.cpp
100644 blob c93e950725adc93276916b3c96c5ac7a5bb5b6b7  dataBusiness/contacts/src/contacts_data_ability.cpp
100644 blob d738c4931bb40ac53519657fb2daa3febfae2bce  dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp
```

工作树在 Windows 上被 `core.autocrlf=true` 转成 CRLF，因此内容哈希统一按 **CRLF→LF 归一化后**计算：

| 文件 | LF SHA-256 | 字节 |
|---|---|---|
| `dataBusiness/contacts/src/contacts_data_ability.cpp` | `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` | 85,339 |
| `dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp` | `a913de9c273ef055de9203f83e890067a8594f1028dce6526844228585aa87a4` | 29,986 |
| `ability/common/utils/src/file_utils.cpp` | `4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f` | 6,843 |

重算命令：

```bash
python3 - <<'EOF'
import hashlib, pathlib
for p in ["dataBusiness/contacts/src/contacts_data_ability.cpp",
          "dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp",
          "ability/common/utils/src/file_utils.cpp"]:
    b = pathlib.Path(p).read_bytes().replace(b"\r\n", b"\n")
    print(hashlib.sha256(b).hexdigest(), len(b), p)
EOF
```

## 3. 11 个被提取的函数

| id | 文件 | 行 | 片段 SHA-256（前 16） |
|---|---|---|---|
| `contacts_batch_insert` | contacts_data_ability.cpp | 601-660 | `d065ea01cf629b71` |
| `batch_insert_one_by_one` | contacts_data_ability.cpp | 696-732 | `36806eea09c6b3f5` |
| `process_single_insert` | contacts_data_ability.cpp | 734-768 | `3d4018b94f5b8e74` |
| `handle_contact_portrait` | contacts_data_ability.cpp | 770-800 | `a988128ed2b52c3a` |
| `save_portrait_file_and_blob` | contacts_data_ability.cpp | 802-841 | `72032d1758fbf196` |
| `build_portrait_value` | contacts_data_ability.cpp | 843-853 | `d4b6261d71918a8f` |
| `get_portrait_value` | contacts_data_ability.cpp | 855-874 | `417a0134bfd3bb33` |
| `get_string_value` | contacts_data_ability.cpp | 876-892 | `c3222f346a8d53a2` |
| `datashare_stub_batch_insert` | contacts_datashare_stub_impl.cpp | 260-306 | `124e5cd4bc25781a` |
| `file_utils_get_group_path` | file_utils.cpp | 155-175 | `57624eb2fdbf1626` |
| `file_utils_delete_file` | file_utils.cpp | 208-215 | `5e0ff2d73a112908` |

完整值见 `harness/generated/extraction_manifest.json`；逐项校验结果见 `verify_extraction.json`。

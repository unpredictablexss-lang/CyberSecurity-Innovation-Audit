# A 线同范围独立复扫一致性

- canonical：`outputs/reports/a_cpp_rescan_20261014/exact-scope`
- replay：`outputs/reports/cpp_same_scope_20261014/run`
- 五组件 repository/commit/tree/snapshot、Detector 状态与逐条诊断身份集合一致。
- JSON 原始哈希保留差异，因为报告包含实际 elapsed_seconds；Markdown 哈希五组件均一致。
- `validated_vulnerability=0`；不据此计算 Precision/Recall。

| 组件 | 诊断 | Source binding | Detector state | Diagnostic identities | Canonical JSON | Replay JSON |
|---|---:|---|---|---|---|---|
| `update_updateservice` | 1 | True | True | True | `f14587ff09978136fb96dfa5a6753bed909634afb02e26e270c3022ac5c4e6f1` | `4bf753371d165ba542d11628d8ae72c1eb9414aa015aff85c88336a2b1becc55` |
| `security_access_token` | 10 | True | True | True | `412c49972fce82f8e39cc230b2a6b3877792d12ccd0ddd15a03a89d53a4a5590` | `915e1a4c9b4d426253dfcdae93131e73a7cafb0ca06098c943b6a195ef172d05` |
| `distributeddatamgr_kv_store` | 167 | True | True | True | `70e351017dcffc114f37ebfdd275bb318a8ae0bd3031e614810fbc205730863c` | `6a70fa10a70c9910fbf97d795963a49022cb72520f394bf47a21679c910a764a` |
| `window_window_manager` | 27 | True | True | True | `a4da71d36c1e733641e0c1d938de2b26a54583811ff399148877110ba387441c` | `270ea7e00b5c577de829014321e8cccb9356fbcaba78d98f856f946a1bea357d` |
| `communication_dsoftbus` | 3 | True | True | True | `d77718d72403f8cae0a3a1a5cd4a7cb95174623d4f165d02b2d405226b8be4f1` | `e31a1ea4c56fb32cf8dbb6e6fea4ea7eb6bec4e3e0a900f8fe7e4632a35011d5` |

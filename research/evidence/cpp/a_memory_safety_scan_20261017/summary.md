# A memory-safety pinned component summary

> Candidate-only; `validated_vulnerability=0`; no Precision/Recall claim.

| Component | Files | Bytes | Candidates | Groups | Wall s | Commit |
|---|---:|---:|---:|---:|---:|---|
| `communication_dsoftbus` | 1656 | 15243597 | 4 | 3 | 15.257 | `652f88e0261ce4d0610f73cc451c26b84d2597af` |
| `distributeddatamgr_kv_store` | 1446 | 11765303 | 8 | 5 | 12.001 | `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` |
| `security_access_token` | 550 | 3484891 | 4 | 2 | 4.339 | `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` |
| `update_updateservice` | 219 | 851345 | 0 | 0 | 1.093 | `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` |
| `window_window_manager` | 1112 | 20206691 | 0 | 0 | 19.388 | `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` |

## Limitations

- Candidate counts are not vulnerability counts and groups are not confirmed root causes.
- Precision/Recall are not computed without an independent reliable labelled holdout.
- The source repositories are pre-fixed local OpenHarmony Git objects; no remote acquisition was performed.

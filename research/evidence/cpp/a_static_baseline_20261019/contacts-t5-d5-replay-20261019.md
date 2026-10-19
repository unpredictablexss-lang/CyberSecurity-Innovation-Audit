# T5 independent replay of frozen D5 — 2026-10-19

## Result

**BLOCK for independent detector acceptance.** The frozen D5 focused suite passes 9/9 and an independent direct-detector replay of the exact A0 source returns the three expected candidate locations with `identity_quality=complete`. A separate guard-order probe exposed a false negative: D5 removes a tainted name from the whole function when it sees a reject-on-separator guard anywhere in that function. A guard after a sink therefore suppresses the earlier, unguarded operation. The guard helper must bind validation to the correct value and establish that the reject branch dominates the specific sink.

The `complete` identity label describes the syntax observation's stable symbol/sink/expression identity. It does not prove source trust, path containment, control-flow dominance, product reachability, or a confirmed vulnerability.

## Reproduction identity

- D5 source commit: `21ba7dcc2df6f7882afde344d5d7d7506f833239`
- T5 cherry-pick commit: `1ce57530fe4a68fe738caebd2963a32a4be8f075`
- T5 base immediately before cherry-pick: `fb4d467f36208113f36561b61fc6739dcebc89f2`
- Detector: `ohscanner.cpp.path_traversal`, rule `ohcpp-path-traversal-source-to-file-sink-candidate-001`, version `0.2.0`
- Focused command: `python -m unittest tests.detectors.test_cpp_path_traversal_detector -v`
- Result: 9 passed, 0 failed.

Exact A0 source: repository `openharmony/applications_contacts_data`, commit `b02aadfc2d801ee30573fcb2d13490298e146fea`, tree `ef183625ccbc842f47b076eb75e68b665d7c21c6`, path `dataBusiness/contacts/src/contacts_data_ability.cpp`, blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`. Exact bytes were retrieved through the official GitHub fetch at the pinned commit and independently checked against local `.repo` commit/tree/blob objects.

### Independent exact replay command

Run from the T5 worktree:

```powershell
@'
import hashlib, json
from pathlib import Path
from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.path_traversal_detector import CppPathTraversalDetector, RULE_ID, RULE_VERSION
p=Path(r'D:/openHarmonyScanner/tmp/contacts-t5-b02aadfc-20261019/contacts_data_ability.cpp')
raw=p.read_bytes(); text=raw.decode('utf-8'); source_sha=hashlib.sha256(raw).hexdigest(); blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(); parsed=parse_source(text,language='cpp')
unit=SourceUnit('dataBusiness/contacts/src/contacts_data_ability.cpp','cpp',text,source_sha,parsed.parse_status)
repo='openharmony/applications_contacts_data'
context=ScanContext(ScanRequest(request_id='contacts-t5-a0-exact',repository=repo,commit='b02aadfc2d801ee30573fcb2d13490298e146fea',snapshot_sha256=snapshot_digest((unit,)),target_id='current-component:'+repo,profile_id='light-ast'),(unit,))
run=CppPathTraversalDetector().detect(context,(unit,))
result={'bytes':len(raw),'blob':blob,'sha256':source_sha,'parser':parsed.parse_status,'parse_issues':len(parsed.parse_issues),'functions':len(parsed.functions),'calls':len(parsed.calls),'rule_id':RULE_ID,'rule_version':RULE_VERSION,'run_status':run.status,'file_outcomes':run.file_outcomes,'findings':[{'line':f.line,'column':f.column,'symbol':f.symbol,'rule_id':f.rule_id,'rule_version':f.rule_version,'source_sha256':f.source_sha256,'identity_quality':f.identity_quality,'ast_fingerprint':f.ast_fingerprint} for f in run.findings],'limitations':run.limitations}
print(json.dumps(result,ensure_ascii=False,sort_keys=True))
'@ | python -
```

Result: the computed Git blob and SHA-256 match the pinned identity; parse is `complete` with 0 issues, 57 functions and 525 calls; detector run/file outcome are `completed`/`complete`; findings are at lines 789, 790 and 794, all with rule `0.2.0`, exact source hash, and `identity_quality=complete`. Fingerprints are respectively `7a1e14e6656d15a3ae1532122fff7bd51b27652d458d3066cd404d6bb8e8e9cf`, `5d739813e4f40cfa2a91ea629ea842aa05ca0eb03d292df1406ea4972545701a`, and `1b9259406adc8cfea406caaa071734268f8404d5f386cea8fd763debf8523999`.

The owner-controlled Catalog does not register D5 in this checkout. Therefore the direct detector replay is valid for D5 implementation behavior but **production CLI integration remains BLOCK**.

## Guard value, polarity, and ordering controls

The following tests were independent in-memory `SourceUnit` probes against the frozen D5 detector. No detector, test, or fixture files were edited in T5. The source skeleton used the existing synthetic cross-function field-flow fixture, changed only in memory so both `open(path)` and `unlink(path)` were in the same `OpenPath(path)` body.

| Probe | Expected | Actual | Result |
|---|---:|---:|---|
| Reject-when-found (`!= npos`) before both sinks | 0 | 0 | Pass for this safe shape |
| Same guard after `open`, before `unlink` | 1 (the earlier `open` is unguarded) | 0 | **Fail: prior unguarded open is suppressed** |
| Same guard after both sinks | 2 | 0 | **Fail: both earlier sinks are suppressed** |
| Reversed (`== npos`) early return before both sinks | 2 | 2 | Pass: reverse polarity preserves candidates |
| Guard checks `other`, sinks use tainted `path` parameter | 2 OpenPath sinks | 2 | Pass for this synthetic variable-binding shape |

Minimal failing form:

```cpp
void OpenPath(const std::string &path) {
    open(path.c_str(), O_RDONLY);
    if (path.find_first_of("/\\") != std::string::npos) return;
    unlink(path.c_str());
}
```

The first `open` occurs before the rejecting check, so it remains an unguarded path operation and must retain a candidate. D5 reports zero findings because `_rejects_path_separators` removes `path` from the function's tainted set without considering statement order or per-sink dominance. A guard after both sinks also produces zero instead of two. The same implementation does preserve candidates for the reversed `== npos` guard in the tested shape. A guard on a different tainted argument (`other`) leaves both expected findings because the actual sink argument `path` remains tainted. Reproduce the guard controls from the T5 worktree with `python research/evidence/cpp/a_static_baseline_20261019/contacts-t5-guard-order-probe-20261019.py`.

## Disposition and next check

This is a rule soundness defect that blocks acceptance of D5 pending a fix. Send it to D5 with these reproductions; after a new immutable fix commit, independently rerun the 9 focused tests, all guard controls, and this exact A0 source replay. Keep the A0 case PARTIAL/BLOCK until a trusted fixed object and product reachability are established. Do not infer Catalog production coverage from the direct detector run.

# OHScanner 审计复核包

候选与复核记录；不是已确认漏洞报告。

- Commit: acfb22aac16161d8fb0cefb6cc9b92f04f489a80
- 原始报告 SHA-256: 7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e
- 候选: 167
- 确认漏洞: 0

## 复核记录（结构化原文）

~~~~json
{
  "schema_version": 1,
  "kind": "workbench_review_bundle",
  "job_id": "f261748b7eff4144bab9646a6b00b607",
  "repository": "openharmony/distributeddatamgr_kv_store",
  "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
  "git_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
  "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
  "scanner_report_sha256": "7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e",
  "findings": [
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:fdd6e227d2ca661e",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/common/js_proxy.h",
      "line": 37,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''instance_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "instance_",
      "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:fdd6e227d2ca661e",
        "file": "frameworks/common/js_proxy.h",
        "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/common/js_proxy.h",
          "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cf558619929424b7",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/common/js_proxy.h",
      "line": 42,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''instance_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "instance_",
      "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cf558619929424b7",
        "file": "frameworks/common/js_proxy.h",
        "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/common/js_proxy.h",
          "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cfae442b046452fe",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 258,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''resultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "resultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "cb1b072294e5ea6098aa9824211d55e7fdc4dadf05f7e3aa33818a6239234634",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cfae442b046452fe",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:af2c69585e088a72",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 292,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8121a37037cbf9c2065780e7f602120e83c78d580a79bba3464b35cb8087bf27",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:af2c69585e088a72",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b25b43e79463d3cd",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 293,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''proxy_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "proxy_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "320431e7a4c9c2c5f057c19afafa7e5b0456aaebf14f937fa30c9ec50cee6a54",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b25b43e79463d3cd",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:17c7396ba8cd044d",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 304,
      "column": 42,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''proxy_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "proxy_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "9c2d08816fa34410ea0972b8b9e1cf28e9ab8ec7095e5f3ab0ae98f61d768d1b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:17c7396ba8cd044d",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:5d6bfd2775f84171",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 309,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5dd064428a3b77c175b6da2f5e4c0db4dbecfaba1d6ee04f9980e031fc93d464",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:5d6bfd2775f84171",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8a191f5a493e83f2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 310,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "cf3c3df489359923ef8d28a2ffd9fcde690d40b39b26bf41e285b7e9eeb53c1d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8a191f5a493e83f2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:234b7be04e659066",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 315,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "caf4378be168e521dc676b2bb3984ead03f77f93d311d7a3f354339fc87ec7fd",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:234b7be04e659066",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8d565e51e487af4b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 316,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "dc5cffc99e88566d11549efa89c6a2f992792878ffac93798ba14b3fe2837022",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8d565e51e487af4b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:df094b1439072139",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 321,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "e6bbeefad94d495de70e52fcf89a4957c302984970c517d48f3ec39a12abf0be",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:df094b1439072139",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:bfbe29ade7b8b2ba",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 322,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "bbeb1f8460888494be92c0a90a43ff041689d133eb5d1a7a450d26d1bbd3928d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:bfbe29ade7b8b2ba",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e642102feb0e0416",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 327,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b82e3904cfad67f3b7b5af31affba1f20165262fba4006be763848681bc201f0",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e642102feb0e0416",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3d902e7f75238641",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 328,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b6dfa4c7a6a560f3d81c84b56813faaad70120043b069782739e131175067977",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3d902e7f75238641",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3e71b34ef6129948",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 333,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "6655f7eb0f547c6e38216a4273d7bf09999ba5b22340526b4a9cf1169722f2b6",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3e71b34ef6129948",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ddc7f76df17eccc3",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 334,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5d5edcc0cdba73611ef96eb6dd0a6996abeae913108308e868082dd62e7a2bc7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ddc7f76df17eccc3",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:bd7f8289f11debad",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 339,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a1ef992f5e34c4515753188bc7b9680f0ff1c74c107e5863948f15ca53a5b18c",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:bd7f8289f11debad",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:54cebe2c5edc1c43",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 340,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "ef9c239936f0c7b6248a08079c51c8d5bb972ec5371d4794f0951328cd939d01",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:54cebe2c5edc1c43",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b5fe05714a80b3f8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 345,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8b5d9986956a784d93a01230239dc82e4336c492eccf1d8cc45bdcbac6dd5b9f",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b5fe05714a80b3f8",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:df37dc393f77cb40",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 346,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "78b1d5185e7140d1f10f70c3a1b218ebc929aba764b11250f7673d5b82426182",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:df37dc393f77cb40",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:487788b4f796c5ae",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 351,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5ec6a1a3b8cd55cabebafbcc167c3d35fdd287c893ee41e7974e8f4e5ccd49a8",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:487788b4f796c5ae",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6771f19caf5e702d",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 352,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8bb1b434861ae3b5ea849b3b473be974ab2818d175b11c91a5cbeeea6ce3684d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6771f19caf5e702d",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3e23920d97a75108",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 357,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3f2176a088b8e5824f7d3a7dabcb162cf46500602b0fe0f75c1b196a3f10fc9a",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3e23920d97a75108",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9a224f6e6e93241b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 358,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3bb34239832c45e2347d4b9f162f5d277f032b335bed681dd9dbed618bd79c29",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9a224f6e6e93241b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b7f2bea0e76aefac",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 363,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "ce9d70d3f718a91b16d66492b99ea314d873cdad902105dd5f223ae2267fc7ed",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b7f2bea0e76aefac",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6d79ce61bd3cbf4c",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 364,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "414926d51cbe938eef89771fe982dfedfb6b929513a98d34cb23feeeed3b8885",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6d79ce61bd3cbf4c",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9bc5bc6b11d24d9e",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 369,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "53127440c42012aacf845bcc1a50adbdc63dae963c0dab242fbc75a2b55d52f3",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9bc5bc6b11d24d9e",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2f2c64a051bfb1c2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 370,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b86e2331f0234c040436cf2dbf47f46a54a24fc3b3800c3c8e1d7b478975263d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2f2c64a051bfb1c2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f78e11cc40cbdb2d",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 375,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "88cca30b1a8adacb2374a5655ac3b1a61f5058ab08de7405750a42692695e1b7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f78e11cc40cbdb2d",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4c07798c2001ed15",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 376,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "4862fdc7e64df1946ed7fc9b29ea25625052c2c38f8d0dee09ff4d0e7ddeb391",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4c07798c2001ed15",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ec0cd2d2f29a6e2a",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 381,
      "column": 20,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8e6f36bea1ea41ec7523efb847079771f35b13813bcf8ebea332a7fba27c9ee9",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ec0cd2d2f29a6e2a",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9f182d8fd661bca8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 383,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "bbbdf87e34a8a442e80c6c82ef44f387da159e57eb1882960fbf0c15fabf1bad",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9f182d8fd661bca8",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:569f13d19b8ee82d",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 393,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeResultSet_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeResultSet_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "de280c2bd4691453ed3459ea5f3990f3bff07621b2f5635bafa715d8e631b919",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:569f13d19b8ee82d",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:beebbed1efd5f4e0",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 406,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "2baad79d52ed715797b97d46ae32a3f4b1e4318759064abca644ec81a4f7ffc6",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:beebbed1efd5f4e0",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:171b00d9f46e8052",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 416,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b686180c6212111b3e2a913a748c66cfad5bc2429bb09bf6329c9351b46336ab",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:171b00d9f46e8052",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a26616defc889363",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 425,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "00452f976acdcaf84be3ab84e3d604c2d35f712e7cd346e97ac8058e5a7ef845",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a26616defc889363",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a05ff995f2dc4825",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 427,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a488f4ab06c4a0d541d53fec872c53a282643919af145a4de23833d8e4819305",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a05ff995f2dc4825",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:21a10f69c1ff3091",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 429,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "9406ba7bd6b4fa176ca610f844621e677a900b37a4edd6674a9cbd6df4b9ca79",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:21a10f69c1ff3091",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b25f8db9420e36e2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 431,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "46b9339a64195f6abf70743ff75b92d4b2c63c8cd69d3456e6040d0ccf71775b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b25f8db9420e36e2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:725dd7dc88c25e5b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 441,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "45968fffee6735fe7e300d50950cc864496dfdd29de1ddafb58afe3cd2d87c25",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:725dd7dc88c25e5b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:baa32045a648dee7",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 443,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "f8d32ae78baab0512f4157a2fb7b140656ccc0be27ce98e7084bb79a1ebc1844",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:baa32045a648dee7",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e5ae518f7f6915f4",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 445,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b31b8ff006bbf5d4c49e37c232548e38f537beb884562cc33726a828c9ecfc98",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e5ae518f7f6915f4",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cd92cbce046925e1",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 447,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3efc19b712318593d38a3905b846e163d15489be6c4fb875da41e1455616674a",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cd92cbce046925e1",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:04aec8aa45460be6",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 457,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "c2b970ab85569108df223514ededf95e9c68811a0dcf59145368aa9e1b7ab375",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:04aec8aa45460be6",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b4fd92da51b48e28",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 459,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "674a2c4199f6a6f6bd809f46dfea1922aa6c8b9772e76bdb5c10418103eac0ac",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b4fd92da51b48e28",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ee668b932492f830",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 461,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "894e199899841721ae7535a098f4cb02cf725a03f18cd84b4a6ee44af7b0477f",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ee668b932492f830",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:533cd36bf65bb46d",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 463,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5c15e924f3dd6b1ac7c4c6d163fac79d90440728da43268350a6e56e5f6b2826",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:533cd36bf65bb46d",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:293f0f63b3e2b491",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 473,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "c7466864946c7354ee3b3fbead4ee32fd35798dada8a89707ea42046d799d2f7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:293f0f63b3e2b491",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:17f940691558fecf",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 475,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5918fb138ce999a3c9aaa05f7de50fcfb853bdaf7ccbad514b96b46abaf2b7ef",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:17f940691558fecf",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b4804247364e94ec",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 477,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a75745889350d77b70c27be277b6b58dbd4fd82ac3476adfce65e1f6052d727c",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b4804247364e94ec",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b4b1ea9180001eb2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 487,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "431c52bb47c4a14e2fbbbcc6681fdeab1bb7ec0c490d5e887ee5462e1e114acd",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b4b1ea9180001eb2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:57fdfced80e96fa6",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 489,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5c8ef925cedbaf353bcd5a477591cca716333abd11693fc6bee4486920bb0a3b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:57fdfced80e96fa6",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:78a60e5947c4300c",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 491,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "6475408e7217ec97b0b83c74ceeff86874476d1ce1c27c60e940b374555ec235",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:78a60e5947c4300c",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2965bb9bb5e6b8dd",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 501,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "961fb9266af46dc98cd6ca279e9c383df07f7da2be97c350b95884b29b045439",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2965bb9bb5e6b8dd",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:88d0520edad7211c",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 503,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b7ca55f4cda2625d68e8461395ff1e84a8da47187026c1e0268fbec439ee65a5",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:88d0520edad7211c",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b73de0a894e0aa92",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 505,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "d5ce02864994a006be5b90a37a1adf9dddc6336adb147acf64eff3322ae1302d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b73de0a894e0aa92",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:459a4dafe1d9dada",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 514,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "74ef285430703348f9139aef2c70c911f5793021be003f75ce6e6b880ae06822",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:459a4dafe1d9dada",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2dfcfb57750a5a19",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 532,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "2e8c79fbf15d0c6ae995c2a4e84137358038b1b315162852246e6603799954c5",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2dfcfb57750a5a19",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4e4bfdd942d3b5c4",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 539,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "26151d91a658e738c37f68f56527dd3cbf265fbd9eb25f0227fc491198d4710d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4e4bfdd942d3b5c4",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d25576be80c9b468",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 548,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "4ee75c339f18fd86f3255f9a617a2697875fd6767e033cf13e9504ee2e37e1f3",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d25576be80c9b468",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:7bd852b5cbe4c9e7",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 566,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "58a4124e0bdbce2ef9c13776063a483d2671e034ece8c82a497a13582ad25ca7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:7bd852b5cbe4c9e7",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:664a1f0b9e62dddc",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 573,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "50301c2e900fcde0dfbbb617dae68f240764b295ca71874f11840971f15de377",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:664a1f0b9e62dddc",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:44f0113835f94f0a",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 582,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8a2c9d4ad7d62deac77df87b77a46016e55d13cb6f478e8c0ca034744ca5440e",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:44f0113835f94f0a",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9be928d3e6e36ee6",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 589,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "ae12f8851f7ba3886c43b9986efea0bd49b96eca0a3b193adc6c121ea86c8c07",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9be928d3e6e36ee6",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:40e31b341bf3ac9b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 596,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "52aabbd4ab2b7c9f5729b6974fd06c434e7ac5c7f03225b516298af0ab4293ad",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:40e31b341bf3ac9b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6e17417092f0cd24",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 602,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "d42f02b32da804b9542ab35e78356819aad693cccb2eff7125732ff60f0f853c",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6e17417092f0cd24",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4d667507557254ce",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 608,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "f8eb7a888b41ce64a0d8c031d830b6c01aab2ba86bda6d3810e2ded34f358418",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4d667507557254ce",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2a76df5d67e11b21",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 615,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8933a4ae1be49b4e737b339cefde497b5375dc026f97c969dc5127fb3972bad1",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2a76df5d67e11b21",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:166deff0576c25d0",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 622,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "366a1e4dc64c9c0fcdcc34fcca233d8b1beb8d6688a7503949329bf8a5b4f80b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:166deff0576c25d0",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4dc0e549a1a6a6e4",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 629,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "f2fad86e6aaf4320e4b63c734f9bb49218f2ce888e82f5576c100e1f6984011a",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4dc0e549a1a6a6e4",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1962f7ddd08d9100",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 636,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b82f221343747d9a230c72ff02da8857549127f6d9e33245d336536db86910cd",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1962f7ddd08d9100",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b1fb88945f1bbd36",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 642,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "2c582cc8a3a374f31a2aa96a8a65b04ba3a9424b601a00ef2e836b768dfd4f79",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b1fb88945f1bbd36",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:586786c558a46888",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 648,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "4f0e31ea3ab696af17bfbd9e177cf0eab95b3e671f986608317084b422e67793",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:586786c558a46888",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cac9b5e014436a33",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 655,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b33b71235ec5ccc363722609cffd85d0f34fbd317ac23bc5b51d93e2ea9f492b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cac9b5e014436a33",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2fb971d735199200",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 662,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "fca8475ad6454679af534ba3a13e7da330c27d706e2418705bf1d622965b1638",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2fb971d735199200",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:17fbcbb4aa066221",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 669,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "df8006c227df76596278d48014c85684f56378b3a5ea44fc561683c2e707a747",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:17fbcbb4aa066221",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1024902cdcd3a52c",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 675,
      "column": 23,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3a488666e745ce219661b39b1c87ca01c84d8cc8c24ab073dd66299085462260",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1024902cdcd3a52c",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2131d3098d74d549",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 681,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeQueryPtr_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeQueryPtr_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "59b07923e50cde1ed3ddc4649670267baae70b731ab95ca92460ef8fef21f887",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2131d3098d74d549",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3363e5e19b4a893a",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 698,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "7a6e968299b9e87796ee8c4c0a881357b28572db011bd57182ba2159190f8156",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3363e5e19b4a893a",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d9c1282f49806143",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 733,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "fb240d277bb20a4eac0baf3cb2173ec5eafc13e1d1f1d8f9851165d932e6cc50",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d9c1282f49806143",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1b9312034864d684",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 749,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "183d2826467a79e9c0d3a2f7c0d067caa8de3a29439d95cabe909f4819a9eb92",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1b9312034864d684",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:37b3186e5e151e72",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 757,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "6c1e4b3d0e42c3afc11385dc669beebd2314437ab77e50afddd2dd5bd1fa27e1",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:37b3186e5e151e72",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a09f050182ac87c0",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 768,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "e64c38c5df64b7eb416d192cc281327e6321d5ff4c779f8d3708a6203f728735",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a09f050182ac87c0",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:afabfec9ab4d2b4a",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 781,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "bd27621de428d95416e922df5dcc5a535edf92d320525b761c54437a5d196d17",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:afabfec9ab4d2b4a",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:962661ee2e90be79",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 802,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "ae441ca488b9cf4ca160a7d3e8e940b5e7505b188d05d3d8e0477930637567c2",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:962661ee2e90be79",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:24e3dae053716936",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 810,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "60664abdedccd193f9ec82a17e97f8b5d327d707fec71305f23b07e751cb7ded",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:24e3dae053716936",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d1849ce6aedc96c2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 816,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "92347244ece9626b21dbde8c5ccd59074cb96d35ab4f3836c5b07aacdcb5da62",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d1849ce6aedc96c2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:54dbefa22db28b51",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 828,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "88e271f51563aca52ae087fcc0fc1191c56c1042a1ecebcd6dbaf25d0bb0d82a",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:54dbefa22db28b51",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0139428ec279b4e9",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 846,
      "column": 18,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "c59864ef57f4aa43fd393bcd55c558e5bf46e450fc574795a1b1c9cb4f01474d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0139428ec279b4e9",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d8d280488fb2deee",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 854,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "7f97fd6a1ccd7ef628597f339cd692c81753e52705d7ed81cd4790cab7d82da6",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d8d280488fb2deee",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f075dc082eb45894",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 868,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "d0d9b0c87cbbbc0b154094c05e39ef78bf3a10972c72f959e692e5c7849cfdf3",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f075dc082eb45894",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:77cc9c85b63deb8e",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 876,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "f693888bbc9048b9a1f784520eb88cce32ab4e7a58b9630f92f76014b8eb7cb0",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:77cc9c85b63deb8e",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8998daf1af829e83",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 885,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "500e2fec3ce51c62b648fb350ac6ccacbb9381f8d04a709aa08b84707dbe62ae",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8998daf1af829e83",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:fa2ec275cbe6109b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 894,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3e5c5745021e19d4a58579321e4d29de5fec273ac6e79539ea93c34ba43bc9f0",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:fa2ec275cbe6109b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:381dc9bc4d8f07fb",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 906,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "920321558ecadefdfa30105c7160026e0b36e7949eb7efe54cf751f1b776d080",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:381dc9bc4d8f07fb",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:eeac15ef7baa9638",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 925,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a264651eaf014d33f5186cd6b1b3dbd85124e1d2c1b875c71a2c17b133f34fa5",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:eeac15ef7baa9638",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:129416f4cbf13775",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 931,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "12a1a9a67e75f2f5bbddbf77c65876f239cc1e92e8a5d50cb3192335fbc36c50",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:129416f4cbf13775",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1e0fba009a606514",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 942,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "4c454ce2c19567fd24111f0027ea52b66982ca465fef9fa09abed8cb9e033a4b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1e0fba009a606514",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:36e621529f8d5714",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 950,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "cc80465e47c15e119028290af6cdc9feb3d43760ddfc2fc241c8c5ba39b6b3a2",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:36e621529f8d5714",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:60a63254b5c75bb9",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 964,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b52f780eb3d033046e527fed5d2e7cafb8946d2f46d9d1f12832f481fac512d5",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:60a63254b5c75bb9",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b545bd6e7a3e3792",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 969,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "49d7919c361fb4852db86bd985846acfaee57342a1279872609138fad889546e",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b545bd6e7a3e3792",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:83ab0c656f5e9542",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 981,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "15026c4aff97ed9f6ac7db4b276b7f480de644333125eb1c3a8953741fbb666a",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:83ab0c656f5e9542",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:aa8d695935c66d0f",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 988,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "9fda549fe2abbd9f23d69dfcd34592aa4b99b2ec54b61c8dca80560380efbf07",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:aa8d695935c66d0f",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9d08d90af6f34ff2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1003,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "f012219b7b3a917f491f01cd25f79775accc71d3d19ef5025b5b32ecdd27c4ac",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9d08d90af6f34ff2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:87275d836f701af3",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1022,
      "column": 18,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "72a35d29243d137aaaa688185a1dca42bc28adc9969e76558888ce45064864a6",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:87275d836f701af3",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3411c81eee2ded0d",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1033,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "162abaa9d09ad13c1135a7cbb7f89e650b850a09f03400e2ee8572ef970ea222",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3411c81eee2ded0d",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6b89357fb90590ad",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1039,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b59d5a04676f466381ee87f4e94c0b16a5a56c610c0b54056bce7f6376f35ab9",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6b89357fb90590ad",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4cac6272e02062e0",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1047,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "becc573683c5219a292e3db99d9d5cae83b98228088021cdd852d1db20512367",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4cac6272e02062e0",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e97c248278fc39d3",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1054,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b6d501602b7ff517eb43b98fda8314c9aeb401ca48509d208921c0f4c9ded6bd",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e97c248278fc39d3",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:af22d2c0bbaac900",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1063,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "f336d5b55665879b4e2c3d8a59851c9e90625e8b3c2cd3b602b7bfa4504e7566",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:af22d2c0bbaac900",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:5bd0bfdcd83f8104",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1067,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "2eaa2ee24e5cc6c592b045e867a4a906cb4ab84a0ac7c082bc2fa42c5be9cb3b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:5bd0bfdcd83f8104",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9c67515570d97c77",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1075,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "0956f0f09200ba2611bb3c436567dc6b1749c4534c1ba6bca8ca81884e525d84",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9c67515570d97c77",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f084f00790fccdff",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1083,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "9f071d0ea5ef227b5308f6ff1125d0b1a9c382bc16a56012da8703a3eceab1a7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f084f00790fccdff",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:62be944470bcd913",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1091,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "93b46419caf2f299c06aa6b28fdaebe4dcb9327ca9552dc871a70d99336cac2e",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:62be944470bcd913",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2d08879c956daa4b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1095,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "6228117e25e509dbdd602990058e60a5027f66007a08a1222783e48898a2ff43",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2d08879c956daa4b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:08d265b5727b667c",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1103,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "ad49658fe262eca8f28889b32d0fcc0bbb88f20e3b8624e2439d86ed78bf4fc7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:08d265b5727b667c",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1779e98ab2290245",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1111,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3e11938b56466f038df0d4e716c4e5906c471ba2b9d01f6a0488490073a8d769",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:1779e98ab2290245",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e625a82d96180c95",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1123,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b94a81321e1f40dfd83f14f4160c077d137aad238cd066cc6f086dcf846eabeb",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e625a82d96180c95",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:28c2dc70c1b55810",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1129,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8735c7de49933f19beb420f8650ba8fc79db5bbad146248ac5d517a9e853436f",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:28c2dc70c1b55810",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f4a4d821c6cf7b34",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1139,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "100e7a581cd8c4071cf51b8584b22eb1f2863879c48f9fef34d9fcaa033b0be8",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f4a4d821c6cf7b34",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:78f9d36adc8657d2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1149,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a0a4986714f00c59597aae54d2434c28a46ea15a4d5c7aada4bc893b98ea2930",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:78f9d36adc8657d2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:c88fe255f0bc1a74",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1157,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "0a4c186985bf9f5ffa1a2eee9fa2522bae19683aa2fb935387688f2983d47c1c",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:c88fe255f0bc1a74",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6639cd42c57a833f",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1161,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "16935c7f570f84c6bb8792480750dbb0d45a1a21eb563c37ddb4dbe87c5d7d10",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6639cd42c57a833f",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:7832cc70002683a2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1169,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "12bc9847cfe7a1b40d4ecad126ca301cbf75cbcd3ebe08e6c020e6baa07d18dd",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:7832cc70002683a2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f20c8bc2be456e59",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1173,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "bf139b0d2affe71cd97453b54fd6f8cdb35241d3cdf5597e10c7e3e0773d694e",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f20c8bc2be456e59",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:82ae77d36824ec02",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1181,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "f573967fad0f63a851f15ba4bd054aa2bfc90c75d59bec7308c672397f325dd9",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:82ae77d36824ec02",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:c4d658608c3aceb2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1185,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "ad005f622f408005298ba5111993b7c5815223075e96760350a1727ec3fb1a48",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:c4d658608c3aceb2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cc2b26f8403a03c1",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1193,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8c11dd07d416258af8b0242b9fde5469f6dcf3d2022806eb04ac3a15b7f81bfb",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:cc2b26f8403a03c1",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:22b43f44056b3aa0",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1197,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "16e3ce73df45ff215bf3bca15335eb5888df29acb24282eb997c322f6ab0d3ad",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:22b43f44056b3aa0",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:92b9c4d2f175419b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1205,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "846d3e4284dd8d9a4b933465a61c536a25e07f39fbab21fbc5d499863c0a822b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:92b9c4d2f175419b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f23d99dbf1f1dc08",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1209,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "9617843ed75680d9e6685ae7b9b4dbd1c084fe07726ed861582eb3e5c2d5cf0b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f23d99dbf1f1dc08",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:10a6ad50896eec19",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1218,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "c58b077ed141dbd140faa465f156f6b7f9bb884935f67361fb10ca46a066f1a6",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:10a6ad50896eec19",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:bbe161b7740e30d9",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1224,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "ca578e6173fce696a7bbd381df0ee7ed17a78d30273923c1535b326cd3ca0f46",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:bbe161b7740e30d9",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4178a12e10f0ff12",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1232,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "6010deb3893210e8200ccdf9c8401f482553ef38df1f339b87b96a4b7bf1f4cf",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4178a12e10f0ff12",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e0c57802621cffc1",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1237,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "65e0d0f9bffa49e7cd5bf62b37cd39284d3ae334a90f232b16a285f3db365d48",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:e0c57802621cffc1",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b706c1cb542496f3",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1246,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a7a71c42c81ca627bebebfa9c772dd4903e51487ec732ef2f658179053473518",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b706c1cb542496f3",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0413ad38b10f8bdf",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1256,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3e9c370912b06b693b645fb0a6326ea20d24bd1e4236bcd1730e04061b8fb817",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0413ad38b10f8bdf",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0564fdcf794a611a",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1266,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "9d5eb3f7f9d679b8a2ce1a991c173ddc434f7695e534c24a96d1d407ef117eac",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0564fdcf794a611a",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b0217fae46af4263",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1278,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "44012735b5e45d2b64b9a91aea6fbb03f21b58436b526fbc227d6323d37cbf0b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b0217fae46af4263",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d3cc240b3036915b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1317,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a3f4f5ef843b321f530f7ccfe7df5fb97c0d3cb326e2d6b9c206ee86a4e1300b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d3cc240b3036915b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ba9bf614038f1f0a",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1348,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "7c7fa88aee077807172dba7e5ec35049e7f13070857c262018691bf9b632b695",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:ba9bf614038f1f0a",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:65439a87e4cf4ef7",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1376,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "0149adbeac200b5be114dd91426b56ee094941ede6c869d630ad4f16c5fd27c2",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:65439a87e4cf4ef7",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a063df7e708bffd1",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1414,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3a0c2bf9f7011a2f6f6c0b6de62730ce3257cfc4002bc84a5917ede22a64a221",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a063df7e708bffd1",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:08bb175cfcf92520",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1439,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5c703b5605ad3775b5cdfa2ff9aa3d03ad87091e3aa546e419de1e945ff27ddc",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:08bb175cfcf92520",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:734b9eb505317359",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1462,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "757791f31e555967b69c66b83df0a638282dbbd6bde77073ac27c497064e4181",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:734b9eb505317359",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:895ec8137eb58684",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1513,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "6c919ee76d43a584e225bfa9e5ac462a2237592faed435f182229d53daa6565a",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:895ec8137eb58684",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:04396ff0a1cefd88",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1518,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''nativeStore_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "nativeStore_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "dc7efdb54320398868215127faba0a7b5782e47109a545b57bb47336b7ca6965",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:04396ff0a1cefd88",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:58de514bd6a3c4f9",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1734,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "4e158172e4c817f7673eb64a0fb5daf2c83dd6189ab548a3d259eaec02586ca2",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:58de514bd6a3c4f9",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d8bf9faa01075888",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1796,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "104e86773561ef8b651299e384feaca7b885e797fde10182497d25a61c8a6b22",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d8bf9faa01075888",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2334e05891622b46",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1815,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "0fb76694954ebac3e7bce15837cc222c195c1891e36e313eac17a76453cfb571",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:2334e05891622b46",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0f879f13fe080e2b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1819,
      "column": 22,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "576072aa7bafa4fcd087b464bad83658e30aa814d56820b3497c0a6d3e5af506",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0f879f13fe080e2b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f617907a86b9b8ff",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1842,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3885450251384ad98003288d53754b9f0167cadbd641e552931701b3a872f0d8",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:f617907a86b9b8ff",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8e6f6de209c6b54f",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1858,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "6a7e3d87146acafc5918598e2aef4cc33e30a49c001cc87c2bc0062e658316dd",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:8e6f6de209c6b54f",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b163333bfefa44ad",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1867,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "9416d20b38025126080104470d87ac6742edd258135bb84742387160ba6b0341",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:b163333bfefa44ad",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:38fd1565fc27ce4c",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1893,
      "column": 49,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3dbe49a2fafcf22b77b161d8f39881035eb0e80b8b70f58fe6e5105a19c44092",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:38fd1565fc27ce4c",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:afa79778c4fecd44",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1894,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8845747d8b3bf117f9bbd418076f0669911981e4cdae3cae54cd3b4b2857761c",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:afa79778c4fecd44",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:93f693538c9ce7d2",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1902,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5871b716a640944bca6aba8998e86ddca0125421ec6fd642419511e191d44848",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:93f693538c9ce7d2",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d810fed69d8a835b",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1918,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b1ce58cd506f18297298a68868a0305918d239eada8b4da011209f980d43a711",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d810fed69d8a835b",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:5ec0c9c13be444f8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1927,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "3cf3b1cdab1302eab1ef67b8b871e7dac4f2928a0c42a57bb3b85c59f27e5798",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:5ec0c9c13be444f8",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:07e4e421bc9b2391",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1955,
      "column": 25,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b05ad108365bd02088323f359c3c37beaedea2c22c04e6c0ca0054ace6be3fa6",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:07e4e421bc9b2391",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:7ca6ebf55bbaf146",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1974,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "8ed8ea3a34ba68a9f650bdd1d3401f4207386dbb8d0e9f5f5680ee441aea2b1f",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:7ca6ebf55bbaf146",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4256b054164c1fd8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1981,
      "column": 40,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "da23ac6ad5926d557d13e0a2de2940e9e3a85999ae0176be12929e8920b0f837",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4256b054164c1fd8",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:01fb9c674bc3c4d5",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 1996,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "2408dfc95a3e4fc192d3d360a8845d0a893284c941074d66501b1b98846cbd5e",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:01fb9c674bc3c4d5",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:776ca7d1327559e8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "line": 2020,
      "column": 13,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''kvDataManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "kvDataManager_",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a7acb883a7fce3ad3ed78f758535300ab52679780eabfe9c416ce4c2e4ee6dd7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:776ca7d1327559e8",
        "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
        "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
          "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:afde9c16d899ceb8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
      "line": 61,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''abilityInfo_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "abilityInfo_",
      "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:afde9c16d899ceb8",
        "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
        "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
          "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:565571f23fbc00e3",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
      "line": 65,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''abilityInfo_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "abilityInfo_",
      "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "de8642d38c52fbba01c43f4d7425d29330fb03e273de8ab740e5b2cc00d2a1d5",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:565571f23fbc00e3",
        "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
        "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
          "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    },
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0176c25c2194b0d7",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
      "line": 81,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''abilityInfo_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "abilityInfo_",
      "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:0176c25c2194b0d7",
        "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
        "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/distributeddatamgr_kv_store",
          "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
          "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
          "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458"
        },
        "consequence_impact": null,
        "consequence_cwe": null,
        "model_version": null,
        "obligations": [
          {
            "kind": "synchronization_proof",
            "description": "Resolve lock and atomic semantics across all accesses.",
            "status": "unknown"
          },
          {
            "kind": "thread_interleaving",
            "description": "Demonstrate feasible concurrent accesses to the same object.",
            "status": "unknown"
          },
          {
            "kind": "product_build_context",
            "description": "Establish real build and template instantiation context.",
            "status": "unknown"
          },
          {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown"
          }
        ]
      },
      "review_status": "unassessed",
      "evidence_level": "candidate"
    }
  ],
  "reviews": [
    {
      "id": 12,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef",
      "status": "plausible_unproven",
      "reviewer": "teammate-A / static review",
      "notes": "Static review JSProxy mutable owner access pair. file=frameworks/common/js_proxy.h:37 symbol=instance_ operation=write. Hypothesis: SetInstance and GetInstance expose a mutable owner pair without a repository-local lock. Remaining unknown: NapiQueue serialization, publication order and attacker-controlled interleaving remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:31.355233+00:00"
    },
    {
      "id": 13,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c",
      "status": "plausible_unproven",
      "reviewer": "teammate-A / static review",
      "notes": "Static review JSProxy mutable owner access pair. file=frameworks/common/js_proxy.h:42 symbol=instance_ operation=read. Hypothesis: SetInstance and GetInstance expose a mutable owner pair without a repository-local lock. Remaining unknown: NapiQueue serialization, publication order and attacker-controlled interleaving remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:31.753789+00:00"
    },
    {
      "id": 14,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "cb1b072294e5ea6098aa9824211d55e7fdc4dadf05f7e3aa33818a6239234634",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:258 symbol=resultSet_ operation=write. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:32.188257+00:00"
    },
    {
      "id": 15,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8121a37037cbf9c2065780e7f602120e83c78d580a79bba3464b35cb8087bf27",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:292 symbol=nativeResultSet_ operation=write. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:32.569283+00:00"
    },
    {
      "id": 16,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "320431e7a4c9c2c5f057c19afafa7e5b0456aaebf14f937fa30c9ec50cee6a54",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:293 symbol=proxy_ operation=write. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:32.960193+00:00"
    },
    {
      "id": 17,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "9c2d08816fa34410ea0972b8b9e1cf28e9ab8ec7095e5f3ab0ae98f61d768d1b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:304 symbol=proxy_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:33.328023+00:00"
    },
    {
      "id": 18,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5dd064428a3b77c175b6da2f5e4c0db4dbecfaba1d6ee04f9980e031fc93d464",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:309 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:33.752401+00:00"
    },
    {
      "id": 19,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "cf3c3df489359923ef8d28a2ffd9fcde690d40b39b26bf41e285b7e9eeb53c1d",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:310 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:34.132731+00:00"
    },
    {
      "id": 20,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "caf4378be168e521dc676b2bb3984ead03f77f93d311d7a3f354339fc87ec7fd",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:315 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:34.567134+00:00"
    },
    {
      "id": 21,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "dc5cffc99e88566d11549efa89c6a2f992792878ffac93798ba14b3fe2837022",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:316 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:35.057626+00:00"
    },
    {
      "id": 22,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "e6bbeefad94d495de70e52fcf89a4957c302984970c517d48f3ec39a12abf0be",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:321 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:35.606608+00:00"
    },
    {
      "id": 23,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "bbeb1f8460888494be92c0a90a43ff041689d133eb5d1a7a450d26d1bbd3928d",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:322 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:36.015767+00:00"
    },
    {
      "id": 24,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b82e3904cfad67f3b7b5af31affba1f20165262fba4006be763848681bc201f0",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:327 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:36.389973+00:00"
    },
    {
      "id": 25,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b6dfa4c7a6a560f3d81c84b56813faaad70120043b069782739e131175067977",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:328 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:36.798735+00:00"
    },
    {
      "id": 26,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "6655f7eb0f547c6e38216a4273d7bf09999ba5b22340526b4a9cf1169722f2b6",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:333 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:37.215484+00:00"
    },
    {
      "id": 27,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5d5edcc0cdba73611ef96eb6dd0a6996abeae913108308e868082dd62e7a2bc7",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:334 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:37.727306+00:00"
    },
    {
      "id": 28,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a1ef992f5e34c4515753188bc7b9680f0ff1c74c107e5863948f15ca53a5b18c",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:339 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:38.118393+00:00"
    },
    {
      "id": 29,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "ef9c239936f0c7b6248a08079c51c8d5bb972ec5371d4794f0951328cd939d01",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:340 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:38.520749+00:00"
    },
    {
      "id": 30,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8b5d9986956a784d93a01230239dc82e4336c492eccf1d8cc45bdcbac6dd5b9f",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:345 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:39.015671+00:00"
    },
    {
      "id": 31,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "78b1d5185e7140d1f10f70c3a1b218ebc929aba764b11250f7673d5b82426182",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:346 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:39.450854+00:00"
    },
    {
      "id": 32,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5ec6a1a3b8cd55cabebafbcc167c3d35fdd287c893ee41e7974e8f4e5ccd49a8",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:351 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:39.855716+00:00"
    },
    {
      "id": 33,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8bb1b434861ae3b5ea849b3b473be974ab2818d175b11c91a5cbeeea6ce3684d",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:352 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:40.213778+00:00"
    },
    {
      "id": 34,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3f2176a088b8e5824f7d3a7dabcb162cf46500602b0fe0f75c1b196a3f10fc9a",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:357 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:40.611242+00:00"
    },
    {
      "id": 35,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3bb34239832c45e2347d4b9f162f5d277f032b335bed681dd9dbed618bd79c29",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:358 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:41.000764+00:00"
    },
    {
      "id": 36,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "ce9d70d3f718a91b16d66492b99ea314d873cdad902105dd5f223ae2267fc7ed",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:363 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:41.360197+00:00"
    },
    {
      "id": 37,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "414926d51cbe938eef89771fe982dfedfb6b929513a98d34cb23feeeed3b8885",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:364 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:41.707001+00:00"
    },
    {
      "id": 38,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "53127440c42012aacf845bcc1a50adbdc63dae963c0dab242fbc75a2b55d52f3",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:369 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:42.088309+00:00"
    },
    {
      "id": 39,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b86e2331f0234c040436cf2dbf47f46a54a24fc3b3800c3c8e1d7b478975263d",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:370 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:42.490535+00:00"
    },
    {
      "id": 40,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "88cca30b1a8adacb2374a5655ac3b1a61f5058ab08de7405750a42692695e1b7",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:375 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:42.905187+00:00"
    },
    {
      "id": 41,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "4862fdc7e64df1946ed7fc9b29ea25625052c2c38f8d0dee09ff4d0e7ddeb391",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:376 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:43.307352+00:00"
    },
    {
      "id": 42,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8e6f36bea1ea41ec7523efb847079771f35b13813bcf8ebea332a7fba27c9ee9",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:381 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:43.801209+00:00"
    },
    {
      "id": 43,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "bbbdf87e34a8a442e80c6c82ef44f387da159e57eb1882960fbf0c15fabf1bad",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:383 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:44.211142+00:00"
    },
    {
      "id": 44,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "de280c2bd4691453ed3459ea5f3990f3bff07621b2f5635bafa715d8e631b919",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:393 symbol=nativeResultSet_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:44.634997+00:00"
    },
    {
      "id": 45,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "2baad79d52ed715797b97d46ae32a3f4b1e4318759064abca644ec81a4f7ffc6",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:406 symbol=nativeQueryPtr_ operation=write. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:45.015575+00:00"
    },
    {
      "id": 46,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b686180c6212111b3e2a913a748c66cfad5bc2429bb09bf6329c9351b46336ab",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:416 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:45.397749+00:00"
    },
    {
      "id": 47,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "00452f976acdcaf84be3ab84e3d604c2d35f712e7cd346e97ac8058e5a7ef845",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:425 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:45.754147+00:00"
    },
    {
      "id": 48,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a488f4ab06c4a0d541d53fec872c53a282643919af145a4de23833d8e4819305",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:427 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:46.187317+00:00"
    },
    {
      "id": 49,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "9406ba7bd6b4fa176ca610f844621e677a900b37a4edd6674a9cbd6df4b9ca79",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:429 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:46.599170+00:00"
    },
    {
      "id": 50,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "46b9339a64195f6abf70743ff75b92d4b2c63c8cd69d3456e6040d0ccf71775b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:431 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:47.017793+00:00"
    },
    {
      "id": 51,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "45968fffee6735fe7e300d50950cc864496dfdd29de1ddafb58afe3cd2d87c25",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:441 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:47.541373+00:00"
    },
    {
      "id": 52,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "f8d32ae78baab0512f4157a2fb7b140656ccc0be27ce98e7084bb79a1ebc1844",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:443 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:47.903333+00:00"
    },
    {
      "id": 53,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b31b8ff006bbf5d4c49e37c232548e38f537beb884562cc33726a828c9ecfc98",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:445 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:48.310446+00:00"
    },
    {
      "id": 54,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3efc19b712318593d38a3905b846e163d15489be6c4fb875da41e1455616674a",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:447 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:48.728843+00:00"
    },
    {
      "id": 55,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "c2b970ab85569108df223514ededf95e9c68811a0dcf59145368aa9e1b7ab375",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:457 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:49.125774+00:00"
    },
    {
      "id": 56,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "674a2c4199f6a6f6bd809f46dfea1922aa6c8b9772e76bdb5c10418103eac0ac",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:459 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:49.646462+00:00"
    },
    {
      "id": 57,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "894e199899841721ae7535a098f4cb02cf725a03f18cd84b4a6ee44af7b0477f",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:461 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:50.198210+00:00"
    },
    {
      "id": 58,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5c15e924f3dd6b1ac7c4c6d163fac79d90440728da43268350a6e56e5f6b2826",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:463 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:50.586681+00:00"
    },
    {
      "id": 59,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "c7466864946c7354ee3b3fbead4ee32fd35798dada8a89707ea42046d799d2f7",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:473 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:51.019224+00:00"
    },
    {
      "id": 60,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5918fb138ce999a3c9aaa05f7de50fcfb853bdaf7ccbad514b96b46abaf2b7ef",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:475 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:51.454046+00:00"
    },
    {
      "id": 61,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a75745889350d77b70c27be277b6b58dbd4fd82ac3476adfce65e1f6052d727c",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:477 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:51.932189+00:00"
    },
    {
      "id": 62,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "431c52bb47c4a14e2fbbbcc6681fdeab1bb7ec0c490d5e887ee5462e1e114acd",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:487 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:52.350224+00:00"
    },
    {
      "id": 63,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5c8ef925cedbaf353bcd5a477591cca716333abd11693fc6bee4486920bb0a3b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:489 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:52.675424+00:00"
    },
    {
      "id": 64,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "6475408e7217ec97b0b83c74ceeff86874476d1ce1c27c60e940b374555ec235",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:491 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:53.008960+00:00"
    },
    {
      "id": 65,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "961fb9266af46dc98cd6ca279e9c383df07f7da2be97c350b95884b29b045439",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:501 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:53.337158+00:00"
    },
    {
      "id": 66,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b7ca55f4cda2625d68e8461395ff1e84a8da47187026c1e0268fbec439ee65a5",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:503 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:53.658676+00:00"
    },
    {
      "id": 67,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "d5ce02864994a006be5b90a37a1adf9dddc6336adb147acf64eff3322ae1302d",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:505 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:54.008056+00:00"
    },
    {
      "id": 68,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "74ef285430703348f9139aef2c70c911f5793021be003f75ce6e6b880ae06822",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:514 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:54.364553+00:00"
    },
    {
      "id": 69,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "2e8c79fbf15d0c6ae995c2a4e84137358038b1b315162852246e6603799954c5",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:532 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:54.736944+00:00"
    },
    {
      "id": 70,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "26151d91a658e738c37f68f56527dd3cbf265fbd9eb25f0227fc491198d4710d",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:539 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:55.313047+00:00"
    },
    {
      "id": 71,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "4ee75c339f18fd86f3255f9a617a2697875fd6767e033cf13e9504ee2e37e1f3",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:548 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:55.724651+00:00"
    },
    {
      "id": 72,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "58a4124e0bdbce2ef9c13776063a483d2671e034ece8c82a497a13582ad25ca7",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:566 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:56.145225+00:00"
    },
    {
      "id": 73,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "50301c2e900fcde0dfbbb617dae68f240764b295ca71874f11840971f15de377",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:573 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:56.513934+00:00"
    },
    {
      "id": 74,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8a2c9d4ad7d62deac77df87b77a46016e55d13cb6f478e8c0ca034744ca5440e",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:582 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:56.879137+00:00"
    },
    {
      "id": 75,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "ae12f8851f7ba3886c43b9986efea0bd49b96eca0a3b193adc6c121ea86c8c07",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:589 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:57.330023+00:00"
    },
    {
      "id": 76,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "52aabbd4ab2b7c9f5729b6974fd06c434e7ac5c7f03225b516298af0ab4293ad",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:596 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:57.746968+00:00"
    },
    {
      "id": 77,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "d42f02b32da804b9542ab35e78356819aad693cccb2eff7125732ff60f0f853c",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:602 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:58.184855+00:00"
    },
    {
      "id": 78,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "f8eb7a888b41ce64a0d8c031d830b6c01aab2ba86bda6d3810e2ded34f358418",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:608 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:58.615839+00:00"
    },
    {
      "id": 79,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8933a4ae1be49b4e737b339cefde497b5375dc026f97c969dc5127fb3972bad1",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:615 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:59.027111+00:00"
    },
    {
      "id": 80,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "366a1e4dc64c9c0fcdcc34fcca233d8b1beb8d6688a7503949329bf8a5b4f80b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:622 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:59.395906+00:00"
    },
    {
      "id": 81,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "f2fad86e6aaf4320e4b63c734f9bb49218f2ce888e82f5576c100e1f6984011a",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:629 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:56:59.730628+00:00"
    },
    {
      "id": 82,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b82f221343747d9a230c72ff02da8857549127f6d9e33245d336536db86910cd",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:636 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:00.116908+00:00"
    },
    {
      "id": 83,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "2c582cc8a3a374f31a2aa96a8a65b04ba3a9424b601a00ef2e836b768dfd4f79",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:642 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:00.490777+00:00"
    },
    {
      "id": 84,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "4f0e31ea3ab696af17bfbd9e177cf0eab95b3e671f986608317084b422e67793",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:648 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:00.864551+00:00"
    },
    {
      "id": 85,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b33b71235ec5ccc363722609cffd85d0f34fbd317ac23bc5b51d93e2ea9f492b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:655 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:01.265682+00:00"
    },
    {
      "id": 86,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "fca8475ad6454679af534ba3a13e7da330c27d706e2418705bf1d622965b1638",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:662 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:01.929089+00:00"
    },
    {
      "id": 87,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "df8006c227df76596278d48014c85684f56378b3a5ea44fc561683c2e707a747",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:669 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:02.464837+00:00"
    },
    {
      "id": 88,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3a488666e745ce219661b39b1c87ca01c84d8cc8c24ab073dd66299085462260",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:675 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:02.835696+00:00"
    },
    {
      "id": 89,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "59b07923e50cde1ed3ddc4649670267baae70b731ab95ca92460ef8fef21f887",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:681 symbol=nativeQueryPtr_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:03.181292+00:00"
    },
    {
      "id": 90,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "7a6e968299b9e87796ee8c4c0a881357b28572db011bd57182ba2159190f8156",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:698 symbol=nativeStore_ operation=write. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:03.684301+00:00"
    },
    {
      "id": 91,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "fb240d277bb20a4eac0baf3cb2173ec5eafc13e1d1f1d8f9851165d932e6cc50",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:733 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:04.230314+00:00"
    },
    {
      "id": 92,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "183d2826467a79e9c0d3a2f7c0d067caa8de3a29439d95cabe909f4819a9eb92",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:749 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:04.665101+00:00"
    },
    {
      "id": 93,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "6c1e4b3d0e42c3afc11385dc669beebd2314437ab77e50afddd2dd5bd1fa27e1",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:757 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:05.065040+00:00"
    },
    {
      "id": 94,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "e64c38c5df64b7eb416d192cc281327e6321d5ff4c779f8d3708a6203f728735",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:768 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:05.467399+00:00"
    },
    {
      "id": 95,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "bd27621de428d95416e922df5dcc5a535edf92d320525b761c54437a5d196d17",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:781 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:05.948510+00:00"
    },
    {
      "id": 96,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "ae441ca488b9cf4ca160a7d3e8e940b5e7505b188d05d3d8e0477930637567c2",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:802 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:06.450890+00:00"
    },
    {
      "id": 97,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "60664abdedccd193f9ec82a17e97f8b5d327d707fec71305f23b07e751cb7ded",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:810 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:06.875421+00:00"
    },
    {
      "id": 98,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "92347244ece9626b21dbde8c5ccd59074cb96d35ab4f3836c5b07aacdcb5da62",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:816 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:07.272820+00:00"
    },
    {
      "id": 99,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "88e271f51563aca52ae087fcc0fc1191c56c1042a1ecebcd6dbaf25d0bb0d82a",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:828 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:07.676134+00:00"
    },
    {
      "id": 100,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "c59864ef57f4aa43fd393bcd55c558e5bf46e450fc574795a1b1c9cb4f01474d",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:846 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:08.072757+00:00"
    },
    {
      "id": 101,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "7f97fd6a1ccd7ef628597f339cd692c81753e52705d7ed81cd4790cab7d82da6",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:854 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:08.436699+00:00"
    },
    {
      "id": 102,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "d0d9b0c87cbbbc0b154094c05e39ef78bf3a10972c72f959e692e5c7849cfdf3",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:868 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:09.006028+00:00"
    },
    {
      "id": 103,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "f693888bbc9048b9a1f784520eb88cce32ab4e7a58b9630f92f76014b8eb7cb0",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:876 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:09.531496+00:00"
    },
    {
      "id": 104,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "500e2fec3ce51c62b648fb350ac6ccacbb9381f8d04a709aa08b84707dbe62ae",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:885 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:09.989103+00:00"
    },
    {
      "id": 105,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3e5c5745021e19d4a58579321e4d29de5fec273ac6e79539ea93c34ba43bc9f0",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:894 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:10.536976+00:00"
    },
    {
      "id": 106,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "920321558ecadefdfa30105c7160026e0b36e7949eb7efe54cf751f1b776d080",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:906 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:10.989240+00:00"
    },
    {
      "id": 107,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a264651eaf014d33f5186cd6b1b3dbd85124e1d2c1b875c71a2c17b133f34fa5",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:925 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:11.495173+00:00"
    },
    {
      "id": 108,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "12a1a9a67e75f2f5bbddbf77c65876f239cc1e92e8a5d50cb3192335fbc36c50",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:931 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:12.016309+00:00"
    },
    {
      "id": 109,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "4c454ce2c19567fd24111f0027ea52b66982ca465fef9fa09abed8cb9e033a4b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:942 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:12.440807+00:00"
    },
    {
      "id": 110,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "cc80465e47c15e119028290af6cdc9feb3d43760ddfc2fc241c8c5ba39b6b3a2",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:950 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:12.956136+00:00"
    },
    {
      "id": 111,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b52f780eb3d033046e527fed5d2e7cafb8946d2f46d9d1f12832f481fac512d5",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:964 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:13.536894+00:00"
    },
    {
      "id": 112,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "49d7919c361fb4852db86bd985846acfaee57342a1279872609138fad889546e",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:969 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:13.937867+00:00"
    },
    {
      "id": 113,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "15026c4aff97ed9f6ac7db4b276b7f480de644333125eb1c3a8953741fbb666a",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:981 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:14.326948+00:00"
    },
    {
      "id": 114,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "9fda549fe2abbd9f23d69dfcd34592aa4b99b2ec54b61c8dca80560380efbf07",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:988 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:14.720312+00:00"
    },
    {
      "id": 115,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "f012219b7b3a917f491f01cd25f79775accc71d3d19ef5025b5b32ecdd27c4ac",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1003 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:15.122390+00:00"
    },
    {
      "id": 116,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "72a35d29243d137aaaa688185a1dca42bc28adc9969e76558888ce45064864a6",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1022 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:15.492094+00:00"
    },
    {
      "id": 117,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "162abaa9d09ad13c1135a7cbb7f89e650b850a09f03400e2ee8572ef970ea222",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1033 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:15.889767+00:00"
    },
    {
      "id": 118,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b59d5a04676f466381ee87f4e94c0b16a5a56c610c0b54056bce7f6376f35ab9",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1039 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:16.321229+00:00"
    },
    {
      "id": 119,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "becc573683c5219a292e3db99d9d5cae83b98228088021cdd852d1db20512367",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1047 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:16.656645+00:00"
    },
    {
      "id": 120,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b6d501602b7ff517eb43b98fda8314c9aeb401ca48509d208921c0f4c9ded6bd",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1054 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:17.047210+00:00"
    },
    {
      "id": 121,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "f336d5b55665879b4e2c3d8a59851c9e90625e8b3c2cd3b602b7bfa4504e7566",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1063 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:17.421721+00:00"
    },
    {
      "id": 122,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "2eaa2ee24e5cc6c592b045e867a4a906cb4ab84a0ac7c082bc2fa42c5be9cb3b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1067 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:18.012299+00:00"
    },
    {
      "id": 123,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "0956f0f09200ba2611bb3c436567dc6b1749c4534c1ba6bca8ca81884e525d84",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1075 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:18.460617+00:00"
    },
    {
      "id": 124,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "9f071d0ea5ef227b5308f6ff1125d0b1a9c382bc16a56012da8703a3eceab1a7",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1083 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:18.876436+00:00"
    },
    {
      "id": 125,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "93b46419caf2f299c06aa6b28fdaebe4dcb9327ca9552dc871a70d99336cac2e",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1091 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:19.272097+00:00"
    },
    {
      "id": 126,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "6228117e25e509dbdd602990058e60a5027f66007a08a1222783e48898a2ff43",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1095 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:19.668939+00:00"
    },
    {
      "id": 127,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "ad49658fe262eca8f28889b32d0fcc0bbb88f20e3b8624e2439d86ed78bf4fc7",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1103 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:20.295872+00:00"
    },
    {
      "id": 128,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3e11938b56466f038df0d4e716c4e5906c471ba2b9d01f6a0488490073a8d769",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1111 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:20.625885+00:00"
    },
    {
      "id": 129,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b94a81321e1f40dfd83f14f4160c077d137aad238cd066cc6f086dcf846eabeb",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1123 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:20.956825+00:00"
    },
    {
      "id": 130,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8735c7de49933f19beb420f8650ba8fc79db5bbad146248ac5d517a9e853436f",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1129 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:21.364496+00:00"
    },
    {
      "id": 131,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "100e7a581cd8c4071cf51b8584b22eb1f2863879c48f9fef34d9fcaa033b0be8",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1139 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:21.796534+00:00"
    },
    {
      "id": 132,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a0a4986714f00c59597aae54d2434c28a46ea15a4d5c7aada4bc893b98ea2930",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1149 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:22.194372+00:00"
    },
    {
      "id": 133,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "0a4c186985bf9f5ffa1a2eee9fa2522bae19683aa2fb935387688f2983d47c1c",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1157 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:22.634023+00:00"
    },
    {
      "id": 134,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "16935c7f570f84c6bb8792480750dbb0d45a1a21eb563c37ddb4dbe87c5d7d10",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1161 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:23.057339+00:00"
    },
    {
      "id": 135,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "12bc9847cfe7a1b40d4ecad126ca301cbf75cbcd3ebe08e6c020e6baa07d18dd",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1169 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:23.449173+00:00"
    },
    {
      "id": 136,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "bf139b0d2affe71cd97453b54fd6f8cdb35241d3cdf5597e10c7e3e0773d694e",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1173 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:23.798913+00:00"
    },
    {
      "id": 137,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "f573967fad0f63a851f15ba4bd054aa2bfc90c75d59bec7308c672397f325dd9",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1181 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:24.200514+00:00"
    },
    {
      "id": 138,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "ad005f622f408005298ba5111993b7c5815223075e96760350a1727ec3fb1a48",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1185 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:24.554973+00:00"
    },
    {
      "id": 139,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8c11dd07d416258af8b0242b9fde5469f6dcf3d2022806eb04ac3a15b7f81bfb",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1193 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:25.134571+00:00"
    },
    {
      "id": 140,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "16e3ce73df45ff215bf3bca15335eb5888df29acb24282eb997c322f6ab0d3ad",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1197 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:25.688843+00:00"
    },
    {
      "id": 141,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "846d3e4284dd8d9a4b933465a61c536a25e07f39fbab21fbc5d499863c0a822b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1205 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:26.127439+00:00"
    },
    {
      "id": 142,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "9617843ed75680d9e6685ae7b9b4dbd1c084fe07726ed861582eb3e5c2d5cf0b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1209 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:26.539415+00:00"
    },
    {
      "id": 143,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "c58b077ed141dbd140faa465f156f6b7f9bb884935f67361fb10ca46a066f1a6",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1218 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:27.030083+00:00"
    },
    {
      "id": 144,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "ca578e6173fce696a7bbd381df0ee7ed17a78d30273923c1535b326cd3ca0f46",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1224 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:27.482276+00:00"
    },
    {
      "id": 145,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "6010deb3893210e8200ccdf9c8401f482553ef38df1f339b87b96a4b7bf1f4cf",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1232 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:27.837639+00:00"
    },
    {
      "id": 146,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "65e0d0f9bffa49e7cd5bf62b37cd39284d3ae334a90f232b16a285f3db365d48",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1237 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:28.237708+00:00"
    },
    {
      "id": 147,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a7a71c42c81ca627bebebfa9c772dd4903e51487ec732ef2f658179053473518",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1246 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:28.699927+00:00"
    },
    {
      "id": 148,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3e9c370912b06b693b645fb0a6326ea20d24bd1e4236bcd1730e04061b8fb817",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1256 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:29.140479+00:00"
    },
    {
      "id": 149,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "9d5eb3f7f9d679b8a2ce1a991c173ddc434f7695e534c24a96d1d407ef117eac",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1266 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:29.609381+00:00"
    },
    {
      "id": 150,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "44012735b5e45d2b64b9a91aea6fbb03f21b58436b526fbc227d6323d37cbf0b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1278 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:30.053519+00:00"
    },
    {
      "id": 151,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a3f4f5ef843b321f530f7ccfe7df5fb97c0d3cb326e2d6b9c206ee86a4e1300b",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1317 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:30.508444+00:00"
    },
    {
      "id": 152,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "7c7fa88aee077807172dba7e5ec35049e7f13070857c262018691bf9b632b695",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1348 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:30.892761+00:00"
    },
    {
      "id": 153,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "0149adbeac200b5be114dd91426b56ee094941ede6c869d630ad4f16c5fd27c2",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1376 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:31.237461+00:00"
    },
    {
      "id": 154,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3a0c2bf9f7011a2f6f6c0b6de62730ce3257cfc4002bc84a5917ede22a64a221",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1414 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:31.571310+00:00"
    },
    {
      "id": 155,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5c703b5605ad3775b5cdfa2ff9aa3d03ad87091e3aa546e419de1e945ff27ddc",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1439 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:31.995770+00:00"
    },
    {
      "id": 156,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "757791f31e555967b69c66b83df0a638282dbbd6bde77073ac27c497064e4181",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1462 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:32.552194+00:00"
    },
    {
      "id": 157,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "6c919ee76d43a584e225bfa9e5ac462a2237592faed435f182229d53daa6565a",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1513 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:33.000233+00:00"
    },
    {
      "id": 158,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "dc7efdb54320398868215127faba0a7b5782e47109a545b57bb47336b7ca6965",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1518 symbol=nativeStore_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:33.409607+00:00"
    },
    {
      "id": 159,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "4e158172e4c817f7673eb64a0fb5daf2c83dd6189ab548a3d259eaec02586ca2",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1734 symbol=kvDataManager_ operation=write. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:33.868778+00:00"
    },
    {
      "id": 160,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "104e86773561ef8b651299e384feaca7b885e797fde10182497d25a61c8a6b22",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1796 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:34.355829+00:00"
    },
    {
      "id": 161,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "0fb76694954ebac3e7bce15837cc222c195c1891e36e313eac17a76453cfb571",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1815 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:34.811976+00:00"
    },
    {
      "id": 162,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "576072aa7bafa4fcd087b464bad83658e30aa814d56820b3497c0a6d3e5af506",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1819 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:35.194470+00:00"
    },
    {
      "id": 163,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3885450251384ad98003288d53754b9f0167cadbd641e552931701b3a872f0d8",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1842 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:35.574516+00:00"
    },
    {
      "id": 164,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "6a7e3d87146acafc5918598e2aef4cc33e30a49c001cc87c2bc0062e658316dd",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1858 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:35.976401+00:00"
    },
    {
      "id": 165,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "9416d20b38025126080104470d87ac6742edd258135bb84742387160ba6b0341",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1867 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:36.567882+00:00"
    },
    {
      "id": 166,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3dbe49a2fafcf22b77b161d8f39881035eb0e80b8b70f58fe6e5105a19c44092",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1893 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:36.976881+00:00"
    },
    {
      "id": 167,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8845747d8b3bf117f9bbd418076f0669911981e4cdae3cae54cd3b4b2857761c",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1894 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:37.393578+00:00"
    },
    {
      "id": 168,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "5871b716a640944bca6aba8998e86ddca0125421ec6fd642419511e191d44848",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1902 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:38.064382+00:00"
    },
    {
      "id": 169,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b1ce58cd506f18297298a68868a0305918d239eada8b4da011209f980d43a711",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1918 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:38.436200+00:00"
    },
    {
      "id": 170,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "3cf3b1cdab1302eab1ef67b8b871e7dac4f2928a0c42a57bb3b85c59f27e5798",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1927 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:38.781883+00:00"
    },
    {
      "id": 171,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "b05ad108365bd02088323f359c3c37beaedea2c22c04e6c0ca0054ace6be3fa6",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1955 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:39.129617+00:00"
    },
    {
      "id": 172,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "8ed8ea3a34ba68a9f650bdd1d3401f4207386dbb8d0e9f5f5680ee441aea2b1f",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1974 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:39.619016+00:00"
    },
    {
      "id": 173,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "da23ac6ad5926d557d13e0a2de2940e9e3a85999ae0176be12929e8920b0f837",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1981 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:40.042833+00:00"
    },
    {
      "id": 174,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "2408dfc95a3e4fc192d3d360a8845d0a893284c941074d66501b1b98846cbd5e",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:1996 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:40.468135+00:00"
    },
    {
      "id": 175,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a7acb883a7fce3ad3ed78f758535300ab52679780eabfe9c416ce4c2e4ee6dd7",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review stable owner pointer shape. file=frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp:2020 symbol=kvDataManager_ operation=read. Hypothesis: The owner is initialized and then read through stable pointer operations; the observed syntax pair is likely owner-race noise. Remaining unknown: Pointee thread safety, safe publication and cross-file owner mutation remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:40.893393+00:00"
    },
    {
      "id": 176,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427",
      "status": "refuted",
      "reviewer": "teammate-A / static review",
      "notes": "Static review non-production mock scope error. file=kvstoremock/external_inner_kit/napi/include/extension_context.h:61 symbol=abilityInfo_ operation=read. Hypothesis: The candidate is outside the production component scope. Remaining unknown: No production vulnerability claim is made from this mock path. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:41.295478+00:00"
    },
    {
      "id": 177,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "de8642d38c52fbba01c43f4d7425d29330fb03e273de8ab740e5b2cc00d2a1d5",
      "status": "refuted",
      "reviewer": "teammate-A / static review",
      "notes": "Static review non-production mock scope error. file=kvstoremock/external_inner_kit/napi/include/extension_context.h:65 symbol=abilityInfo_ operation=write. Hypothesis: The candidate is outside the production component scope. Remaining unknown: No production vulnerability claim is made from this mock path. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:41.653485+00:00"
    },
    {
      "id": 178,
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d",
      "status": "refuted",
      "reviewer": "teammate-A / static review",
      "notes": "Static review non-production mock scope error. file=kvstoremock/external_inner_kit/napi/include/extension_context.h:81 symbol=abilityInfo_ operation=read. Hypothesis: The candidate is outside the production component scope. Remaining unknown: No production vulnerability claim is made from this mock path. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:57:41.999163+00:00"
    }
  ],
  "supplemental_evidence": [
    {
      "id": "c0a92049ff874013a1684d131c8aebd8",
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/distributeddatamgr_kv_store",
      "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
      "git_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
      "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
      "report_sha256": "7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e",
      "file": "frameworks/common/js_proxy.h",
      "blob": "19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46",
      "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
      "start_line": 29,
      "end_line": 45,
      "text": "    ~JSCreator() = default;\n};\n\ntemplate<typename T>\nclass JSProxy {\npublic:\n    void SetInstance(std::shared_ptr<T> instance)\n    {\n        instance_ = std::move(instance);\n    }\n\n    std::shared_ptr<T> GetInstance() const\n    {\n        return instance_;\n    }\n\nprotected:\n",
      "excerpt_sha256": "5ed91d395d51e9a1ca2c5c2742555e567cbd7a93ca6cb8173a8de2797e03f174",
      "note": "JSProxy mutable owner access pair; representative fixed-source context.",
      "created_at": "2026-10-14T15:57:42.964121+00:00"
    },
    {
      "id": "ca5f7a5dca044585b255d1c88c2ec85b",
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/distributeddatamgr_kv_store",
      "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
      "git_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
      "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
      "report_sha256": "7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e",
      "file": "frameworks/common/js_proxy.h",
      "blob": "19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46",
      "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
      "start_line": 34,
      "end_line": 50,
      "text": "public:\n    void SetInstance(std::shared_ptr<T> instance)\n    {\n        instance_ = std::move(instance);\n    }\n\n    std::shared_ptr<T> GetInstance() const\n    {\n        return instance_;\n    }\n\nprotected:\n    // It is not allowed to directly use parent class objects for construction and destruction\n    JSProxy() = default;\n    ~JSProxy() = default;\n\nprivate:\n",
      "excerpt_sha256": "1c88d7c0a1767e77c103e39d020edc045ab0528a3dfa36d6a5ae8265f4f65633",
      "note": "JSProxy mutable owner access pair; representative fixed-source context.",
      "created_at": "2026-10-14T15:57:43.887211+00:00"
    },
    {
      "id": "7a54e19931c24017bad2489f3b78e623",
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "cb1b072294e5ea6098aa9824211d55e7fdc4dadf05f7e3aa33818a6239234634",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/distributeddatamgr_kv_store",
      "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
      "git_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
      "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
      "report_sha256": "7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "blob": "655562b9f0380ac161d8bd20f375bb6a29e9a703",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "start_line": 250,
      "end_line": 266,
      "text": "    int32_t skip_ = 0;\n};\n\nclass ResultSetProxy final : public OHOS::JSProxy::JSCreator<OHOS::DataShare::ResultSetBridge> {\npublic:\n    ResultSetProxy() = default;\n    explicit ResultSetProxy(std::shared_ptr<DistributedKv::KvStoreResultSet> resultSet)\n    {\n        resultSet_ = resultSet;\n    }\n\n    ResultSetProxy operator=(std::shared_ptr<DistributedKv::KvStoreResultSet> resultSet)\n    {\n        if (resultSet_ == resultSet) {\n            return *this;\n        }\n        resultSet_ = resultSet;\n",
      "excerpt_sha256": "602d47eb4a13c30dee2e9104ebf2590792731cd40d74a3582a7459a1e1b2c4b7",
      "note": "stable owner pointer shape; representative fixed-source context.",
      "created_at": "2026-10-14T15:57:44.778775+00:00"
    },
    {
      "id": "c24c67d04fdd4a10b6562564ce39f046",
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a7acb883a7fce3ad3ed78f758535300ab52679780eabfe9c416ce4c2e4ee6dd7",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/distributeddatamgr_kv_store",
      "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
      "git_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
      "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
      "report_sha256": "7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e",
      "file": "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
      "blob": "655562b9f0380ac161d8bd20f375bb6a29e9a703",
      "source_sha256": "30f3515bf5e3ea40296d82b8466011544237f374a0198252cd5117514e306ac3",
      "start_line": 2012,
      "end_line": 2028,
      "text": "        auto observer = std::make_shared<AniObserverUtils::AniServiceDeathObserver>(taiheCallback);\n        kvDataManager_->RegisterKvStoreServiceDeathRecipient(observer);\n        jsDeathCbList_.emplace_back(std::move(observer));\n    }\n\n    void OffDistributedDataServiceDie(::taihe::optional_view<\n        ::taihe::callback<void(::ohos::data::distributedkvstore::OneUndef const& para)>> optCallback)\n    {\n        if (kvDataManager_ == nullptr) {\n            ZLOGE(\"KVManager is null, failed!\");\n            return;\n        }\n        if (!optCallback.has_value()) {\n            ZLOGI(\"SubEvent op=off_all kit=ArkData event=distributedDataServiceDie\");\n        }\n        std::lock_guard<std::recursive_mutex> lock(cbDeathListMutex_);\n        std::optional<AniObserverUtils::JsServiceDeathType> stdOptCallback;\n",
      "excerpt_sha256": "991bd4b1829c9a93a87bcbc132802eef0f2a227512d6f18b47ff67811bc0b353",
      "note": "stable owner pointer shape; representative fixed-source context.",
      "created_at": "2026-10-14T15:57:45.671972+00:00"
    },
    {
      "id": "ade2b207c18e415cb28d21444f0699f0",
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/distributeddatamgr_kv_store",
      "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
      "git_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
      "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
      "report_sha256": "7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e",
      "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
      "blob": "6454f335e87e326ce97bfc405f15347e814aa700",
      "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
      "start_line": 53,
      "end_line": 69,
      "text": "};\n\nclass ExtensionContext : public ContextImpl {\npublic:\n    ExtensionContext() = default;\n    virtual ~ExtensionContext() = default;\n\n    std::shared_ptr<AppExecFwk::AbilityInfo> GetAbilityInfo() const {\n        return abilityInfo_;\n    }\n\n    void SetAbilityInfo(const std::shared_ptr<AppExecFwk::AbilityInfo> &abilityInfo) {\n        abilityInfo_ = abilityInfo;\n    }\n\n    using SelfType = ExtensionContext;\n    static const size_t CONTEXT_TYPE_ID;\n",
      "excerpt_sha256": "6715bfa641913f88dcfb2b45b17d194bbdbe4865a610f0bf8a6541dfecd95db2",
      "note": "non-production mock scope error; representative fixed-source context.",
      "created_at": "2026-10-14T15:57:46.680425+00:00"
    },
    {
      "id": "3f66843d0b53457085f0beacddbf40c1",
      "job_id": "f261748b7eff4144bab9646a6b00b607",
      "candidate_id": "a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/distributeddatamgr_kv_store",
      "commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
      "git_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
      "snapshot_sha256": "a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3",
      "report_sha256": "7b191e16eff0454d64c3d4b9e3ae446f9b1415d1040c3e067d7f3fdf5890de9e",
      "file": "kvstoremock/external_inner_kit/napi/include/extension_context.h",
      "blob": "6454f335e87e326ce97bfc405f15347e814aa700",
      "source_sha256": "fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458",
      "start_line": 73,
      "end_line": 89,
      "text": "};\n\nclass AbilityContext : public Context {\npublic:\n    AbilityContext() = default;\n    virtual ~AbilityContext() = default;\n\n    std::shared_ptr<AppExecFwk::AbilityInfo> GetAbilityInfo() const {\n        return abilityInfo_;\n    }\n\nprotected:\n    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo_;\n};\n\n} // namespace AbilityRuntime\n} // namespace OHOS\n",
      "excerpt_sha256": "0d1388f36bbb305c13afefbfea54e9288e3807d7a246b0e3bcc1e4e53710c982",
      "note": "non-production mock scope error; representative fixed-source context.",
      "created_at": "2026-10-14T15:57:47.586903+00:00"
    }
  ],
  "cases": [
    {
      "id": "8f4e0cae84a54a56a6132f822520967b",
      "title": "distributeddatamgr_kv_store: non-production mock scope error",
      "created_at": "2026-10-14T15:57:48.472474+00:00",
      "status": "investigation",
      "links": [
        {
          "case_id": "8f4e0cae84a54a56a6132f822520967b",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427",
          "rationale": "Review group RC-SCOPE-MOCK; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "8f4e0cae84a54a56a6132f822520967b",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d",
          "rationale": "Review group RC-SCOPE-MOCK; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "8f4e0cae84a54a56a6132f822520967b",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "de8642d38c52fbba01c43f4d7425d29330fb03e273de8ab740e5b2cc00d2a1d5",
          "rationale": "Review group RC-SCOPE-MOCK; candidate-level hypothesis only, not a shared root-cause proof."
        }
      ]
    },
    {
      "id": "2355d54bbfa04ad7873671b929b809e0",
      "title": "distributeddatamgr_kv_store: stable owner pointer shape",
      "created_at": "2026-10-14T15:57:48.156638+00:00",
      "status": "investigation",
      "links": [
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "00452f976acdcaf84be3ab84e3d604c2d35f712e7cd346e97ac8058e5a7ef845",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "0149adbeac200b5be114dd91426b56ee094941ede6c869d630ad4f16c5fd27c2",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "0956f0f09200ba2611bb3c436567dc6b1749c4534c1ba6bca8ca81884e525d84",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "0a4c186985bf9f5ffa1a2eee9fa2522bae19683aa2fb935387688f2983d47c1c",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "0fb76694954ebac3e7bce15837cc222c195c1891e36e313eac17a76453cfb571",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "100e7a581cd8c4071cf51b8584b22eb1f2863879c48f9fef34d9fcaa033b0be8",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "104e86773561ef8b651299e384feaca7b885e797fde10182497d25a61c8a6b22",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "12a1a9a67e75f2f5bbddbf77c65876f239cc1e92e8a5d50cb3192335fbc36c50",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "12bc9847cfe7a1b40d4ecad126ca301cbf75cbcd3ebe08e6c020e6baa07d18dd",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "15026c4aff97ed9f6ac7db4b276b7f480de644333125eb1c3a8953741fbb666a",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "162abaa9d09ad13c1135a7cbb7f89e650b850a09f03400e2ee8572ef970ea222",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "16935c7f570f84c6bb8792480750dbb0d45a1a21eb563c37ddb4dbe87c5d7d10",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "16e3ce73df45ff215bf3bca15335eb5888df29acb24282eb997c322f6ab0d3ad",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "183d2826467a79e9c0d3a2f7c0d067caa8de3a29439d95cabe909f4819a9eb92",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "2408dfc95a3e4fc192d3d360a8845d0a893284c941074d66501b1b98846cbd5e",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "26151d91a658e738c37f68f56527dd3cbf265fbd9eb25f0227fc491198d4710d",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "2baad79d52ed715797b97d46ae32a3f4b1e4318759064abca644ec81a4f7ffc6",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "2c582cc8a3a374f31a2aa96a8a65b04ba3a9424b601a00ef2e836b768dfd4f79",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "2e8c79fbf15d0c6ae995c2a4e84137358038b1b315162852246e6603799954c5",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "2eaa2ee24e5cc6c592b045e867a4a906cb4ab84a0ac7c082bc2fa42c5be9cb3b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "320431e7a4c9c2c5f057c19afafa7e5b0456aaebf14f937fa30c9ec50cee6a54",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "366a1e4dc64c9c0fcdcc34fcca233d8b1beb8d6688a7503949329bf8a5b4f80b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3885450251384ad98003288d53754b9f0167cadbd641e552931701b3a872f0d8",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3a0c2bf9f7011a2f6f6c0b6de62730ce3257cfc4002bc84a5917ede22a64a221",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3a488666e745ce219661b39b1c87ca01c84d8cc8c24ab073dd66299085462260",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3bb34239832c45e2347d4b9f162f5d277f032b335bed681dd9dbed618bd79c29",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3cf3b1cdab1302eab1ef67b8b871e7dac4f2928a0c42a57bb3b85c59f27e5798",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3dbe49a2fafcf22b77b161d8f39881035eb0e80b8b70f58fe6e5105a19c44092",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3e11938b56466f038df0d4e716c4e5906c471ba2b9d01f6a0488490073a8d769",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3e5c5745021e19d4a58579321e4d29de5fec273ac6e79539ea93c34ba43bc9f0",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3e9c370912b06b693b645fb0a6326ea20d24bd1e4236bcd1730e04061b8fb817",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3efc19b712318593d38a3905b846e163d15489be6c4fb875da41e1455616674a",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "3f2176a088b8e5824f7d3a7dabcb162cf46500602b0fe0f75c1b196a3f10fc9a",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "414926d51cbe938eef89771fe982dfedfb6b929513a98d34cb23feeeed3b8885",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "431c52bb47c4a14e2fbbbcc6681fdeab1bb7ec0c490d5e887ee5462e1e114acd",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "44012735b5e45d2b64b9a91aea6fbb03f21b58436b526fbc227d6323d37cbf0b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "45968fffee6735fe7e300d50950cc864496dfdd29de1ddafb58afe3cd2d87c25",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "46b9339a64195f6abf70743ff75b92d4b2c63c8cd69d3456e6040d0ccf71775b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "4862fdc7e64df1946ed7fc9b29ea25625052c2c38f8d0dee09ff4d0e7ddeb391",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "49d7919c361fb4852db86bd985846acfaee57342a1279872609138fad889546e",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "4c454ce2c19567fd24111f0027ea52b66982ca465fef9fa09abed8cb9e033a4b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "4e158172e4c817f7673eb64a0fb5daf2c83dd6189ab548a3d259eaec02586ca2",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "4ee75c339f18fd86f3255f9a617a2697875fd6767e033cf13e9504ee2e37e1f3",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "4f0e31ea3ab696af17bfbd9e177cf0eab95b3e671f986608317084b422e67793",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "500e2fec3ce51c62b648fb350ac6ccacbb9381f8d04a709aa08b84707dbe62ae",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "50301c2e900fcde0dfbbb617dae68f240764b295ca71874f11840971f15de377",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "52aabbd4ab2b7c9f5729b6974fd06c434e7ac5c7f03225b516298af0ab4293ad",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "53127440c42012aacf845bcc1a50adbdc63dae963c0dab242fbc75a2b55d52f3",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "576072aa7bafa4fcd087b464bad83658e30aa814d56820b3497c0a6d3e5af506",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5871b716a640944bca6aba8998e86ddca0125421ec6fd642419511e191d44848",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "58a4124e0bdbce2ef9c13776063a483d2671e034ece8c82a497a13582ad25ca7",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5918fb138ce999a3c9aaa05f7de50fcfb853bdaf7ccbad514b96b46abaf2b7ef",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "59b07923e50cde1ed3ddc4649670267baae70b731ab95ca92460ef8fef21f887",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5c15e924f3dd6b1ac7c4c6d163fac79d90440728da43268350a6e56e5f6b2826",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5c703b5605ad3775b5cdfa2ff9aa3d03ad87091e3aa546e419de1e945ff27ddc",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5c8ef925cedbaf353bcd5a477591cca716333abd11693fc6bee4486920bb0a3b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5d5edcc0cdba73611ef96eb6dd0a6996abeae913108308e868082dd62e7a2bc7",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5dd064428a3b77c175b6da2f5e4c0db4dbecfaba1d6ee04f9980e031fc93d464",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "5ec6a1a3b8cd55cabebafbcc167c3d35fdd287c893ee41e7974e8f4e5ccd49a8",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "6010deb3893210e8200ccdf9c8401f482553ef38df1f339b87b96a4b7bf1f4cf",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "60664abdedccd193f9ec82a17e97f8b5d327d707fec71305f23b07e751cb7ded",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "6228117e25e509dbdd602990058e60a5027f66007a08a1222783e48898a2ff43",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "6475408e7217ec97b0b83c74ceeff86874476d1ce1c27c60e940b374555ec235",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "65e0d0f9bffa49e7cd5bf62b37cd39284d3ae334a90f232b16a285f3db365d48",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "6655f7eb0f547c6e38216a4273d7bf09999ba5b22340526b4a9cf1169722f2b6",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "674a2c4199f6a6f6bd809f46dfea1922aa6c8b9772e76bdb5c10418103eac0ac",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "6a7e3d87146acafc5918598e2aef4cc33e30a49c001cc87c2bc0062e658316dd",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "6c1e4b3d0e42c3afc11385dc669beebd2314437ab77e50afddd2dd5bd1fa27e1",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "6c919ee76d43a584e225bfa9e5ac462a2237592faed435f182229d53daa6565a",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "72a35d29243d137aaaa688185a1dca42bc28adc9969e76558888ce45064864a6",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "74ef285430703348f9139aef2c70c911f5793021be003f75ce6e6b880ae06822",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "757791f31e555967b69c66b83df0a638282dbbd6bde77073ac27c497064e4181",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "78b1d5185e7140d1f10f70c3a1b218ebc929aba764b11250f7673d5b82426182",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "7a6e968299b9e87796ee8c4c0a881357b28572db011bd57182ba2159190f8156",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "7c7fa88aee077807172dba7e5ec35049e7f13070857c262018691bf9b632b695",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "7f97fd6a1ccd7ef628597f339cd692c81753e52705d7ed81cd4790cab7d82da6",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8121a37037cbf9c2065780e7f602120e83c78d580a79bba3464b35cb8087bf27",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "846d3e4284dd8d9a4b933465a61c536a25e07f39fbab21fbc5d499863c0a822b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8735c7de49933f19beb420f8650ba8fc79db5bbad146248ac5d517a9e853436f",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8845747d8b3bf117f9bbd418076f0669911981e4cdae3cae54cd3b4b2857761c",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "88cca30b1a8adacb2374a5655ac3b1a61f5058ab08de7405750a42692695e1b7",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "88e271f51563aca52ae087fcc0fc1191c56c1042a1ecebcd6dbaf25d0bb0d82a",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8933a4ae1be49b4e737b339cefde497b5375dc026f97c969dc5127fb3972bad1",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "894e199899841721ae7535a098f4cb02cf725a03f18cd84b4a6ee44af7b0477f",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8a2c9d4ad7d62deac77df87b77a46016e55d13cb6f478e8c0ca034744ca5440e",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8b5d9986956a784d93a01230239dc82e4336c492eccf1d8cc45bdcbac6dd5b9f",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8bb1b434861ae3b5ea849b3b473be974ab2818d175b11c91a5cbeeea6ce3684d",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8c11dd07d416258af8b0242b9fde5469f6dcf3d2022806eb04ac3a15b7f81bfb",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8e6f36bea1ea41ec7523efb847079771f35b13813bcf8ebea332a7fba27c9ee9",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "8ed8ea3a34ba68a9f650bdd1d3401f4207386dbb8d0e9f5f5680ee441aea2b1f",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "920321558ecadefdfa30105c7160026e0b36e7949eb7efe54cf751f1b776d080",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "92347244ece9626b21dbde8c5ccd59074cb96d35ab4f3836c5b07aacdcb5da62",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "93b46419caf2f299c06aa6b28fdaebe4dcb9327ca9552dc871a70d99336cac2e",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "9406ba7bd6b4fa176ca610f844621e677a900b37a4edd6674a9cbd6df4b9ca79",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "9416d20b38025126080104470d87ac6742edd258135bb84742387160ba6b0341",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "9617843ed75680d9e6685ae7b9b4dbd1c084fe07726ed861582eb3e5c2d5cf0b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "961fb9266af46dc98cd6ca279e9c383df07f7da2be97c350b95884b29b045439",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "9c2d08816fa34410ea0972b8b9e1cf28e9ab8ec7095e5f3ab0ae98f61d768d1b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "9d5eb3f7f9d679b8a2ce1a991c173ddc434f7695e534c24a96d1d407ef117eac",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "9f071d0ea5ef227b5308f6ff1125d0b1a9c382bc16a56012da8703a3eceab1a7",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "9fda549fe2abbd9f23d69dfcd34592aa4b99b2ec54b61c8dca80560380efbf07",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a0a4986714f00c59597aae54d2434c28a46ea15a4d5c7aada4bc893b98ea2930",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a1ef992f5e34c4515753188bc7b9680f0ff1c74c107e5863948f15ca53a5b18c",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a264651eaf014d33f5186cd6b1b3dbd85124e1d2c1b875c71a2c17b133f34fa5",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a3f4f5ef843b321f530f7ccfe7df5fb97c0d3cb326e2d6b9c206ee86a4e1300b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a488f4ab06c4a0d541d53fec872c53a282643919af145a4de23833d8e4819305",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a75745889350d77b70c27be277b6b58dbd4fd82ac3476adfce65e1f6052d727c",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a7a71c42c81ca627bebebfa9c772dd4903e51487ec732ef2f658179053473518",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "a7acb883a7fce3ad3ed78f758535300ab52679780eabfe9c416ce4c2e4ee6dd7",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "ad005f622f408005298ba5111993b7c5815223075e96760350a1727ec3fb1a48",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "ad49658fe262eca8f28889b32d0fcc0bbb88f20e3b8624e2439d86ed78bf4fc7",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "ae12f8851f7ba3886c43b9986efea0bd49b96eca0a3b193adc6c121ea86c8c07",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "ae441ca488b9cf4ca160a7d3e8e940b5e7505b188d05d3d8e0477930637567c2",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b05ad108365bd02088323f359c3c37beaedea2c22c04e6c0ca0054ace6be3fa6",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b1ce58cd506f18297298a68868a0305918d239eada8b4da011209f980d43a711",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b31b8ff006bbf5d4c49e37c232548e38f537beb884562cc33726a828c9ecfc98",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b33b71235ec5ccc363722609cffd85d0f34fbd317ac23bc5b51d93e2ea9f492b",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b52f780eb3d033046e527fed5d2e7cafb8946d2f46d9d1f12832f481fac512d5",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b59d5a04676f466381ee87f4e94c0b16a5a56c610c0b54056bce7f6376f35ab9",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b686180c6212111b3e2a913a748c66cfad5bc2429bb09bf6329c9351b46336ab",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b6d501602b7ff517eb43b98fda8314c9aeb401ca48509d208921c0f4c9ded6bd",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b6dfa4c7a6a560f3d81c84b56813faaad70120043b069782739e131175067977",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b7ca55f4cda2625d68e8461395ff1e84a8da47187026c1e0268fbec439ee65a5",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b82e3904cfad67f3b7b5af31affba1f20165262fba4006be763848681bc201f0",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b82f221343747d9a230c72ff02da8857549127f6d9e33245d336536db86910cd",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b86e2331f0234c040436cf2dbf47f46a54a24fc3b3800c3c8e1d7b478975263d",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "b94a81321e1f40dfd83f14f4160c077d137aad238cd066cc6f086dcf846eabeb",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "bbbdf87e34a8a442e80c6c82ef44f387da159e57eb1882960fbf0c15fabf1bad",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "bbeb1f8460888494be92c0a90a43ff041689d133eb5d1a7a450d26d1bbd3928d",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "bd27621de428d95416e922df5dcc5a535edf92d320525b761c54437a5d196d17",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "becc573683c5219a292e3db99d9d5cae83b98228088021cdd852d1db20512367",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "bf139b0d2affe71cd97453b54fd6f8cdb35241d3cdf5597e10c7e3e0773d694e",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "c2b970ab85569108df223514ededf95e9c68811a0dcf59145368aa9e1b7ab375",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "c58b077ed141dbd140faa465f156f6b7f9bb884935f67361fb10ca46a066f1a6",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "c59864ef57f4aa43fd393bcd55c558e5bf46e450fc574795a1b1c9cb4f01474d",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "c7466864946c7354ee3b3fbead4ee32fd35798dada8a89707ea42046d799d2f7",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "ca578e6173fce696a7bbd381df0ee7ed17a78d30273923c1535b326cd3ca0f46",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "caf4378be168e521dc676b2bb3984ead03f77f93d311d7a3f354339fc87ec7fd",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "cb1b072294e5ea6098aa9824211d55e7fdc4dadf05f7e3aa33818a6239234634",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "cc80465e47c15e119028290af6cdc9feb3d43760ddfc2fc241c8c5ba39b6b3a2",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "ce9d70d3f718a91b16d66492b99ea314d873cdad902105dd5f223ae2267fc7ed",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "cf3c3df489359923ef8d28a2ffd9fcde690d40b39b26bf41e285b7e9eeb53c1d",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "d0d9b0c87cbbbc0b154094c05e39ef78bf3a10972c72f959e692e5c7849cfdf3",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "d42f02b32da804b9542ab35e78356819aad693cccb2eff7125732ff60f0f853c",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "d5ce02864994a006be5b90a37a1adf9dddc6336adb147acf64eff3322ae1302d",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "da23ac6ad5926d557d13e0a2de2940e9e3a85999ae0176be12929e8920b0f837",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "dc5cffc99e88566d11549efa89c6a2f992792878ffac93798ba14b3fe2837022",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "dc7efdb54320398868215127faba0a7b5782e47109a545b57bb47336b7ca6965",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "de280c2bd4691453ed3459ea5f3990f3bff07621b2f5635bafa715d8e631b919",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "df8006c227df76596278d48014c85684f56378b3a5ea44fc561683c2e707a747",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "e64c38c5df64b7eb416d192cc281327e6321d5ff4c779f8d3708a6203f728735",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "e6bbeefad94d495de70e52fcf89a4957c302984970c517d48f3ec39a12abf0be",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "ef9c239936f0c7b6248a08079c51c8d5bb972ec5371d4794f0951328cd939d01",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "f012219b7b3a917f491f01cd25f79775accc71d3d19ef5025b5b32ecdd27c4ac",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "f2fad86e6aaf4320e4b63c734f9bb49218f2ce888e82f5576c100e1f6984011a",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "f336d5b55665879b4e2c3d8a59851c9e90625e8b3c2cd3b602b7bfa4504e7566",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "f573967fad0f63a851f15ba4bd054aa2bfc90c75d59bec7308c672397f325dd9",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "f693888bbc9048b9a1f784520eb88cce32ab4e7a58b9630f92f76014b8eb7cb0",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "f8d32ae78baab0512f4157a2fb7b140656ccc0be27ce98e7084bb79a1ebc1844",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "f8eb7a888b41ce64a0d8c031d830b6c01aab2ba86bda6d3810e2ded34f358418",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "fb240d277bb20a4eac0baf3cb2173ec5eafc13e1d1f1d8f9851165d932e6cc50",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "2355d54bbfa04ad7873671b929b809e0",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "fca8475ad6454679af534ba3a13e7da330c27d706e2418705bf1d622965b1638",
          "rationale": "Review group RC-KV-OWNER; candidate-level hypothesis only, not a shared root-cause proof."
        }
      ]
    },
    {
      "id": "11a6ee64deaf4b329aedb2ce0a67b556",
      "title": "distributeddatamgr_kv_store: JSProxy mutable owner access pair",
      "created_at": "2026-10-14T15:57:47.868826+00:00",
      "status": "investigation",
      "links": [
        {
          "case_id": "11a6ee64deaf4b329aedb2ce0a67b556",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef",
          "rationale": "Review group RC-JSPROXY; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "11a6ee64deaf4b329aedb2ce0a67b556",
          "job_id": "f261748b7eff4144bab9646a6b00b607",
          "candidate_id": "844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c",
          "rationale": "Review group RC-JSPROXY; candidate-level hypothesis only, not a shared root-cause proof."
        }
      ]
    }
  ],
  "validated_vulnerability": 0,
  "limitations": [
    "Manual annotations and case links are not vulnerability confirmation.",
    "No runtime validation or product impact gate implemented in workbench v1."
  ]
}
~~~~

# OHScanner 审计复核包

候选与复核记录；不是已确认漏洞报告。

- Commit: 17d88bfb36bea6c9370ba919ac41a22d16dd66b3
- 原始报告 SHA-256: 574cbe3549ce106f32854052da214f14d254076a0199d4c186838b1faa8289cd
- 候选: 10
- 确认漏洞: 0

## 复核记录（结构化原文）

~~~~json
{
  "schema_version": 1,
  "kind": "workbench_review_bundle",
  "job_id": "3097947a93074475abe9c01088d948bb",
  "repository": "openharmony/security_access_token",
  "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
  "git_tree": "4621b3e40b31a958a4bbe9be87690afb6cec44b0",
  "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
  "scanner_report_sha256": "574cbe3549ce106f32854052da214f14d254076a0199d4c186838b1faa8289cd",
  "findings": [
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d8af1c4db4ad6579",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/cj/accesstoken/include/at_manager_impl.h",
      "line": 115,
      "column": 86,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''data_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "data_",
      "source_sha256": "287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d8af1c4db4ad6579",
        "file": "interfaces/kits/cj/accesstoken/include/at_manager_impl.h",
        "source_sha256": "287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/cj/accesstoken/include/at_manager_impl.h",
          "source_sha256": "287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a2e8ea87344f261f",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h",
      "line": 51,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''asyncContextPtr''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "asyncContextPtr",
      "source_sha256": "1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "93c2385311e2c10ecbfe8c0f78776474bc6264b5cbd0baeb50e33caaf4aeeb30",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:a2e8ea87344f261f",
        "file": "interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h",
        "source_sha256": "1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h",
          "source_sha256": "1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:089c58a01b3a66a8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h",
      "line": 49,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''asyncContextPtr''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "asyncContextPtr",
      "source_sha256": "a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "a1278c524438add8635a68621e5f4b9d5bd8b9f98775d34ab6f8d39b783dc116",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:089c58a01b3a66a8",
        "file": "interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h",
        "source_sha256": "a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h",
          "source_sha256": "a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d9832942dc24a7fd",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h",
      "line": 61,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''asyncContextPtr''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "asyncContextPtr",
      "source_sha256": "01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "16da132f19039393f70288746451ca9bf29f3276beb08e9f4819448d60c6c710",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:d9832942dc24a7fd",
        "file": "interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h",
        "source_sha256": "01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h",
          "source_sha256": "01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9f15e9ed288e908f",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h",
      "line": 68,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''asyncContextPtr''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "asyncContextPtr",
      "source_sha256": "96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "25ed03d67f1c9d5397936181c95cf65131311f145f8a9f42cd358eef8b4bf122",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9f15e9ed288e908f",
        "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h",
        "source_sha256": "96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h",
          "source_sha256": "96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3b5c55b6b40da278",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h",
      "line": 72,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''asyncContextPtr''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "asyncContextPtr",
      "source_sha256": "ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "2c8c1796905c2ba3189b24ea3fb4537419cfc3fa215adebc63b65a36bffba8bc",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3b5c55b6b40da278",
        "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h",
        "source_sha256": "ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h",
          "source_sha256": "ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6b05864947153293",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h",
      "line": 117,
      "column": 71,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''data_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "data_",
      "source_sha256": "ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "21a7bd798474558ed52232e03e58ace103497d48a30fb6f5b11a0f3cf8df66b4",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:6b05864947153293",
        "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h",
        "source_sha256": "ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h",
          "source_sha256": "ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:104a194d0e487cc4",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h",
      "line": 63,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''asyncContextPtr''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "asyncContextPtr",
      "source_sha256": "c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:104a194d0e487cc4",
        "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h",
        "source_sha256": "c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h",
          "source_sha256": "c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9206921efb49a379",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
      "line": 37,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''ptrChannel_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "ptrChannel_",
      "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:9206921efb49a379",
        "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
        "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
          "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3bac2f99cba097b8",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
      "line": 41,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''ptrChannel_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "ptrChannel_",
      "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3bac2f99cba097b8",
        "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
        "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/security_access_token",
          "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
          "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
          "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7"
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
      "id": 2,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/cj/accesstoken/include/at_manager_impl.h:115 symbol=data_ operation=read. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:27.759721+00:00"
    },
    {
      "id": 3,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "93c2385311e2c10ecbfe8c0f78776474bc6264b5cbd0baeb50e33caaf4aeeb30",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h:51 symbol=asyncContextPtr operation=write. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:28.131098+00:00"
    },
    {
      "id": 4,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "a1278c524438add8635a68621e5f4b9d5bd8b9f98775d34ab6f8d39b783dc116",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h:49 symbol=asyncContextPtr operation=write. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:28.448495+00:00"
    },
    {
      "id": 5,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "16da132f19039393f70288746451ca9bf29f3276beb08e9f4819448d60c6c710",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h:61 symbol=asyncContextPtr operation=write. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:28.787054+00:00"
    },
    {
      "id": 6,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "25ed03d67f1c9d5397936181c95cf65131311f145f8a9f42cd358eef8b4bf122",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h:68 symbol=asyncContextPtr operation=write. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:29.117481+00:00"
    },
    {
      "id": 7,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "2c8c1796905c2ba3189b24ea3fb4537419cfc3fa215adebc63b65a36bffba8bc",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:72 symbol=asyncContextPtr operation=write. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:29.430865+00:00"
    },
    {
      "id": 8,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "21a7bd798474558ed52232e03e58ace103497d48a30fb6f5b11a0f3cf8df66b4",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:117 symbol=data_ operation=read. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:29.760101+00:00"
    },
    {
      "id": 9,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review constructor or single lexical access noise. file=interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h:63 symbol=asyncContextPtr operation=write. Hypothesis: The observed access is initialization or a single lexical access, not a proven conflicting pair. Remaining unknown: Cross-file mutation, publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:30.223693+00:00"
    },
    {
      "id": 10,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b",
      "status": "plausible_unproven",
      "reviewer": "teammate-A / static review",
      "notes": "Static review RemoteCommandExecutor channel owner pair. file=services/tokensyncmanager/include/remote/remote_command_executor.h:37 symbol=ptrChannel_ operation=read. Hypothesis: Repository call sites are under RemoteCommandManager::mutex_, but GetChannel returns a member reference. Remaining unknown: External callers, reference lifetime and product thread ownership remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:30.740738+00:00"
    },
    {
      "id": 11,
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b",
      "status": "plausible_unproven",
      "reviewer": "teammate-A / static review",
      "notes": "Static review RemoteCommandExecutor channel owner pair. file=services/tokensyncmanager/include/remote/remote_command_executor.h:41 symbol=ptrChannel_ operation=write. Hypothesis: Repository call sites are under RemoteCommandManager::mutex_, but GetChannel returns a member reference. Remaining unknown: External callers, reference lifetime and product thread ownership remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T15:52:31.129082+00:00"
    }
  ],
  "supplemental_evidence": [
    {
      "id": "c97e059a48a4475e89858b6a42993224",
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/security_access_token",
      "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
      "git_tree": "4621b3e40b31a958a4bbe9be87690afb6cec44b0",
      "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
      "report_sha256": "574cbe3549ce106f32854052da214f14d254076a0199d4c186838b1faa8289cd",
      "file": "interfaces/kits/cj/accesstoken/include/at_manager_impl.h",
      "blob": "93c786e28ddd7dc390dbe6a2f24c784cb2f9a872",
      "source_sha256": "287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1",
      "start_line": 107,
      "end_line": 123,
      "text": "\nprivate:\n    int32_t sessionId_ = 0;\n    std::shared_ptr<RequestAsyncContext> reqContext_ = nullptr;\n};\n\nclass AuthorizationResult : public Security::AccessToken::TokenCallbackStub {\npublic:\n    explicit AuthorizationResult(const std::shared_ptr<RequestAsyncContext>& data) : data_(data) {}\n    ~AuthorizationResult() override = default;\n    void GrantResultsCallback(const std::vector<std::string>& permissions,\n        const std::vector<int>& grantResults) override;\n\nprivate:\n    std::shared_ptr<RequestAsyncContext> data_ = nullptr;\n};\n\n",
      "excerpt_sha256": "80dbbdbf32c562deea54134683f567b512032b23ef7ec4cfcdcc0e5b433146cf",
      "note": "constructor or single lexical access noise; representative fixed-source context.",
      "created_at": "2026-10-14T15:52:32.084975+00:00"
    },
    {
      "id": "47894fab38114b43b1ec4f480e61e5ea",
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/security_access_token",
      "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
      "git_tree": "4621b3e40b31a958a4bbe9be87690afb6cec44b0",
      "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
      "report_sha256": "574cbe3549ce106f32854052da214f14d254076a0199d4c186838b1faa8289cd",
      "file": "interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h",
      "blob": "7828aceaf6d50c98c2b70d49f7ea17bda654a982",
      "source_sha256": "c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560",
      "start_line": 55,
      "end_line": 71,
      "text": "    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;\n#endif\n    int32_t contextType_ = static_cast<int32_t>(REQUEST_PERMISSION_ON_SETTING);\n};\n\nstruct RequestOnSettingAsyncContextHandle {\n    explicit RequestOnSettingAsyncContextHandle(std::shared_ptr<RequestPermOnSettingAsyncContext>& requestAsyncContext)\n    {\n        asyncContextPtr = requestAsyncContext;\n    }\n\n    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContextPtr;\n};\n\nclass RequestOnSettingAsyncInstanceControl {\n    public:\n        static void AddCallbackByInstanceId(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext);\n",
      "excerpt_sha256": "844a74b10eadef96d408f58d8fbf589711a7e2e2d287129cd60cf51bdf1794f6",
      "note": "constructor or single lexical access noise; representative fixed-source context.",
      "created_at": "2026-10-14T15:52:32.918635+00:00"
    },
    {
      "id": "81b50d33b31141118b1ba9dfb0830f24",
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/security_access_token",
      "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
      "git_tree": "4621b3e40b31a958a4bbe9be87690afb6cec44b0",
      "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
      "report_sha256": "574cbe3549ce106f32854052da214f14d254076a0199d4c186838b1faa8289cd",
      "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
      "blob": "f5f6974f1d47ed2456af573b62e975e28e499276",
      "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7",
      "start_line": 29,
      "end_line": 45,
      "text": "namespace AccessToken {\r\nclass RemoteCommandExecutor final : public std::enable_shared_from_this<RemoteCommandExecutor>  {\r\npublic:\r\n    explicit RemoteCommandExecutor(const std::string &targetNodeId);\r\n    virtual ~RemoteCommandExecutor();\r\n\r\n    const std::shared_ptr<RpcChannel>& GetChannel() const\r\n    {\r\n        return ptrChannel_;\r\n    }\r\n    void SetChannel(const std::shared_ptr<RpcChannel>& ptrChannel)\r\n    {\r\n        ptrChannel_ = ptrChannel;\r\n    }\r\n\r\n    /**\r\n     * @brief Factory method to create a rpc channel. we will only create SoftBusChannel by now.\r\n",
      "excerpt_sha256": "f5f709692e738adc24d1c16c2745e61cb1fe1ec122360c67b7ac378a740cb3fe",
      "note": "RemoteCommandExecutor channel owner pair; representative fixed-source context.",
      "created_at": "2026-10-14T15:52:33.749433+00:00"
    },
    {
      "id": "0445007773d14851934c8a14d2a6e97f",
      "job_id": "3097947a93074475abe9c01088d948bb",
      "candidate_id": "5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/security_access_token",
      "commit": "17d88bfb36bea6c9370ba919ac41a22d16dd66b3",
      "git_tree": "4621b3e40b31a958a4bbe9be87690afb6cec44b0",
      "snapshot_sha256": "ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d",
      "report_sha256": "574cbe3549ce106f32854052da214f14d254076a0199d4c186838b1faa8289cd",
      "file": "services/tokensyncmanager/include/remote/remote_command_executor.h",
      "blob": "f5f6974f1d47ed2456af573b62e975e28e499276",
      "source_sha256": "2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7",
      "start_line": 33,
      "end_line": 49,
      "text": "    virtual ~RemoteCommandExecutor();\r\n\r\n    const std::shared_ptr<RpcChannel>& GetChannel() const\r\n    {\r\n        return ptrChannel_;\r\n    }\r\n    void SetChannel(const std::shared_ptr<RpcChannel>& ptrChannel)\r\n    {\r\n        ptrChannel_ = ptrChannel;\r\n    }\r\n\r\n    /**\r\n     * @brief Factory method to create a rpc channel. we will only create SoftBusChannel by now.\r\n     *\r\n     * @param targetNodeId target device node id(udid)\r\n     * @return Returns <b>a shared_ptr</b> if the operation is successful, returns <b>nullptr</b> otherwise.\r\n     * @see SoftBusChannel\r\n",
      "excerpt_sha256": "49c18a34af090f8275606b53951a3169a3731f67a2ac0e27e58f1464ef2a42f2",
      "note": "RemoteCommandExecutor channel owner pair; representative fixed-source context.",
      "created_at": "2026-10-14T15:52:34.536391+00:00"
    }
  ],
  "cases": [
    {
      "id": "f9cc30666a2546cf8f78aaf982890abb",
      "title": "security_access_token: RemoteCommandExecutor channel owner pair",
      "created_at": "2026-10-14T15:52:35.119778+00:00",
      "status": "investigation",
      "links": [
        {
          "case_id": "f9cc30666a2546cf8f78aaf982890abb",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b",
          "rationale": "Review group RC-REMOTE-CHANNEL; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "f9cc30666a2546cf8f78aaf982890abb",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b",
          "rationale": "Review group RC-REMOTE-CHANNEL; candidate-level hypothesis only, not a shared root-cause proof."
        }
      ]
    },
    {
      "id": "e7f2dcd9350342ccaf99e54b89c756f9",
      "title": "security_access_token: constructor or single lexical access noise",
      "created_at": "2026-10-14T15:52:34.807815+00:00",
      "status": "investigation",
      "links": [
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "16da132f19039393f70288746451ca9bf29f3276beb08e9f4819448d60c6c710",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "21a7bd798474558ed52232e03e58ace103497d48a30fb6f5b11a0f3cf8df66b4",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "25ed03d67f1c9d5397936181c95cf65131311f145f8a9f42cd358eef8b4bf122",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "2c8c1796905c2ba3189b24ea3fb4537419cfc3fa215adebc63b65a36bffba8bc",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "93c2385311e2c10ecbfe8c0f78776474bc6264b5cbd0baeb50e33caaf4aeeb30",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "a1278c524438add8635a68621e5f4b9d5bd8b9f98775d34ab6f8d39b783dc116",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "e7f2dcd9350342ccaf99e54b89c756f9",
          "job_id": "3097947a93074475abe9c01088d948bb",
          "candidate_id": "cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495",
          "rationale": "Review group RC-CONSTRUCTOR-NOISE; candidate-level hypothesis only, not a shared root-cause proof."
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

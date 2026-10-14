# OHScanner 审计复核包

候选与复核记录；不是已确认漏洞报告。

- Commit: 652f88e0261ce4d0610f73cc451c26b84d2597af
- 原始报告 SHA-256: 0b49b21edbf4f65731f5840650fbaee0f1f6030cc700b8a40cf4e4dc1259868e
- 候选: 3
- 确认漏洞: 0

## 复核记录（结构化原文）

~~~~json
{
  "schema_version": 1,
  "kind": "workbench_review_bundle",
  "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
  "repository": "openharmony/communication_dsoftbus",
  "commit": "652f88e0261ce4d0610f73cc451c26b84d2597af",
  "git_tree": "f8a14c30ef815217fa4d267939cff84db1fd5057",
  "snapshot_sha256": "5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7",
  "scanner_report_sha256": "0b49b21edbf4f65731f5840650fbaee0f1f6030cc700b8a40cf4e4dc1259868e",
  "findings": [
    {
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3a00ec7ac4a80075",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
      "line": 67,
      "column": 86,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''streamListener_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "streamListener_",
      "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:3a00ec7ac4a80075",
        "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
        "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/communication_dsoftbus",
          "commit": "652f88e0261ce4d0610f73cc451c26b84d2597af",
          "snapshot_sha256": "5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
          "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:fec8a84569dd9290",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
      "line": 93,
      "column": 9,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member write of ''msgManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "msgManager_",
      "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "34b5ae7d82474f0dd15f9274b14a620b5f333392c14aa67e6c871cbcee62d7b8",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:fec8a84569dd9290",
        "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
        "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/communication_dsoftbus",
          "commit": "652f88e0261ce4d0610f73cc451c26b84d2597af",
          "snapshot_sha256": "5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
          "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100"
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
      "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4b71fdc86ef47d7c",
      "provider": "ohscanner.cpp.shared_ptr_race",
      "evidence_type": "syntax",
      "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
      "line": 97,
      "column": 16,
      "rule_id": "ohcpp-shared-ptr-race-candidate-001",
      "severity": "unassessed",
      "message": "Candidate only: candidate/unknown non-atomic shared_ptr member read of ''msgManager_''. Primary candidate root cause is a possible race condition (CWE-362); CWE-416/use-after-free is only a possible consequence. This syntax evidence does not prove UAF, guard dominance, concurrent interleaving, attacker control, or security impact; it is not proof of safety.",
      "candidate_cwe": "CWE-362",
      "confidence": "unassessed",
      "symbol": "msgManager_",
      "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
      "consequence_impact": null,
      "consequence_cwe": null,
      "source_binding": "bound",
      "id": "d4f6c83d4d77c5fbbda5e1f1871be665c386f2ede09da177f6c2814f083469bf",
      "detector_id": "ohscanner.cpp.shared_ptr_race",
      "detector_version": "0.4.0",
      "evidence": {
        "diagnostic_id": "ohscanner.cpp.shared_ptr_race:4b71fdc86ef47d7c",
        "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
        "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
        "analysis_status": "analyzed",
        "source_binding": {
          "repository": "openharmony/communication_dsoftbus",
          "commit": "652f88e0261ce4d0610f73cc451c26b84d2597af",
          "snapshot_sha256": "5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7",
          "profile_id": "light-ast",
          "detector_id": "ohscanner.cpp.shared_ptr_race",
          "detector_version": "0.4.0",
          "rule_id": "ohcpp-shared-ptr-race-candidate-001",
          "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
          "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100"
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
      "id": 206,
      "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
      "candidate_id": "1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7",
      "status": "plausible_unproven",
      "reviewer": "teammate-A / static review",
      "notes": "Static review StreamManager listener cross-file mutation. file=sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67 symbol=streamListener_ operation=read. Hypothesis: streamListener_ is initialized in the header and reassigned in stream_manager.cpp without a lexical lock. Remaining unknown: Cross-file call ordering, event-loop ownership and feasible concurrent interleaving remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T16:07:37.037005+00:00"
    },
    {
      "id": 207,
      "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
      "candidate_id": "34b5ae7d82474f0dd15f9274b14a620b5f333392c14aa67e6c871cbcee62d7b8",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review StreamManager manager pointer publication shape. file=sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:93 symbol=msgManager_ operation=write. Hypothesis: The manager pointer is set before factory return and no repository-local getter mutation was observed. Remaining unknown: Product publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T16:07:37.432718+00:00"
    },
    {
      "id": 208,
      "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
      "candidate_id": "d4f6c83d4d77c5fbbda5e1f1871be665c386f2ede09da177f6c2814f083469bf",
      "status": "likely_false_positive",
      "reviewer": "teammate-A / static review",
      "notes": "Static review StreamManager manager pointer publication shape. file=sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:97 symbol=msgManager_ operation=read. Hypothesis: The manager pointer is set before factory return and no repository-local getter mutation was observed. Remaining unknown: Product publication and pointee thread safety remain unknown. Evidence obligations: [{\"description\": \"Resolve lock and atomic semantics across all accesses.\", \"kind\": \"synchronization_proof\", \"status\": \"unknown\"}, {\"description\": \"Demonstrate feasible concurrent accesses to the same object.\", \"kind\": \"thread_interleaving\", \"status\": \"unknown\"}, {\"description\": \"Establish real build and template instantiation context.\", \"kind\": \"product_build_context\", \"status\": \"unknown\"}, {\"description\": \"Verify reachable trigger and concrete CIA impact independently.\", \"kind\": \"security_impact\", \"status\": \"unknown\"}]. This review is candidate-level analysis, not confirmed/reportable evidence.",
      "created_at": "2026-10-14T16:07:37.817548+00:00"
    }
  ],
  "supplemental_evidence": [
    {
      "id": "7c04b5caf8964de7bd9fcaefb092490d",
      "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
      "candidate_id": "1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/communication_dsoftbus",
      "commit": "652f88e0261ce4d0610f73cc451c26b84d2597af",
      "git_tree": "f8a14c30ef815217fa4d267939cff84db1fd5057",
      "snapshot_sha256": "5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7",
      "report_sha256": "0b49b21edbf4f65731f5840650fbaee0f1f6030cc700b8a40cf4e4dc1259868e",
      "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
      "blob": "1f8eb2e331021766be3485a3b56746c074be4687",
      "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
      "start_line": 59,
      "end_line": 75,
      "text": "        {\n            listener_->OnRippleStats(data);\n        }\n\n    private:\n        std::shared_ptr<IStreamManagerListener> listener_ = nullptr;\n    };\n\n    explicit StreamManager(std::shared_ptr<IStreamManagerListener> streamListener) : streamListener_(streamListener) {}\n    StreamManager() = delete;\n    virtual ~StreamManager() = default;\n\n    int32_t CreateStreamClientChannel(IpAndPort &local, IpAndPort remote, Proto protocol,\n        int32_t streamType, std::pair<uint8_t*, uint32_t> sessionKey) override;\n\n    int32_t CreateStreamServerChannel(IpAndPort &local, Proto protocol, int32_t streamType,\n        std::pair<uint8_t*, uint32_t> sessionKey) override;\n",
      "excerpt_sha256": "1ec59785b73c9dc4f1664c0066a54c0dc8d7f3fc5274f1e9cd02a0cb018c6488",
      "note": "StreamManager listener cross-file mutation; representative fixed-source context.",
      "created_at": "2026-10-14T16:07:38.738805+00:00"
    },
    {
      "id": "3101c38b15f849ad87e8ed6db3eedd8b",
      "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
      "candidate_id": "34b5ae7d82474f0dd15f9274b14a620b5f333392c14aa67e6c871cbcee62d7b8",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/communication_dsoftbus",
      "commit": "652f88e0261ce4d0610f73cc451c26b84d2597af",
      "git_tree": "f8a14c30ef815217fa4d267939cff84db1fd5057",
      "snapshot_sha256": "5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7",
      "report_sha256": "0b49b21edbf4f65731f5840650fbaee0f1f6030cc700b8a40cf4e4dc1259868e",
      "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
      "blob": "1f8eb2e331021766be3485a3b56746c074be4687",
      "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
      "start_line": 85,
      "end_line": 101,
      "text": "    StreamAttr GetOption(int32_t type) const override;\n\n    void SetStreamRecvListener(std::shared_ptr<IStreamManagerListener> recvListener) override;\n    bool PrepareEnvironment(const std::string &pkgName) override;\n    void DestroyEnvironment(const std::string &pkgName) override;\n\n    void SetStreamMsgManager(std::shared_ptr<IStreamMsgManager> manager)\n    {\n        msgManager_ = manager;\n    }\n    std::shared_ptr<IStreamMsgManager> GetStreamMsgManager()\n    {\n        return msgManager_;\n    }\n\nprivate:\n    StreamManager(const StreamManager &) = delete;\n",
      "excerpt_sha256": "87e0a90950935b5afa98ae417cb86861c420f53f9f76544e4020268d8e6b2807",
      "note": "StreamManager manager pointer publication shape; representative fixed-source context.",
      "created_at": "2026-10-14T16:07:39.609219+00:00"
    },
    {
      "id": "10b0e18f46c548e5a805be053e47293f",
      "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
      "candidate_id": "d4f6c83d4d77c5fbbda5e1f1871be665c386f2ede09da177f6c2814f083469bf",
      "kind": "source_excerpt",
      "interpretation": "human_selected_context_not_path_or_runtime_proof",
      "repository": "openharmony/communication_dsoftbus",
      "commit": "652f88e0261ce4d0610f73cc451c26b84d2597af",
      "git_tree": "f8a14c30ef815217fa4d267939cff84db1fd5057",
      "snapshot_sha256": "5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7",
      "report_sha256": "0b49b21edbf4f65731f5840650fbaee0f1f6030cc700b8a40cf4e4dc1259868e",
      "file": "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h",
      "blob": "1f8eb2e331021766be3485a3b56746c074be4687",
      "source_sha256": "66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100",
      "start_line": 89,
      "end_line": 105,
      "text": "    void DestroyEnvironment(const std::string &pkgName) override;\n\n    void SetStreamMsgManager(std::shared_ptr<IStreamMsgManager> manager)\n    {\n        msgManager_ = manager;\n    }\n    std::shared_ptr<IStreamMsgManager> GetStreamMsgManager()\n    {\n        return msgManager_;\n    }\n\nprivate:\n    StreamManager(const StreamManager &) = delete;\n    StreamManager(StreamManager &&) = delete;\n    StreamManager &operator=(const StreamManager &) = delete;\n    StreamManager &operator=(StreamManager &&) = delete;\n\n",
      "excerpt_sha256": "133c98c52a4f7062be59d7bf3421b2642a0a9ceda028a808fa4f5d212bd1c910",
      "note": "StreamManager manager pointer publication shape; representative fixed-source context.",
      "created_at": "2026-10-14T16:07:40.483886+00:00"
    }
  ],
  "cases": [
    {
      "id": "af3f3c6a213444a08e5a26b63c1ad493",
      "title": "communication_dsoftbus: StreamManager manager pointer publication shape",
      "created_at": "2026-10-14T16:07:41.135510+00:00",
      "status": "investigation",
      "links": [
        {
          "case_id": "af3f3c6a213444a08e5a26b63c1ad493",
          "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
          "candidate_id": "34b5ae7d82474f0dd15f9274b14a620b5f333392c14aa67e6c871cbcee62d7b8",
          "rationale": "Review group RC-STREAM-MANAGER; candidate-level hypothesis only, not a shared root-cause proof."
        },
        {
          "case_id": "af3f3c6a213444a08e5a26b63c1ad493",
          "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
          "candidate_id": "d4f6c83d4d77c5fbbda5e1f1871be665c386f2ede09da177f6c2814f083469bf",
          "rationale": "Review group RC-STREAM-MANAGER; candidate-level hypothesis only, not a shared root-cause proof."
        }
      ]
    },
    {
      "id": "58ad4b0cd04b4e0d8222448b2c8832c1",
      "title": "communication_dsoftbus: StreamManager listener cross-file mutation",
      "created_at": "2026-10-14T16:07:40.778637+00:00",
      "status": "investigation",
      "links": [
        {
          "case_id": "58ad4b0cd04b4e0d8222448b2c8832c1",
          "job_id": "8e96ef0ed3dc4b809efdb22e56746ecb",
          "candidate_id": "1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7",
          "rationale": "Review group RC-STREAM-LISTENER; candidate-level hypothesis only, not a shared root-cause proof."
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
